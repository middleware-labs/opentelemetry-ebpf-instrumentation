// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_endian.h>

#include <common/connection_info.h>
#include <common/sock_port_ns.h>
#include <common/sockaddr.h>

#include <logger/bpf_dbg.h>

#include <statsolly/inet_sock_set_state.h>
#include <statsolly/tcp_counters.h>
#include <statsolly/types.h>
#include <statsolly/maps/sock_owner.h>
#include <statsolly/maps/sock_role.h>
#include <statsolly/maps/socket_traffic.h>
#include <statsolly/maps/socket_traffic_bind_sock.h>
#include <statsolly/maps/socket_traffic_closed.h>
#include <statsolly/maps/socket_traffic_drops.h>
#include <statsolly/maps/socket_traffic_sendmsg_sock.h>
#include <statsolly/maps/socket_traffic_udp_dport.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/udp_port_bindings.h>

// Bytes and packets per socket, counted where the application sends and reads them, with
// the row lifecycle of Datadog's conn_stats: the rows hold totals, user space reads them
// periodically without deleting them, and a closed socket sends its final row once.

enum {
    // ip_make_skb and ip6_make_skb return ERR_PTR(-errno) on failure
    k_max_errno = 4095,
    k_ip_version_4 = 4,
    k_ip_version_6 = 6,
};

// To be injected from userspace: the TCP rows also hold the TCP stat metrics
volatile const bool stats_tcp_metrics_enabled = false;

// Force structs into the ELF for automatic creation of Golang struct
const socket_traffic_key_t *unused_socket_traffic_key __attribute__((unused));
const socket_traffic_t *unused_socket_traffic __attribute__((unused));
const socket_traffic_closed_t *unused_socket_traffic_closed __attribute__((unused));
const enum socket_traffic_drop *unused_socket_traffic_drop __attribute__((unused));

static __always_inline void count_socket_traffic_drop(const enum socket_traffic_drop drop) {
    const u32 index = drop;
    u64 *const drops = bpf_map_lookup_elem(&socket_traffic_drops, &index);
    if (drops) {
        *drops += 1;
    }
}

// A UDP socket bound to its local port is the server side, like Datadog's
// determine_connection_direction.
static __always_inline enum tcp_handshake_role udp_role(const socket_traffic_key_t *const key) {
    const struct sock_port_ns pn = {.netns = key->netns, .port = key->conn.s_port};
    return bpf_map_lookup_elem(&udp_port_bindings, &pn) ? role_server : role_client;
}

static __always_inline enum tcp_handshake_role tcp_role(struct sock *const sk) {
    const u8 *const role = bpf_map_lookup_elem(&sock_role, &sk);
    return role ? *role : role_unknown;
}

static __always_inline void
set_row_process(struct sock *const sk, socket_traffic_t *const row, const bool in_process) {
    if (in_process) {
        row->cgroup_id = bpf_get_current_cgroup_id();
        row->pid = bpf_get_current_pid_tgid() >> 32;
        current_exe_name(row->exe_name);
        return;
    }
    // softirq or timer: the current task is not the application
    if (!stats_sock_owner_enabled) {
        return;
    }
    const sock_owner_t *const owner = find_sock_owner(sk);
    if (owner) {
        row->cgroup_id = (u64)owner->cgroup_id_hi << 32 | owner->cgroup_id_lo;
        row->pid = owner->pid;
        __builtin_memcpy(row->exe_name, owner->exe_name, sizeof(row->exe_name));
    }
}

// in_process is false in softirq and timers: the row then takes the process of the socket from
// sock_owner, or none, and the first send or receive sets it.
static __always_inline socket_traffic_t *socket_traffic_row(const socket_traffic_key_t *const key,
                                                            struct sock *const sk,
                                                            const bool in_process) {
    socket_traffic_t *row = bpf_map_lookup_elem(&socket_traffic, key);
    if (row) {
        if (!row->pid && in_process) {
            set_row_process(sk, row, true);
        }
        return row;
    }

    // last_update_ns is set at creation, so user space never takes a new row for an idle one
    socket_traffic_t new_row = {
        .last_update_ns = bpf_ktime_get_ns(),
        .sock = key->protocol == IPPROTO_TCP ? (u64)(uintptr_t)sk : 0,
        .role = key->protocol == IPPROTO_TCP ? tcp_role(sk) : udp_role(key),
    };
    set_row_process(sk, &new_row, in_process);

    // another CPU might create the same row in between: BPF_NOEXIST keeps theirs
    bpf_map_update_elem(&socket_traffic, key, &new_row, BPF_NOEXIST);
    row = bpf_map_lookup_elem(&socket_traffic, key);
    if (!row) {
        count_socket_traffic_drop(k_socket_traffic_drop_insert);
    }
    return row;
}

static __always_inline bool tcp_traffic_key(struct sock *const sk,
                                            socket_traffic_key_t *const key) {
    if (!parse_sock_info(sk, &key->conn)) {
        return false;
    }
    // a reset or timed out connection releases its port (inet_num = 0) before the application
    // closes it: inet_sport keeps it, so tcp_close still finds the row
    if (!key->conn.s_port) {
        key->conn.s_port = bpf_ntohs(BPF_CORE_READ((struct inet_sock *)sk, inet_sport));
    }
    key->netns = sock_netns(sk);
    key->protocol = IPPROTO_TCP;
    return true;
}

// TCP packets are the socket totals, like Datadog's get_tcp_segment_counts: user space
// computes their increases. With the TCP stat metrics, also the RTT and the congestion totals,
// like Datadog's handle_tcp_stats.
static __always_inline void store_tcp_counters(struct sock *const sk, socket_traffic_t *const row) {
    const struct tcp_sock *const tp = (const struct tcp_sock *)sk;
    row->tx_packets = BPF_CORE_READ(tp, segs_out) - row->tx_segs_base;
    row->rx_packets = BPF_CORE_READ(tp, segs_in) - row->rx_segs_base;
    if (!stats_tcp_metrics_enabled) {
        return;
    }

    // undo the scaling to have the real us
    row->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
    tcp_cong_vals_t cong = {};
    read_cong_vals(sk, &cong);
    row->delivered_ce = cong.delivered_ce - row->delivered_ce_base;
    row->reord_seen = cong.reord_seen - row->reord_seen_base;
    row->rcv_ooopack = cong.rcv_ooopack - row->rcv_ooopack_base;
}

static __always_inline bool tcp_fin_received(struct sock *const sk) {
    const unsigned long flags = BPF_CORE_READ(sk, __sk_common.skc_flags);
    return flags & (1UL << bpf_core_enum_value(enum sock_flags, SOCK_DONE));
}

// The bytes the application has read from the socket since it opened, like Datadog's
// tcp_recvmsg return value. copied_seq only moves when data is consumed, so a MSG_PEEK read
// adds nothing, and the extra tcp_cleanup_rbuf calls of a recvmsg waiting for MSG_WAITALL
// or SO_RCVLOWAT add only the new bytes. Only call it with the socket locked: the softirq
// updates bytes_received and rcv_nxt one after the other.
static __always_inline u64 tcp_bytes_read(struct sock *const sk) {
    const struct tcp_sock *const tp = (const struct tcp_sock *)sk;
    const u64 received = BPF_CORE_READ(tp, bytes_received);
    const u32 unread = BPF_CORE_READ(tp, rcv_nxt) - BPF_CORE_READ(tp, copied_seq);

    // the FIN takes one sequence number, counted in bytes_received and rcv_nxt: it cancels
    // out until the application reads it, then copied_seq counts it too
    if (unread == 0 && received > 0 && tcp_fin_received(sk)) {
        return received - 1;
    }
    return received - unread;
}

// A new connection with the same addresses found the row of another one: a closed one whose
// close event was lost (sock is then 0, as its struct sock may be reused by the new one), or
// one that got a reset and is not closed yet. Its counters continue the row's totals.
static __always_inline void adopt_tcp_row(struct sock *const sk, socket_traffic_t *const row) {
    if (row->sock == (u64)(uintptr_t)sk) {
        return;
    }
    row->sock = (u64)(uintptr_t)sk;
    row->rx_base_set = 0;
    row->tx_segs_base = 0 - row->tx_packets;
    row->rx_segs_base = 0 - row->rx_packets;
    row->delivered_ce_base = 0 - row->delivered_ce;
    row->reord_seen_base = 0 - row->reord_seen;
    row->rcv_ooopack_base = 0 - row->rcv_ooopack;
}

// Runs in tcp_cleanup_rbuf, where the socket is locked. The first read of a connection sets
// the base: it counts its own bytes, at most copied (none for MSG_PEEK), and continues the
// row's total.
static __always_inline void
count_tcp_read(struct sock *const sk, socket_traffic_t *const row, const u32 copied) {
    const u64 read = tcp_bytes_read(sk);
    if (!row->rx_base_set) {
        const u64 consumed = read < copied ? read : copied;
        row->rx_read_base = read - consumed - row->rx_bytes;
        row->rx_base_set = 1;
    }
    // only grows: another CPU might have stored a newer total
    const s64 rx_bytes = (s64)(read - row->rx_read_base);
    if (rx_bytes > (s64)row->rx_bytes) {
        row->rx_bytes = rx_bytes;
    }
}

// Sends the final row of a closed socket to user space and deletes it, like Datadog's
// conn_close_event. The row is deleted before the event is submitted, so user space never
// reads it from the map after handling the close event. When the event cannot be reserved,
// the row is kept: user space reads it later and deletes it once it is idle.
static __always_inline void flush_closed_row(const socket_traffic_key_t *const key,
                                             struct sock *const sk) {
    socket_traffic_t *const row = bpf_map_lookup_elem(&socket_traffic, key);
    if (!row) {
        return;
    }
    if (key->protocol == IPPROTO_TCP) {
        // a connection that got a reset can be closed after a new one with the same
        // addresses took the row over: that row is not its own
        if (row->sock != (u64)(uintptr_t)sk) {
            return;
        }
        store_tcp_counters(sk, row);
    }

    socket_traffic_closed_t *const event =
        bpf_ringbuf_reserve(&socket_traffic_closed, sizeof(*event), 0);
    if (!event) {
        count_socket_traffic_drop(k_socket_traffic_drop_close);
        // the next connection with the same addresses takes the row over
        row->sock = 0;
        return;
    }
    event->key = *key;
    __builtin_memset(event->_pad, 0, sizeof(event->_pad));
    event->value = *row;

    bpf_map_delete_elem(&socket_traffic, key);
    bpf_ringbuf_submit(event, stats_ringbuf_flags(&socket_traffic_closed));
}

// rx_copied is the copied argument of tcp_cleanup_rbuf, 0 when sending
static __always_inline void
count_tcp_traffic(struct sock *const sk, const u32 tx_bytes, const u32 rx_copied) {
    socket_traffic_key_t key = {};
    if (!tcp_traffic_key(sk, &key)) {
        return;
    }

    socket_traffic_t *const row = socket_traffic_row(&key, sk, true);
    if (!row) {
        return;
    }
    adopt_tcp_row(sk, row);

    if (tx_bytes) {
        __sync_fetch_and_add(&row->tx_bytes, tx_bytes);
    }
    if (rx_copied) {
        count_tcp_read(sk, row, rx_copied);
    }
    store_tcp_counters(sk, row);
    row->last_update_ns = bpf_ktime_get_ns();
}

static __always_inline bool sock_dead(struct sock *const sk) {
    const unsigned long flags = BPF_CORE_READ(sk, __sk_common.skc_flags);
    return flags & (1UL << bpf_core_enum_value(enum sock_flags, SOCK_DEAD));
}

// A row created after the application closed its socket (its last row was already sent) only
// counts from now on: the socket totals are the bases.
static __always_inline void count_from_now(struct sock *const sk, socket_traffic_t *const row) {
    const struct tcp_sock *const tp = (const struct tcp_sock *)sk;
    tcp_cong_vals_t cong = {};
    read_cong_vals(sk, &cong);
    row->tx_segs_base = BPF_CORE_READ(tp, segs_out);
    row->rx_segs_base = BPF_CORE_READ(tp, segs_in);
    row->delivered_ce_base = cong.delivered_ce;
    row->reord_seen_base = cong.reord_seen;
    row->rcv_ooopack_base = cong.rcv_ooopack;
}

// The row of a TCP event that runs in softirq or a timer, created if needed
static __always_inline socket_traffic_t *tcp_event_row(struct sock *const sk) {
    socket_traffic_key_t key = {};
    if (!tcp_traffic_key(sk, &key)) {
        return NULL;
    }
    socket_traffic_t *row = bpf_map_lookup_elem(&socket_traffic, &key);
    if (!row) {
        row = socket_traffic_row(&key, sk, false);
        if (row && sock_dead(sk)) {
            count_from_now(sk, row);
        }
    }
    if (!row) {
        return NULL;
    }
    adopt_tcp_row(sk, row);
    return row;
}

// A connection is established: its row is created, so the connections without data are counted
// too. The role comes from the handshake.
SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_tcp_row(struct trace_event_raw_inet_sock_set_state *args) {
    if (!inet_sock_set_state_tcp(args) || args->newstate != TCP_ESTABLISHED ||
        (args->oldstate != TCP_SYN_SENT && args->oldstate != TCP_SYN_RECV)) {
        return 0;
    }

    struct sock *const sk = (struct sock *)args->skaddr;
    socket_traffic_t *const row = tcp_event_row(sk);
    if (!row) {
        return 0;
    }
    row->role = args->oldstate == TCP_SYN_SENT ? role_client : role_server;
    __sync_fetch_and_add(&row->established, 1);
    store_tcp_counters(sk, row);
    row->last_update_ns = bpf_ktime_get_ns();
    return 0;
}

// The segments of a retransmitted skb: tcp_skb_pcount(skb), what __tcp_retransmit_skb adds to
// total_retrans and TcpRetransSegs before this tracepoint fires
static __always_inline u32 retransmitted_segs(struct sk_buff *const skb) {
    const struct tcp_skb_cb *const cb = (const struct tcp_skb_cb *)&skb->cb;
    const u16 segs = BPF_CORE_READ(cb, tcp_gso_segs);
    return segs ? segs : 1;
}

// Counts the retransmitted segments, like Datadog's tcp_retransmit_skb probes, including the
// SYN retransmits. The retransmit events count one per tcp_retransmit_skb.
SEC("raw_tracepoint/tcp_retransmit_skb")
int obi_stats_raw_tp_tcp_retransmit_skb_row(struct bpf_raw_tracepoint_args *ctx) {
    struct sock *const sk = (struct sock *)ctx->args[0];
    socket_traffic_t *const row = tcp_event_row(sk);
    if (!row) {
        return 0;
    }
    const u32 segs = retransmitted_segs((struct sk_buff *)ctx->args[1]);
    switch (sk_retransmit_type(sk)) {
    case retransmit_type_fast:
        __sync_fetch_and_add(&row->retrans_fast, segs);
        break;
    case retransmit_type_timeout:
        __sync_fetch_and_add(&row->retrans_timeout, segs);
        break;
    default:
        __sync_fetch_and_add(&row->retrans_other, segs);
        break;
    }
    row->last_update_ns = bpf_ktime_get_ns();
    return 0;
}

// Like the flow control events, one per zero window probe
SEC("kprobe/tcp_send_probe0")
int BPF_KPROBE(obi_stats_kprobe_tcp_send_probe0_row, struct sock *sk) {
    (void)ctx;
    socket_traffic_t *const row = tcp_event_row(sk);
    if (!row) {
        return 0;
    }
    __sync_fetch_and_add(&row->zero_window_probes, 1);
    row->last_update_ns = bpf_ktime_get_ns();
    return 0;
}

static __always_inline void save_tcp_send_sock(struct sock *const sk) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&socket_traffic_sendmsg_sock, &pid_tgid, &sk, BPF_ANY);
}

static __always_inline void count_tcp_sent(const int sent) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *const *const skp = bpf_map_lookup_elem(&socket_traffic_sendmsg_sock, &pid_tgid);
    if (!skp) {
        return;
    }
    struct sock *const sk = *skp;
    bpf_map_delete_elem(&socket_traffic_sendmsg_sock, &pid_tgid);

    if (sent <= 0) {
        return;
    }

    count_tcp_traffic(sk, (u32)sent, 0);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(obi_stats_kprobe_tcp_sendmsg_traffic, struct sock *sk) {
    (void)ctx;
    save_tcp_send_sock(sk);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(obi_stats_kretprobe_tcp_sendmsg_traffic, int sent) {
    (void)ctx;
    count_tcp_sent(sent);
    return 0;
}

// sendfile() and splice() before kernel 6.5. Without scatter-gather, tcp_sendpage falls
// back to tcp_sendmsg_locked, not tcp_sendmsg, so the bytes are not counted twice.
SEC("kprobe/tcp_sendpage")
int BPF_KPROBE(obi_stats_kprobe_tcp_sendpage_traffic, struct sock *sk) {
    (void)ctx;
    save_tcp_send_sock(sk);
    return 0;
}

SEC("kretprobe/tcp_sendpage")
int BPF_KRETPROBE(obi_stats_kretprobe_tcp_sendpage_traffic, int sent) {
    (void)ctx;
    count_tcp_sent(sent);
    return 0;
}

// every receive path (recvmsg, splice, kTLS, zerocopy) ends in tcp_cleanup_rbuf. It is also
// called for MSG_PEEK and several times per recvmsg waiting for MSG_WAITALL, so the bytes
// come from tcp_bytes_read, not from copied.
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(obi_stats_kprobe_tcp_cleanup_rbuf_traffic, struct sock *sk, int copied) {
    (void)ctx;
    if (copied <= 0) {
        return 0;
    }

    count_tcp_traffic(sk, 0, (u32)copied);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_stats_kprobe_tcp_close_traffic, struct sock *sk) {
    (void)ctx;
    socket_traffic_key_t key = {};
    if (!tcp_traffic_key(sk, &key)) {
        return 0;
    }

    flush_closed_row(&key, sk);
    return 0;
}

// With the TCP stat metrics, the rows of the sockets that end without tcp_close
static __always_inline void flush_ended_row(struct sock *const sk) {
    // sk_protocol is a bitfield before kernel 5.6
    if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP) {
        return;
    }
    socket_traffic_key_t key = {};
    if (tcp_traffic_key(sk, &key)) {
        flush_closed_row(&key, sk);
    }
}

// a connection that the listener never accepted is disconnected, which clears its addresses,
// before it is destroyed
SEC("kprobe/tcp_disconnect")
int BPF_KPROBE(obi_stats_kprobe_tcp_disconnect_row, struct sock *sk) {
    (void)ctx;
    flush_ended_row(sk);
    return 0;
}

// a closed socket whose late retransmits created a row again
SEC("kprobe/inet_csk_destroy_sock")
int BPF_KPROBE(obi_stats_kprobe_inet_csk_destroy_sock_row, struct sock *sk) {
    (void)ctx;
    flush_ended_row(sk);
    return 0;
}

// Reads the IPv4 or IPv6 addresses of the skb's network header into conn: s_addr is
// the local address and d_addr the remote one. A sent packet has the local address as
// source, a received one as destination.
static __always_inline bool skb_ip_addrs(const unsigned char *const head,
                                         const u16 network_header,
                                         const bool outgoing,
                                         connection_info_t *const conn) {
    const unsigned char *const nh = head + network_header;
    u8 version_ihl = 0;
    bpf_probe_read_kernel(&version_ihl, sizeof(version_ihl), nh);

    switch (version_ihl >> 4) {
    case k_ip_version_4: {
        struct iphdr ip;
        bpf_probe_read_kernel(&ip, sizeof(ip), nh);
        const __be32 local = outgoing ? ip.saddr : ip.daddr;
        const __be32 remote = outgoing ? ip.daddr : ip.saddr;
        __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(conn->s_addr + sizeof(ip4ip6_prefix), &local, sizeof(local));
        __builtin_memcpy(conn->d_addr + sizeof(ip4ip6_prefix), &remote, sizeof(remote));
        return true;
    }
    case k_ip_version_6: {
        struct ipv6hdr ip6;
        bpf_probe_read_kernel(&ip6, sizeof(ip6), nh);
        __builtin_memcpy(conn->s_addr, outgoing ? &ip6.saddr : &ip6.daddr, sizeof(ip6.saddr));
        __builtin_memcpy(conn->d_addr, outgoing ? &ip6.daddr : &ip6.saddr, sizeof(ip6.daddr));
        return true;
    }
    default:
        return false;
    }
}

static __always_inline void count_udp_traffic(struct sock *const sk,
                                              const socket_traffic_key_t *const key,
                                              const u32 tx_bytes,
                                              const u32 rx_bytes) {
    socket_traffic_t *const row = socket_traffic_row(key, sk, true);
    if (!row) {
        return;
    }

    if (tx_bytes) {
        __sync_fetch_and_add(&row->tx_bytes, tx_bytes);
        __sync_fetch_and_add(&row->tx_packets, 1);
    }
    if (rx_bytes) {
        __sync_fetch_and_add(&row->rx_bytes, rx_bytes);
        __sync_fetch_and_add(&row->rx_packets, 1);
    }
    row->last_update_ns = bpf_ktime_get_ns();
}

// Saves the destination port of sendto() / sendmsg(), like Datadog takes it from the flowi4
// of ip_make_skb. Without an address, the socket is connected and has its own remote port.
static __always_inline void save_udp_dport(struct msghdr *const msg) {
    struct sockaddr *const addr = BPF_CORE_READ(msg, msg_name);
    const u16 dport = addr ? get_sockaddr_port(addr) : 0;
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    if (dport) {
        bpf_map_update_elem(&socket_traffic_udp_dport, &pid_tgid, &dport, BPF_ANY);
        return;
    }
    if (bpf_map_lookup_elem(&socket_traffic_udp_dport, &pid_tgid)) {
        bpf_map_delete_elem(&socket_traffic_udp_dport, &pid_tgid);
    }
}

static __always_inline u16 udp_sent_dport(struct sock *const sk) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u16 *const dport = bpf_map_lookup_elem(&socket_traffic_udp_dport, &pid_tgid);
    if (dport) {
        return *dport;
    }
    return bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

// udpv6_sendmsg calls udp_sendmsg for IPv4-mapped destinations, which saves the port again
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(obi_stats_kprobe_udp_sendmsg_traffic, struct sock *sk, struct msghdr *msg) {
    (void)ctx;
    (void)sk;
    save_udp_dport(msg);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(obi_stats_kprobe_udpv6_sendmsg_traffic, struct sock *sk, struct msghdr *msg) {
    (void)ctx;
    (void)sk;
    save_udp_dport(msg);
    return 0;
}

// The returned skb holds one whole datagram: the IP header is built, the UDP header
// is only reserved and filled later. The addresses come from the IP header, so the
// unconnected sockets get the destination of each datagram. The local port comes from
// the socket, the remote port from the udp_sendmsg probes.
static __always_inline void count_udp_sent_skb(struct sk_buff *const skb) {
    if (!skb || (unsigned long)skb >= (unsigned long)-k_max_errno) {
        return;
    }

    struct sock *const sk = BPF_CORE_READ(skb, sk);
    if (!sk) {
        return;
    }

    const unsigned char *const head = BPF_CORE_READ(skb, head);
    const u16 network_header = BPF_CORE_READ(skb, network_header);
    const u16 transport_header = BPF_CORE_READ(skb, transport_header);
    const u32 len = BPF_CORE_READ(skb, len);

    // skb->data is at the network header: len counts the IP headers, the UDP header and the payload
    const u32 headers_len = (u32)(transport_header - network_header) + sizeof(struct udphdr);
    if (transport_header < network_header || len <= headers_len) {
        return;
    }

    socket_traffic_key_t key = {};
    if (!skb_ip_addrs(head, network_header, true, &key.conn)) {
        return;
    }
    key.conn.s_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.conn.d_port = udp_sent_dport(sk);
    key.netns = sock_netns(sk);
    key.protocol = IPPROTO_UDP;

    count_udp_traffic(sk, &key, len - headers_len, 0);
}

SEC("kretprobe/ip_make_skb")
int BPF_KRETPROBE(obi_stats_kretprobe_ip_make_skb_traffic, struct sk_buff *skb) {
    (void)ctx;
    count_udp_sent_skb(skb);
    return 0;
}

SEC("kretprobe/ip6_make_skb")
int BPF_KRETPROBE(obi_stats_kretprobe_ip6_make_skb_traffic, struct sk_buff *skb) {
    (void)ctx;
    count_udp_sent_skb(skb);
    return 0;
}

// udp_recvmsg and udpv6_recvmsg call it once per datagram read, with the payload bytes
// copied to the application (negative when peeking or on error).
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(obi_stats_kprobe_skb_consume_udp_traffic,
               struct sock *sk,
               struct sk_buff *skb,
               int len) {
    (void)ctx;
    if (len <= 0) {
        return 0;
    }

    const unsigned char *const head = BPF_CORE_READ(skb, head);
    const u16 network_header = BPF_CORE_READ(skb, network_header);
    const u16 transport_header = BPF_CORE_READ(skb, transport_header);

    socket_traffic_key_t key = {};
    if (!skb_ip_addrs(head, network_header, false, &key.conn)) {
        return 0;
    }

    struct udphdr udp;
    bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header);
    key.conn.s_port = bpf_ntohs(udp.dest);
    key.conn.d_port = bpf_ntohs(udp.source);
    key.netns = sock_netns(sk);
    key.protocol = IPPROTO_UDP;

    count_udp_traffic(sk, &key, 0, (u32)len);
    return 0;
}

static __always_inline void unbind_udp_port(struct sock *const sk) {
    const struct sock_port_ns pn = sock_port_ns_from_sk(sk);
    u32 *const count = bpf_map_lookup_elem(&udp_port_bindings, &pn);
    if (!count) {
        return;
    }
    if (*count <= 1) {
        bpf_map_delete_elem(&udp_port_bindings, &pn);
        return;
    }
    __sync_fetch_and_add(count, -1);
}

// Only a connected socket has a row keyed by its own addresses: the rows of the
// unconnected sockets (one per remote) leave through the user space idle cleanup.
static __always_inline void udp_socket_destroyed(struct sock *const sk) {
    socket_traffic_key_t key = {};
    if (parse_sock_info(sk, &key.conn)) {
        key.netns = sock_netns(sk);
        key.protocol = IPPROTO_UDP;
        flush_closed_row(&key, sk);
    }
    unbind_udp_port(sk);
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(obi_stats_kprobe_udp_destroy_sock_traffic, struct sock *sk) {
    (void)ctx;
    udp_socket_destroyed(sk);
    return 0;
}

SEC("kprobe/udpv6_destroy_sock")
int BPF_KPROBE(obi_stats_kprobe_udpv6_destroy_sock_traffic, struct sock *sk) {
    (void)ctx;
    udp_socket_destroyed(sk);
    return 0;
}

static __always_inline void save_bind_sock(struct socket *const sock, struct sockaddr *const addr) {
    // binds to port 0 are most likely clients, not servers: Datadog's sys_enter_bind skips them
    if (!get_sockaddr_port(addr)) {
        return;
    }
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&socket_traffic_bind_sock, &pid_tgid, &sock, BPF_ANY);
}

// Counts the local port of a UDP socket after a successful bind(), like Datadog's
// add_port_bind.
static __always_inline void bind_udp_port(const int ret) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    struct socket *const *const sockp = bpf_map_lookup_elem(&socket_traffic_bind_sock, &pid_tgid);
    if (!sockp) {
        return;
    }
    struct socket *const sock = *sockp;
    bpf_map_delete_elem(&socket_traffic_bind_sock, &pid_tgid);

    if (ret != 0) {
        return;
    }

    struct sock *const sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        return;
    }
    // sk_protocol is a bitfield before kernel 5.6
    if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_UDP) {
        return;
    }

    const struct sock_port_ns pn = sock_port_ns_from_sk(sk);
    u32 *count = bpf_map_lookup_elem(&udp_port_bindings, &pn);
    if (!count) {
        const u32 one = 1;
        if (bpf_map_update_elem(&udp_port_bindings, &pn, &one, BPF_NOEXIST) == 0) {
            return;
        }
        // another CPU bound the same port in between
        count = bpf_map_lookup_elem(&udp_port_bindings, &pn);
        if (!count) {
            return;
        }
    }
    __sync_fetch_and_add(count, 1);
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(obi_stats_kprobe_inet_bind_traffic, struct socket *sock, struct sockaddr *addr) {
    (void)ctx;
    save_bind_sock(sock, addr);
    return 0;
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(obi_stats_kretprobe_inet_bind_traffic, int ret) {
    (void)ctx;
    bind_udp_port(ret);
    return 0;
}

SEC("kprobe/inet6_bind")
int BPF_KPROBE(obi_stats_kprobe_inet6_bind_traffic, struct socket *sock, struct sockaddr *addr) {
    (void)ctx;
    save_bind_sock(sock, addr);
    return 0;
}

SEC("kretprobe/inet6_bind")
int BPF_KRETPROBE(obi_stats_kretprobe_inet6_bind_traffic, int ret) {
    (void)ctx;
    bind_udp_port(ret);
    return 0;
}
