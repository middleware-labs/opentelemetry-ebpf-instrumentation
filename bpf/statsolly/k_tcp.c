// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/sockaddr.h>

#include <logger/bpf_dbg.h>

#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/sock_role.h>
#include <statsolly/maps/sock_owner.h>
#include <statsolly/maps/tcp_sendmsg_sock.h>
#include <statsolly/maps/tcp_io_accum.h>
#include <statsolly/maps/tcp_cong_last.h>
#include <statsolly/maps/tcp_cong_drops.h>
#include <statsolly/tcp_counters.h>

enum {
    k_usec_per_sec = 1000000ULL,
    k_max_srtt_allowed = 60 * k_usec_per_sec,
};

typedef struct tcp_rtt {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_handshake_role role;
    u8 _pad[2];
    u32 srtt_us;
    connection_info_t conn;
    sock_owner_t owner;
} tcp_rtt_t;

typedef struct tcp_io {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum network_io_direction direction;
    u8 count;
    u8 _pad[1];
    u32 bytes[k_tcp_io_batch_size];
    connection_info_t conn;
    sock_owner_t owner;
} tcp_io_t;

typedef struct tcp_flow_control {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_flow_control_event event;
    enum tcp_handshake_role role;
    u8 _pad[1];
    connection_info_t conn;
    sock_owner_t owner;
} tcp_flow_control_t;

typedef struct tcp_congestion {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_handshake_role role;
    u8 _pad[2];
    tcp_cong_vals_t delta; // increase since the last event for this socket
    connection_info_t conn;
    sock_owner_t owner;
} tcp_congestion_t;

// To be injected from userspace during eBPF program load & initialization.
// Minimum time between two congestion events of the same socket. When 0, there is no rate limit.
volatile const u64 stats_congestion_min_interval_ns;

// Force structs into the ELF for automatic creation of Golang struct
const tcp_rtt_t *unused_tcp_rtt __attribute__((unused));
const tcp_io_t *unused_tcp_io __attribute__((unused));
const tcp_flow_control_t *unused_tcp_flow_control __attribute__((unused));
const tcp_congestion_t *unused_tcp_congestion __attribute__((unused));

static __always_inline void flush_tcp_io_accum(struct sock *sk,
                                               enum network_io_direction direction,
                                               const tcp_io_accum_t *accum) {
    tcp_io_t *se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("tcp_io_accum: stats_events ring buffer full, dropping batch");
        return;
    }
    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        bpf_ringbuf_discard(se, 0);
        return;
    }
    se->flags = k_stat_type_tcp_io;
    se->direction = direction;
    se->count = accum->count;
    bpf_memcpy(se->bytes, accum->bytes, sizeof(se->bytes));
    se->conn = conn;
    read_sock_owner(sk, &se->owner);
    bpf_ringbuf_submit(se, stats_events_flags());
}

static __always_inline void flush_and_delete_io_accum(struct sock *sk,
                                                      enum network_io_direction direction) {
    const tcp_io_accum_key_t key = {.sock_ptr = (u64)(uintptr_t)sk, .direction = direction};
    tcp_io_accum_t *accum = bpf_map_lookup_elem(&tcp_io_accum, &key);
    if (!accum) {
        return;
    }
    if (accum->count > 0) {
        flush_tcp_io_accum(sk, direction, accum);
    }
    bpf_map_delete_elem(&tcp_io_accum, &key);
}

static __always_inline void
accumulate_tcp_io(struct sock *sk, enum network_io_direction direction, u32 bytes) {
    const tcp_io_accum_key_t key = {.sock_ptr = (u64)(uintptr_t)sk, .direction = direction};
    tcp_io_accum_t *accum = bpf_map_lookup_elem(&tcp_io_accum, &key);
    if (!accum) {
        tcp_io_accum_t new_accum = {};
        new_accum.bytes[0] = bytes;
        new_accum.count = 1;
        if (bpf_map_update_elem(&tcp_io_accum, &key, &new_accum, BPF_NOEXIST) != 0) {
            bpf_d_printk("tcp_io_accum map full, dropping %u bytes", bytes);
        }
        return;
    }
    const u8 idx = accum->count;
    if (idx < k_tcp_io_batch_size) {
        accum->bytes[idx] = bytes;
        accum->count = idx + 1;
        if (accum->count >= k_tcp_io_batch_size) {
            flush_tcp_io_accum(sk, direction, accum);
            bpf_map_delete_elem(&tcp_io_accum, &key);
        }
    }
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_stats_kprobe_tcp_close_io_flush, struct sock *sk) {
    (void)ctx;
    flush_and_delete_io_accum(sk, direction_transmit);
    flush_and_delete_io_accum(sk, direction_receive);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_stats_kprobe_tcp_close_srtt, struct sock *sk) {
    (void)ctx;

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    if (is_tcp_socket_never_connected(sk)) {
        return 0;
    }

    u32 srtt_us = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);

    srtt_us = srtt_us >> 3; // undo the scaling to have the real us

    if (srtt_us == 0) {
        return 0;
    }

    if (srtt_us > k_max_srtt_allowed) {
        return 0;
    }

    tcp_rtt_t *se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_stat_type_tcp_rtt;
    se->srtt_us = srtt_us;
    se->conn = conn;
    const u8 *role_ptr = bpf_map_lookup_elem(&sock_role, &sk);
    se->role = role_ptr ? *role_ptr : role_unknown;
    read_sock_owner(sk, &se->owner);

    bpf_d_printk(
        "tcp rtt: s_port=%d, d_port=%d, srtt_us=%u", se->conn.s_port, se->conn.d_port, se->srtt_us);
    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(obi_stats_kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    (void)ctx;
    (void)msg;
    (void)size;
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_sendmsg_sock, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
// sent is an int: the upper half of the return register is undefined, and a failed send
// (-EAGAIN) read as a long is a positive number of bytes
int BPF_KRETPROBE(obi_stats_kretprobe_tcp_sendmsg, int sent) {
    (void)ctx;
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *const *skp = bpf_map_lookup_elem(&tcp_sendmsg_sock, &pid_tgid);

    if (!skp) {
        return 0;
    }
    struct sock *const sk = *skp;
    bpf_map_delete_elem(&tcp_sendmsg_sock, &pid_tgid);

    if (sent <= 0) {
        return 0;
    }

    accumulate_tcp_io(sk, direction_transmit, (u32)sent);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(obi_stats_kprobe_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    (void)ctx;

    if (copied <= 0) {
        return 0;
    }

    accumulate_tcp_io(sk, direction_receive, (u32)copied);
    return 0;
}

// tcp_send_probe0 is called by the probe timer once per zero-window probe, while
// the peer keeps advertising a zero receive window: one event per probe.
SEC("kprobe/tcp_send_probe0")
int BPF_KPROBE(obi_stats_kprobe_tcp_send_probe0, struct sock *sk) {
    (void)ctx;

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    tcp_flow_control_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_stat_type_tcp_flow_control;
    se->event = flow_control_event_zero_window;
    const u8 *role_ptr = bpf_map_lookup_elem(&sock_role, &sk);
    se->role = role_ptr ? *role_ptr : role_unknown;
    se->conn = conn;
    read_sock_owner(sk, &se->owner);

    bpf_d_printk("tcp zero window probe: s_port=%d, d_port=%d", conn.s_port, conn.d_port);
    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}

// The kernel keeps delivered_ce, reord_seen and rcv_ooopack as per-socket totals and updates them
// from softirq. We read them at send, receive and close, and send the increase since the last event.
static __always_inline bool cong_vals_zero(const tcp_cong_vals_t *vals) {
    return !(vals->delivered_ce | vals->reord_seen | vals->rcv_ooopack);
}

static __always_inline bool cong_vals_went_back(const tcp_cong_vals_t *cur,
                                                const tcp_cong_vals_t *sent) {
    return cur->delivered_ce < sent->delivered_ce || cur->reord_seen < sent->reord_seen ||
           cur->rcv_ooopack < sent->rcv_ooopack;
}

static __always_inline void count_tcp_congestion_drop(void) {
    const u32 key = 0;
    u64 *const drops = bpf_map_lookup_elem(&tcp_cong_drops, &key);
    if (drops) {
        *drops += 1;
    }
}

static __always_inline bool emit_tcp_congestion(struct sock *sk, const tcp_cong_vals_t *delta) {
    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return false;
    }

    tcp_congestion_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        count_tcp_congestion_drop();
        return false;
    }

    se->flags = k_stat_type_tcp_congestion;
    const u8 *role_ptr = bpf_map_lookup_elem(&sock_role, &sk);
    se->role = role_ptr ? *role_ptr : role_unknown;
    se->delta = *delta;
    se->conn = conn;
    read_sock_owner(sk, &se->owner);

    bpf_d_printk("tcp congestion: s_port=%d, d_port=%d", conn.s_port, conn.d_port);
    bpf_ringbuf_submit(se, stats_events_flags());

    return true;
}

static __always_inline void track_tcp_congestion(struct sock *sk, const bool closing) {
    tcp_cong_vals_t cur = {};
    read_cong_vals(sk, &cur);

    const tcp_cong_last_t *last = bpf_map_lookup_elem(&tcp_cong_last, &sk);

    // healthy socket that never had a problem: no map write, no event
    if (!last && cong_vals_zero(&cur)) {
        return;
    }

    tcp_cong_vals_t sent = {};
    u64 last_emit_ns = 0;
    if (last) {
        sent = last->sent;
        last_emit_ns = last->last_emit_ns;
        // a stale entry from a reused struct sock address: count from 0 again
        if (cong_vals_went_back(&cur, &sent)) {
            sent = (tcp_cong_vals_t){};
        }
    }

    const tcp_cong_vals_t delta = {
        .delivered_ce = cur.delivered_ce - sent.delivered_ce,
        .reord_seen = cur.reord_seen - sent.reord_seen,
        .rcv_ooopack = cur.rcv_ooopack - sent.rcv_ooopack,
    };

    if (!cong_vals_zero(&delta)) {
        const u64 now = bpf_ktime_get_ns();
        const bool rate_ok =
            closing || !last || now - last_emit_ns >= stats_congestion_min_interval_ns;

        // the baseline moves only after a successful send, so a full ring buffer delays the delta
        if (rate_ok && emit_tcp_congestion(sk, &delta) && !closing) {
            const tcp_cong_last_t upd = {.sent = cur, .last_emit_ns = now};
            bpf_map_update_elem(&tcp_cong_last, &sk, &upd, BPF_ANY);
        }
    }

    if (closing && last) {
        bpf_map_delete_elem(&tcp_cong_last, &sk);
    }
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(obi_stats_kprobe_tcp_sendmsg_congestion, struct sock *sk) {
    (void)ctx;
    track_tcp_congestion(sk, false);
    return 0;
}

// every receive path (recvmsg, splice, kTLS, zerocopy) ends in tcp_cleanup_rbuf
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(obi_stats_kprobe_tcp_cleanup_rbuf_congestion, struct sock *sk) {
    (void)ctx;
    track_tcp_congestion(sk, false);
    return 0;
}

// final flush: ignores the rate limit and forgets the socket
SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_stats_kprobe_tcp_close_congestion, struct sock *sk) {
    (void)ctx;
    track_tcp_congestion(sk, true);
    return 0;
}
