// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/pin_internal.h>
#include <common/sock_port_ns.h>
#include <common/sockaddr.h>

#include <statsolly/exe_name.h>

// The process of a TCP socket, added to each TCP stat event. Many of them run where the current
// task is not the application (softirq, timers): handshakes, retransmits, zero window probes.
// The cgroup ID is split because the stat events are only 4-byte aligned.
typedef struct sock_owner {
    u32 pid;
    u32 netns; // of the socket, to find the other side of a loopback connection
    u32 cgroup_id_lo;
    u32 cgroup_id_hi;
    unsigned char exe_name[k_exe_name_len];
} sock_owner_t;

// A local socket address. The network namespace is only set for the loopback and the any
// addresses, which exist in every namespace.
typedef struct endpoint_key {
    unsigned char addr[16];
    u32 netns;
    u16 port;
    u8 _pad[2];
} endpoint_key_t;

// When an address has two records (its own and its listener's), the newer one is used: the
// server restarted since the address was last used
typedef struct endpoint_owner {
    sock_owner_t owner;
    u64 recorded_ns;
} endpoint_owner_t;

// An entry of sock_owner, with the connection it belongs to. A struct sock is reused by new
// sockets, and the delete of a closed one can be missed: the kernel skips a tracing program that
// fires while another one runs on the same CPU. Like Datadog keys tcp_ongoing_connect_pid by the
// socket and its tuple, an entry only names the socket of the same connection.
typedef struct sock_owner_entry {
    sock_owner_t owner;
    unsigned char daddr[16];
    u16 dport;
    u16 sport; // 0 when recorded before the local port was chosen
    u8 _pad[4];
} sock_owner_entry_t;

// The process of each socket, like Datadog's tcp_ongoing_connect_pid: written by connect() for
// the clients, by the first send or receive for the others. Deleted when the socket closes.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct sock *);
    __type(value, sock_owner_entry_t);
    __uint(max_entries, 1 << 16);
    __uint(pinning, OBI_PIN_INTERNAL);
} sock_owner SEC(".maps");

// The process of each local address: the listeners, and the sockets above. It names the server
// of a new connection before the application reads it, and user space finds in it the remote
// process of a connection on this host. Not deleted on close, so it can be read after the close:
// a reused address overwrites it.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, endpoint_key_t);
    __type(value, endpoint_owner_t);
    __uint(max_entries, 1 << 16);
    __uint(pinning, OBI_PIN_INTERNAL);
} endpoint_owner SEC(".maps");

// To be injected from userspace: 0 when no process or container attribute of the TCP stat
// metrics is selected. The stat events then do not look up the process of their socket.
volatile const bool stats_sock_owner_enabled = false;

// The loopback and the any addresses exist in every network namespace
static __always_inline bool needs_netns(const unsigned char *const addr) {
    bool v4_mapped = true;
    bool v6_any_or_loopback = addr[15] <= 1;
    for (u8 i = 0; i < sizeof(ip4ip6_prefix); i++) {
        v4_mapped = v4_mapped && addr[i] == ip4ip6_prefix[i];
    }
    for (u8 i = 0; i < 15; i++) {
        v6_any_or_loopback = v6_any_or_loopback && addr[i] == 0;
    }
    const unsigned char *const v4 = addr + sizeof(ip4ip6_prefix);
    const bool v4_any = !(v4[0] | v4[1] | v4[2] | v4[3]);
    return (v4_mapped && (v4[0] == 127 || v4_any)) || v6_any_or_loopback;
}

static __always_inline bool sock_conn(struct sock *const sk, connection_info_t *const conn) {
    if (!parse_sock_info(sk, conn)) {
        return false;
    }
    // a reset or timed out connection releases its port (inet_num = 0): inet_sport keeps it
    if (!conn->s_port) {
        conn->s_port = bpf_ntohs(BPF_CORE_READ((struct inet_sock *)sk, inet_sport));
    }
    return true;
}

// Returns false when the socket has no local port (connect() before the port is chosen)
static __always_inline bool local_endpoint(struct sock *const sk, endpoint_key_t *const key) {
    connection_info_t conn;
    if (!sock_conn(sk, &conn) || !conn.s_port) {
        return false;
    }
    __builtin_memcpy(key->addr, conn.s_addr, sizeof(key->addr));
    key->port = conn.s_port;
    key->netns = needs_netns(key->addr) ? sock_netns(sk) : 0;
    return true;
}

static __always_inline void record_endpoint_owner(struct sock *const sk,
                                                  const sock_owner_t *const owner) {
    endpoint_key_t key = {};
    if (!local_endpoint(sk, &key)) {
        return;
    }
    const endpoint_owner_t value = {.owner = *owner, .recorded_ns = bpf_ktime_get_ns()};
    bpf_map_update_elem(&endpoint_owner, &key, &value, BPF_ANY);
}

static __always_inline void current_owner(struct sock *const sk, sock_owner_t *const owner) {
    const u64 cgroup_id = bpf_get_current_cgroup_id();
    owner->pid = bpf_get_current_pid_tgid() >> 32;
    owner->netns = sock_netns(sk);
    owner->cgroup_id_lo = (u32)cgroup_id;
    owner->cgroup_id_hi = (u32)(cgroup_id >> 32);
    current_exe_name(owner->exe_name);
}

// Records the current task as the process of the socket
static __always_inline void record_sock_owner(struct sock *const sk) {
    connection_info_t conn;
    if (!sock_conn(sk, &conn)) {
        return;
    }
    sock_owner_entry_t entry = {.dport = conn.d_port, .sport = conn.s_port};
    __builtin_memcpy(entry.daddr, conn.d_addr, sizeof(entry.daddr));
    current_owner(sk, &entry.owner);
    bpf_map_update_elem(&sock_owner, &sk, &entry, BPF_ANY);
    record_endpoint_owner(sk, &entry.owner);
}

static __always_inline bool same_addr(const unsigned char *const a, const unsigned char *const b) {
    u64 a_words[2];
    u64 b_words[2];
    __builtin_memcpy(a_words, a, sizeof(a_words));
    __builtin_memcpy(b_words, b, sizeof(b_words));
    return a_words[0] == b_words[0] && a_words[1] == b_words[1];
}

// The sock_owner entry of the socket's connection, NULL when there is none, or when it belongs to
// another socket that had the same address
static __always_inline sock_owner_entry_t *own_sock_owner(struct sock *const sk) {
    sock_owner_entry_t *const entry = bpf_map_lookup_elem(&sock_owner, &sk);
    connection_info_t conn;
    if (!entry || !sock_conn(sk, &conn)) {
        return NULL;
    }
    if (entry->dport != conn.d_port || (entry->sport && entry->sport != conn.s_port) ||
        !same_addr(entry->daddr, conn.d_addr)) {
        return NULL;
    }
    return entry;
}

// The process of a socket: the recorded one, else the newer of the process of its local address
// and the listener of its port on all the addresses (a new server connection that the
// application did not read yet). NULL when unknown.
static __always_inline const sock_owner_t *find_sock_owner(struct sock *sk) {
    const sock_owner_entry_t *const entry = own_sock_owner(sk);
    if (entry) {
        return &entry->owner;
    }

    endpoint_key_t key = {};
    if (!local_endpoint(sk, &key)) {
        return NULL;
    }
    const endpoint_owner_t *const local = bpf_map_lookup_elem(&endpoint_owner, &key);

    __builtin_memset(key.addr, 0, sizeof(key.addr));
    if (BPF_CORE_READ(sk, __sk_common.skc_family) == AF_INET) {
        __builtin_memcpy(key.addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    }
    key.netns = sock_netns(sk);
    const endpoint_owner_t *const listener = bpf_map_lookup_elem(&endpoint_owner, &key);

    if (local && (!listener || local->recorded_ns >= listener->recorded_ns)) {
        return &local->owner;
    }
    return listener ? &listener->owner : NULL;
}

// Fills the process of the socket of a stat event, zero when unknown
static __always_inline void read_sock_owner(struct sock *const sk, sock_owner_t *const out) {
    __builtin_memset(out, 0, sizeof(*out));
    if (!stats_sock_owner_enabled) {
        return;
    }
    const sock_owner_t *const owner = find_sock_owner(sk);
    if (owner) {
        *out = *owner;
    }
    out->netns = sock_netns(sk);
}
