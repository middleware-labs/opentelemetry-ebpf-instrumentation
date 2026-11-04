// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/sockaddr.h>

#include <logger/bpf_dbg.h>

#include <statsolly/inet_sock_set_state.h>
#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/sock_role.h>
#include <statsolly/maps/sock_owner.h>
#include <statsolly/tcp_counters.h>
#include <statsolly/tcp_failure.h>

typedef struct tcp_failed_connection {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_fail_reason reason;
    enum tcp_handshake_role role;
    u8 _pad[1];
    connection_info_t conn;
    sock_owner_t owner;
} tcp_failed_connection_t;

typedef struct tcp_retransmit {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_retransmit_type type;
    enum tcp_handshake_role role;
    u8 _pad[1];
    connection_info_t conn;
    sock_owner_t owner;
} tcp_retransmit_t;

typedef struct tcp_successful_connection {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_handshake_role role;
    u8 _pad[2];
    connection_info_t conn;
    sock_owner_t owner;
} tcp_successful_connection_t;

typedef struct tcp_closed_connection {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum tcp_handshake_role role;
    u8 _pad[2];
    connection_info_t conn;
    sock_owner_t owner;
} tcp_closed_connection_t;

// Force structs into the ELF for automatic creation of Golang struct
const tcp_failed_connection_t *unused_tcp_failed_connection __attribute__((unused));
const tcp_retransmit_t *unused_tcp_retransmit_t __attribute__((unused));
const tcp_successful_connection_t *unused_tcp_successful_connection __attribute__((unused));
const tcp_closed_connection_t *unused_tcp_closed_connection __attribute__((unused));

// tcp_set_state(TCP_CLOSE) calls inet_put_port() before this tracepoint fires,
// which zeroes skc_num for sockets with an auto-assigned port; inet_sport is kept
static __always_inline void
fix_closed_sport(connection_info_t *const conn,
                 const struct trace_event_raw_inet_sock_set_state *const args) {
    if (conn->s_port == 0) {
        conn->s_port = args->sport;
    }
}

// a SYN retransmit comes before the handshake sets sock_role
static __always_inline enum tcp_handshake_role retransmit_sock_role(struct sock *const sk) {
    const u8 *const role_ptr = bpf_map_lookup_elem(&sock_role, &sk);
    if (role_ptr) {
        return *role_ptr;
    }
    if (BPF_CORE_READ(sk, __sk_common.skc_state) == TCP_SYN_SENT) {
        return role_client;
    }
    return role_unknown;
}

// obi_stats_tp_inet_sock_set_state_conn_role is the sole owner of the sock_role map.
// It writes the role (client/server) when a connection is established and
// it also handles all cleanup: any transition to TCP_CLOSE removes the entry,
// covering both normal graceful closes and abnormal ones.
//
// Attachment order invariant: this program must be attached AFTER
// obi_stats_tp_inet_sock_set_state_tcp_failed_connection and
// obi_stats_tp_inet_sock_set_state_tcp_closed_connection (or any future tp probes that need the role)
// on the same tracepoint. BPF programs on a tracepoint run FIFO, so the probe(s) read sock_role first,
// then this program deletes it. Reversing the order would cause tcp_failed_conn or any other probes
// to see a stale NULL on the same TCP_CLOSE event.
SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_conn_role(struct trace_event_raw_inet_sock_set_state *args) {
    if (!inet_sock_set_state_tcp(args)) {
        return 0;
    }

    struct sock *const sk = (struct sock *)args->skaddr;

    if (args->oldstate == TCP_SYN_SENT || args->oldstate == TCP_SYN_RECV) {
        if (args->newstate == TCP_ESTABLISHED) {
            const u8 role = (args->oldstate == TCP_SYN_SENT) ? role_client : role_server;
            bpf_map_update_elem(&sock_role, &sk, &role, BPF_ANY);
        }
    }

    if (args->newstate == TCP_CLOSE) {
        bpf_map_delete_elem(&sock_role, &sk);
        return 0;
    }

    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_tcp_failed_connection(
    struct trace_event_raw_inet_sock_set_state *args) {
    if (!inet_sock_set_state_tcp(args)) {
        return 0;
    }

    struct sock *const sk = (struct sock *)args->skaddr;

    enum tcp_fail_reason reason;
    if (!tcp_failure(sk, args, &reason)) {
        return 0;
    }

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }
    fix_closed_sport(&conn, args);

    bpf_d_printk("tcp failed: s_port=%d, d_port=%d, reason=%d", conn.s_port, conn.d_port, reason);

    tcp_failed_connection_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_stat_type_tcp_failed_connection;
    se->reason = reason;
    se->conn = conn;
    se->role = closing_sock_role(sk, args);
    read_sock_owner(sk, &se->owner);

    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_tcp_closed_connection(
    struct trace_event_raw_inet_sock_set_state *args) {
    if (!inet_sock_set_state_tcp(args)) {
        return 0;
    }

    if (args->newstate != TCP_CLOSE) {
        return 0;
    }

    // TCP_LISTEN->TCP_CLOSE is a listener shutting down, not a connection.
    // TCP_CLOSE->TCP_CLOSE: the tracepoint also fires when the state does not change,
    // skip it so an already closed connection is not counted twice.
    if (args->oldstate == TCP_LISTEN || args->oldstate == TCP_CLOSE) {
        return 0;
    }

    struct sock *const sk = (struct sock *)args->skaddr;
    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }
    fix_closed_sport(&conn, args);

    bpf_d_printk("tcp closed: s_port=%d, d_port=%d", conn.s_port, conn.d_port);

    tcp_closed_connection_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_stat_type_tcp_closed_connection;
    se->conn = conn;
    se->role = closing_sock_role(sk, args);
    read_sock_owner(sk, &se->owner);

    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_tcp_successful_connection(
    struct trace_event_raw_inet_sock_set_state *args) {
    if (!inet_sock_set_state_tcp(args)) {
        return 0;
    }

    const int newstate = args->newstate;
    const int oldstate = args->oldstate;

    if (newstate == TCP_ESTABLISHED && (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV)) {
        struct sock *const sk = (struct sock *)args->skaddr;
        connection_info_t conn;
        if (!parse_sock_info(sk, &conn)) {
            return 0;
        }

        bpf_d_printk("tcp successful: s_port=%d, d_port=%d", conn.s_port, conn.d_port);

        tcp_successful_connection_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
        if (!se) {
            return 0;
        }

        se->flags = k_stat_type_tcp_successful_connection;
        se->conn = conn;
        if (oldstate == TCP_SYN_SENT) {
            se->role = role_client;
        } else {
            se->role = role_server;
        }
        read_sock_owner(sk, &se->owner);

        bpf_ringbuf_submit(se, stats_events_flags());
    }
    return 0;
}

SEC("raw_tracepoint/tcp_retransmit_skb")
int obi_stats_raw_tp_tcp_retransmit_skb(struct bpf_raw_tracepoint_args *ctx) {

    struct sock *const sk = (struct sock *)ctx->args[0];

    connection_info_t conn;
    if (!parse_sock_info(sk, &conn)) {
        return 0;
    }

    bpf_d_printk("tcp retransmit: s_port=%d, d_port=%d", conn.s_port, conn.d_port);

    tcp_retransmit_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        return 0;
    }

    se->flags = k_stat_type_tcp_retransmit;
    se->type = sk_retransmit_type(sk);
    se->role = retransmit_sock_role(sk);
    se->conn = conn;
    read_sock_owner(sk, &se->owner);

    bpf_ringbuf_submit(se, stats_events_flags());

    return 0;
}
