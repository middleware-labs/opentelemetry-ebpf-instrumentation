// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <statsolly/inet_sock_set_state.h>
#include <statsolly/maps/sock_owner.h>

// Records the process of each TCP socket for the TCP stat events, see maps/sock_owner.h

// Attachment order invariant: like obi_stats_tp_inet_sock_set_state_conn_role, this program
// must be attached after the programs of this tracepoint that read sock_owner on TCP_CLOSE.
SEC("tracepoint/sock/inet_sock_set_state")
int obi_stats_tp_inet_sock_set_state_sock_owner(struct trace_event_raw_inet_sock_set_state *args) {
    if (!inet_sock_set_state_tcp(args)) {
        return 0;
    }

    struct sock *const sk = (struct sock *)args->skaddr;

    switch (args->newstate) {
    case TCP_SYN_SENT:
        // connect(), in the client process. The local port is not chosen yet.
        record_sock_owner(sk);
        break;
    case TCP_ESTABLISHED: {
        // in softirq. Records the local address of the connection, for the stats of its remote
        // side on this host: the client knows its local port now, and a new server connection
        // takes the process of its listener.
        sock_owner_entry_t *const entry = own_sock_owner(sk);
        if (entry && !entry->sport) {
            connection_info_t conn;
            if (sock_conn(sk, &conn)) {
                entry->sport = conn.s_port;
            }
        }
        const sock_owner_t *const owner = entry ? &entry->owner : find_sock_owner(sk);
        if (owner) {
            record_endpoint_owner(sk, owner);
        }
        break;
    }
    case TCP_CLOSE:
        bpf_map_delete_elem(&sock_owner, &sk);
        break;
    default:
        break;
    }

    return 0;
}

// listen(), in the server process: the new connections of the listener get its process until
// the application uses them. inet_csk_listen_start is the listen of both TCP and MPTCP (the
// default of the Go listeners), which does not call inet_listen.
SEC("kprobe/inet_csk_listen_start")
int BPF_KPROBE(obi_stats_kprobe_inet_csk_listen_start_owner, struct sock *sk) {
    (void)ctx;
    // sk_protocol is a bitfield before kernel 5.6
    if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP) {
        return 0;
    }
    sock_owner_t owner = {};
    current_owner(sk, &owner);
    record_endpoint_owner(sk, &owner);
    return 0;
}

// The first send or receive of a socket whose process is unknown: accepted server sockets, and
// the sockets created before OBI started. A closed socket is skipped: its entry would never be
// deleted, and a new socket at the same address would take it.
static __always_inline void record_unknown_sock_owner(struct sock *sk) {
    if (BPF_CORE_READ(sk, __sk_common.skc_state) == TCP_CLOSE) {
        return;
    }
    if (!own_sock_owner(sk)) {
        record_sock_owner(sk);
    }
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(obi_stats_kprobe_tcp_sendmsg_owner, struct sock *sk) {
    (void)ctx;
    record_unknown_sock_owner(sk);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(obi_stats_kprobe_tcp_cleanup_rbuf_owner, struct sock *sk) {
    (void)ctx;
    record_unknown_sock_owner(sk);
    return 0;
}

// The application closes a socket that is already closed (reset, timed out): its entry is
// deleted here if a send or receive recorded it again while it was closing
SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_stats_kprobe_tcp_close_owner, struct sock *sk) {
    (void)ctx;
    if (BPF_CORE_READ(sk, __sk_common.skc_state) == TCP_CLOSE) {
        bpf_map_delete_elem(&sock_owner, &sk);
    }
    return 0;
}
