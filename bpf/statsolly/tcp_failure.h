// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <statsolly/types.h>

// The failed connections of the socket traffic rows. tp_tcp.c has the same logic for the events.

#ifndef ECONNREFUSED
#define ECONNREFUSED 111
#endif
#ifndef ECONNRESET
#define ECONNRESET 104
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH 113
#endif
#ifndef ENETUNREACH
#define ENETUNREACH 101
#endif

static __always_inline enum tcp_fail_reason row_fail_reason(const int err) {
    switch (err) {
    case ECONNREFUSED:
        return reason_connection_refused;
    case ECONNRESET:
        return reason_connection_reset;
    case ETIMEDOUT:
        return reason_timed_out;
    case EHOSTUNREACH:
        return reason_host_unreachable;
    case ENETUNREACH:
        return reason_net_unreachable;
    case 0:
        return reason_unknown;
    default:
        return reason_other;
    }
}

// Tells whether a transition to TCP_CLOSE ends a failed connection, and why
static __always_inline bool
tcp_failure(struct sock *const sk,
            const struct trace_event_raw_inet_sock_set_state *const args,
            enum tcp_fail_reason *const reason) {
    if (args->newstate != TCP_CLOSE) {
        return false;
    }
    // {TCP_LAST_ACK|TCP_TIME_WAIT}->TCP_CLOSE are normal close transitions
    // TCP_LISTEN->TCP_CLOSE is what happens when a listener socket is shut down
    if (args->oldstate == TCP_LAST_ACK || args->oldstate == TCP_TIME_WAIT ||
        args->oldstate == TCP_LISTEN) {
        return false;
    }
    const int err = BPF_CORE_READ(sk, sk_err);
    // Trust sk_err: err==0 means the kernel saw no problem (e.g. local close()
    // with unread data sends RST without setting sk_err).
    // Exception: aborted connect (TCP_SYN_SENT -> TCP_CLOSE) never established, still a failure.
    if (err == 0 && args->oldstate != TCP_SYN_SENT) {
        return false;
    }
    *reason = row_fail_reason(err);
    return true;
}
