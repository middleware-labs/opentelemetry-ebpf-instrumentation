// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>

// The protocol field of inet_sock_set_state is a u16, but a u8 followed by the source address on
// RHEL 8 (4.18): CO-RE fixes its offset, not its size, so the protocol is read from the socket.
static __always_inline bool
inet_sock_set_state_tcp(const struct trace_event_raw_inet_sock_set_state *const args) {
    struct sock *const sk = (struct sock *)args->skaddr;
    // sk_protocol is a bitfield before kernel 5.6
    return BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) == IPPROTO_TCP;
}
