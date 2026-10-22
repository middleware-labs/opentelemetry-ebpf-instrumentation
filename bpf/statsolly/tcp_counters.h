// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>

#include <statsolly/types.h>
#include <statsolly/maps/tcp_cong_last.h>

static __always_inline void read_cong_vals(struct sock *sk, tcp_cong_vals_t *vals) {
    const struct tcp_sock *tp = (const struct tcp_sock *)sk;

    // RHEL 4.18 backports may lack some of these fields: they then stay 0
    if (bpf_core_field_exists(tp->delivered_ce)) {
        vals->delivered_ce = BPF_CORE_READ(tp, delivered_ce);
    }
    if (bpf_core_field_exists(tp->reord_seen)) {
        vals->reord_seen = BPF_CORE_READ(tp, reord_seen);
    }
    if (bpf_core_field_exists(tp->rcv_ooopack)) {
        vals->rcv_ooopack = BPF_CORE_READ(tp, rcv_ooopack);
    }
}

// The congestion state is already updated when tcp_retransmit_skb fires:
// tcp_enter_loss (RTO) sets TCP_CA_Loss, tcp_enter_recovery (dup ACKs/SACK) sets TCP_CA_Recovery.
static __always_inline enum tcp_retransmit_type sk_retransmit_type(struct sock *const sk) {
    // icsk_ca_state is a bitfield, BPF_CORE_READ cannot read it
    const u8 ca_state =
        BPF_CORE_READ_BITFIELD_PROBED((struct inet_connection_sock *)sk, icsk_ca_state);

    switch (ca_state) {
    case TCP_CA_Loss:
        return retransmit_type_timeout;
    case TCP_CA_Recovery:
        return retransmit_type_fast;
    default:
        return retransmit_type_other;
    }
}
