// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

typedef struct tcp_cong_vals {
    u32 delivered_ce;
    u32 reord_seen;
    u32 rcv_ooopack;
} tcp_cong_vals_t;

typedef struct tcp_cong_last {
    tcp_cong_vals_t sent; // values already sent to user space
    u8 _pad[4];
    u64 last_emit_ns; // for the per-socket rate limit
} tcp_cong_last_t;

// Only sockets that ever had a non-zero CE / reordering / out-of-order count
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct sock *);
    __type(value, tcp_cong_last_t);
    __uint(max_entries, 1 << 14);
    __uint(pinning, OBI_PIN_INTERNAL);
} tcp_cong_last SEC(".maps");
