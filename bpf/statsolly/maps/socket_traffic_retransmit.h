// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// A tcp_retransmit_skb call runs in softirq or a timer, where the current task can be the idle
// task of every CPU: the CPU is part of the key. The socket is locked, so the call returns on
// the same CPU.
typedef struct socket_traffic_retransmit_key {
    u64 pid_tgid;
    u32 cpu;
    u8 _pad[4];
} socket_traffic_retransmit_key_t;

typedef struct socket_traffic_retransmit {
    u64 sk; // struct sock *
    u32 retrans_out_pre;
    u8 _pad[4];
} socket_traffic_retransmit_t;

// The tcp_retransmit_skb call in progress, for its kretprobe
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, socket_traffic_retransmit_key_t);
    __type(value, socket_traffic_retransmit_t);
    __uint(max_entries, 1 << 12);
    __uint(pinning, OBI_PIN_INTERNAL);
} socket_traffic_retransmit SEC(".maps");
