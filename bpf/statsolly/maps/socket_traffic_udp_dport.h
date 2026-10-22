// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// The destination port passed to sendto() / sendmsg() of the udp_sendmsg call in progress,
// for the ip_make_skb kretprobe: an unconnected socket has no remote port.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, u16);
    __uint(max_entries, 1 << 14);
    __uint(pinning, OBI_PIN_INTERNAL);
} socket_traffic_udp_dport SEC(".maps");
