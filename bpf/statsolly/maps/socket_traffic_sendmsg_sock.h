// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// The socket of the tcp_sendmsg or tcp_sendpage call in progress, for its kretprobe.
// Not shared with tcp_sendmsg_sock, so stats_tcp_io and the socket traffic can be enabled separately.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, struct sock *);
    __uint(max_entries, 1 << 14);
    __uint(pinning, OBI_PIN_INTERNAL);
} socket_traffic_sendmsg_sock SEC(".maps");
