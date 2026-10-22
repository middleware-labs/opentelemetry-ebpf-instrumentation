// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// The socket of the inet_bind / inet6_bind call in progress, for its kretprobe
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, struct socket *);
    __uint(max_entries, 1 << 12);
    __uint(pinning, OBI_PIN_INTERNAL);
} socket_traffic_bind_sock SEC(".maps");
