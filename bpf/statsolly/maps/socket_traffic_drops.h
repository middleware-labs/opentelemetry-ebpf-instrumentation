// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

enum socket_traffic_drop : u32 {
    // a row could not be created: the socket_traffic map is full
    k_socket_traffic_drop_insert = 0,
    // a close event could not be reserved: the row is kept, user space reads it later
    k_socket_traffic_drop_close = 1,
    k_socket_traffic_drop_count = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, k_socket_traffic_drop_count);
    __uint(pinning, OBI_PIN_INTERNAL);
} socket_traffic_drops SEC(".maps");
