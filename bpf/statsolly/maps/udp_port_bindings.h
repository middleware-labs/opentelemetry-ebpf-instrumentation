// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/sock_port_ns.h>

// Number of UDP sockets bound to each local port, like Datadog's udp_port_bindings.
// A UDP row whose local port is bound is the server side. User space seeds it with the
// ports bound before OBI started.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock_port_ns);
    __type(value, u32);
    __uint(max_entries, 1 << 13);
    __uint(pinning, OBI_PIN_INTERNAL);
} udp_port_bindings SEC(".maps");
