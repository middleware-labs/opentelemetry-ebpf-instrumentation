// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// DNS packets have their own ring buffer: they are about 8 times larger than the
// TCP stats events, so DNS bursts would otherwise push the TCP events out of stats_events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
    __uint(pinning, OBI_PIN_INTERNAL);
} stats_dns_events SEC(".maps");
