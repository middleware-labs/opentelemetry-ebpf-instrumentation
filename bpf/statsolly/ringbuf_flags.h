// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <statsolly/maps/stats_events.h>

// stats_events_flags for the other stat ring buffers: the same stats_wakeup_data_bytes batching
static __always_inline long stats_ringbuf_flags(void *const ringbuf) {
    if (!stats_wakeup_data_bytes) {
        return 0;
    }
    const u64 avail_data = bpf_ringbuf_query(ringbuf, BPF_RB_AVAIL_DATA);
    return avail_data >= stats_wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}
