// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>

static __always_inline u32 sock_netns(const struct sock *const sk) {
    return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}
