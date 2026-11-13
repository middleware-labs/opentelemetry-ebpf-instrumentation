// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

enum { k_exe_name_len = 16 };

// The base name of the executable of the current task, like OBI's process.executable.name, else
// its command name (kernel threads). Truncated to k_exe_name_len bytes, without the terminating
// zero when it is longer.
static __always_inline void current_exe_name(unsigned char *const out) {
    struct task_struct *const task = (struct task_struct *)bpf_get_current_task();
    const unsigned char *const name = BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name);
    // a dentry keeps the names shorter than DNAME_INLINE_LEN (at least 32) inline, and allocates
    // the longer ones: reading k_exe_name_len bytes stays in the name
    if (!name || bpf_probe_read_kernel(out, k_exe_name_len, name) || !out[0]) {
        bpf_get_current_comm(out, k_exe_name_len);
    }
}
