// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/pin_internal.h>

#include <statsolly/maps/socket_traffic.h>

// The other direction of a NAT-ed conntrack entry, like Datadog's conntrack map
typedef struct nat_translation {
    connection_info_t conn; // the tuple of the other direction, s_* its source
    u8 is_reply;            // conn is the reply tuple: the key is the original one, the client's
    u8 _pad[3];
} nat_translation_t;

// The NAT-ed conntrack entries by the tuple of each of their directions, with the protocol and
// the network namespace of the entry. User space looks up the rows. LRU: the entries are not
// deleted when their connection ends.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, socket_traffic_key_t);
    __type(value, nat_translation_t);
    __uint(max_entries, 1 << 17);
    __uint(pinning, OBI_PIN_INTERNAL);
} nat_translations SEC(".maps");

// The conntrack entry of the __nf_conntrack_confirm or nf_conntrack_hash_check_insert call in
// progress, for its kretprobe
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, struct nf_conn *);
    __uint(max_entries, 1 << 12);
    __uint(pinning, OBI_PIN_INTERNAL);
} nat_conntrack_args SEC(".maps");
