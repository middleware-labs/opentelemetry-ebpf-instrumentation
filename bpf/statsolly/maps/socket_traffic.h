// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/pin_internal.h>

#include <statsolly/exe_name.h>
#include <statsolly/types.h>

// One row per TCP connection or UDP socket/peer. protocol is IPPROTO_TCP or IPPROTO_UDP.
typedef struct socket_traffic_key {
    connection_info_t conn; // s_* is the local side, d_* the remote side
    u32 netns;
    u8 protocol;
    u8 _pad[3];
} socket_traffic_key_t;

// Totals since the row was created, like Datadog's conn_stats. Bytes and UDP packets only
// grow; TCP packets are the socket's segs_out / segs_in. User space computes the increases.
typedef struct socket_traffic {
    u64 tx_bytes;
    u64 rx_bytes;
    u64 tx_packets;
    u64 rx_packets;
    u64 last_update_ns;
    // TCP: the socket counters are reported minus these bases. A new connection with the
    // same addresses can find the row of a closed one whose close event was lost: the bases
    // are then moved so its counters add to the row's totals.
    u64 sock; // the struct sock * the bases belong to, 0 after a lost close event
    u64 rx_read_base;
    u64 tx_segs_base;
    u64 rx_segs_base;
    // The process that created the row: its PID, and its executable name and cgroup, which user
    // space still needs when the process ended before the row was read (short-lived clients)
    u64 cgroup_id;
    unsigned char exe_name[k_exe_name_len];
    // The TCP stat metrics, when user space reads them from the rows (like Datadog's tcp_stats)
    u32 established; // TCP_ESTABLISHED transitions of the row's connections
    u32 retrans_fast;
    u32 retrans_timeout;
    u32 retrans_other;
    u32 zero_window_probes;
    u32 srtt_us; // the latest smoothed RTT
    // socket totals minus the bases, like the packets
    u32 delivered_ce;
    u32 reord_seen;
    u32 rcv_ooopack;
    u32 delivered_ce_base;
    u32 reord_seen_base;
    u32 rcv_ooopack_base;
    u32 pid;
    enum tcp_handshake_role role;
    u8 rx_base_set; // rx_read_base is set by the first read of the connection
    u8 _pad[2];
} socket_traffic_t;

// The final row of a closed socket, sent through socket_traffic_closed
typedef struct socket_traffic_closed_event {
    socket_traffic_key_t key;
    u8 _pad[4];
    socket_traffic_t value;
} socket_traffic_closed_t;

// A plain hash map, so a full map fails the insert (counted in socket_traffic_drops) instead
// of evicting unread rows. Rows are deleted when their socket closes, or by user space when
// they are idle. User space sets max_entries from the stats socket traffic configuration.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, socket_traffic_key_t);
    __type(value, socket_traffic_t);
    __uint(max_entries, 1 << 16);
    __uint(pinning, OBI_PIN_INTERNAL);
} socket_traffic SEC(".maps");
