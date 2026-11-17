// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/protocol_defs.h>

// Helpers for the socket filters that read DNS messages from a raw AF_PACKET socket

enum : u16 { k_dns_port = 53 };

enum {
    k_dns_header_size = 12,
    // DNS over TCP starts each message with its 2-byte length
    k_dns_tcp_length_size = 2,
};

// The source and destination ports start both the UDP and the TCP headers
struct l4_ports {
    __be16 source;
    __be16 dest;
};

// Returns the offset of the transport header, or 0 when the packet is not UDP or TCP over IPv4 or IPv6.
static __always_inline u32 l4_header_offset(struct __sk_buff *skb,
                                            bool *const ipv6,
                                            u8 *const l4_proto) {
    u16 h_proto = 0;
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));

    u32 l4_off = 0;

    switch (bpf_ntohs(h_proto)) {
    case ETH_P_IP: {
        u8 ihl = 0;
        bpf_skb_load_bytes(skb, ETH_HLEN, &ihl, sizeof(ihl));
        ihl = (ihl & 0x0f) * 4;
        if (ihl < sizeof(struct iphdr)) {
            return 0;
        }
        bpf_skb_load_bytes(
            skb, ETH_HLEN + offsetof(struct iphdr, protocol), l4_proto, sizeof(*l4_proto));
        l4_off = ETH_HLEN + ihl;
        break;
    }
    case ETH_P_IPV6:
        bpf_skb_load_bytes(
            skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr), l4_proto, sizeof(*l4_proto));
        l4_off = ETH_HLEN + sizeof(struct ipv6hdr);
        *ipv6 = true;
        break;
    default:
        return 0;
    }

    return (*l4_proto == IPPROTO_UDP || *l4_proto == IPPROTO_TCP) ? l4_off : 0;
}

// Returns the offset of the DNS message, or 0 when the packet can't carry one.
// DNS over TCP is read without reassembly: only a message that starts a segment is read.
static __always_inline u32 dns_message_offset(struct __sk_buff *skb,
                                              const u32 l4_off,
                                              const u8 l4_proto) {
    if (l4_proto == IPPROTO_UDP) {
        return l4_off + sizeof(struct udphdr);
    }

    // the data offset is the upper 4 bits of the byte after ack_seq, in 32-bit words
    u8 doff = 0;
    bpf_skb_load_bytes(
        skb, l4_off + offsetof(struct tcphdr, ack_seq) + sizeof(u32), &doff, sizeof(doff));
    doff = (doff >> 4) * 4;
    if (doff < sizeof(struct tcphdr)) {
        return 0;
    }
    return l4_off + doff + k_dns_tcp_length_size;
}
