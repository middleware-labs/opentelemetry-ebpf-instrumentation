// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>

#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/stats_dns_events.h>

enum : u16 { k_dns_port = 53 };

enum {
    k_dns_header_size = 12,
    // DNS over TCP starts each message with its 2-byte length
    k_dns_tcp_length_size = 2,
    // DNS header + the longest question (255-byte name, type and class).
    // Userspace only parses the header and the question, never the answers.
    k_dns_packet_buf_size = 272,
};

typedef struct dns_packet {
    u8 flags;    // k_stat_type_dns_packet
    u8 l4_proto; // IPPROTO_UDP or IPPROTO_TCP
    u16 len;     // bytes copied into buf
    connection_info_t conn;
    u64 ts;
    unsigned char buf[k_dns_packet_buf_size];
} dns_packet_t;

// Force emitting struct into the ELF for bpf2go
const dns_packet_t *unused_dns_packet __attribute__((unused));

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

static __always_inline void
read_dns_addrs(struct __sk_buff *skb, connection_info_t *const conn, const bool ipv6) {
    if (ipv6) {
        bpf_skb_load_bytes(
            skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr), conn->s_addr, sizeof(conn->s_addr));
        bpf_skb_load_bytes(
            skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr), conn->d_addr, sizeof(conn->d_addr));
        return;
    }

    __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    bpf_skb_load_bytes(skb,
                       ETH_HLEN + offsetof(struct iphdr, saddr),
                       conn->s_addr + sizeof(ip4ip6_prefix),
                       sizeof(u32));
    bpf_skb_load_bytes(skb,
                       ETH_HLEN + offsetof(struct iphdr, daddr),
                       conn->d_addr + sizeof(ip4ip6_prefix),
                       sizeof(u32));
}

// Attached to a raw AF_PACKET socket in OBI's network namespace, so it runs for every packet.
// Non-DNS packets must exit as early as possible. It always returns 0, so the socket itself
// never receives any packet: the DNS packets are only forwarded through stats_dns_events.
SEC("socket/stats_dns")
int obi_stats_socket_dns(struct __sk_buff *skb) {
    bool ipv6 = false;
    u8 l4_proto = 0;
    const u32 l4_off = l4_header_offset(skb, &ipv6, &l4_proto);
    if (!l4_off) {
        return 0;
    }

    struct l4_ports ports;
    if (bpf_skb_load_bytes(skb, l4_off, &ports, sizeof(ports))) {
        return 0;
    }

    const u16 s_port = bpf_ntohs(ports.source);
    const u16 d_port = bpf_ntohs(ports.dest);
    if (s_port != k_dns_port && d_port != k_dns_port) {
        return 0;
    }

    // also skips the TCP segments without a DNS message, like the handshake and the ACKs
    const u32 dns_off = dns_message_offset(skb, l4_off, l4_proto);
    if (!dns_off || skb->len < dns_off + k_dns_header_size) {
        return 0;
    }

    u32 len = skb->len - dns_off;
    bpf_clamp_umax(len, k_dns_packet_buf_size);
    bpf_clamp_umin(len, k_dns_header_size);

    dns_packet_t *const pkt = bpf_ringbuf_reserve(&stats_dns_events, sizeof(*pkt), 0);
    if (!pkt) {
        return 0;
    }

    pkt->flags = k_stat_type_dns_packet;
    pkt->l4_proto = l4_proto;
    pkt->len = len;
    pkt->ts = bpf_ktime_get_ns();
    pkt->conn.s_port = s_port;
    pkt->conn.d_port = d_port;
    read_dns_addrs(skb, &pkt->conn, ipv6);

    if (bpf_skb_load_bytes(skb, dns_off, pkt->buf, len)) {
        bpf_ringbuf_discard(pkt, 0);
        return 0;
    }

    bpf_ringbuf_submit(pkt, stats_ringbuf_flags(&stats_dns_events));
    return 0;
}
