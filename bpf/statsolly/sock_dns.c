// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/dns_skb.h>
#include <common/protocol_defs.h>

#include <statsolly/types.h>
#include <statsolly/ringbuf_flags.h>
#include <statsolly/maps/stats_dns_events.h>

enum {
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
