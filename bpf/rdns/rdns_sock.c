// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/utils.h>

#include <common/dns_skb.h>
#include <common/pin_internal.h>

// Reverse DNS by means of DNS response inspection.
// This socket filter runs on a raw AF_PACKET socket and forwards the DNS responses that
// answer a query to user space, which maps the answered addresses to the queried name.
// It never touches the packets nor the network interfaces.
// For reference, see:
// https://datatracker.ietf.org/doc/html/rfc1035

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum {
    // The UDP payload size that DNS software defaults to since DNS Flag Day 2020, so it fits
    // nearly every UDP response. Longer responses are skipped, since user space only parses
    // complete messages.
    k_rdns_buf_size = 1232,
    // User space is only woken up once this fraction of the ring buffer is waiting, and polls
    // the rest periodically: a wake-up per response costs more than parsing it.
    k_rdns_wakeup_fraction = 16,
};

enum : u8 {
    k_dns_flag_response = 0x80, // QR, in the high flags byte
    k_dns_opcode_mask = 0x78,   // OPCODE, in the high flags byte; 0 is a standard query
    k_dns_rcode_mask = 0x0f,    // RCODE, in the low flags byte; 0 is no error
};

struct dns_header {
    __be16 id;
    u8 flags_hi;
    u8 flags_lo;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

_Static_assert(sizeof(struct dns_header) == k_dns_header_size, "unexpected DNS header size");

typedef struct rdns_response {
    u16 len; // bytes copied into buf
    unsigned char buf[k_rdns_buf_size];
} rdns_response_t;

// Force emitting struct into the ELF for bpf2go
const rdns_response_t *unused_rdns_response __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __uint(pinning, OBI_PIN_INTERNAL);
} rdns_responses SEC(".maps");

static __always_inline long rdns_submit_flags(void) {
    const u64 avail_data = bpf_ringbuf_query(&rdns_responses, BPF_RB_AVAIL_DATA);
    const u64 ring_size = bpf_ringbuf_query(&rdns_responses, BPF_RB_RING_SIZE);
    return avail_data >= ring_size / k_rdns_wakeup_fraction ? BPF_RB_FORCE_WAKEUP
                                                            : BPF_RB_NO_WAKEUP;
}

static __always_inline bool is_answered_query(const struct dns_header *const hdr) {
    return (hdr->flags_hi & k_dns_flag_response) && !(hdr->flags_hi & k_dns_opcode_mask) &&
           !(hdr->flags_lo & k_dns_rcode_mask) && hdr->qdcount && hdr->ancount;
}

// Runs for every packet of the socket's network namespace, so other packets must exit as early
// as possible. It always returns 0: the socket itself never receives any packet, the responses
// are only forwarded through rdns_responses.
SEC("socket/rdns")
int obi_rdns_socket_dns(struct __sk_buff *skb) {
    bool ipv6 = false;
    u8 l4_proto = 0;
    const u32 l4_off = l4_header_offset(skb, &ipv6, &l4_proto);
    if (!l4_off) {
        return 0;
    }

    struct l4_ports ports;
    if (bpf_skb_load_bytes(skb, l4_off, &ports, sizeof(ports)) ||
        bpf_ntohs(ports.source) != k_dns_port) {
        return 0;
    }

    // also skips the TCP segments without a DNS message, like the handshake and the ACKs
    const u32 dns_off = dns_message_offset(skb, l4_off, l4_proto);
    if (!dns_off) {
        return 0;
    }

    struct dns_header hdr;
    if (bpf_skb_load_bytes(skb, dns_off, &hdr, sizeof(hdr)) || !is_answered_query(&hdr)) {
        return 0;
    }

    u32 len = skb->len - dns_off;
    if (len > k_rdns_buf_size) {
        return 0;
    }
    bpf_clamp_umax(len, k_rdns_buf_size);
    bpf_clamp_umin(len, k_dns_header_size);

    rdns_response_t *const resp = bpf_ringbuf_reserve(&rdns_responses, sizeof(*resp), 0);
    if (!resp) {
        return 0;
    }

    resp->len = len;
    if (bpf_skb_load_bytes(skb, dns_off, resp->buf, len)) {
        bpf_ringbuf_discard(resp, 0);
        return 0;
    }

    bpf_ringbuf_submit(resp, rdns_submit_flags());
    return 0;
}
