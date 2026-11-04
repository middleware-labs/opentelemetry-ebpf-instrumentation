// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_endian.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>

#include <statsolly/maps/nat_translations.h>
#include <statsolly/maps/sock_owner.h>

// The NAT translations of the conntrack entries, like Datadog's eBPF conntracker: both directions
// of each NAT-ed entry, saved when the kernel inserts it. User space looks up the tuple of each
// socket row to get its addresses after NAT (the client side) or before it (the server side).

enum {
    k_nf_accept = 1,
    // the lower bits of sk_buff._nfct are the ctinfo, the rest the nf_conn pointer
    k_nfct_info_mask = 7,
};

// Force structs into the ELF for automatic creation of Golang struct
const nat_translation_t *unused_nat_translation __attribute__((unused));

static __always_inline void
nat_addr(u8 *const dst, const union nf_inet_addr *const addr, const u16 family) {
    if (family == AF_INET) {
        __builtin_memcpy(dst, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(dst + sizeof(ip4ip6_prefix), &addr->ip, sizeof(addr->ip));
        return;
    }
    __builtin_memcpy(dst, &addr->in6, IP_V6_ADDR_LEN);
}

// nat_tuple converts a conntrack tuple to the socket traffic key layout: IPv6 or IPv4-mapped
// addresses, ports in host byte order
static __always_inline bool nat_tuple(const struct nf_conntrack_tuple *const tuple,
                                      socket_traffic_key_t *const key) {
    const u8 protocol = tuple->dst.protonum;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        return false;
    }
    const u16 family = tuple->src.l3num;
    if (family != AF_INET && family != AF_INET6) {
        return false;
    }

    key->protocol = protocol;
    key->conn.s_port = bpf_ntohs(tuple->src.u.all);
    key->conn.d_port = bpf_ntohs(tuple->dst.u.all);
    nat_addr(key->conn.s_addr, &tuple->src.u3, family);
    nat_addr(key->conn.d_addr, &tuple->dst.u3, family);
    return key->conn.s_port && key->conn.d_port;
}

// is_nat tells whether the reply tuple is not the original one reversed
static __always_inline bool is_nat(const connection_info_t *const orig,
                                   const connection_info_t *const reply) {
    return !same_addr(orig->s_addr, reply->d_addr) || !same_addr(orig->d_addr, reply->s_addr) ||
           orig->s_port != reply->d_port || orig->d_port != reply->s_port;
}

static __always_inline void save_nat(struct nf_conn *const ct) {
    struct nf_conntrack_tuple orig_tuple = {};
    struct nf_conntrack_tuple reply_tuple = {};
    BPF_CORE_READ_INTO(&orig_tuple, ct, tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    BPF_CORE_READ_INTO(&reply_tuple, ct, tuplehash[IP_CT_DIR_REPLY].tuple);

    socket_traffic_key_t orig = {};
    socket_traffic_key_t reply = {};
    if (!nat_tuple(&orig_tuple, &orig) || !nat_tuple(&reply_tuple, &reply) ||
        !is_nat(&orig.conn, &reply.conn)) {
        return;
    }
    orig.netns = reply.netns = BPF_CORE_READ(ct, ct_net.net, ns.inum);

    const nat_translation_t to_reply = {.conn = reply.conn, .is_reply = 1};
    const nat_translation_t to_orig = {.conn = orig.conn};
    bpf_map_update_elem(&nat_translations, &orig, &to_reply, BPF_ANY);
    bpf_map_update_elem(&nat_translations, &reply, &to_orig, BPF_ANY);
}

SEC("kprobe/__nf_conntrack_hash_insert")
int BPF_KPROBE(obi_stats_kprobe_nf_conntrack_hash_insert_nat, struct nf_conn *ct) {
    (void)ctx;
    save_nat(ct);
    return 0;
}

// The alternate probes, where __nf_conntrack_hash_insert is inlined, like Datadog's: the entry is
// saved when its insert succeeded.

static __always_inline void save_conntrack_arg(struct nf_conn *ct) {
    if (!ct) {
        return;
    }
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&nat_conntrack_args, &pid_tgid, &ct, BPF_ANY);
}

static __always_inline void save_nat_on_return(const int ret, const int success) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    struct nf_conn *const *const ctp = bpf_map_lookup_elem(&nat_conntrack_args, &pid_tgid);
    if (!ctp) {
        return;
    }
    struct nf_conn *const ct = *ctp;
    bpf_map_delete_elem(&nat_conntrack_args, &pid_tgid);
    if (ret == success) {
        save_nat(ct);
    }
}

SEC("kprobe/__nf_conntrack_confirm")
int BPF_KPROBE(obi_stats_kprobe_nf_conntrack_confirm_nat, struct sk_buff *skb) {
    (void)ctx;
    const unsigned long nfct = BPF_CORE_READ(skb, _nfct);
    save_conntrack_arg((struct nf_conn *)(nfct & ~(unsigned long)k_nfct_info_mask));
    return 0;
}

SEC("kretprobe/__nf_conntrack_confirm")
int BPF_KRETPROBE(obi_stats_kretprobe_nf_conntrack_confirm_nat, int ret) {
    (void)ctx;
    save_nat_on_return(ret, k_nf_accept);
    return 0;
}

SEC("kprobe/nf_conntrack_hash_check_insert")
int BPF_KPROBE(obi_stats_kprobe_nf_conntrack_hash_check_insert_nat, struct nf_conn *ct) {
    (void)ctx;
    save_conntrack_arg(ct);
    return 0;
}

SEC("kretprobe/nf_conntrack_hash_check_insert")
int BPF_KRETPROBE(obi_stats_kretprobe_nf_conntrack_hash_check_insert_nat, int ret) {
    (void)ctx;
    save_nat_on_return(ret, 0);
    return 0;
}
