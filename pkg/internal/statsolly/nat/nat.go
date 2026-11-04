// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package nat finds the address translation of the socket traffic rows in conntrack, like
// Datadog's conntrackers: the eBPF conntrack probes, else netlink, and the Cilium load balancer.
package nat // import "go.opentelemetry.io/obi/pkg/internal/statsolly/nat"

import (
	"context"
	"log/slog"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// key is a connection tuple: IPv6 or IPv4-mapped addresses, ports in host byte order. The
// nat_translations map has the tuples of both directions of each NAT-ed conntrack entry.
type key = ebpf.StatsSocketTrafficKeyT

// translation is the other direction of the conntrack entry of a tuple
type translation = ebpf.StatsNatTranslationT

// conntrack finds the other direction of the conntrack entry of a tuple
type conntrack interface {
	lookup(k *key) (translation, bool)
}

// Tracker finds the address translation of the socket traffic rows
type Tracker struct {
	log *slog.Logger
	// rootNetns is where the NAT rules usually are, also for the pods and containers
	rootNetns uint32
	// conntrack is the eBPF conntrack probes, else netlink. nil when neither is available.
	conntrack conntrack
	// netlink reads the conntrack events when the eBPF probes are not attached
	netlink *netlinkConntrack
	// cilium is nil without the Cilium load balancer
	cilium *ciliumLB
}

// New returns the tracker of the NAT translations. translations is the map that the eBPF
// conntrack probes fill, nil when they are not attached: the conntrack events are then read
// with netlink, like Datadog falls back to its netlink conntracker.
func New(translations *ciliumebpf.Map) *Tracker {
	log := slog.With("component", "nat.Tracker")
	t := &Tracker{log: log}
	if root, err := netns.Inode(1); err == nil {
		t.rootNetns = uint32(root)
	} else {
		log.Warn("can't read the root network namespace: the NAT of the containers is not found", "error", err)
	}

	if translations != nil {
		ebpfConntrack := &ebpfConntrack{translations: translations}
		// the entries inserted before the probes were attached, like Datadog's dumpInitialTables
		if err := dumpConntrack(t.rootNetns, ebpfConntrack.add); err != nil {
			log.Warn("can't read the conntrack entries created before OBI started", "error", err)
		}
		t.conntrack = ebpfConntrack
	} else if netlinkConntrack, err := newNetlinkConntrack(t.rootNetns); err == nil {
		log.Info("the eBPF conntrack probes are not attached: reading the NAT from netlink")
		t.conntrack, t.netlink = netlinkConntrack, netlinkConntrack
	} else {
		log.Warn("no conntrack: src.address and dst.address are the addresses of the sockets", "error", err)
	}

	cilium, err := newCiliumLB()
	if err != nil {
		log.Warn("can't read the Cilium load balancer maps", "error", err)
	}
	t.cilium = cilium
	return t
}

// Run reads the conntrack events with netlink and the Cilium load balancer backends, until ctx
// is done
func (t *Tracker) Run(ctx context.Context) {
	if t.netlink != nil {
		go t.netlink.run(ctx)
	}
	if t.cilium != nil {
		go t.cilium.run(ctx)
	}
}

// NAT returns the address translation of a socket traffic row, nil without NAT. k is the tuple
// of its socket, the local side as source; client tells whether it is the client side.
func (t *Tracker) NAT(k *key, client bool) *ebpf.NAT {
	tr, ok := t.lookup(k, client)
	if !ok {
		return nil
	}
	return natOf(k, &tr)
}

func (t *Tracker) lookup(k *key, client bool) (translation, bool) {
	if t.conntrack != nil {
		// the root network namespace first, then the one of the socket, like Datadog
		root := *k
		root.Netns = t.rootNetns
		if tr, ok := t.conntrack.lookup(&root); ok {
			return tr, true
		}
		if k.Netns != t.rootNetns {
			if tr, ok := t.conntrack.lookup(k); ok {
				return tr, true
			}
		}
	}
	// the load balancer only translates the services that the clients connect to
	if t.cilium != nil && client {
		return t.cilium.lookup(k)
	}
	return translation{}, false
}

// natOf returns the endpoints of a socket before and after NAT. Its tuple is the original
// direction of the conntrack entry on the client, the reply direction on the server: the other
// direction, reversed, is after NAT on the client and before it on the server.
func natOf(k *key, tr *translation) *ebpf.NAT {
	socket := ebpf.Endpoints{
		SrcAddr: k.Conn.S_addr, DstAddr: k.Conn.D_addr,
		SrcPort: k.Conn.S_port, DstPort: k.Conn.D_port,
	}
	other := ebpf.Endpoints{
		SrcAddr: tr.Conn.D_addr, DstAddr: tr.Conn.S_addr,
		SrcPort: tr.Conn.D_port, DstPort: tr.Conn.S_port,
	}
	if tr.IsReply != 0 {
		return &ebpf.NAT{Pre: socket, Post: other}
	}
	return &ebpf.NAT{Pre: other, Post: socket}
}

// ebpfConntrack reads the nat_translations map that the eBPF conntrack probes fill
type ebpfConntrack struct {
	translations *ciliumebpf.Map
}

func (c *ebpfConntrack) lookup(k *key) (translation, bool) {
	var tr translation
	err := c.translations.Lookup(k, &tr)
	return tr, err == nil
}

// add adds a NAT-ed conntrack entry by both its directions, unless the probes added it already
func (c *ebpfConntrack) add(orig, reply *key) {
	toReply := translation{Conn: reply.Conn, IsReply: 1}
	toOrig := translation{Conn: orig.Conn}
	_ = c.translations.Update(orig, &toReply, ciliumebpf.UpdateNoExist)
	_ = c.translations.Update(reply, &toOrig, ciliumebpf.UpdateNoExist)
}

// isNAT tells whether the reply tuple of a conntrack entry is not its original one reversed
func isNAT(orig, reply *key) bool {
	return orig.Conn.S_addr != reply.Conn.D_addr || orig.Conn.D_addr != reply.Conn.S_addr ||
		orig.Conn.S_port != reply.Conn.D_port || orig.Conn.D_port != reply.Conn.S_port
}
