// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nat // import "go.opentelemetry.io/obi/pkg/internal/statsolly/nat"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/netns"
)

const (
	// conntrackRateLimit is the most conntrack events per second read from netlink, Datadog's
	// conntrack_rate_limit
	conntrackRateLimit = 500
	// conntrackRateInterval is how often their rate is measured, Datadog's
	// conntrack_rate_limit_interval
	conntrackRateInterval = 3 * time.Second
	// overshootFactor lowers the sampling rate below the limit, Datadog's
	overshootFactor = 0.95
	// conntrackCacheSize is the most NAT-ed entries kept, Datadog's conntrack_max_state_size
	conntrackCacheSize = 1 << 17
	// netlinkBufferSize is the receive buffer of the netlink socket, Datadog's
	netlinkBufferSize = 1 << 20

	// the messages of the new conntrack entries
	ctNewMessage = unix.NFNL_SUBSYS_CTNETLINK<<8 | nl.IPCTNL_MSG_CT_NEW
)

// netlinkConntrack keeps the NAT-ed conntrack entries from the netlink events, like Datadog's
// netlink conntracker: the table at start, then the new entries. Above conntrackRateLimit, the
// socket is opened again with a filter that samples the events.
type netlinkConntrack struct {
	log       *slog.Logger
	rootNetns uint32
	mu        sync.Mutex
	entries   *simplelru.LRU[key, translation]
	breaker   *circuitBreaker
	// samplingRate is the share of the events read, from 0 to 1
	samplingRate float64
}

func newNetlinkConntrack(rootNetns uint32) (*netlinkConntrack, error) {
	entries, err := simplelru.NewLRU[key, translation](conntrackCacheSize, nil)
	if err != nil {
		return nil, err
	}
	c := &netlinkConntrack{
		log:          slog.With("component", "nat.netlinkConntrack"),
		rootNetns:    rootNetns,
		entries:      entries,
		breaker:      newCircuitBreaker(conntrackRateLimit, conntrackRateInterval, time.Now()),
		samplingRate: 1,
	}
	if err := dumpConntrack(rootNetns, c.add); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *netlinkConntrack) lookup(k *key) (translation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries.Get(*k)
}

func (c *netlinkConntrack) add(orig, reply *key) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries.Add(*orig, translation{Conn: reply.Conn, IsReply: 1})
	c.entries.Add(*reply, translation{Conn: orig.Conn})
}

// run reads the new conntrack entries until ctx is done
func (c *netlinkConntrack) run(ctx context.Context) {
	for ctx.Err() == nil {
		sock, err := c.subscribe()
		if err != nil {
			c.log.Warn("can't read the conntrack events: the NAT of the new connections is not found", "error", err)
			return
		}
		stop := context.AfterFunc(ctx, sock.Close)
		tripped := c.read(sock)
		stop()
		sock.Close()
		if !tripped {
			return
		}

		c.samplingRate = min(1, conntrackRateLimit/c.breaker.rate*c.samplingRate*overshootFactor)
		c.log.Warn("too many conntrack events: sampling them", "rate", int(c.breaker.rate),
			"limit", conntrackRateLimit, "samplingRate", c.samplingRate)
		c.breaker.reset(time.Now())
	}
}

// read adds the NAT-ed entries of the events until the socket is closed, or until their rate
// trips the circuit breaker
func (c *netlinkConntrack) read(sock *nl.NetlinkSocket) (tripped bool) {
	for {
		msgs, _, err := sock.Receive()
		if errors.Is(err, unix.ENOBUFS) {
			c.log.Debug("conntrack events lost: the netlink receive buffer is full")
			continue
		}
		if err != nil {
			return false
		}
		for i := range msgs {
			c.addEvent(&msgs[i])
		}
		if c.breaker.tick(len(msgs), time.Now()) {
			return true
		}
	}
}

func (c *netlinkConntrack) addEvent(msg *syscall.NetlinkMessage) {
	if msg.Header.Type != ctNewMessage {
		return
	}
	orig, reply, ok := parseConntrack(msg.Data, c.rootNetns)
	if ok && isNAT(&orig, &reply) {
		c.add(&orig, &reply)
	}
}

// subscribe opens a socket for the new conntrack entries of the root network namespace
func (c *netlinkConntrack) subscribe() (*nl.NetlinkSocket, error) {
	var sock *nl.NetlinkSocket
	err := netns.WithNetNS(1, func() error {
		var err error
		sock, err = nl.Subscribe(unix.NETLINK_NETFILTER, unix.NFNLGRP_CONNTRACK_NEW)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("subscribing to the conntrack events: %w", err)
	}
	// a larger buffer loses fewer events in bursts
	if err := unix.SetsockoptInt(sock.GetFd(), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, netlinkBufferSize); err != nil {
		c.log.Debug("can't set the netlink receive buffer", "error", err)
	}
	if c.samplingRate < 1 {
		if err := attachSampler(sock.GetFd(), c.samplingRate); err != nil {
			sock.Close()
			return nil, err
		}
	}
	return sock, nil
}

// attachSampler attaches a socket filter that keeps the given share of the messages, like
// Datadog's GenerateBPFSampler
func attachSampler(fd int, rate float64) error {
	insts, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadExtension{Num: bpf.ExtRand},
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: uint32(rate * math.MaxUint32), SkipTrue: 1},
		bpf.RetConstant{Val: math.MaxUint32},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		return err
	}
	filter := make([]unix.SockFilter, len(insts))
	for i, inst := range insts {
		filter[i] = unix.SockFilter{Code: inst.Op, Jt: inst.Jt, Jf: inst.Jf, K: inst.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("attaching the conntrack sampling filter: %w", err)
	}
	return nil
}

// dumpConntrack reads the conntrack table of the root network namespace, and calls add with
// both directions of each NAT-ed entry
func dumpConntrack(rootNetns uint32, add func(orig, reply *key)) error {
	return netns.WithNetNS(1, func() error {
		var errs []error
		for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
			flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
			if err != nil {
				errs = append(errs, fmt.Errorf("dumping the conntrack table of family %d: %w", family, err))
				continue
			}
			for _, flow := range flows {
				orig, okOrig := tupleKey(&flow.Forward, rootNetns)
				reply, okReply := tupleKey(&flow.Reverse, rootNetns)
				if okOrig && okReply && isNAT(&orig, &reply) {
					add(&orig, &reply)
				}
			}
		}
		return errors.Join(errs...)
	})
}

func tupleKey(t *netlink.IPTuple, rootNetns uint32) (key, bool) {
	k := key{Netns: rootNetns, Protocol: t.Protocol}
	k.Conn.S_port, k.Conn.D_port = t.SrcPort, t.DstPort
	src, dst := t.SrcIP.To16(), t.DstIP.To16()
	if src == nil || dst == nil {
		return k, false
	}
	copy(k.Conn.S_addr[:], src)
	copy(k.Conn.D_addr[:], dst)
	return k, validTuple(&k)
}

// parseConntrack parses both tuples of a conntrack netlink message: a nfgenmsg header, then
// the attributes
func parseConntrack(data []byte, rootNetns uint32) (orig, reply key, ok bool) {
	if len(data) < nl.SizeofNfgenmsg {
		return orig, reply, false
	}
	attrs, err := nl.ParseRouteAttr(data[nl.SizeofNfgenmsg:])
	if err != nil {
		return orig, reply, false
	}
	var okOrig, okReply bool
	for _, a := range attrs {
		switch a.Attr.Type & nl.NLA_TYPE_MASK {
		case nl.CTA_TUPLE_ORIG:
			okOrig = parseTuple(a.Value, &orig)
		case nl.CTA_TUPLE_REPLY:
			okReply = parseTuple(a.Value, &reply)
		}
	}
	orig.Netns, reply.Netns = rootNetns, rootNetns
	return orig, reply, okOrig && okReply
}

func parseTuple(data []byte, k *key) bool {
	attrs, err := nl.ParseRouteAttr(data)
	if err != nil {
		return false
	}
	for _, a := range attrs {
		switch a.Attr.Type & nl.NLA_TYPE_MASK {
		case nl.CTA_TUPLE_IP:
			parseTupleIP(a.Value, k)
		case nl.CTA_TUPLE_PROTO:
			parseTupleProto(a.Value, k)
		}
	}
	return validTuple(k)
}

func parseTupleIP(data []byte, k *key) {
	attrs, err := nl.ParseRouteAttr(data)
	if err != nil {
		return
	}
	for _, a := range attrs {
		switch a.Attr.Type & nl.NLA_TYPE_MASK {
		case nl.CTA_IP_V4_SRC, nl.CTA_IP_V6_SRC:
			copy(k.Conn.S_addr[:], net.IP(a.Value).To16())
		case nl.CTA_IP_V4_DST, nl.CTA_IP_V6_DST:
			copy(k.Conn.D_addr[:], net.IP(a.Value).To16())
		}
	}
}

func parseTupleProto(data []byte, k *key) {
	attrs, err := nl.ParseRouteAttr(data)
	if err != nil {
		return
	}
	const portLen = 2
	for _, a := range attrs {
		switch t := a.Attr.Type & nl.NLA_TYPE_MASK; {
		case t == nl.CTA_PROTO_NUM && len(a.Value) > 0:
			k.Protocol = a.Value[0]
		case t == nl.CTA_PROTO_SRC_PORT && len(a.Value) >= portLen:
			k.Conn.S_port = binary.BigEndian.Uint16(a.Value)
		case t == nl.CTA_PROTO_DST_PORT && len(a.Value) >= portLen:
			k.Conn.D_port = binary.BigEndian.Uint16(a.Value)
		}
	}
}

// validTuple tells whether a tuple is a TCP or UDP connection, like the socket traffic rows
func validTuple(k *key) bool {
	return (k.Protocol == unix.IPPROTO_TCP || k.Protocol == unix.IPPROTO_UDP) &&
		k.Conn.S_port != 0 && k.Conn.D_port != 0
}
