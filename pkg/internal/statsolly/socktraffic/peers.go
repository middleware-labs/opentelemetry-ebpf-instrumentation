// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"net"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// endpoint is a local socket address. The network namespace is only kept for loopback
// addresses: the same 127.0.0.1:80 can exist in many containers.
type endpoint struct {
	netns uint32
	addr  pipe.IPAddr
	port  uint16
	proto uint8
}

// pair is a socket without its local port, by its local address and its remote server: it
// finds the client of the rolled-up server stats, whose remote client port is 0.
type pair struct {
	local      endpoint
	remoteAddr pipe.IPAddr
	remotePort uint16
}

type peerEntry struct {
	pid      uint32
	execName string
	cgroupID uint64
	seen     time.Duration
}

// peerIndex finds the process of the remote side of a socket when it is on this host, from
// the rows of both sides, like Datadog's same-host resolver (pkg/process/net/resolver). The
// reader writes it, and the DNS tracer reads it through LocalOwners.
type peerIndex struct {
	mu        sync.RWMutex
	ttl       time.Duration
	endpoints map[endpoint]peerEntry
	pairs     map[pair]peerEntry
}

func newPeerIndex(ttl time.Duration) *peerIndex {
	return &peerIndex{ttl: ttl, endpoints: map[endpoint]peerEntry{}, pairs: map[pair]peerEntry{}}
}

func newEndpoint(netns uint32, addr pipe.IPAddr, port uint16, proto uint8) endpoint {
	if !net.IP(addr[:]).IsLoopback() {
		netns = 0
	}
	return endpoint{netns: netns, addr: addr, port: port, proto: proto}
}

func newPeerEntry(r *row, seen time.Duration) peerEntry {
	return peerEntry{pid: r.Pid, execName: ebpf.CString(r.ExeName[:]), cgroupID: r.CgroupId, seen: seen}
}

// add records the local side of a row. A row without process still tells that its socket is
// on this host.
func (p *peerIndex) add(k *key, r *row, now time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := newPeerEntry(r, now)
	local := newEndpoint(k.Netns, pipe.IPAddr(k.Conn.S_addr), k.Conn.S_port, k.Protocol)
	keepProcess(p.endpoints, local, e)
	local.port = 0
	keepProcess(p.pairs, pair{local: local, remoteAddr: pipe.IPAddr(k.Conn.D_addr), remotePort: k.Conn.D_port}, e)
}

// addTranslated records the local side of a translated row by its endpoints after NAT, as its
// remote side sees them: a rolled-up server stat finds its client that dialed a DNAT-ed address
func (p *peerIndex) addTranslated(k *key, r *row, post ebpf.Endpoints) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := newPeerEntry(r, time.Duration(r.LastUpdateNs))
	local := newEndpoint(k.Netns, post.SrcAddr, 0, k.Protocol)
	keepProcess(p.pairs, pair{local: local, remoteAddr: post.DstAddr, remotePort: post.DstPort}, e)
}

// keepProcess stores an entry without replacing a known process by an unknown one: the rows
// of a server port can have no process
func keepProcess[K comparable](entries map[K]peerEntry, k K, e peerEntry) {
	if old, ok := entries[k]; ok && e.pid == 0 && old.pid != 0 {
		old.seen = max(old.seen, e.seen)
		e = old
	}
	entries[k] = e
}

// remote returns the process of the remote side of a stat, and whether that side is a socket
// of this host. The pid is 0 when its process is not known. It takes the endpoints after NAT,
// like Datadog: a connection to a service finds its backend.
func (p *peerIndex) remote(s *ebpf.Stat) (peerEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	a := s.Endpoints()
	// the TCP stats read from the rows carry the socket in their owner
	netns, transport := s.Owner.NetNS, uint8(syscall.IPPROTO_TCP)
	if t := s.SocketTraffic; t != nil {
		netns, transport = t.NetNS, t.Transport
	}
	if a.DstPort != 0 {
		e, ok := p.endpoints[newEndpoint(netns, a.DstAddr, a.DstPort, transport)]
		return e, ok
	}
	// a rolled-up server stat: the client is a socket of its address whose remote side is this server
	client := newEndpoint(netns, a.DstAddr, 0, transport)
	e, ok := p.pairs[pair{local: client, remoteAddr: a.SrcAddr, remotePort: a.SrcPort}]
	return e, ok
}

// has tells whether a local socket is known
func (p *peerIndex) has(local endpoint) bool {
	_, ok := p.local(local)
	return ok
}

func (p *peerIndex) local(local endpoint) (peerEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.endpoints[local]
	return e, ok
}

// sameHostAddrs tells whether two addresses are both on this host whatever its sockets, like
// Datadog's IntraHost: the same address, or two loopback addresses
func sameHostAddrs(local, remote pipe.IPAddr) bool {
	return local == remote || net.IP(local[:]).IsLoopback() && net.IP(remote[:]).IsLoopback()
}

// prune forgets the sockets not seen since before the TTL
func (p *peerIndex) prune(now time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, e := range p.endpoints {
		if now-e.seen > p.ttl {
			delete(p.endpoints, k)
		}
	}
	for k, e := range p.pairs {
		if now-e.seen > p.ttl {
			delete(p.pairs, k)
		}
	}
}

// Owner is the process of a local socket
type Owner struct {
	Pid      uint32
	ExecName string
	CgroupID uint64
}

// LocalOwners finds the process of the local sockets of the rows, like Datadog joins its DNS
// stats to the connections of their client (pkg/network/state.go). It is safe for concurrent use.
type LocalOwners struct {
	peers *peerIndex
}

// LocalOwners returns the process of the local sockets, for the DNS lookups. It must be called
// before the reader runs.
func (r *Reader) LocalOwners() *LocalOwners {
	if r.peers == nil {
		r.peers = newPeerIndex(peerTTLIntervals * r.interval)
	}
	return &LocalOwners{peers: r.peers}
}

// Find returns the process of a local socket address, which is not a loopback one. found is
// false when the socket is not known yet: the reader learns it at its next map read, or when
// it closes.
func (o *LocalOwners) Find(addr pipe.IPAddr, port uint16, proto uint8) (owner Owner, found bool) {
	e, ok := o.peers.local(newEndpoint(0, addr, port, proto))
	if !ok || e.pid == 0 {
		return Owner{}, false
	}
	return Owner{Pid: e.pid, ExecName: e.execName, CgroupID: e.cgroupID}, true
}
