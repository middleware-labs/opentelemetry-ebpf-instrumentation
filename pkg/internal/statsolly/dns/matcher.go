// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package dns matches the DNS questions and answers that the stats socket filter sees
// in OBI's network namespace, to build host-wide DNS lookups.
package dns // import "go.opentelemetry.io/obi/pkg/internal/statsolly/dns"

import (
	"time"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

// Config of the Matcher.
type Config struct {
	// Timeout after which a question without answer becomes a timed-out lookup.
	Timeout time.Duration
	// DupWindow is the time in which a question copy that matches only the server side
	// (client address and port changed by SNAT) is considered the same question.
	DupWindow time.Duration
	// MaxPending is the maximum number of questions waiting for an answer. New questions are dropped above it.
	MaxPending int
	// CollectLocal enables the lookups to loopback DNS servers (e.g. systemd-resolved at 127.0.0.53).
	CollectLocal bool
}

// DefaultConfig follows Datadog's DNS monitor, except for the timeout, which is the same as OBI's application DNS.
var DefaultConfig = Config{
	Timeout:    5 * time.Second,
	DupWindow:  10 * time.Millisecond,
	MaxPending: 10_000,
}

// serverPort mirrors k_dns_port in bpf/statsolly/sock_dns.c.
const serverPort = 53

// Endpoint is one side of a DNS exchange.
type Endpoint struct {
	Addr pipe.IPAddr
	Port uint16
}

// Packet is a DNS question or answer seen by the socket filter.
type Packet struct {
	// TS is the kernel monotonic time when the packet was seen, in nanoseconds.
	TS uint64
	// Proto is the transport protocol: syscall.IPPROTO_UDP or syscall.IPPROTO_TCP.
	Proto    uint8
	Src      Endpoint
	Dst      Endpoint
	ID       uint16
	Response bool
	RCode    uint16
	QName    string
	QType    uint16
}

// Lookup is a DNS question with its answer, or a question that got no answer before the timeout.
type Lookup struct {
	Client   Endpoint
	Server   Endpoint
	Duration time.Duration
	RCode    uint16
	Timeout  bool
	QName    string
	QType    uint16
}

// question is the part of a DNS message that is the same in all the copies of a question and in its answer.
type question struct {
	proto uint8
	id    uint16
	qtype uint16
	qname string
}

type clientKey struct {
	client Endpoint
	question
}

type serverKey struct {
	server pipe.IPAddr
	question
}

// pending is a question waiting for its answer. NAT changes one side of the packet at a time,
// so each copy of the question matches it by the client key (DNAT changed the server)
// or by the server key (SNAT changed the client), and adds its other key.
type pending struct {
	question
	ts         uint64   // first copy
	client     Endpoint // first copy, before SNAT
	server     Endpoint // latest copy, after DNAT
	clientKeys []clientKey
	serverKeys []serverKey
}

// Matcher matches DNS questions and answers. It is not safe for concurrent use.
type Matcher struct {
	cfg      Config
	open     map[*pending]struct{}
	byClient map[clientKey]*pending
	byServer map[serverKey]*pending

	watermark       uint64
	pendingDrops    uint64
	serverKeyMerges uint64
}

func NewMatcher(cfg Config) *Matcher {
	return &Matcher{
		cfg:      cfg,
		open:     map[*pending]struct{}{},
		byClient: map[clientKey]*pending{},
		byServer: map[serverKey]*pending{},
	}
}

// Packet processes a DNS packet and returns the lookup that its answer completes, if any.
func (m *Matcher) Packet(p *Packet) (Lookup, bool) {
	m.watermark = max(m.watermark, p.TS)

	if !fromClientToServer(p) {
		return Lookup{}, false
	}

	if p.Response {
		if m.skipServer(p.Src.Addr) {
			return Lookup{}, false
		}
		return m.answer(p)
	}

	if !m.skipServer(p.Dst.Addr) {
		m.question(p)
	}
	return Lookup{}, false
}

// Expire removes the questions that got no answer before the timeout, at the given packet time,
// and returns them as timed-out lookups.
func (m *Matcher) Expire(now uint64) []Lookup {
	var expired []Lookup
	for pd := range m.open {
		if now < pd.ts || now-pd.ts <= uint64(m.cfg.Timeout) {
			continue
		}
		m.remove(pd)
		expired = append(expired, Lookup{
			Client:   pd.client,
			Server:   pd.server,
			Duration: m.cfg.Timeout,
			Timeout:  true,
			QName:    pd.qname,
			QType:    pd.qtype,
		})
	}
	return expired
}

// Watermark returns the newest packet time seen.
func (m *Matcher) Watermark() uint64 {
	return m.watermark
}

// Pending returns the number of questions waiting for an answer.
func (m *Matcher) Pending() int {
	return len(m.open)
}

// PendingDrops returns how many questions were dropped because MaxPending questions were waiting.
func (m *Matcher) PendingDrops() uint64 {
	return m.pendingDrops
}

// ServerKeyMerges returns how many question copies were matched only by the server key.
// Two different clients asking the same server the same question with the same DNS ID
// within DupWindow would also be counted here, as a wrong merge.
func (m *Matcher) ServerKeyMerges() uint64 {
	return m.serverKeyMerges
}

// fromClientToServer checks that a question goes to the DNS port and an answer comes from it.
// DNS over TCP is read without reassembly, so a later segment of a long TCP answer can be
// read as a message: it must not become a question that never gets an answer.
func fromClientToServer(p *Packet) bool {
	if p.Response {
		return p.Src.Port == serverPort
	}
	return p.Dst.Port == serverPort
}

func (m *Matcher) skipServer(server pipe.IPAddr) bool {
	return !m.cfg.CollectLocal && server.IP().IsLoopback()
}

func (m *Matcher) question(p *Packet) {
	q := question{proto: p.Proto, id: p.ID, qtype: p.QType, qname: p.QName}
	ck := clientKey{client: p.Src, question: q}
	sk := serverKey{server: p.Dst.Addr, question: q}

	// another copy of the question (the server may have changed by DNAT), or a client retry
	if pd, ok := m.byClient[ck]; ok {
		pd.server = p.Dst
		m.addServerKey(pd, sk)
		return
	}

	// another copy of the question with the client changed by SNAT. Out of DupWindow,
	// it is the same question from another client
	if pd, ok := m.byServer[sk]; ok && absDiff(p.TS, pd.ts) <= uint64(m.cfg.DupWindow) {
		m.serverKeyMerges++
		pd.server = p.Dst
		m.addClientKey(pd, ck)
		return
	}

	if len(m.open) >= m.cfg.MaxPending {
		m.pendingDrops++
		return
	}

	pd := &pending{question: q, ts: p.TS, client: p.Src, server: p.Dst}
	m.open[pd] = struct{}{}
	m.addClientKey(pd, ck)
	m.addServerKey(pd, sk)
}

// answer completes the question of the first copy of an answer. The later copies find nothing.
// Answers are matched only by the client key: every question copy adds its client, so the answer
// copies before and after SNAT both match. Matching by the server key could close another client's question.
func (m *Matcher) answer(p *Packet) (Lookup, bool) {
	q := question{proto: p.Proto, id: p.ID, qtype: p.QType, qname: p.QName}

	pd, ok := m.byClient[clientKey{client: p.Dst, question: q}]
	if !ok {
		return Lookup{}, false
	}

	m.remove(pd)

	// packets from different CPUs can reach the ring buffer a few microseconds out of order
	var duration time.Duration
	if p.TS > pd.ts {
		duration = time.Duration(p.TS - pd.ts)
	}
	return Lookup{
		Client:   pd.client,
		Server:   pd.server,
		Duration: duration,
		RCode:    p.RCode,
		QName:    pd.qname,
		QType:    pd.qtype,
	}, true
}

func (m *Matcher) addClientKey(pd *pending, ck clientKey) {
	m.byClient[ck] = pd
	pd.clientKeys = append(pd.clientKeys, ck)
}

// addServerKey points the server key to the newest question that has it,
// since different clients can ask the same server the same question.
func (m *Matcher) addServerKey(pd *pending, sk serverKey) {
	if m.byServer[sk] == pd {
		return
	}
	m.byServer[sk] = pd
	pd.serverKeys = append(pd.serverKeys, sk)
}

func (m *Matcher) remove(pd *pending) {
	delete(m.open, pd)
	for _, ck := range pd.clientKeys {
		delete(m.byClient, ck)
	}
	for _, sk := range pd.serverKeys {
		if m.byServer[sk] == pd {
			delete(m.byServer, sk)
		}
	}
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
