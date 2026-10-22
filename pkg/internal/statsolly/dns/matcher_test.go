// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

const (
	dnsID   = 0x1234
	qName   = "api.example.com"
	clientP = 40000
)

func ep(ip string, port uint16) Endpoint {
	var addr pipe.IPAddr
	copy(addr[:], net.ParseIP(ip).To16())
	return Endpoint{Addr: addr, Port: port}
}

var (
	pod       = ep("10.244.1.5", clientP)
	clusterIP = ep("10.96.0.10", 53)
	coreDNS   = ep("10.244.1.7", 53)
	node      = ep("192.168.1.10", 61000)
	google    = ep("8.8.8.8", 53)
)

func ms(n int) uint64 {
	return uint64(time.Duration(n) * time.Millisecond)
}

func query(ts uint64, src, dst Endpoint) *Packet {
	return &Packet{TS: ts, Proto: syscall.IPPROTO_UDP, Src: src, Dst: dst, ID: dnsID, QName: qName, QType: uint16(dnsparser.TypeA)}
}

func answer(ts uint64, src, dst Endpoint, rcode dnsparser.RCode) *Packet {
	p := query(ts, src, dst)
	p.Response = true
	p.RCode = uint16(rcode)
	return p
}

func noLookup(t *testing.T, m *Matcher, p *Packet) {
	t.Helper()
	_, ok := m.Packet(p)
	require.False(t, ok)
}

func mustLookup(t *testing.T, m *Matcher, p *Packet) Lookup {
	t.Helper()
	l, ok := m.Packet(p)
	require.True(t, ok)
	return l
}

func TestMatcherQuestionAndAnswer(t *testing.T) {
	m := NewMatcher(DefaultConfig)

	noLookup(t, m, query(ms(1000), pod, google))
	l := mustLookup(t, m, answer(ms(1050), google, pod, dnsparser.RCodeSuccess))

	assert.Equal(t, Lookup{
		Client:   pod,
		Server:   google,
		Duration: 50 * time.Millisecond,
		RCode:    uint16(dnsparser.RCodeSuccess),
		QName:    qName,
		QType:    uint16(dnsparser.TypeA),
	}, l)
	assert.Zero(t, m.Pending())
}

func TestMatcherErrorAnswers(t *testing.T) {
	for _, rcode := range []dnsparser.RCode{dnsparser.RCodeNameError, dnsparser.RCodeServerFailure} {
		t.Run(rcode.String(), func(t *testing.T) {
			m := NewMatcher(DefaultConfig)
			noLookup(t, m, query(ms(1000), pod, google))
			l := mustLookup(t, m, answer(ms(1010), google, pod, rcode))
			assert.Equal(t, uint16(rcode), l.RCode)
			assert.False(t, l.Timeout)
		})
	}
}

func TestMatcherTimeout(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), pod, google))

	assert.Empty(t, m.Expire(ms(1000)+uint64(DefaultConfig.Timeout)), "exactly the timeout is not expired yet")

	expired := m.Expire(ms(1001) + uint64(DefaultConfig.Timeout))
	require.Len(t, expired, 1)
	assert.Equal(t, Lookup{
		Client:   pod,
		Server:   google,
		Duration: DefaultConfig.Timeout,
		Timeout:  true,
		QName:    qName,
		QType:    uint16(dnsparser.TypeA),
	}, expired[0])

	// a late answer finds nothing
	noLookup(t, m, answer(ms(7000), google, pod, dnsparser.RCodeSuccess))
	assert.Zero(t, m.Pending())
}

func TestMatcherExpireIgnoresQuestionsNewerThanNow(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(9000), pod, google))
	assert.Empty(t, m.Expire(ms(1000)))
	assert.Equal(t, 1, m.Pending())
}

func TestMatcherWatermark(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), pod, google))
	noLookup(t, m, query(ms(999), node, google)) // a few µs out of order between CPUs
	assert.Equal(t, ms(1000), m.Watermark())

	// answers and skipped packets move it too
	noLookup(t, m, answer(ms(1200), ep("127.0.0.53", 53), pod, dnsparser.RCodeSuccess))
	assert.Equal(t, ms(1200), m.Watermark())
}

func TestMatcherOutOfOrderAnswerHasNoNegativeDuration(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), pod, google))
	l := mustLookup(t, m, answer(ms(1000)-1000, google, pod, dnsparser.RCodeSuccess))
	assert.Zero(t, l.Duration)
}

func TestMatcherQuestionSeenTwice(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	// e.g. the outgoing and the incoming copy on the loopback interface, or a client retry
	noLookup(t, m, query(ms(1000), pod, google))
	noLookup(t, m, query(ms(1002), pod, google))
	assert.Equal(t, 1, m.Pending())

	l := mustLookup(t, m, answer(ms(1020), google, pod, dnsparser.RCodeSuccess))
	assert.Equal(t, 20*time.Millisecond, l.Duration, "the time of the first copy is kept")
	assert.Zero(t, m.Pending())
}

func TestMatcherDNAT(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), pod, clusterIP)) // pod veth, before DNAT
	noLookup(t, m, query(ms(1000)+50_000, pod, coreDNS))
	assert.Equal(t, 1, m.Pending())

	l := mustLookup(t, m, answer(ms(1003), coreDNS, pod, dnsparser.RCodeSuccess))
	noLookup(t, m, answer(ms(1003)+50_000, clusterIP, pod, dnsparser.RCodeSuccess)) // after reverse NAT

	assert.Equal(t, pod, l.Client)
	assert.Equal(t, coreDNS, l.Server, "the server of the latest copy, after DNAT")
	assert.Equal(t, 3*time.Millisecond, l.Duration)
	assert.Zero(t, m.ServerKeyMerges())
}

func TestMatcherSNAT(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), pod, google))         // pod veth, before SNAT
	noLookup(t, m, query(ms(1000)+80_000, node, google)) // eth0, after SNAT
	assert.Equal(t, 1, m.Pending())
	assert.Equal(t, uint64(1), m.ServerKeyMerges())

	l := mustLookup(t, m, answer(ms(1020), google, node, dnsparser.RCodeSuccess))
	noLookup(t, m, answer(ms(1020)+80_000, google, pod, dnsparser.RCodeSuccess))

	assert.Equal(t, pod, l.Client, "the client of the first copy, before SNAT")
	assert.Equal(t, google, l.Server)
	assert.Equal(t, 20*time.Millisecond, l.Duration)
	assert.Zero(t, m.Pending())
}

func TestMatcherSameServerKeyOutOfDupWindow(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	other := ep("10.244.2.9", 50000)
	noLookup(t, m, query(ms(1000), pod, google))
	noLookup(t, m, query(ms(1050), other, google))
	assert.Equal(t, 2, m.Pending())
	assert.Zero(t, m.ServerKeyMerges())

	first := mustLookup(t, m, answer(ms(1060), google, pod, dnsparser.RCodeSuccess))
	second := mustLookup(t, m, answer(ms(1070), google, other, dnsparser.RCodeSuccess))
	assert.Equal(t, pod, first.Client)
	assert.Equal(t, 60*time.Millisecond, first.Duration)
	assert.Equal(t, other, second.Client)
	assert.Equal(t, 20*time.Millisecond, second.Duration)
}

func TestMatcherSameIDDifferentQuestion(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), pod, google))
	other := query(ms(1001), pod, google)
	other.QName = "other.example.com"
	noLookup(t, m, other)
	assert.Equal(t, 2, m.Pending())

	otherAnswer := answer(ms(1030), google, pod, dnsparser.RCodeNameError)
	otherAnswer.QName = "other.example.com"
	l := mustLookup(t, m, otherAnswer)
	assert.Equal(t, "other.example.com", l.QName)
	assert.Equal(t, uint16(dnsparser.RCodeNameError), l.RCode)

	l = mustLookup(t, m, answer(ms(1040), google, pod, dnsparser.RCodeSuccess))
	assert.Equal(t, qName, l.QName)
}

func TestMatcherLoopbackServer(t *testing.T) {
	resolved := ep("127.0.0.53", 53)
	local := ep("127.0.0.1", 45000)

	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), local, resolved))
	noLookup(t, m, answer(ms(1001), resolved, local, dnsparser.RCodeSuccess))
	assert.Zero(t, m.Pending())

	cfg := DefaultConfig
	cfg.CollectLocal = true
	m = NewMatcher(cfg)
	noLookup(t, m, query(ms(1000), local, resolved))
	noLookup(t, m, query(ms(1000), local, resolved)) // the incoming copy on the loopback interface
	mustLookup(t, m, answer(ms(1001), resolved, local, dnsparser.RCodeSuccess))
	noLookup(t, m, answer(ms(1001), resolved, local, dnsparser.RCodeSuccess))
}

func TestMatcherIPv6LoopbackServer(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), ep("::1", 45000), ep("::1", 53)))
	assert.Zero(t, m.Pending())
}

func TestMatcherAnswerWithoutQuestion(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, answer(ms(1000), google, pod, dnsparser.RCodeSuccess))
	assert.Zero(t, m.Pending())
}

func TestMatcherMaxPending(t *testing.T) {
	cfg := DefaultConfig
	cfg.MaxPending = 2
	m := NewMatcher(cfg)

	// different DNS IDs: the same ID within DupWindow would be merged by the server key
	withID := func(p *Packet, id uint16) *Packet {
		p.ID = id
		return p
	}
	for id := range uint16(3) {
		noLookup(t, m, withID(query(ms(1000), pod, google), id))
	}
	assert.Equal(t, 2, m.Pending())
	assert.Equal(t, uint64(1), m.PendingDrops())

	// a copy of an open question is still matched when the limit is reached
	noLookup(t, m, withID(query(ms(1001), pod, google), 0))
	assert.Equal(t, uint64(1), m.PendingDrops())

	noLookup(t, m, withID(answer(ms(1010), google, pod, dnsparser.RCodeSuccess), 2))
	mustLookup(t, m, withID(answer(ms(1010), google, pod, dnsparser.RCodeSuccess), 0))
	assert.Equal(t, 1, m.Pending())
}

func TestMatcherRemovesAllTheKeys(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	noLookup(t, m, query(ms(1000), pod, clusterIP))
	noLookup(t, m, query(ms(1000), pod, coreDNS))
	noLookup(t, m, query(ms(1000), node, coreDNS))
	mustLookup(t, m, answer(ms(1010), coreDNS, pod, dnsparser.RCodeSuccess))

	assert.Empty(t, m.open)
	assert.Empty(t, m.byClient)
	assert.Empty(t, m.byServer)
}

func TestMatcherServerKeyMergeIsCounted(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	other := ep("10.244.2.9", 50000)
	// the known risk: two clients, same server, same DNS ID and question, within DupWindow
	noLookup(t, m, query(ms(1000), pod, google))
	noLookup(t, m, query(ms(1005), other, google))
	assert.Equal(t, 1, m.Pending())
	assert.Equal(t, uint64(1), m.ServerKeyMerges())
}

func TestMatcherUDPAndTCPAreDifferentQuestions(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	// after a truncated UDP answer, the client asks again over TCP, often with the same DNS ID
	noLookup(t, m, query(ms(1000), pod, google))
	tcpQuery := query(ms(1001), pod, google)
	tcpQuery.Proto = syscall.IPPROTO_TCP
	noLookup(t, m, tcpQuery)
	assert.Equal(t, 2, m.Pending())
	assert.Zero(t, m.ServerKeyMerges())

	tcpAnswer := answer(ms(1030), google, pod, dnsparser.RCodeSuccess)
	tcpAnswer.Proto = syscall.IPPROTO_TCP
	l := mustLookup(t, m, tcpAnswer)
	assert.Equal(t, 29*time.Millisecond, l.Duration)
	assert.Equal(t, 1, m.Pending(), "the UDP question still waits for its own answer")
}

func TestMatcherIgnoresMessagesInTheWrongDirection(t *testing.T) {
	m := NewMatcher(DefaultConfig)
	// e.g. a later segment of a long TCP answer, read as if it started a message
	noLookup(t, m, query(ms(1000), google, pod))
	assert.Zero(t, m.Pending(), "a question must go to the DNS port")

	noLookup(t, m, query(ms(1000), pod, google))
	noLookup(t, m, answer(ms(1010), pod, google, dnsparser.RCodeSuccess))
	assert.Equal(t, 1, m.Pending(), "an answer must come from the DNS port")
}
