// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"encoding/binary"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/dns"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const (
	wireSizeDNSPacket      = 320
	wireDNSProtoOffset     = 1
	wireDNSLenOffset       = 2
	wireDNSConnOffset      = 4
	wireDNSTsOffset        = 40
	wireDNSBufOffset       = 48
	dnsTestQuestionTS      = uint64(10 * time.Second)
	dnsTestAnswerLatencyNS = uint64(50 * time.Millisecond)
)

var (
	dnsClient = ebpf.Conn{S_addr: testIP("10.244.1.5"), S_port: 40000, D_addr: testIP("10.96.0.10"), D_port: 53}
	dnsServer = ebpf.Conn{S_addr: testIP("10.96.0.10"), S_port: 53, D_addr: testIP("10.244.1.5"), D_port: 40000}
)

func dnsMessage(t *testing.T, response bool, rcode dnsmessage.RCode) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 77, Response: response, RCode: rcode})
	require.NoError(t, b.StartQuestions())
	require.NoError(t, b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}))
	msg, err := b.Finish()
	require.NoError(t, err)
	return msg
}

func newWireDNSPacket(ts uint64, conn ebpf.Conn, msg []byte) []byte {
	raw := newWireStat(ebpf.StatTypeDNSLookup, wireSizeDNSPacket, wireDNSConnOffset, conn)
	raw[wireDNSProtoOffset] = syscall.IPPROTO_UDP
	binary.NativeEndian.PutUint16(raw[wireDNSLenOffset:], uint16(len(msg)))
	binary.NativeEndian.PutUint64(raw[wireDNSTsOffset:], ts)
	copy(raw[wireDNSBufOffset:], msg)
	return raw
}

func TestDNSPacketWireLayout(t *testing.T) {
	assert.Equal(t, uintptr(wireSizeDNSPacket), unsafe.Sizeof(ebpf.StatsDNSPacket{}))
	assert.Equal(t, unsafe.Sizeof(ebpf.StatsDnsPacketT{}), unsafe.Sizeof(ebpf.StatsDNSPacket{}))
	assert.Len(t, ebpf.StatsDnsPacketT{}.Buf, ebpf.DNSPacketBufSize)

	var p ebpf.StatsDNSPacket
	assert.Equal(t, uintptr(wireDNSProtoOffset), unsafe.Offsetof(p.L4Proto))
	assert.Equal(t, uintptr(wireDNSLenOffset), unsafe.Offsetof(p.Len))
	assert.Equal(t, uintptr(wireDNSConnOffset), unsafe.Offsetof(p.Conn))
	assert.Equal(t, uintptr(wireDNSTsOffset), unsafe.Offsetof(p.TS))
	assert.Equal(t, uintptr(wireDNSBufOffset), unsafe.Offsetof(p.Buf))
}

func TestReadDNSPacket(t *testing.T) {
	ipv6 := ebpf.Conn{S_addr: testIP("fd00::5"), S_port: 40000, D_addr: testIP("fd00::53"), D_port: 53}
	raw := newWireDNSPacket(dnsTestQuestionTS, ipv6, dnsMessage(t, false, dnsmessage.RCodeSuccess))
	raw[wireDNSProtoOffset] = syscall.IPPROTO_TCP

	p, err := readDNSPacket(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)
	assert.Equal(t, dns.Packet{
		TS:    dnsTestQuestionTS,
		Proto: syscall.IPPROTO_TCP,
		Src:   dns.Endpoint{Addr: pipe.IPAddr(ipv6.S_addr), Port: 40000},
		Dst:   dns.Endpoint{Addr: pipe.IPAddr(ipv6.D_addr), Port: 53},
		ID:    77,
		QName: "example.com",
		QType: uint16(dnsmessage.TypeA),
	}, p)
}

func TestReadDNSPacketBoundsLength(t *testing.T) {
	raw := newWireDNSPacket(dnsTestQuestionTS, dnsClient, dnsMessage(t, false, dnsmessage.RCodeSuccess))
	binary.NativeEndian.PutUint16(raw[wireDNSLenOffset:], ^uint16(0))

	_, err := readDNSPacket(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)

	_, err = readDNSPacket(&ringbuf.Record{RawSample: raw[:wireSizeDNSPacket-1]})
	require.Error(t, err)
}

func TestExpiryTime(t *testing.T) {
	watermark := uint64(10 * time.Second)
	clock := uint64(20 * time.Second)

	assert.Equal(t, watermark, expiryTime(watermark, clock, false), "OBI reads behind the kernel: only the packet time is safe")
	assert.Equal(t, clock-uint64(dnsClockSlack), expiryTime(watermark, clock, true), "nothing waiting: the clock is safe")
	assert.Equal(t, clock, expiryTime(clock, uint64(5*time.Second), true), "the packet time never goes back")
	assert.Equal(t, watermark, expiryTime(watermark, uint64(dnsClockSlack)-1, true))
}

type fakeRead struct {
	raw []byte
	err error
}

// fakeDNSReader returns its reads in order, then ErrClosed.
type fakeDNSReader struct {
	reads     []fakeRead
	available int
}

func (r *fakeDNSReader) SetDeadline(time.Time) {}

func (r *fakeDNSReader) ReadInto(record *ringbuf.Record) error {
	if len(r.reads) == 0 {
		return ringbuf.ErrClosed
	}
	next := r.reads[0]
	r.reads = r.reads[1:]
	record.RawSample = next.raw
	return next.err
}

func (r *fakeDNSReader) AvailableBytes() int {
	return r.available
}

type dnsMetricsRecorder struct {
	imetrics.NoopReporter
	droppedQuestions uint64
	lag              float64
}

func (r *dnsMetricsRecorder) StatsDNSCounters(droppedQuestions, _ uint64) {
	r.droppedQuestions = droppedQuestions
}

func (r *dnsMetricsRecorder) StatsDNSReaderLag(seconds float64) {
	r.lag = seconds
}

func newTestDNSTracer(clock *time.Duration, metrics imetrics.Reporter) *DNSTracer {
	tracer := NewDNSTracer(nil, &config.EBPFTracer{BatchLength: 100}, metrics, true)
	tracer.monoNow = func() time.Duration { return *clock }
	return tracer
}

func runReadLoop(t *testing.T, tracer *DNSTracer, reader *fakeDNSReader) [][]*ebpf.Stat {
	t.Helper()
	out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	output := out.Subscribe()
	tracer.readLoop(t.Context(), reader, out)
	out.Close()

	var batches [][]*ebpf.Stat
	for batch := range output {
		batches = append(batches, batch)
	}
	return batches
}

func TestDNSTracerQuestionAndAnswer(t *testing.T) {
	clock := time.Duration(dnsTestQuestionTS + dnsTestAnswerLatencyNS)
	metrics := &dnsMetricsRecorder{}
	reader := &fakeDNSReader{reads: []fakeRead{
		{raw: newWireDNSPacket(dnsTestQuestionTS, dnsClient, dnsMessage(t, false, dnsmessage.RCodeSuccess))},
		{raw: []byte{byte(ebpf.StatTypeDNSLookup)}}, // malformed records are skipped
		{raw: newWireDNSPacket(dnsTestQuestionTS+dnsTestAnswerLatencyNS, dnsServer, dnsMessage(t, true, dnsmessage.RCodeNameError))},
		{err: os.ErrDeadlineExceeded},
	}}

	batches := runReadLoop(t, newTestDNSTracer(&clock, metrics), reader)

	require.Len(t, batches, 1)
	assert.Equal(t, []*ebpf.Stat{{
		Type: ebpf.StatTypeDNSLookup,
		DNSLookup: &ebpf.DNSLookup{
			Duration: 50 * time.Millisecond,
			RCode:    uint16(dnsmessage.RCodeNameError),
			QName:    "example.com",
			QType:    uint16(dnsmessage.TypeA),
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcAddr: pipe.IPAddr(dnsClient.S_addr),
			DstAddr: pipe.IPAddr(dnsClient.D_addr),
			SrcPort: dnsClient.S_port,
			DstPort: dnsClient.D_port,
		},
	}}, batches[0])
	assert.InDelta(t, 0.05, metrics.lag, 1e-9, "the question was read 50 ms after the kernel saw it")
}

func TestDNSTracerQuietTimeout(t *testing.T) {
	// one question, no other DNS packet and nothing waiting in the ring buffer: the clock decides
	clock := time.Duration(dnsTestQuestionTS) + dns.DefaultConfig.Timeout + dnsClockSlack + time.Nanosecond
	reader := &fakeDNSReader{reads: []fakeRead{
		{raw: newWireDNSPacket(dnsTestQuestionTS, dnsClient, dnsMessage(t, false, dnsmessage.RCodeSuccess))},
		{err: os.ErrDeadlineExceeded},
	}}

	batches := runReadLoop(t, newTestDNSTracer(&clock, nil), reader)

	require.Len(t, batches, 1)
	require.Len(t, batches[0], 1)
	assert.Equal(t, &ebpf.DNSLookup{
		Duration: dns.DefaultConfig.Timeout,
		Timeout:  true,
		QName:    "example.com",
		QType:    uint16(dnsmessage.TypeA),
	}, batches[0][0].DNSLookup)
}

func TestDNSTracerNotYetTimedOut(t *testing.T) {
	clock := time.Duration(dnsTestQuestionTS) + dns.DefaultConfig.Timeout
	reader := &fakeDNSReader{reads: []fakeRead{
		{raw: newWireDNSPacket(dnsTestQuestionTS, dnsClient, dnsMessage(t, false, dnsmessage.RCodeSuccess))},
		{err: os.ErrDeadlineExceeded},
	}}

	assert.Empty(t, runReadLoop(t, newTestDNSTracer(&clock, nil), reader))
}

func TestDNSTracerSlowReader(t *testing.T) {
	// the answer is still waiting in the ring buffer, 10 s after its question
	clock := time.Duration(dnsTestQuestionTS) + 10*time.Second
	tracer := newTestDNSTracer(&clock, nil)

	question := newWireDNSPacket(dnsTestQuestionTS, dnsClient, dnsMessage(t, false, dnsmessage.RCodeSuccess))
	tracer.addLookup(&ringbuf.Record{RawSample: question})
	assert.Empty(t, tracer.sweep(false), "no false timeout while the ring buffer is not empty")

	answer := newWireDNSPacket(dnsTestQuestionTS+dnsTestAnswerLatencyNS, dnsServer, dnsMessage(t, true, dnsmessage.RCodeSuccess))
	tracer.addLookup(&ringbuf.Record{RawSample: answer})
	batch := tracer.sweep(false)
	require.Len(t, batch, 1)
	assert.False(t, batch[0].DNSLookup.Timeout)
	assert.Equal(t, 50*time.Millisecond, batch[0].DNSLookup.Duration, "the latency comes from the kernel times, not from the read time")
}

// withClientPort returns the question and answer connections of a client using port
func withClientPort(port uint16) (question, answer ebpf.Conn) {
	question, answer = dnsClient, dnsServer
	question.S_port, answer.D_port = port, port
	return question, answer
}

func TestDNSTracerSendsAtTheSweepInChunks(t *testing.T) {
	clock := time.Duration(dnsTestQuestionTS)
	tracer := newTestDNSTracer(&clock, nil)
	tracer.cfg.BatchLength = 1

	var reads []fakeRead
	for _, port := range []uint16{40000, 40001} {
		question, answer := withClientPort(port)
		reads = append(reads,
			fakeRead{raw: newWireDNSPacket(dnsTestQuestionTS, question, dnsMessage(t, false, dnsmessage.RCodeSuccess))},
			fakeRead{raw: newWireDNSPacket(dnsTestQuestionTS+dnsTestAnswerLatencyNS, answer, dnsMessage(t, true, dnsmessage.RCodeSuccess))})
	}
	reads = append(reads, fakeRead{err: os.ErrDeadlineExceeded})

	batches := runReadLoop(t, tracer, &fakeDNSReader{reads: reads})
	require.Len(t, batches, 2, "two lookups kept apart by their client port, sent in chunks of BatchLength")
	require.Len(t, batches[0], 1)
	require.Len(t, batches[1], 1)
}

func TestDNSTracerMergesLookups(t *testing.T) {
	clock := time.Duration(dnsTestQuestionTS)
	tracer := NewDNSTracer(nil, &config.EBPFTracer{BatchLength: 100}, nil, false)
	tracer.monoNow = func() time.Duration { return clock }

	// three clients ports asking the same question, answered after 10, 20 and 30 ms
	for i, port := range []uint16{40000, 40001, 40002} {
		question, answer := withClientPort(port)
		latency := uint64(i+1) * uint64(10*time.Millisecond)
		tracer.addLookup(&ringbuf.Record{RawSample: newWireDNSPacket(dnsTestQuestionTS, question, dnsMessage(t, false, dnsmessage.RCodeSuccess))})
		tracer.addLookup(&ringbuf.Record{RawSample: newWireDNSPacket(dnsTestQuestionTS+latency, answer, dnsMessage(t, true, dnsmessage.RCodeSuccess))})
	}
	// a different result is a different stat
	question, answer := withClientPort(40003)
	tracer.addLookup(&ringbuf.Record{RawSample: newWireDNSPacket(dnsTestQuestionTS, question, dnsMessage(t, false, dnsmessage.RCodeSuccess))})
	tracer.addLookup(&ringbuf.Record{RawSample: newWireDNSPacket(dnsTestQuestionTS+dnsTestAnswerLatencyNS, answer, dnsMessage(t, true, dnsmessage.RCodeNameError))})

	batch := tracer.sweep(false)
	require.Len(t, batch, 2)
	slices.SortFunc(batch, func(a, b *ebpf.Stat) int { return int(a.DNSLookup.RCode) - int(b.DNSLookup.RCode) })

	merged := batch[0]
	assert.Equal(t, uint16(0), merged.CommonAttrs.SrcPort, "the client port is not kept")
	durations := append([]time.Duration{merged.DNSLookup.Duration}, merged.DNSLookup.Merged...)
	assert.ElementsMatch(t, []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}, durations,
		"every duration is still recorded")
	assert.Empty(t, batch[1].DNSLookup.Merged)
	assert.Equal(t, uint16(dnsmessage.RCodeNameError), batch[1].DNSLookup.RCode)

	assert.Empty(t, tracer.sweep(false), "the sweep starts a new interval")
}
