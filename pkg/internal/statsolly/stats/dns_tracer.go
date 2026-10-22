// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/dns"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// dnsSweepInterval is how often the questions without answer are checked for timeout,
// the matched lookups are sent to the pipeline, and the internal metrics are reported.
const dnsSweepInterval = time.Second

// dnsClockSlack is subtracted from the clock when it decides the timeouts, for the packets
// that the kernel was still writing when the ring buffer was found empty.
const dnsClockSlack = time.Second

func dtlog() *slog.Logger {
	return slog.With("component", "stat.DNSTracer")
}

// dnsReader extracts the used methods from ringbuf.Reader, for testing.
type dnsReader interface {
	SetDeadline(time.Time)
	ReadInto(*ringbuf.Record) error
	AvailableBytes() int
}

// DNSTracer reads the DNS packets of the stats DNS socket filter, matches the questions
// with their answers, and forwards the lookups to the pipeline.
type DNSTracer struct {
	log     *slog.Logger
	events  *ciliumebpf.Map
	cfg     *config.EBPFTracer
	metrics imetrics.Reporter
	matcher *dns.Matcher
	// monoNow is the kernel monotonic clock, replaceable for testing
	monoNow func() time.Duration
	// maxLag is the longest time between a packet and its read since the last sweep
	maxLag time.Duration
	// lookups merges the lookups until the next sweep
	lookups *lookupAggregator
}

// NewDNSTracer reads the DNS packets. keepClientPort keeps the client port of the lookups,
// when it is a reported or filtered attribute: otherwise the lookups of each second that only
// differ by it are merged.
func NewDNSTracer(events *ciliumebpf.Map, cfg *config.EBPFTracer, metrics imetrics.Reporter, keepClientPort bool) *DNSTracer {
	if metrics == nil {
		metrics = imetrics.NoopReporter{}
	}
	return &DNSTracer{
		log:     dtlog(),
		events:  events,
		cfg:     cfg,
		metrics: metrics,
		matcher: dns.NewMatcher(dns.DefaultConfig),
		monoNow: timing.MonoClock(),
		lookups: newLookupAggregator(keepClientPort),
	}
}

func (t *DNSTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()

		reader, err := ringbuf.NewReader(t.events)
		if err != nil {
			t.log.Error("creating DNS ring buffer reader. Exiting", "error", err)
			return
		}
		go func() {
			<-ctx.Done()
			_ = reader.Close()
		}()

		t.readLoop(ctx, reader, out)
	}
}

// readLoop is the only user of the matcher. The read deadline wakes it up for the sweeps
// when no DNS packet arrives, and the ring buffer is then empty. The lookups are sent at the
// sweeps, merged.
func (t *DNSTracer) readLoop(ctx context.Context, reader dnsReader, out *msg.Queue[[]*ebpf.Stat]) {
	var record ringbuf.Record
	nextSweep := time.Now().Add(dnsSweepInterval)

	for {
		reader.SetDeadline(nextSweep)
		err := reader.ReadInto(&record)
		if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
			return
		}

		ringEmpty := errors.Is(err, os.ErrDeadlineExceeded)
		switch {
		case err == nil:
			t.addLookup(&record)
		case !ringEmpty:
			t.log.Debug("error reading DNS ring buffer", "error", err)
		}

		now := time.Now()
		if !ringEmpty && now.Before(nextSweep) {
			continue
		}
		batch := t.sweep(ringEmpty || reader.AvailableBytes() == 0)
		nextSweep = now.Add(dnsSweepInterval)
		for chunk := range slices.Chunk(batch, max(t.cfg.BatchLength, 1)) {
			out.SendCtx(ctx, chunk)
		}
	}
}

func (t *DNSTracer) addLookup(record *ringbuf.Record) {
	packet, err := readDNSPacket(record)
	if err != nil {
		t.log.Debug("error parsing DNS packet", "error", err)
		return
	}

	t.maxLag = max(t.maxLag, t.monoNow()-time.Duration(packet.TS))

	if lookup, ok := t.matcher.Packet(&packet); ok {
		t.lookups.add(&lookup)
	}
}

// sweep returns the merged lookups of the interval, with the questions that timed out
func (t *DNSTracer) sweep(ringEmpty bool) []*ebpf.Stat {
	now := expiryTime(t.matcher.Watermark(), uint64(t.monoNow()), ringEmpty)
	for _, lookup := range t.matcher.Expire(now) {
		t.lookups.add(&lookup)
	}

	t.metrics.StatsDNSCounters(t.matcher.PendingDrops(), t.matcher.ServerKeyMerges())
	t.metrics.StatsDNSReaderLag(t.maxLag.Seconds())
	t.maxLag = 0

	return t.lookups.flush()
}

// expiryTime is the packet time that decides which questions timed out. The newest packet
// time seen is always safe. The clock is only used when the ring buffer is empty: otherwise,
// when OBI reads behind the kernel, answers still waiting there would become false timeouts.
// The clock is needed too: without other DNS packets, the newest packet time does not move.
func expiryTime(watermark, monoNow uint64, ringEmpty bool) uint64 {
	if !ringEmpty || monoNow < uint64(dnsClockSlack) {
		return watermark
	}
	return max(watermark, monoNow-uint64(dnsClockSlack))
}

func readDNSPacket(record *ringbuf.Record) (dns.Packet, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsDNSPacket](record.RawSample)
	if err != nil {
		return dns.Packet{}, err
	}
	src := dns.Endpoint{Addr: pipe.IPAddr(event.S_addr), Port: event.S_port}
	dst := dns.Endpoint{Addr: pipe.IPAddr(event.D_addr), Port: event.D_port}
	return dns.ParsePacket(event.TS, event.L4Proto, src, dst, event.Buf[:min(int(event.Len), len(event.Buf))])
}

// lookupToStat reports the client as the source and the DNS server as the destination.
func lookupToStat(lookup *dns.Lookup) *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeDNSLookup,
		DNSLookup: &ebpf.DNSLookup{
			Duration: lookup.Duration,
			RCode:    lookup.RCode,
			Timeout:  lookup.Timeout,
			QName:    lookup.QName,
			QType:    lookup.QType,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcAddr: lookup.Client.Addr,
			DstAddr: lookup.Server.Addr,
			SrcPort: lookup.Client.Port,
			DstPort: lookup.Server.Port,
		},
	}
}

// lookupAggregator merges the lookups of a sweep interval that only differ by their duration
// (and by the client port, when it is not kept), like Datadog's DNS stat keeper
// (pkg/network/dns/stats.go): their stat is decorated and labeled once, and still records
// every duration. Clients use a new port for each question, so most lookups merge.
type lookupAggregator struct {
	keepClientPort bool
	stats          map[dns.Lookup]*ebpf.Stat
}

func newLookupAggregator(keepClientPort bool) *lookupAggregator {
	return &lookupAggregator{keepClientPort: keepClientPort, stats: map[dns.Lookup]*ebpf.Stat{}}
}

func (a *lookupAggregator) add(lookup *dns.Lookup) {
	k := *lookup
	k.Duration = 0
	if !a.keepClientPort {
		k.Client.Port = 0
	}
	if s, ok := a.stats[k]; ok {
		s.DNSLookup.Merged = append(s.DNSLookup.Merged, lookup.Duration)
		return
	}
	s := lookupToStat(lookup)
	s.CommonAttrs.SrcPort = k.Client.Port
	a.stats[k] = s
}

func (a *lookupAggregator) flush() []*ebpf.Stat {
	if len(a.stats) == 0 {
		return nil
	}
	stats := make([]*ebpf.Stat, 0, len(a.stats))
	for _, s := range a.stats {
		stats = append(stats, s)
	}
	clear(a.stats)
	return stats
}
