// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/docker"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/dns"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// dnsSweepInterval is how often the questions without answer are checked for timeout,
// the matched lookups are sent to the pipeline, and the internal metrics are reported.
const dnsSweepInterval = time.Second

// dnsClockSlack is subtracted from the clock when it decides the timeouts, for the packets
// that the kernel was still writing when the ring buffer was found empty.
const dnsClockSlack = time.Second

// maxWaitingLookups bounds the lookups waiting for the process of their client, like Datadog's
// max_dns_stats. The lookups above it are sent without process.
const maxWaitingLookups = 20_000

func dtlog() *slog.Logger {
	return slog.With("component", "stat.DNSTracer")
}

// dnsReader extracts the used methods from ringbuf.Reader, for testing.
type dnsReader interface {
	SetDeadline(time.Time)
	ReadInto(*ringbuf.Record) error
	AvailableBytes() int
}

// localOwners extracts the used method of socktraffic.LocalOwners, for testing.
type localOwners interface {
	Find(addr pipe.IPAddr, port uint16, proto uint8) (socktraffic.Owner, bool)
}

// containerAddrs extracts the used method of docker.AddrIndex, for testing.
type containerAddrs interface {
	ContainerID(addr docker.Addr) (docker.ContainerID, bool)
}

// waitingLookup is a lookup whose client socket is not known yet
type waitingLookup struct {
	lookup dns.Lookup
	since  time.Duration
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
	// owners finds the process of the client and the server of the lookups, nil when no
	// process or container attribute is selected
	owners localOwners
	// ownerWait is how long a lookup waits for its client socket to be known
	ownerWait time.Duration
	waiting   []waitingLookup
	// containers finds the container of the servers without socket, nil without Docker or
	// when no dst process or container attribute is selected
	containers containerAddrs
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

// FindOwners sets the process and container of the lookups, like Datadog joins its DNS stats to
// the connections of their client: the client socket is found in the socket traffic rows,
// which the reader learns at its map reads and at their close. A lookup waits up to wait for
// it, and is then sent without process.
func (t *DNSTracer) FindOwners(owners *socktraffic.LocalOwners, wait time.Duration) {
	if owners != nil {
		t.owners, t.ownerWait = owners, wait
	}
}

// FindContainers sets the container of the servers not found in the socket traffic rows from
// their address, like Datadog's LocalResolver falls back to the addresses of the containers. It
// gives the container, not the process.
func (t *DNSTracer) FindContainers(containers *docker.AddrIndex) {
	if containers != nil {
		t.containers = containers
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
		t.resolve(&lookup)
	}
}

// resolve merges a lookup with the process of its client, or keeps it until the client is known
func (t *DNSTracer) resolve(lookup *dns.Lookup) {
	if t.owners == nil {
		t.lookups.add(lookup, t.sockOwner(lookup, socktraffic.Owner{}))
		return
	}
	owner, found := t.owners.Find(lookup.Client.Addr, lookup.Client.Port, lookup.Proto)
	if !found && len(t.waiting) < maxWaitingLookups {
		t.waiting = append(t.waiting, waitingLookup{lookup: *lookup, since: t.monoNow()})
		return
	}
	t.lookups.add(lookup, t.sockOwner(lookup, owner))
}

// sockOwner is the process of the client of a lookup, and of its server when it is on this host.
// A server without socket gets its container only, when it is a local container.
func (t *DNSTracer) sockOwner(lookup *dns.Lookup, client socktraffic.Owner) ebpf.SockOwner {
	owner := ebpf.SockOwner{Pid: client.Pid, ExecName: client.ExecName, CgroupID: client.CgroupID}
	if t.owners != nil {
		if server, found := t.owners.Find(lookup.Server.Addr, lookup.Server.Port, lookup.Proto); found {
			owner.DstPid, owner.DstExecName, owner.DstCgroupID = server.Pid, server.ExecName, server.CgroupID
			return owner
		}
	}
	if t.containers != nil {
		id, _ := t.containers.ContainerID(serverAddr(lookup))
		owner.DstContainerID = string(id)
	}
	return owner
}

// serverAddr is the address of the server of a lookup, as the containers declare it
func serverAddr(lookup *dns.Lookup) docker.Addr {
	proto := "udp"
	if lookup.Proto == syscall.IPPROTO_TCP {
		proto = "tcp"
	}
	return docker.Addr{IP: netip.AddrFrom16(lookup.Server.Addr), Port: lookup.Server.Port, Proto: proto}
}

// resolveWaiting merges the waiting lookups whose client is known now, or that waited too long
func (t *DNSTracer) resolveWaiting() {
	now := t.monoNow()
	waiting := t.waiting[:0]
	for _, w := range t.waiting {
		owner, found := t.owners.Find(w.lookup.Client.Addr, w.lookup.Client.Port, w.lookup.Proto)
		if !found && now-w.since < t.ownerWait {
			waiting = append(waiting, w)
			continue
		}
		t.lookups.add(&w.lookup, t.sockOwner(&w.lookup, owner))
	}
	clear(t.waiting[len(waiting):])
	t.waiting = waiting
}

// sweep returns the merged lookups of the interval, with the questions that timed out
func (t *DNSTracer) sweep(ringEmpty bool) []*ebpf.Stat {
	now := expiryTime(t.matcher.Watermark(), uint64(t.monoNow()), ringEmpty)
	for _, lookup := range t.matcher.Expire(now) {
		t.resolve(&lookup)
	}
	if t.owners != nil {
		t.resolveWaiting()
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

// lookupKey is what the merged lookups share: all but their duration (and their client port,
// when it is not kept), with the processes of their client and server
type lookupKey struct {
	lookup dns.Lookup
	owner  ebpf.SockOwner
}

// lookupAggregator merges the lookups of a sweep interval that only differ by their duration
// (and by the client port, when it is not kept), like Datadog's DNS stat keeper
// (pkg/network/dns/stats.go): their stat is decorated and labeled once, and still records
// every duration. Clients use a new port for each question, so most lookups merge.
type lookupAggregator struct {
	keepClientPort bool
	stats          map[lookupKey]*ebpf.Stat
}

func newLookupAggregator(keepClientPort bool) *lookupAggregator {
	return &lookupAggregator{keepClientPort: keepClientPort, stats: map[lookupKey]*ebpf.Stat{}}
}

func (a *lookupAggregator) add(lookup *dns.Lookup, owner ebpf.SockOwner) {
	k := lookupKey{lookup: *lookup, owner: owner}
	k.lookup.Duration = 0
	if !a.keepClientPort {
		k.lookup.Client.Port = 0
	}
	if s, ok := a.stats[k]; ok {
		s.DNSLookup.Merged = append(s.DNSLookup.Merged, lookup.Duration)
		return
	}
	s := lookupToStat(lookup)
	s.CommonAttrs.SrcPort = k.lookup.Client.Port
	s.Owner = owner
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
