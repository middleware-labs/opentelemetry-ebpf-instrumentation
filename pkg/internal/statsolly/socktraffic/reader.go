// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"syscall"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	// rows without traffic for this long are reported and deleted: they catch the lost close
	// events, the sockets that never close cleanly and the rows of the unconnected UDP sockets
	// (one per remote). Like Datadog, an idle TCP row is kept while its connection is open,
	// and checked again after the same time. Datadog's TCPConnTimeout and UDPConnTimeout defaults.
	tcpIdleTimeout = 2 * time.Minute
	udpIdleTimeout = 30 * time.Second
	// deltaRetention is how long the totals of a key are kept after it was last read
	deltaRetention = 10 * time.Minute
	// peerTTLIntervals is how many read intervals a socket is kept in the peer index
	peerTTLIntervals = 3
	// closedBufferLen is how many close events wait in user space while the map is read
	closedBufferLen = 1 << 16
	// pendingRetryInterval is how often the closed stats whose remote socket was not known at
	// their close are looked up again: the remote side of a local connection usually closes
	// right after
	pendingRetryInterval = time.Second
	// wellKnownPorts bounds the server ports of the remote hosts, like Datadog's
	// fixIncomingConnectionDirection
	wellKnownPorts = 1024
)

type rowsReader interface {
	lookup(fn func(*key, *row)) error
	delete(k *key) error
}

// closedReader extracts the used methods from ringbuf.Reader, for testing.
type closedReader interface {
	SetDeadline(time.Time)
	ReadInto(*ringbuf.Record) error
}

// dropsMap extracts the used methods from ebpf.Map, for testing.
type dropsMap interface {
	Lookup(key, valueOut any) error
}

// Reader reports the bytes and packets of each socket. At every interval it reads the
// socket_traffic map without deleting the rows, and in between it reads the final row of
// the closed sockets from the socket_traffic_closed ring buffer. The rows hold totals:
// the reader reports their increases.
type Reader struct {
	log          *slog.Logger
	interval     time.Duration
	batchLen     int
	rows         rowsReader
	closedEvents *ciliumebpf.Map
	drops        dropsMap
	metrics      imetrics.Reporter
	emit         Emit
	deltas       *deltaTracker
	tcpSockets   *tcpSockets
	// rollup merges the closed connections until the next map read, nil when disabled
	rollup *connectionRollup
	// peers finds the remote side on this host: for the dst.* process and container attributes,
	// network.peer.same_host and the UDP role. nil when none of them is used.
	peers *peerIndex
	// resolveRemote is true when a dst.* process or container attribute or network.peer.same_host
	// is selected: a closed connection whose remote socket is not known yet waits in
	// pendingClosed until it is, or until the next map read.
	resolveRemote bool
	pendingClosed []*ebpf.Stat
	// retryClosed are the closed stats whose remote socket was not found yet: its close event
	// can come after the map read. They wait one more read.
	retryClosed []*ebpf.Stat
	// monoNow is the kernel monotonic clock, replaceable for testing
	monoNow func() time.Duration
	// the ephemeral port range, for the role of the UDP rows
	ephemeralLow, ephemeralHigh uint16

	insertDrops uint64
}

func NewReader(
	trafficMap, closedEvents, drops *ciliumebpf.Map,
	ebpfCfg *config.EBPFTracer,
	cfg *config.SocketTrafficConfig,
	procRoot string,
	emit Emit,
	resolvePeers bool,
	metrics imetrics.Reporter,
) *Reader {
	if metrics == nil {
		metrics = imetrics.NoopReporter{}
	}
	var rollup *connectionRollup
	if cfg.ConnectionRollup {
		rollup = newConnectionRollup()
	}
	var peers *peerIndex
	// the role of a UDP row can depend on its remote socket being on this host
	udpRole := cfg.UDP() && (emit.Role || emit.ServerPort || cfg.ConnectionRollup)
	if resolvePeers || udpRole {
		// a closed socket stays known for a while: its peer can close later
		peers = newPeerIndex(peerTTLIntervals * cfg.ReadInterval)
	}
	ephemeralLow, ephemeralHigh := ephemeralPortRange(procRoot)
	return &Reader{
		log:           slog.With("component", "socktraffic.Reader"),
		interval:      cfg.ReadInterval,
		rollup:        rollup,
		peers:         peers,
		resolveRemote: resolvePeers,
		ephemeralLow:  ephemeralLow,
		ephemeralHigh: ephemeralHigh,
		batchLen:      max(ebpfCfg.BatchLength, 1),
		rows:          newMapReader[*ciliumebpf.MapIterator](trafficMap, ebpfCfg.ForceBPFMapReader),
		closedEvents:  closedEvents,
		drops:         drops,
		metrics:       metrics,
		emit:          emit,
		deltas:        newDeltaTracker(),
		tcpSockets:    newTCPSockets(procRoot),
		monoNow:       timing.MonoClock(),
	}
}

func (r *Reader) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()

		events, err := ringbuf.NewReader(r.closedEvents)
		if err != nil {
			r.log.Error("creating socket traffic close events reader. Exiting", "error", err)
			return
		}
		go func() {
			<-ctx.Done()
			_ = events.Close()
		}()

		r.readLoop(ctx, events, out)
	}
}

// readLoop handles the close events and reads the map every interval. The close events are
// read from the kernel by drainClosed, so the ring buffer keeps draining while the map is read,
// like Datadog's closed connections channel. One goroutine handles both: the close event of a
// socket is handled after the map reads that saw its row, as the kernel deletes the row before
// it sends the event.
func (r *Reader) readLoop(ctx context.Context, events closedReader, out *msg.Queue[[]*ebpf.Stat]) {
	records := make(chan []byte, closedBufferLen)
	go r.drainClosed(ctx, events, records)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	var retry <-chan time.Time
	if r.resolveRemote {
		retryTicker := time.NewTicker(pendingRetryInterval)
		defer retryTicker.Stop()
		retry = retryTicker.C
	}

	var batch []*ebpf.Stat
	send := func() {
		for chunk := range slices.Chunk(batch, r.batchLen) {
			out.SendCtx(ctx, chunk)
		}
		batch = nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case sample, ok := <-records:
			if !ok {
				return
			}
			batch = r.appendClosed(batch, &ringbuf.Record{RawSample: sample})
			if len(batch) >= r.batchLen {
				send()
			}
		case <-retry:
			batch = r.resolvePending(batch)
			send()
		case <-ticker.C:
			batch = r.readMap(batch)
			send()
		}
	}
}

// drainClosed reads the close events from the kernel until the reader is closed
func (r *Reader) drainClosed(ctx context.Context, events closedReader, records chan<- []byte) {
	defer close(records)
	var record ringbuf.Record
	for {
		// the kernel only wakes the reader up when stats_wakeup_data_bytes are waiting: at the
		// deadline, the reader reads the events below it
		events.SetDeadline(time.Now().Add(r.interval))
		err := events.ReadInto(&record)
		if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
			return
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			r.log.Debug("error reading socket traffic close events", "error", err)
			continue
		}
		// ReadInto reuses the buffer of the record
		select {
		case records <- slices.Clone(record.RawSample):
		case <-ctx.Done():
			return
		}
	}
}

func (r *Reader) appendClosed(stats []*ebpf.Stat, record *ringbuf.Record) []*ebpf.Stat {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsSocketTrafficClosedT](record.RawSample)
	if err != nil {
		r.log.Debug("error parsing socket traffic close event", "error", err)
		return stats
	}
	now := r.monoNow()
	if r.peers != nil {
		r.peers.add(&event.Key, &event.Value, now)
	}
	delta := r.deltas.closed(&event.Key, rowTotals(&event.Value), now)
	return r.appendClosedStats(stats, &event.Key, &event.Value, delta)
}

// appendClosedStats appends the stats of a closed connection, or keeps them until the next
// map read: in the rollup, or to find the remote process.
func (r *Reader) appendClosedStats(stats []*ebpf.Stat, k *key, v *row, delta totals) []*ebpf.Stat {
	role := r.connectionRole(k, v)
	switch {
	case r.rollup != nil:
		for _, s := range r.rowStats(nil, k, v, role, delta, true) {
			if !r.rollup.add(s, role) {
				r.keepClosed(s)
			}
		}
		return stats
	case r.resolveRemote:
		// sent now when the remote socket is known: holding every closed connection until the
		// map read would send them all at once
		for _, s := range r.rowStats(nil, k, v, role, delta, true) {
			if r.findRemote(s) {
				stats = append(stats, s)
			} else {
				r.pendingClosed = append(r.pendingClosed, s)
			}
		}
		return stats
	default:
		return r.rowStats(stats, k, v, role, delta, true)
	}
}

// keepClosed sends a closed connection stat with the next map read when the remote process is
// looked up, or now
func (r *Reader) keepClosed(s *ebpf.Stat) {
	r.pendingClosed = append(r.pendingClosed, s)
}

// rowStats appends the stats of the increase of a row, with the port of its server side and
// the role of the connection (from connectionRole) when they are selected
func (r *Reader) rowStats(stats []*ebpf.Stat, k *key, v *row, role uint8, delta totals, closed bool) []*ebpf.Stat {
	if r.emit.Role && role != uint8(v.Role) {
		resolved := *v
		resolved.Role = ebpf.StatsTcpHandshakeRole(role)
		v = &resolved
	}
	n := len(stats)
	stats = r.emit.appendRowStats(stats, k, v, delta, closed)
	if r.emit.ServerPort {
		for _, s := range stats[n:] {
			s.ServerPort = ebpf.ServerPortOf(role, k.Conn.S_port, k.Conn.D_port)
		}
	}
	return stats
}

// roleUsed tells whether the role of the rows is reported, or merges the closed connections
func (r *Reader) roleUsed() bool {
	return r.emit.Role || r.emit.ServerPort || r.rollup != nil
}

// connectionRole returns the role of a row when it is used. A TCP connection opened before OBI
// started has no handshake role: like Datadog, it is the server side when its local port is
// listening. A UDP row takes its role from the bound ports, which udpRole corrects.
func (r *Reader) connectionRole(k *key, v *row) uint8 {
	role := uint8(v.Role)
	if !r.roleUsed() {
		return role
	}
	if k.Protocol == syscall.IPPROTO_UDP {
		return r.udpRole(k, role)
	}
	if ebpf.NetworkTCPHandshakeRoleCode(role) != ebpf.CodeRoleUnknown || k.Protocol != syscall.IPPROTO_TCP {
		return role
	}
	listening, known := r.tcpSockets.isListening(k, v.Pid)
	switch {
	case !known:
		return role
	case listening:
		return uint8(ebpf.CodeRoleServer)
	default:
		return uint8(ebpf.CodeRoleClient)
	}
}

// udpRole returns the role of a UDP row, corrected like Datadog's fixIncomingConnectionDirection
// and fixOutgoingConnectionDirection
func (r *Reader) udpRole(k *key, role uint8) uint8 {
	fixed, ifIntraHost := r.udpRoleFix(k, role)
	if ifIntraHost && !r.intraHost(k) {
		return role
	}
	return fixed
}

// udpRoleFix returns the corrected role of a UDP row, and whether it only applies when the remote
// socket is on this host. The kernel takes the role from the bound ports: a client can bind its
// port, and a server port can be bound before its bind is seen.
func (r *Reader) udpRoleFix(k *key, role uint8) (fixed uint8, ifIntraHost bool) {
	localEphemeral, remoteEphemeral := r.ephemeral(k.Conn.S_port), r.ephemeral(k.Conn.D_port)
	switch ebpf.NetworkTCPHandshakeRoleCode(role) {
	case ebpf.CodeRoleServer:
		if localEphemeral && k.Conn.D_port < wellKnownPorts {
			return uint8(ebpf.CodeRoleClient), false
		}
		if localEphemeral && !remoteEphemeral {
			return uint8(ebpf.CodeRoleClient), true
		}
	case ebpf.CodeRoleClient:
		if !localEphemeral && remoteEphemeral {
			return uint8(ebpf.CodeRoleServer), true
		}
	}
	return role, false
}

func (r *Reader) ephemeral(port uint16) bool {
	return port >= r.ephemeralLow && port <= r.ephemeralHigh
}

// intraHost tells whether the remote side of a row is on this host, like Datadog's IntraHost
func (r *Reader) intraHost(k *key) bool {
	remote := pipe.IPAddr(k.Conn.D_addr)
	return sameHostAddrs(pipe.IPAddr(k.Conn.S_addr), remote) ||
		r.peers != nil && r.peers.has(newEndpoint(k.Netns, remote, k.Conn.D_port, k.Protocol))
}

// roleNeedsAllRows tells whether the role of a row depends on its remote socket being on this
// host: the row is then handled after the map read, as its remote socket can come later
func (r *Reader) roleNeedsAllRows(k *key, v *row) bool {
	if k.Protocol != syscall.IPPROTO_UDP || !r.roleUsed() {
		return false
	}
	_, ifIntraHost := r.udpRoleFix(k, uint8(v.Role))
	return ifIntraHost
}

// resolvePending appends the pending closed stats whose remote socket is known now
func (r *Reader) resolvePending(stats []*ebpf.Stat) []*ebpf.Stat {
	pending := r.pendingClosed[:0]
	for _, s := range r.pendingClosed {
		if r.findRemote(s) {
			stats = append(stats, s)
		} else {
			pending = append(pending, s)
		}
	}
	clear(r.pendingClosed[len(pending):])
	r.pendingClosed = pending
	return stats
}

// flushClosed appends the stats kept until the map read and finds their remote processes
func (r *Reader) flushClosed(stats []*ebpf.Stat, now time.Duration) []*ebpf.Stat {
	closed := r.pendingClosed
	r.pendingClosed = nil
	if r.rollup != nil {
		closed = r.rollup.flush(closed)
	}
	if !r.resolveRemote {
		if r.peers != nil {
			r.peers.prune(now)
		}
		return append(stats, closed...)
	}

	for _, s := range stats {
		r.findRemote(s)
	}
	retry := r.retryClosed
	r.retryClosed = nil
	for _, s := range closed {
		if !r.findRemote(s) {
			r.retryClosed = append(r.retryClosed, s)
			continue
		}
		stats = append(stats, s)
	}
	for _, s := range retry {
		r.findRemote(s)
		stats = append(stats, s)
	}
	r.peers.prune(now)
	return stats
}

// findRemote sets the remote process of a stat and whether it is on this host, and tells whether
// the process is known
func (r *Reader) findRemote(s *ebpf.Stat) bool {
	if t := s.SocketTraffic; t != nil {
		if t.DstPid != 0 {
			return true
		}
		peer := r.remote(s)
		t.DstPid, t.DstExecName, t.DstCgroupID = peer.pid, peer.execName, peer.cgroupID
		return peer.pid != 0
	}
	o := &s.Owner
	if o.DstPid != 0 {
		return true
	}
	peer := r.remote(s)
	o.DstPid, o.DstExecName, o.DstCgroupID = peer.pid, peer.execName, peer.cgroupID
	return peer.pid != 0
}

// remote returns the process of the remote side of a stat, and sets whether that side is on
// this host
func (r *Reader) remote(s *ebpf.Stat) peerEntry {
	peer, found := r.peers.remote(s)
	s.SameHost = found || sameHostAddrs(s.CommonAttrs.SrcAddr, s.CommonAttrs.DstAddr)
	return peer
}

// keptRow is a row handled after the map read
type keptRow struct {
	key key
	row row
}

func (r *Reader) readMap(stats []*ebpf.Stat) []*ebpf.Stat {
	now := r.monoNow()
	rowCount := 0
	var idle, later []keptRow
	r.tcpSockets.reset()
	err := r.rows.lookup(func(k *key, v *row) {
		rowCount++
		if r.peers != nil {
			r.peers.add(k, v, time.Duration(v.LastUpdateNs))
		}
		if r.roleNeedsAllRows(k, v) {
			later = append(later, keptRow{key: *k, row: *v})
			return
		}
		stats = r.readRow(stats, &idle, k, v, now)
	})
	if err != nil {
		r.log.Warn("error reading the socket traffic map", "error", err)
	}
	for i := range later {
		stats = r.readRow(stats, &idle, &later[i].key, &later[i].row, now)
	}

	for i := range idle {
		k, v := &idle[i].key, &idle[i].row
		if k.Protocol == syscall.IPPROTO_TCP && r.tcpSockets.isOpen(k, v.Pid) {
			stats = r.rowStats(stats, k, v, r.connectionRole(k, v), r.deltas.update(k, rowTotals(v), now), false)
			r.deltas.markOpen(k, now)
			continue
		}
		// a row that is already gone was closed in between: its close event reports it
		if err := r.rows.delete(k); err != nil {
			continue
		}
		stats = r.appendClosedStats(stats, k, v, r.deltas.closed(k, rowTotals(v), now))
	}
	r.deltas.prune(now - deltaRetention)
	stats = r.flushClosed(stats, now)

	r.reportCounters(rowCount)
	return stats
}

// readRow appends the stats of a row read from the map, or keeps it in idle
func (r *Reader) readRow(stats []*ebpf.Stat, idle *[]keptRow, k *key, v *row, now time.Duration) []*ebpf.Stat {
	if isIdle(k, v, now) && !r.deltas.openSince(k, now-tcpIdleTimeout) {
		*idle = append(*idle, keptRow{key: *k, row: *v})
		return stats
	}
	return r.rowStats(stats, k, v, r.connectionRole(k, v), r.deltas.update(k, rowTotals(v), now), false)
}

func isIdle(k *key, v *row, now time.Duration) bool {
	timeout := tcpIdleTimeout
	if k.Protocol == syscall.IPPROTO_UDP {
		timeout = udpIdleTimeout
	}
	return now-time.Duration(v.LastUpdateNs) > timeout
}

func (r *Reader) reportCounters(rows int) {
	insertDrops := r.readDrops(ebpf.StatsSocketTrafficDropK_socketTrafficDropInsert)
	if insertDrops > r.insertDrops {
		r.log.Warn("socket traffic map full: the traffic of new sockets is not counted until rows free up."+
			" Increase stats.socket_traffic.max_entries", "drops", insertDrops-r.insertDrops)
	}
	r.insertDrops = insertDrops

	r.metrics.StatsSocketTrafficCounters(insertDrops,
		r.readDrops(ebpf.StatsSocketTrafficDropK_socketTrafficDropClose), r.deltas.underflows)
	r.metrics.StatsSocketTrafficRows(rows)
}

// readDrops sums a per-CPU drop counter
func (r *Reader) readDrops(drop ebpf.StatsSocketTrafficDrop) uint64 {
	var perCPU []uint64
	if err := r.drops.Lookup(uint32(drop), &perCPU); err != nil {
		r.log.Debug("error reading the socket traffic drops", "error", err)
		return 0
	}
	var total uint64
	for _, drops := range perCPU {
		total += drops
	}
	return total
}
