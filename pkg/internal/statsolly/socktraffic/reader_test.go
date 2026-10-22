// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestAppendStatsSplitsDirections(t *testing.T) {
	k := key{Protocol: syscall.IPPROTO_TCP}
	copy(k.Conn.S_addr[:], net.ParseIP("10.0.0.1").To16())
	copy(k.Conn.D_addr[:], net.ParseIP("10.0.0.2").To16())
	k.Conn.S_port = 40000
	k.Conn.D_port = 80
	r := row{Pid: 1234, Role: ebpf.StatsTcpHandshakeRoleRoleClient}

	stats := appendStats(nil, &k, &r, totals{txBytes: 76, txPackets: 2, rxBytes: 853, rxPackets: 3})
	require.Len(t, stats, 2)

	wantAttrs := pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(k.Conn.S_addr),
		DstAddr: pipe.IPAddr(k.Conn.D_addr),
		SrcPort: 40000,
		DstPort: 80,
	}
	assert.Equal(t, &ebpf.Stat{
		Type: ebpf.StatTypeSocketTraffic,
		SocketTraffic: &ebpf.SocketTraffic{
			Transport: syscall.IPPROTO_TCP,
			Direction: uint8(ebpf.CodeDirectionTransmit),
			Role:      uint8(ebpf.CodeRoleClient),
			Pid:       1234,
			Bytes:     76,
			Packets:   2,
		},
		CommonAttrs: wantAttrs,
	}, stats[0])
	assert.Equal(t, &ebpf.Stat{
		Type: ebpf.StatTypeSocketTraffic,
		SocketTraffic: &ebpf.SocketTraffic{
			Transport: syscall.IPPROTO_TCP,
			Direction: uint8(ebpf.CodeDirectionReceive),
			Role:      uint8(ebpf.CodeRoleClient),
			Pid:       1234,
			Bytes:     853,
			Packets:   3,
		},
		CommonAttrs: wantAttrs,
	}, stats[1])
}

func TestAppendStatsSkipsDirectionsWithoutTraffic(t *testing.T) {
	k := udpKey(53)

	stats := appendStats(nil, &k, &row{}, totals{rxBytes: 40, rxPackets: 1})
	require.Len(t, stats, 1)
	assert.Equal(t, uint8(ebpf.CodeDirectionReceive), stats[0].SocketTraffic.Direction)

	// a TCP close can add packets without bytes
	stats = appendStats(nil, &k, &row{}, totals{txPackets: 1})
	require.Len(t, stats, 1)
	assert.Equal(t, uint8(ebpf.CodeDirectionTransmit), stats[0].SocketTraffic.Direction)

	assert.Empty(t, appendStats(nil, &k, &row{}, totals{}))
}

type fakeDrops struct{ perCPU map[uint32][]uint64 }

func (f fakeDrops) Lookup(k, valueOut any) error {
	*valueOut.(*[]uint64) = f.perCPU[k.(uint32)]
	return nil
}

type countersReporter struct {
	imetrics.NoopReporter
	insertDrops, closeDrops, underflows uint64
	rows                                int
}

func (c *countersReporter) StatsSocketTrafficCounters(insertDrops, closeDrops, underflows uint64) {
	c.insertDrops, c.closeDrops, c.underflows = insertDrops, closeDrops, underflows
}

func (c *countersReporter) StatsSocketTrafficRows(rows int) { c.rows = rows }

func testReader(t *testing.T, m *fakeMap, now *time.Duration) (*Reader, *countersReporter) {
	metrics := &countersReporter{}
	return &Reader{
		log:      slog.Default(),
		interval: time.Hour,
		batchLen: 100,
		rows:     newMapReader[*fakeIterator](m, config.MapReaderAuto),
		drops: fakeDrops{perCPU: map[uint32][]uint64{
			uint32(ebpf.StatsSocketTrafficDropK_socketTrafficDropInsert): {1, 0, 4},
			uint32(ebpf.StatsSocketTrafficDropK_socketTrafficDropClose):  {2},
		}},
		metrics:    metrics,
		emit:       Emit{Traffic: true},
		deltas:     newDeltaTracker(),
		tcpSockets: newTCPSockets(t.TempDir()),
		monoNow:    func() time.Duration { return *now },
		// ip_local_port_range: 32768 60999
		ephemeralLow:  defaultEphemeralLow,
		ephemeralHigh: defaultEphemeralHigh,
	}, metrics
}

// sumTraffic adds the bytes and packets of the stats by direction
func sumTraffic(stats []*ebpf.Stat) totals {
	var sum totals
	for _, s := range stats {
		if s.SocketTraffic.Direction == uint8(ebpf.CodeDirectionTransmit) {
			sum.txBytes += s.SocketTraffic.Bytes
			sum.txPackets += s.SocketTraffic.Packets
		} else {
			sum.rxBytes += s.SocketTraffic.Bytes
			sum.rxPackets += s.SocketTraffic.Packets
		}
	}
	return sum
}

func TestReaderReadMapReportsIncreases(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 2}
	k := tcpKey(1)
	m.set(k, row{TxBytes: 100, TxPackets: 3, LastUpdateNs: uint64(now)})
	r, metrics := testReader(t, m, &now)

	assert.Equal(t, totals{txBytes: 100, txPackets: 3}, sumTraffic(r.readMap(nil)))
	assert.Len(t, m.keys, 1, "reading must not delete the rows")
	assert.Equal(t, 1, metrics.rows)
	assert.Equal(t, uint64(5), metrics.insertDrops, "drops are summed over the CPUs")
	assert.Equal(t, uint64(2), metrics.closeDrops)

	// a keep-alive connection without traffic is not counted again
	now += 10 * time.Second
	assert.Empty(t, r.readMap(nil))

	now += 10 * time.Second
	m.set(k, row{TxBytes: 150, RxBytes: 20, TxPackets: 4, RxPackets: 2, LastUpdateNs: uint64(now)})
	assert.Equal(t, totals{txBytes: 50, rxBytes: 20, txPackets: 1, rxPackets: 2}, sumTraffic(r.readMap(nil)))
}

func TestReaderIdleCleanup(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 10}
	idleOpenTCP := tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 5432)
	idleClosedTCP := tcpConnKey("10.0.0.9", 40001, "10.0.0.2", 5432)
	busyTCP, idleUDP := tcpKey(2), udpKey(3)
	idleSince := uint64(now - tcpIdleTimeout - time.Second)
	m.set(idleOpenTCP, row{TxBytes: 10, TxPackets: 1, Pid: 100, LastUpdateNs: idleSince})
	m.set(idleClosedTCP, row{TxBytes: 40, TxPackets: 2, Pid: 100, LastUpdateNs: idleSince})
	m.set(busyTCP, row{TxBytes: 20, TxPackets: 1, LastUpdateNs: uint64(now - udpIdleTimeout - time.Second)})
	m.set(idleUDP, row{TxBytes: 30, TxPackets: 1, LastUpdateNs: uint64(now - udpIdleTimeout - time.Second)})
	r, _ := testReader(t, m, &now)
	writeProcNet(t, r.tcpSockets.procRoot, 100, "tcp", procNetLine(net.ParseIP("10.0.0.1"), 40000, net.ParseIP("10.0.0.2"), 5432))

	// every row reports its traffic once; the idle ones whose socket is gone are deleted
	assert.Equal(t, totals{txBytes: 100, txPackets: 5}, sumTraffic(r.readMap(nil)))
	assert.ElementsMatch(t, []key{idleOpenTCP, busyTCP}, m.keys, "an open idle TCP connection keeps its row, like Datadog")
	assert.NotContains(t, r.deltas.entries, idleClosedTCP)
	assert.NotContains(t, r.deltas.entries, idleUDP)

	// the open connection is not checked again before the idle timeout
	require.NoError(t, os.RemoveAll(filepath.Join(r.tcpSockets.procRoot, "100")))
	now += 10 * time.Second
	assert.Empty(t, r.readMap(nil))
	assert.Contains(t, m.keys, idleOpenTCP)

	// it sends again after a long time: only the new traffic is counted, not its whole packet total
	now += time.Hour
	m.set(idleOpenTCP, row{TxBytes: 15, TxPackets: 3, Pid: 100, LastUpdateNs: uint64(now)})
	assert.Equal(t, totals{txBytes: 5, txPackets: 2}, sumTraffic(r.readMap(nil)))
}

// closedRecord encodes a close event like the kernel writes it in the ring buffer
func closedRecord(t *testing.T, k key, v row) []byte {
	t.Helper()
	buf := bytes.Buffer{}
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, ebpf.StatsSocketTrafficClosedT{Key: k, Value: v}))
	return buf.Bytes()
}

type fakeEvents struct{ records [][]byte }

func (f *fakeEvents) SetDeadline(time.Time) {}

func (f *fakeEvents) ReadInto(record *ringbuf.Record) error {
	if len(f.records) == 0 {
		return ringbuf.ErrClosed
	}
	record.RawSample = f.records[0]
	f.records = f.records[1:]
	return nil
}

func TestReaderCloseEvents(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 2}
	readBefore := tcpKey(1)
	m.set(readBefore, row{TxBytes: 100, TxPackets: 3, LastUpdateNs: uint64(now)})
	r, _ := testReader(t, m, &now)
	r.batchLen = 1
	r.readMap(nil)

	// the kernel deletes the row before sending its close event
	m.keys, m.rows = nil, nil
	shortConnection := tcpKey(2)
	events := &fakeEvents{records: [][]byte{
		closedRecord(t, readBefore, row{TxBytes: 120, RxBytes: 30, TxPackets: 5, RxPackets: 2}),
		closedRecord(t, shortConnection, row{TxBytes: 76, RxBytes: 853, TxPackets: 5, RxPackets: 4}),
	}}

	out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	received := out.Subscribe()
	r.readLoop(t.Context(), events, out)

	var stats []*ebpf.Stat
	for range 4 {
		stats = append(stats, <-received...)
	}
	// the connection read before reports its last increase
	assert.Equal(t, totals{txBytes: 20, rxBytes: 30, txPackets: 2, rxPackets: 2}, sumTraffic(stats[:2]))
	// the short connection was never read: its whole totals, packets included
	assert.Equal(t, totals{txBytes: 76, rxBytes: 853, txPackets: 5, rxPackets: 4}, sumTraffic(stats[2:]))
	assert.Empty(t, r.deltas.entries, "closed sockets are forgotten")
}

// deadlineEvents has no event until its first deadline, like a quiet kernel ring buffer whose
// events are below the wake-up threshold
type deadlineEvents struct {
	fakeEvents
	deadlines atomic.Int32
}

func (d *deadlineEvents) SetDeadline(time.Time) { d.deadlines.Add(1) }

func (d *deadlineEvents) ReadInto(record *ringbuf.Record) error {
	if d.deadlines.Load() == 1 {
		return os.ErrDeadlineExceeded
	}
	return d.fakeEvents.ReadInto(record)
}

func TestReaderDrainsTheEventsBelowTheWakeupThreshold(t *testing.T) {
	now := time.Hour
	r, _ := testReader(t, &fakeMap{batchLen: 1}, &now)
	events := &deadlineEvents{fakeEvents: fakeEvents{records: [][]byte{
		closedRecord(t, tcpKey(1), row{TxBytes: 76, TxPackets: 2}),
	}}}
	records := make(chan []byte, 1)
	go r.drainClosed(t.Context(), events, records)

	select {
	case sample := <-records:
		assert.NotEmpty(t, sample)
	case <-time.After(5 * time.Second):
		t.Fatal("the event after the deadline was not read")
	}
	assert.GreaterOrEqual(t, events.deadlines.Load(), int32(2), "a deadline is set before each read")
}

func TestReaderServerPort(t *testing.T) {
	now := time.Hour
	r, _ := testReader(t, &fakeMap{batchLen: 10}, &now)
	procRoot := t.TempDir()
	r.tcpSockets = newTCPSockets(procRoot)
	r.emit.ServerPort = true
	// postgres listens on 5432 in the network namespace of process 300
	writeProcNet(t, procRoot, 300, "tcp", procNetListenLine(net.ParseIP("0.0.0.0"), 5432))

	server := tcpConnKey("10.0.0.2", 5432, "10.0.0.1", 41001)
	client := tcpConnKey("10.0.0.1", 41001, "10.0.0.2", 5432)
	for _, tt := range []struct {
		name string
		k    key
		v    row
		want uint16
	}{
		{"client", client, row{Pid: 999, Role: ebpf.StatsTcpHandshakeRoleRoleClient}, 5432},
		{"server", server, row{Pid: 999, Role: ebpf.StatsTcpHandshakeRoleRoleServer}, 5432},
		// opened before OBI started: no handshake role
		{"local port listening: server", server, row{Pid: 300}, 5432},
		{"local port not listening: client", client, row{Pid: 300}, 5432},
		{"process ended: unknown", server, row{Pid: 555}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r.tcpSockets.reset()
			stats := r.rowStats(nil, &tt.k, &tt.v, r.connectionRole(&tt.k, &tt.v), totals{txBytes: 10, rxBytes: 5}, false)
			require.Len(t, stats, 2)
			for _, s := range stats {
				assert.Equal(t, tt.want, s.ServerPort)
			}
		})
	}

	r.emit.ServerPort = false
	v := row{Role: ebpf.StatsTcpHandshakeRoleRoleClient}
	stats := r.rowStats(nil, &client, &v, r.connectionRole(&client, &v), totals{txBytes: 10}, false)
	require.Len(t, stats, 1)
	assert.Zero(t, stats[0].ServerPort, "not selected")
}

func TestReaderRole(t *testing.T) {
	now := time.Hour
	r, _ := testReader(t, &fakeMap{batchLen: 10}, &now)
	procRoot := t.TempDir()
	r.tcpSockets = newTCPSockets(procRoot)
	r.emit.Role, r.emit.TCPClosed = true, true
	// postgres listens on 5432 in the network namespace of process 300
	writeProcNet(t, procRoot, 300, "tcp", procNetListenLine(net.ParseIP("0.0.0.0"), 5432))

	server := tcpConnKey("10.0.0.2", 5432, "10.0.0.1", 41001)
	client := tcpConnKey("10.0.0.1", 41001, "10.0.0.2", 5432)
	roles := func(stats []*ebpf.Stat) []ebpf.NetworkTCPHandshakeRoleCode {
		var roles []ebpf.NetworkTCPHandshakeRoleCode
		for _, s := range stats {
			if s.SocketTraffic != nil {
				roles = append(roles, ebpf.NetworkTCPHandshakeRoleCode(s.SocketTraffic.Role))
			} else {
				roles = append(roles, ebpf.NetworkTCPHandshakeRoleCode(s.TCPClosedConnection.Role))
			}
		}
		return roles
	}
	for _, tt := range []struct {
		name string
		k    key
		v    row
		want ebpf.NetworkTCPHandshakeRoleCode
	}{
		{"handshake role", client, row{Pid: 999, Role: ebpf.StatsTcpHandshakeRoleRoleClient}, ebpf.CodeRoleClient},
		// opened before OBI started: no handshake role
		{"local port listening: server", server, row{Pid: 300}, ebpf.CodeRoleServer},
		{"local port not listening: client", client, row{Pid: 300}, ebpf.CodeRoleClient},
		{"process ended: unknown", server, row{Pid: 555}, ebpf.CodeRoleUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r.tcpSockets.reset()
			// the socket bytes of both directions, and the closed connection
			tt.v.TxBytes, tt.v.RxBytes = 10, 5
			stats := r.rowStats(nil, &tt.k, &tt.v, r.connectionRole(&tt.k, &tt.v), totals{txBytes: 10, rxBytes: 5}, true)
			assert.Equal(t, []ebpf.NetworkTCPHandshakeRoleCode{tt.want, tt.want, tt.want}, roles(stats))
		})
	}

	r.emit.Role = false
	v := row{Pid: 300, TxBytes: 10}
	stats := r.rowStats(nil, &server, &v, r.connectionRole(&server, &v), totals{txBytes: 10}, true)
	assert.Equal(t, []ebpf.NetworkTCPHandshakeRoleCode{ebpf.CodeRoleUnknown, ebpf.CodeRoleUnknown}, roles(stats), "not selected")
	assert.Equal(t, ebpf.StatsTcpHandshakeRoleRoleUnknown, v.Role, "the row is not changed")
}

func udpConnKey(local string, localPort uint16, remote string, remotePort uint16) key {
	k := tcpConnKey(local, localPort, remote, remotePort)
	k.Protocol = syscall.IPPROTO_UDP
	return k
}

func TestReaderUDPRole(t *testing.T) {
	now := time.Hour
	r, _ := testReader(t, &fakeMap{batchLen: 10}, &now)
	r.peers = newPeerIndex(time.Minute)
	r.emit.Role = true
	// a NetFlow receiver of this host, on its Docker bridge address
	collector := udpConnKey("172.30.0.1", 2055, "172.30.0.4", 50000)
	r.peers.add(&collector, &row{}, now)

	server := ebpf.StatsTcpHandshakeRoleRoleServer
	client := ebpf.StatsTcpHandshakeRoleRoleClient
	for _, tt := range []struct {
		name string
		k    key
		role ebpf.StatsTcpHandshakeRole
		want ebpf.NetworkTCPHandshakeRoleCode
	}{
		{"bound server port", udpConnKey("10.0.0.1", 53, "10.0.0.9", 40000), server, ebpf.CodeRoleServer},
		{"connected client", udpConnKey("10.0.0.1", 40000, "10.0.0.9", 53), client, ebpf.CodeRoleClient},
		// a client that binds an ephemeral port
		{"bound ephemeral port to a well-known port", udpConnKey("10.0.0.1", 40000, "8.8.8.8", 53), server, ebpf.CodeRoleClient},
		{"bound ephemeral port to a local server", udpConnKey("127.0.0.1", 40000, "127.0.0.1", 8125), server, ebpf.CodeRoleClient},
		{"bound ephemeral port to a remote host", udpConnKey("10.0.0.1", 40000, "10.0.0.9", 8125), server, ebpf.CodeRoleServer},
		// a server port bound before its bind was seen
		{"local server to a local client", udpConnKey("127.0.0.1", 8125, "127.0.0.1", 44700), client, ebpf.CodeRoleServer},
		{"fixed ports on both sides", udpConnKey("172.30.0.4", 2055, "172.30.0.1", 2055), client, ebpf.CodeRoleClient},
		{"client of a local server", udpConnKey("172.30.0.4", 50000, "172.30.0.1", 2055), client, ebpf.CodeRoleClient},
		{"local port to a remote host", udpConnKey("10.0.0.1", 8125, "10.0.0.9", 44700), client, ebpf.CodeRoleClient},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, uint8(tt.want), r.connectionRole(&tt.k, &row{Role: tt.role}))
		})
	}

	k := udpConnKey("127.0.0.1", 8125, "127.0.0.1", 44700)
	r.emit.Role = false
	assert.Equal(t, uint8(client), r.connectionRole(&k, &row{Role: client}), "the role is not used")
}

func TestReaderUDPRoleOfTheRemoteSocketReadLater(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 1}
	r, _ := testReader(t, m, &now)
	r.peers = newPeerIndex(time.Minute)
	r.emit.Role = true

	// the receiver row took the client role, and comes before the row of its client
	receiver := udpConnKey("172.30.0.1", 2055, "172.30.0.4", 50000)
	sender := udpConnKey("172.30.0.4", 50000, "172.30.0.1", 2055)
	m.set(receiver, row{RxBytes: 10, RxPackets: 1, Role: ebpf.StatsTcpHandshakeRoleRoleClient, LastUpdateNs: uint64(now)})
	m.set(sender, row{TxBytes: 10, TxPackets: 1, Role: ebpf.StatsTcpHandshakeRoleRoleClient, LastUpdateNs: uint64(now)})

	stats := r.readMap(nil)
	require.Len(t, stats, 2)
	for _, s := range stats {
		want := ebpf.CodeRoleClient
		if s.CommonAttrs.SrcPort == 2055 {
			want = ebpf.CodeRoleServer
		}
		assert.Equal(t, uint8(want), s.SocketTraffic.Role, "local port %d", s.CommonAttrs.SrcPort)
	}
}

func TestReaderRollupTakesTheCorrectedRole(t *testing.T) {
	now := time.Hour
	r, _ := testReader(t, &fakeMap{batchLen: 10}, &now)
	r.peers = newPeerIndex(time.Minute)
	r.rollup = newConnectionRollup()

	// two closed rows of a local server whose port was bound before its bind was seen
	for _, clientPort := range []uint16{44700, 44701} {
		k := udpConnKey("127.0.0.1", 8125, "127.0.0.1", clientPort)
		r.appendClosedStats(nil, &k, &row{Role: ebpf.StatsTcpHandshakeRoleRoleClient, RxBytes: 10}, totals{rxBytes: 10, rxPackets: 1})
	}
	stats := r.flushClosed(nil, now)
	require.Len(t, stats, 1, "merged by the server port")
	assert.Equal(t, uint16(8125), stats[0].CommonAttrs.SrcPort)
	assert.Zero(t, stats[0].CommonAttrs.DstPort, "the client ports are dropped")
	assert.Equal(t, uint64(20), stats[0].SocketTraffic.Bytes)
}
