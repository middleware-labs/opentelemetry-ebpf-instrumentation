// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

var allTCP = EmitFor(new(export.FeatureStats), true)

// byType groups stats by type
func byType(stats []*ebpf.Stat) map[ebpf.StatType][]*ebpf.Stat {
	m := map[ebpf.StatType][]*ebpf.Stat{}
	for _, s := range stats {
		m[s.Type] = append(m[s.Type], s)
	}
	return m
}

func TestEmitFor(t *testing.T) {
	features := export.FeatureStatsTCPRtt | export.FeatureStatsSocketBytes | export.FeatureStatsTCPFailedConnections
	assert.Equal(t, Emit{Traffic: true, TCPRtt: true}, EmitFor(&features, true))
	assert.Equal(t, Emit{Traffic: true}, EmitFor(&features, false), "the TCP metrics are events")
}

func TestAppendTCPStats(t *testing.T) {
	k := tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80)
	r := row{
		Role: ebpf.StatsTcpHandshakeRole(ebpf.CodeRoleClient), Pid: 42, CgroupId: 7,
		ExeName: [16]uint8{'c', 'u', 'r', 'l'}, SrttUs: 1500, Established: 1, TxBytes: 76, RxBytes: 853,
	}
	delta := totals{
		txBytes: 76, rxBytes: 853, established: 1, retransFast: 2, retransTimeout: 1, zeroWindow: 3,
		deliveredCE: 4, reordSeen: 5, rcvOOOPack: 6,
	}

	stats := byType(allTCP.appendTCPStats(nil, &k, &r, delta, false))
	require.Len(t, stats[ebpf.StatTypeTCPSuccessfulConnection], 1)
	successful := stats[ebpf.StatTypeTCPSuccessfulConnection][0]
	assert.Equal(t, uint64(1), successful.Events())
	assert.Equal(t, uint8(ebpf.CodeRoleClient), successful.TCPSuccessfulConnection.Role)
	assert.Equal(t, ebpf.SockOwner{Pid: 42, NetNS: k.Netns, ExecName: "curl", CgroupID: 7}, successful.Owner)
	assert.Equal(t, uint16(40000), successful.CommonAttrs.SrcPort)

	assert.Empty(t, stats[ebpf.StatTypeTCPClosedConnection], "not closed yet")
	require.Len(t, stats[ebpf.StatTypeTCPRtt], 1)
	assert.Equal(t, uint32(1500), stats[ebpf.StatTypeTCPRtt][0].TCPRtt.SrttUs)

	retransmits := map[uint8]uint64{}
	for _, s := range stats[ebpf.StatTypeTCPRetransmit] {
		retransmits[s.TCPRetransmitType] = s.Events()
	}
	assert.Equal(t, map[uint8]uint64{uint8(ebpf.CodeRetransmitFast): 2, uint8(ebpf.CodeRetransmitTimeout): 1}, retransmits)

	io := map[uint8]uint64{}
	for _, s := range stats[ebpf.StatTypeTCPIo] {
		io[s.TCPIo.Direction] = s.TCPIo.Bytes
	}
	assert.Equal(t, map[uint8]uint64{uint8(ebpf.CodeDirectionTransmit): 76, uint8(ebpf.CodeDirectionReceive): 853}, io)

	require.Len(t, stats[ebpf.StatTypeTCPFlowControl], 1)
	assert.Equal(t, uint64(3), stats[ebpf.StatTypeTCPFlowControl][0].Events())
	require.Len(t, stats[ebpf.StatTypeTCPCongestion], 1)
	assert.Equal(t, ebpf.TCPCongestion{DeliveredCE: 4, ReordSeen: 5, RcvOOOPack: 6, Role: uint8(ebpf.CodeRoleClient)},
		*stats[ebpf.StatTypeTCPCongestion][0].TCPCongestion)
}

func TestAppendTCPStatsClosedAndIdle(t *testing.T) {
	k := tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80)
	established := row{Established: 1, SrttUs: 900}

	// an idle connection: no stat, not even its RTT
	assert.Empty(t, allTCP.appendTCPStats(nil, &k, &established, totals{}, false))

	// its close: the closed connection and its last RTT
	stats := byType(allTCP.appendTCPStats(nil, &k, &established, totals{}, true))
	assert.Len(t, stats[ebpf.StatTypeTCPClosedConnection], 1)
	assert.Len(t, stats[ebpf.StatTypeTCPRtt], 1)

	// a connection that took the row over before the previous one with the same addresses
	// sent its close: both are closed
	reused := row{Established: 2, SrttUs: 900}
	stats = byType(allTCP.appendTCPStats(nil, &k, &reused, totals{}, true))
	require.Len(t, stats[ebpf.StatTypeTCPClosedConnection], 1)
	assert.Equal(t, uint64(2), stats[ebpf.StatTypeTCPClosedConnection][0].Events())

	// a connection that never established (only SYN retransmits): not a closed connection
	failed := row{RetransTimeout: 2}
	stats = byType(allTCP.appendTCPStats(nil, &k, &failed, totals{retransTimeout: 2}, true))
	assert.Empty(t, stats[ebpf.StatTypeTCPClosedConnection])
	assert.Empty(t, stats[ebpf.StatTypeTCPRtt], "no RTT measured")

	// a late retransmit of a socket closed by the application: no new connection, no new RTT
	orphan := row{RetransTimeout: 1, SrttUs: 900}
	stats = byType(allTCP.appendTCPStats(nil, &k, &orphan, totals{retransTimeout: 1}, true))
	assert.Empty(t, stats[ebpf.StatTypeTCPClosedConnection])
	assert.Empty(t, stats[ebpf.StatTypeTCPRtt])
	assert.Len(t, stats[ebpf.StatTypeTCPRetransmit], 1)
	assert.Len(t, stats[ebpf.StatTypeTCPRetransmit], 1)

	// an RTT that is not one
	tooLong := row{Established: 1, SrttUs: uint32((2 * maxSrtt).Microseconds())}
	assert.Empty(t, byType(allTCP.appendTCPStats(nil, &k, &tooLong, totals{}, true))[ebpf.StatTypeTCPRtt])
}

func TestConnectionRollupMergesTheTCPStats(t *testing.T) {
	r := newConnectionRollup()
	server := ebpf.StatsTcpHandshakeRole(ebpf.CodeRoleServer)
	for i, port := range []uint16{40001, 40002, 40003} {
		k := tcpConnKey("10.0.0.2", 80, "10.0.0.1", port)
		v := row{Role: server, Pid: 9, Established: 1, SrttUs: uint32(100 * (i + 1)), RetransFast: 1}
		for _, s := range allTCP.appendTCPStats(nil, &k, &v, rowTotals(&v), true) {
			require.True(t, r.add(s, uint8(server)))
		}
	}
	stats := byType(r.flush(nil))

	require.Len(t, stats[ebpf.StatTypeTCPSuccessfulConnection], 1)
	assert.Equal(t, uint64(3), stats[ebpf.StatTypeTCPSuccessfulConnection][0].Events())
	assert.Zero(t, stats[ebpf.StatTypeTCPSuccessfulConnection][0].CommonAttrs.DstPort, "the client port is rolled up")
	require.Len(t, stats[ebpf.StatTypeTCPClosedConnection], 1)
	assert.Equal(t, uint64(3), stats[ebpf.StatTypeTCPClosedConnection][0].Events())
	require.Len(t, stats[ebpf.StatTypeTCPRetransmit], 1)
	assert.Equal(t, uint64(3), stats[ebpf.StatTypeTCPRetransmit][0].Events())

	require.Len(t, stats[ebpf.StatTypeTCPRtt], 1)
	rtt := stats[ebpf.StatTypeTCPRtt][0].TCPRtt
	assert.ElementsMatch(t, []uint32{100, 200, 300}, append([]uint32{rtt.SrttUs}, rtt.Merged...), "every RTT is kept")
}

func TestReaderTCPStatsOfAConnection(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 10}
	r, _ := testReader(t, m, &now)
	r.emit = allTCP

	conn := tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80)
	m.set(conn, row{Established: 1, SrttUs: 500, TxBytes: 10, Role: ebpf.StatsTcpHandshakeRole(ebpf.CodeRoleClient), LastUpdateNs: uint64(now)})
	first := byType(r.readMap(nil))
	assert.Len(t, first[ebpf.StatTypeTCPSuccessfulConnection], 1)
	assert.Empty(t, first[ebpf.StatTypeTCPClosedConnection])

	// two retransmits, then the close: the connection is not counted again
	m.set(conn, row{Established: 1, SrttUs: 700, TxBytes: 10, RetransTimeout: 2, LastUpdateNs: uint64(now)})
	second := byType(r.readMap(nil))
	assert.Empty(t, second[ebpf.StatTypeTCPSuccessfulConnection])
	require.Len(t, second[ebpf.StatTypeTCPRetransmit], 1)
	assert.Equal(t, uint64(2), second[ebpf.StatTypeTCPRetransmit][0].Events())

	m.keys, m.rows = nil, nil
	record := ringbufRecord(closedRecord(t, conn, row{Established: 1, SrttUs: 800, TxBytes: 10, RetransTimeout: 2}))
	closed := byType(r.appendClosed(nil, &record))
	assert.Empty(t, closed[ebpf.StatTypeTCPSuccessfulConnection])
	assert.Empty(t, closed[ebpf.StatTypeTCPRetransmit])
	assert.Len(t, closed[ebpf.StatTypeTCPClosedConnection], 1)
	require.Len(t, closed[ebpf.StatTypeTCPRtt], 1)
	assert.Equal(t, uint32(800), closed[ebpf.StatTypeTCPRtt][0].TCPRtt.SrttUs)
}
