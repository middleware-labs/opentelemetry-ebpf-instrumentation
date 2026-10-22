// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func rolledStat(role ebpf.NetworkTCPHandshakeRoleCode, srcPort, dstPort uint16, bytes uint64) *ebpf.Stat {
	k := tcpConnKey("10.0.0.1", srcPort, "10.0.0.2", dstPort)
	return appendStats(nil, &k, &row{Role: ebpf.StatsTcpHandshakeRole(role), Pid: 7}, totals{txBytes: bytes, txPackets: 1})[0]
}

func TestConnectionRollup(t *testing.T) {
	r := newConnectionRollup()

	// three short client connections to 10.0.0.2:80 from different ephemeral ports
	for i, port := range []uint16{40001, 40002, 40003} {
		require.True(t, r.add(rolledStat(ebpf.CodeRoleClient, port, 80, uint64(76*(i+1))), uint8(ebpf.CodeRoleClient)))
	}
	// the server side of two connections from different client ports
	for _, port := range []uint16{50001, 50002} {
		require.True(t, r.add(rolledStat(ebpf.CodeRoleServer, 80, port, 853), uint8(ebpf.CodeRoleServer)))
	}
	// without a role, it is not known which port is the client's
	assert.False(t, r.add(rolledStat(ebpf.CodeRoleUnknown, 40004, 80, 1), uint8(ebpf.CodeRoleUnknown)))

	stats := r.flush(nil)
	require.Len(t, stats, 2)
	byRole := map[uint8]*ebpf.Stat{}
	for _, s := range stats {
		byRole[s.SocketTraffic.Role] = s
	}

	client := byRole[uint8(ebpf.CodeRoleClient)]
	assert.Equal(t, uint64(76+152+228), client.SocketTraffic.Bytes)
	assert.Equal(t, uint64(3), client.SocketTraffic.Packets)
	assert.Equal(t, uint16(0), client.CommonAttrs.SrcPort, "the client's ephemeral port is rolled up")
	assert.Equal(t, uint16(80), client.CommonAttrs.DstPort)

	server := byRole[uint8(ebpf.CodeRoleServer)]
	assert.Equal(t, uint64(2*853), server.SocketTraffic.Bytes)
	assert.Equal(t, uint16(80), server.CommonAttrs.SrcPort)
	assert.Equal(t, uint16(0), server.CommonAttrs.DstPort, "the client's ephemeral port is rolled up")

	assert.Empty(t, r.flush(nil), "a flush starts a new read interval")
}

func TestReaderRollsUpClosedConnections(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 10}
	r, _ := testReader(t, m, &now)
	r.rollup = newConnectionRollup()

	var stats []*ebpf.Stat
	for _, port := range []uint16{40001, 40002, 40003} {
		k := tcpConnKey("10.0.0.1", port, "10.0.0.2", 80)
		record := ringbufRecord(closedRecord(t, k, row{TxBytes: 76, RxBytes: 853, TxPackets: 4, RxPackets: 3, Role: ebpf.StatsTcpHandshakeRoleRoleClient}))
		stats = r.appendClosed(stats, &record)
	}
	assert.Empty(t, stats, "rolled up connections wait for the next map read")

	// an open connection read from the map is not rolled up
	open := tcpConnKey("10.0.0.1", 40009, "10.0.0.2", 80)
	m.set(open, row{TxBytes: 10, Role: ebpf.StatsTcpHandshakeRoleRoleClient, LastUpdateNs: uint64(now)})

	stats = r.readMap(nil)
	require.Len(t, stats, 3)
	assert.Equal(t, totals{txBytes: 3*76 + 10, rxBytes: 3 * 853, txPackets: 12, rxPackets: 9}, sumTraffic(stats))
	ports := map[uint16]bool{}
	for _, s := range stats {
		ports[s.CommonAttrs.SrcPort] = true
		assert.Equal(t, syscall.IPPROTO_TCP, int(s.SocketTraffic.Transport))
		assert.Equal(t, net.ParseIP("10.0.0.2").To16(), net.IP(s.CommonAttrs.DstAddr[:]))
	}
	assert.Equal(t, map[uint16]bool{0: true, 40009: true}, ports)
}

func ringbufRecord(sample []byte) ringbuf.Record {
	return ringbuf.Record{RawSample: sample}
}
