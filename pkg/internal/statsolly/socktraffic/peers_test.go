// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic

import (
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func statOf(t *testing.T, k key, r row) *ebpf.Stat {
	t.Helper()
	stats := appendStats(nil, &k, &r, totals{txBytes: 1})
	require.Len(t, stats, 1)
	return stats[0]
}

func remotePid(p *peerIndex, s *ebpf.Stat) uint32 {
	peer, _ := p.remote(s)
	return peer.pid
}

func TestPeerIndexSameHost(t *testing.T) {
	p := newPeerIndex(time.Minute)
	client := tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80)
	server := tcpConnKey("10.0.0.2", 80, "10.0.0.1", 40000)
	remote := tcpConnKey("10.0.0.1", 40001, "192.168.9.9", 443)
	p.add(&client, &row{Pid: 100}, 0)
	p.add(&server, &row{Pid: 200}, 0)
	p.add(&remote, &row{Pid: 100}, 0)

	assert.Equal(t, uint32(200), remotePid(p, statOf(t, client, row{Pid: 100})), "the client finds the server")
	assert.Equal(t, uint32(100), remotePid(p, statOf(t, server, row{Pid: 200})), "the server finds the client")
	assert.Zero(t, remotePid(p, statOf(t, remote, row{Pid: 100})), "the remote side is on another host")

	// a rolled-up server stat lost the client port: the client is found by its addresses
	rolled := statOf(t, server, row{Pid: 200, Role: ebpf.StatsTcpHandshakeRoleRoleServer})
	rolled.CommonAttrs.DstPort = 0
	assert.Equal(t, uint32(100), remotePid(p, rolled))

	p.prune(2 * time.Minute)
	assert.Zero(t, remotePid(p, statOf(t, client, row{Pid: 100})), "forgotten after the TTL")
}

func TestPeerIndexLoopbackKeepsNamespacesApart(t *testing.T) {
	p := newPeerIndex(time.Minute)
	serverA := tcpConnKey("127.0.0.1", 80, "127.0.0.1", 40000)
	serverA.Netns = 1
	serverB := serverA
	serverB.Netns = 2
	p.add(&serverA, &row{Pid: 100}, 0)
	p.add(&serverB, &row{Pid: 200}, 0)

	client := tcpConnKey("127.0.0.1", 40000, "127.0.0.1", 80)
	client.Netns = 2
	s := statOf(t, client, row{Pid: 300})
	assert.Equal(t, uint32(2), s.SocketTraffic.NetNS)
	assert.Equal(t, uint32(200), remotePid(p, s), "127.0.0.1 is the server of the same network namespace")
}

func TestPeerIndexRowsWithoutProcess(t *testing.T) {
	p := newPeerIndex(time.Minute)
	server := tcpConnKey("10.0.0.2", 80, "10.0.0.1", 40000)
	p.add(&server, &row{}, 0)

	client := statOf(t, tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80), row{Pid: 100})
	peer, found := p.remote(client)
	assert.True(t, found, "a row without process is still a socket of this host")
	assert.Zero(t, peer.pid)

	p.add(&server, &row{Pid: 200}, time.Second)
	p.add(&server, &row{}, 2*time.Second)
	peer, found = p.remote(client)
	assert.True(t, found)
	assert.Equal(t, uint32(200), peer.pid, "a row without process keeps the known one")
	assert.Equal(t, 2*time.Second, peer.seen)
}

func TestSameHostAddrs(t *testing.T) {
	for _, tt := range []struct {
		local, remote string
		want          bool
	}{
		{"10.0.0.1", "10.0.0.1", true},
		{"127.0.0.1", "127.0.0.53", true},
		{"::1", "::1", true},
		{"10.0.0.1", "10.0.0.2", false},
		{"127.0.0.1", "10.0.0.2", false},
	} {
		s := statOf(t, tcpConnKey(tt.local, 40000, tt.remote, 80), row{})
		assert.Equal(t, tt.want, sameHostAddrs(s.CommonAttrs.SrcAddr, s.CommonAttrs.DstAddr), "%s -> %s", tt.local, tt.remote)
	}
}

func TestReaderSameHost(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 10}
	r, _ := testReader(t, m, &now)
	r.peers, r.resolveRemote = newPeerIndex(time.Minute), true

	udp := func(k key) key { k.Protocol = syscall.IPPROTO_UDP; return k }
	rows := map[string]key{
		// a client and its server on this host, the server without process
		"client":    tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80),
		"server":    tcpConnKey("10.0.0.2", 80, "10.0.0.1", 40000),
		"external":  tcpConnKey("10.0.0.1", 40001, "192.168.9.9", 443),
		"loopback":  tcpConnKey("127.0.0.1", 40002, "127.0.0.1", 6379),
		"generator": udp(tcpConnKey("172.30.0.2", 50000, "172.30.0.1", 2055)),
		"collector": udp(tcpConnKey("172.30.0.1", 2055, "172.30.0.2", 50000)),
		// the same port over TCP is not the UDP socket
		"tcp to udp port": tcpConnKey("172.30.0.2", 50001, "172.30.0.1", 2055),
	}
	want := map[key]bool{}
	for name, k := range rows {
		v := row{TxBytes: 10, Pid: 100, LastUpdateNs: uint64(now)}
		if name == "server" {
			v.Pid = 0
		}
		m.set(k, v)
		want[k] = name != "external" && name != "tcp to udp port"
	}

	stats := r.readMap(nil)
	require.Len(t, stats, len(rows))
	for _, s := range stats {
		k := tcpConnKey(s.CommonAttrs.SrcAddr.IP().String(), s.CommonAttrs.SrcPort,
			s.CommonAttrs.DstAddr.IP().String(), s.CommonAttrs.DstPort)
		k.Protocol = s.SocketTraffic.Transport
		assert.Equal(t, want[k], s.SameHost, "%s:%d -> %s:%d/%d", s.CommonAttrs.SrcAddr.IP(), s.CommonAttrs.SrcPort,
			s.CommonAttrs.DstAddr.IP(), s.CommonAttrs.DstPort, k.Protocol)
	}
}

func TestReaderFindsRemoteProcessOfClosedConnections(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 10}
	r, _ := testReader(t, m, &now)
	r.peers, r.resolveRemote = newPeerIndex(time.Minute), true

	// both sides of a short connection close between two map reads, the client first
	client := tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80)
	server := tcpConnKey("10.0.0.2", 80, "10.0.0.1", 40000)
	record := ringbufRecord(closedRecord(t, client, row{TxBytes: 10, Pid: 100}))
	assert.Empty(t, r.appendClosed(nil, &record), "the server is not known yet")

	record = ringbufRecord(closedRecord(t, server, row{TxBytes: 10, Pid: 200}))
	stats := r.appendClosed(nil, &record)
	require.Len(t, stats, 1, "the client is known: sent at the close")
	stats = r.resolvePending(stats)
	require.Len(t, stats, 2, "the client is sent at the next lookup")
	for _, s := range stats {
		want := map[uint32]uint32{100: 200, 200: 100}[s.SocketTraffic.Pid]
		assert.Equal(t, want, s.SocketTraffic.DstPid, "pid %d", s.SocketTraffic.Pid)
		assert.Equal(t, uint8(syscall.IPPROTO_TCP), s.SocketTraffic.Transport)
	}
	assert.Empty(t, r.pendingClosed)
	assert.Empty(t, r.readMap(nil))
}

func TestReaderRetriesTheRemoteProcessOnce(t *testing.T) {
	now := time.Hour
	m := &fakeMap{batchLen: 10}
	r, _ := testReader(t, m, &now)
	r.peers, r.resolveRemote = newPeerIndex(time.Minute), true

	// the server closes before a map read, the client after it
	server := tcpConnKey("10.0.0.2", 80, "10.0.0.1", 40000)
	record := ringbufRecord(closedRecord(t, server, row{TxBytes: 10, Pid: 200}))
	r.appendClosed(nil, &record)
	assert.Empty(t, r.readMap(nil), "the client is not known yet: one more read")

	client := tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80)
	record = ringbufRecord(closedRecord(t, client, row{TxBytes: 5, Pid: 100, ExeName: [16]uint8{'w', 'g', 'e', 't'}}))
	stats := r.appendClosed(nil, &record)
	require.Len(t, stats, 1, "the server is known: sent at the close")
	assert.Equal(t, uint32(200), stats[0].SocketTraffic.DstPid)

	stats = r.readMap(nil)
	require.Len(t, stats, 1)
	assert.Equal(t, uint32(100), stats[0].SocketTraffic.DstPid)
	assert.Equal(t, "wget", stats[0].SocketTraffic.DstExecName)

	// a remote socket on another host is sent after one more read, without a remote process
	remote := tcpConnKey("10.0.0.1", 40001, "192.168.9.9", 443)
	record = ringbufRecord(closedRecord(t, remote, row{TxBytes: 1, Pid: 100}))
	r.appendClosed(nil, &record)
	assert.Empty(t, r.readMap(nil))
	stats = r.readMap(nil)
	require.Len(t, stats, 1)
	assert.Zero(t, stats[0].SocketTraffic.DstPid)
}
