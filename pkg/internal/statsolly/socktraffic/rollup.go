// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// rollupKey is everything a stat of a row carries, with the client's ephemeral port 0
type rollupKey struct {
	statType ebpf.StatType
	// variant is the attribute value of the stat type: the direction of the traffic and the TCP
	// I/O, the retransmit type
	variant          uint8
	transport, role  uint8
	pid, netns       uint32
	srcAddr, dstAddr pipe.IPAddr
	srcPort, dstPort uint16
}

// connectionRollup merges the stats of the closed connections that only differ by the client's
// ephemeral port, like Datadog's connection rollup (pkg/network/state.go connectionAggregator):
// the client side drops its local port, the server side the remote one. Many short connections
// then cost a few stats per read interval instead of one per connection.
type connectionRollup struct {
	stats map[rollupKey]*ebpf.Stat
}

func newConnectionRollup() *connectionRollup {
	return &connectionRollup{stats: map[rollupKey]*ebpf.Stat{}}
}

// add merges a stat of a row with the given role into the stats of the read interval. It
// returns false when the role is unknown: it is then not known which port is the client's.
func (r *connectionRollup) add(s *ebpf.Stat, role uint8) bool {
	k := rollupKey{
		statType: s.Type,
		role:     role,
		srcAddr:  s.CommonAttrs.SrcAddr,
		dstAddr:  s.CommonAttrs.DstAddr,
		srcPort:  s.CommonAttrs.SrcPort,
		dstPort:  s.CommonAttrs.DstPort,
	}
	switch {
	case s.SocketTraffic != nil:
		k.variant, k.transport = s.SocketTraffic.Direction, s.SocketTraffic.Transport
		k.pid, k.netns = s.SocketTraffic.Pid, s.SocketTraffic.NetNS
	case s.TCPIo != nil:
		k.variant, k.pid, k.netns = s.TCPIo.Direction, s.Owner.Pid, s.Owner.NetNS
	default:
		k.variant, k.pid, k.netns = s.TCPRetransmitType, s.Owner.Pid, s.Owner.NetNS
	}
	switch ebpf.NetworkTCPHandshakeRoleCode(role) {
	case ebpf.CodeRoleClient:
		k.srcPort = 0
	case ebpf.CodeRoleServer:
		k.dstPort = 0
	default:
		return false
	}

	if merged, ok := r.stats[k]; ok {
		merge(merged, s)
		return true
	}
	s.CommonAttrs.SrcPort, s.CommonAttrs.DstPort = k.srcPort, k.dstPort
	r.stats[k] = s
	return true
}

// merge adds the values of s into merged, a stat with the same key
func merge(merged, s *ebpf.Stat) {
	switch {
	case s.SocketTraffic != nil:
		merged.SocketTraffic.Bytes += s.SocketTraffic.Bytes
		merged.SocketTraffic.Packets += s.SocketTraffic.Packets
	case s.TCPIo != nil:
		merged.TCPIo.Bytes += s.TCPIo.Bytes
	case s.TCPRtt != nil:
		merged.TCPRtt.Merged = append(append(merged.TCPRtt.Merged, s.TCPRtt.SrttUs), s.TCPRtt.Merged...)
	case s.TCPCongestion != nil:
		merged.TCPCongestion.DeliveredCE += s.TCPCongestion.DeliveredCE
		merged.TCPCongestion.ReordSeen += s.TCPCongestion.ReordSeen
		merged.TCPCongestion.RcvOOOPack += s.TCPCongestion.RcvOOOPack
	default:
		// the connections, retransmits and zero window probes
		merged.Count = merged.Events() + s.Events()
	}
}

// flush appends the merged stats of the read interval and starts a new one
func (r *connectionRollup) flush(stats []*ebpf.Stat) []*ebpf.Stat {
	for _, s := range r.stats {
		stats = append(stats, s)
	}
	clear(r.stats)
	return stats
}
