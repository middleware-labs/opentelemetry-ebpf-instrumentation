// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"syscall"
	"time"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// maxSrtt mirrors k_max_srtt_allowed of the TCP RTT events: a larger value is not an RTT
const maxSrtt = 60 * time.Second

// Emit are the stats the reader sends from the rows
type Emit struct {
	// Traffic are the socket bytes and packets
	Traffic bool
	// the TCP stat metrics read from the rows (stats.socket_traffic.tcp_metrics)
	TCPRtt, TCPSuccessful, TCPClosed, TCPRetransmits, TCPIo, TCPFlowControl, TCPCongestion bool
	// ServerPort sets the port of the server side of each stat (server.port is selected)
	ServerPort bool
	// Role sets the role of the TCP connections opened before OBI started (network.connection.role
	// or network.tcp.handshake.role is selected)
	Role bool
}

// EmitFor returns the stats to send for the enabled features
func EmitFor(features *export.Features, tcpFromRows bool) Emit {
	return Emit{
		Traffic:        features.StatsSocketTraffic(),
		TCPRtt:         tcpFromRows && features.StatsTCPRtt(),
		TCPSuccessful:  tcpFromRows && features.StatsTCPSuccessfulConnections(),
		TCPClosed:      tcpFromRows && features.StatsTCPClosedConnections(),
		TCPRetransmits: tcpFromRows && features.StatsTCPRetransmits(),
		TCPIo:          tcpFromRows && features.StatsTCPIo(),
		TCPFlowControl: tcpFromRows && features.StatsTCPFlowControl(),
		TCPCongestion:  tcpFromRows && features.StatsTCPCongestion(),
	}
}

func (e *Emit) tcp() bool {
	return e.TCPRtt || e.TCPSuccessful || e.TCPClosed || e.TCPRetransmits || e.TCPIo || e.TCPFlowControl || e.TCPCongestion
}

// appendRowStats appends the stats of the increase of a row. closed is true for the final row
// of a closed socket.
func (e *Emit) appendRowStats(stats []*ebpf.Stat, k *key, r *row, delta totals, closed bool) []*ebpf.Stat {
	if e.Traffic {
		stats = appendStats(stats, k, r, delta)
	}
	if k.Protocol == syscall.IPPROTO_TCP && e.tcp() {
		stats = e.appendTCPStats(stats, k, r, delta, closed)
	}
	return stats
}

// appendTCPStats appends the TCP stat metrics of the increase of a TCP row, like Datadog's
// connection stats: the counters are the increases, the RTT is the latest one of each
// connection with activity since the previous read, and of each closed connection.
func (e *Emit) appendTCPStats(stats []*ebpf.Stat, k *key, r *row, delta totals, closed bool) []*ebpf.Stat {
	role := uint8(r.Role)
	// a row created by a late retransmit of a socket that the application closed holds no
	// connection: only its retransmits are counted
	connection := r.Established > 0 || r.TxBytes > 0 || r.RxBytes > 0
	newStat := func(t ebpf.StatType, count uint64) *ebpf.Stat {
		s := &ebpf.Stat{
			Type:  t,
			Count: count,
			Owner: ebpf.SockOwner{
				Pid: r.Pid, NetNS: k.Netns, ExecName: ebpf.CString(r.ExeName[:]), CgroupID: r.CgroupId,
			},
			CommonAttrs: pipe.CommonAttrs{
				SrcAddr: pipe.IPAddr(k.Conn.S_addr),
				DstAddr: pipe.IPAddr(k.Conn.D_addr),
				SrcPort: k.Conn.S_port,
				DstPort: k.Conn.D_port,
			},
		}
		stats = append(stats, s)
		return s
	}

	if e.TCPSuccessful && delta.established > 0 {
		newStat(ebpf.StatTypeTCPSuccessfulConnection, delta.established).
			TCPSuccessfulConnection = &ebpf.TCPSuccessfulConnection{Role: role}
	}
	// like Datadog, only the established connections: the failed ones are the failed connections.
	// Every connection established on the row has ended: a new connection with the same
	// addresses can take the row over before the close of the previous one, which is then not
	// sent (the previous socket closes later, or its tcp_close was missed).
	if e.TCPClosed && closed && connection {
		newStat(ebpf.StatTypeTCPClosedConnection, uint64(max(r.Established, 1))).
			TCPClosedConnection = &ebpf.TCPClosedConnection{Role: role}
	}
	if srtt := time.Duration(r.SrttUs) * time.Microsecond; e.TCPRtt && connection && srtt > 0 && srtt <= maxSrtt && (closed || delta.any()) {
		newStat(ebpf.StatTypeTCPRtt, 0).TCPRtt = &ebpf.TCPRtt{SrttUs: r.SrttUs, Role: role}
	}
	if e.TCPRetransmits {
		for _, rt := range []struct {
			code  ebpf.NetworkTCPRetransmitTypeCode
			count uint64
		}{
			{ebpf.CodeRetransmitFast, delta.retransFast},
			{ebpf.CodeRetransmitTimeout, delta.retransTimeout},
			{ebpf.CodeRetransmitOther, delta.retransOther},
		} {
			if rt.count > 0 {
				s := newStat(ebpf.StatTypeTCPRetransmit, rt.count)
				s.TCPRetransmit, s.TCPRetransmitType = true, uint8(rt.code)
			}
		}
	}
	if e.TCPIo {
		for _, d := range []struct {
			direction ebpf.NetworkIoDirectionCode
			bytes     uint64
		}{
			{ebpf.CodeDirectionTransmit, delta.txBytes},
			{ebpf.CodeDirectionReceive, delta.rxBytes},
		} {
			if d.bytes > 0 {
				newStat(ebpf.StatTypeTCPIo, 0).TCPIo = &ebpf.TCPIo{Direction: uint8(d.direction), Bytes: d.bytes}
			}
		}
	}
	if e.TCPFlowControl && delta.zeroWindow > 0 {
		newStat(ebpf.StatTypeTCPFlowControl, delta.zeroWindow).TCPFlowControl = &ebpf.TCPFlowControl{
			Event: uint8(ebpf.CodeFlowControlEventZeroWindow), Role: role,
		}
	}
	if e.TCPCongestion && (delta.deliveredCE > 0 || delta.reordSeen > 0 || delta.rcvOOOPack > 0) {
		newStat(ebpf.StatTypeTCPCongestion, 0).TCPCongestion = &ebpf.TCPCongestion{
			DeliveredCE: uint32(delta.deliveredCE), ReordSeen: uint32(delta.reordSeen),
			RcvOOOPack: uint32(delta.rcvOOOPack), Role: role,
		}
	}
	return stats
}
