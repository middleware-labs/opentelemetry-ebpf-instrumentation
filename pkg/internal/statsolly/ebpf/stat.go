// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"bytes"
	"structs"
	"time"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/procmeta"
)

type StatType uint8

// These alias the bpf2go-generated constants derived from enum stat_type in
// bpf/statsolly/types.h, so kernel and userspace values cannot drift.
const (
	StatTypeTCPRtt                  = StatType(StatsStatTypeK_statTypeTcpRtt)
	StatTypeTCPFailedConnection     = StatType(StatsStatTypeK_statTypeTcpFailedConnection)
	StatTypeTCPRetransmit           = StatType(StatsStatTypeK_statTypeTcpRetransmit)
	StatTypeTCPIo                   = StatType(StatsStatTypeK_statTypeTcpIo)
	StatTypeTCPSuccessfulConnection = StatType(StatsStatTypeK_statTypeTcpSuccessfulConnection)
	StatTypeTCPFlowControl          = StatType(StatsStatTypeK_statTypeTcpFlowControl)
	StatTypeTCPCongestion           = StatType(StatsStatTypeK_statTypeTcpCongestion)
	StatTypeTCPClosedConnection     = StatType(StatsStatTypeK_statTypeTcpClosedConnection)
	// StatTypeDNSLookup stats are built in userspace by matching the DNS packets
	// that the kernel sends with the k_stat_type_dns_packet type.
	StatTypeDNSLookup = StatType(StatsStatTypeK_statTypeDnsPacket)
	// StatTypeSocketTraffic stats are read from the socket_traffic map, not from the ring buffer.
	StatTypeSocketTraffic = StatType(StatsStatTypeK_statTypeSocketTraffic)
)

type TCPFailReasonType string

const (
	Unknown           TCPFailReasonType = "unknown"
	ConnectionRefused TCPFailReasonType = "refused"
	ConnectionReset   TCPFailReasonType = "reset"
	TimedOut          TCPFailReasonType = "timed-out"
	HostUnreachable   TCPFailReasonType = "host-unreachable"
	NetUnreachable    TCPFailReasonType = "net-unreachable"
	Other             TCPFailReasonType = "other"
)

// TCPFailReasonTypeCode aliases the bpf2go-generated constants derived from
// enum tcp_fail_reason in bpf/statsolly/types.h.
type TCPFailReasonTypeCode uint8

const (
	CodeUnknown           = TCPFailReasonTypeCode(StatsTcpFailReasonReasonUnknown)
	CodeConnectionRefused = TCPFailReasonTypeCode(StatsTcpFailReasonReasonConnectionRefused)
	CodeConnectionReset   = TCPFailReasonTypeCode(StatsTcpFailReasonReasonConnectionReset)
	CodeTimedOut          = TCPFailReasonTypeCode(StatsTcpFailReasonReasonTimedOut)
	CodeHostUnreachable   = TCPFailReasonTypeCode(StatsTcpFailReasonReasonHostUnreachable)
	CodeNetUnreachable    = TCPFailReasonTypeCode(StatsTcpFailReasonReasonNetUnreachable)
	CodeOther             = TCPFailReasonTypeCode(StatsTcpFailReasonReasonOther)
)

type NetworkTCPHandshakeRoleType string

const (
	RoleUnknown NetworkTCPHandshakeRoleType = "unknown"
	RoleClient  NetworkTCPHandshakeRoleType = "client"
	RoleServer  NetworkTCPHandshakeRoleType = "server"
)

// NetworkTCPHandshakeRoleCode aliases the bpf2go-generated constants derived
// from enum tcp_handshake_role in bpf/statsolly/types.h.
type NetworkTCPHandshakeRoleCode uint8

const (
	CodeRoleUnknown = NetworkTCPHandshakeRoleCode(StatsTcpHandshakeRoleRoleUnknown)
	CodeRoleClient  = NetworkTCPHandshakeRoleCode(StatsTcpHandshakeRoleRoleClient)
	CodeRoleServer  = NetworkTCPHandshakeRoleCode(StatsTcpHandshakeRoleRoleServer)
)

type NetworkTCPRetransmitType string

const (
	RetransmitOther   NetworkTCPRetransmitType = "other"
	RetransmitFast    NetworkTCPRetransmitType = "fast"
	RetransmitTimeout NetworkTCPRetransmitType = "timeout"
)

// NetworkTCPRetransmitTypeCode aliases the bpf2go-generated constants derived
// from enum tcp_retransmit_type in bpf/statsolly/types.h.
type NetworkTCPRetransmitTypeCode uint8

const (
	CodeRetransmitOther   = NetworkTCPRetransmitTypeCode(StatsTcpRetransmitTypeRetransmitTypeOther)
	CodeRetransmitFast    = NetworkTCPRetransmitTypeCode(StatsTcpRetransmitTypeRetransmitTypeFast)
	CodeRetransmitTimeout = NetworkTCPRetransmitTypeCode(StatsTcpRetransmitTypeRetransmitTypeTimeout)
)

type NetworkTCPFlowControlEventType string

const (
	FlowControlEventUnknown    NetworkTCPFlowControlEventType = "unknown"
	FlowControlEventZeroWindow NetworkTCPFlowControlEventType = "zero_window"
)

// NetworkTCPFlowControlEventCode aliases the bpf2go-generated constants derived
// from enum tcp_flow_control_event in bpf/statsolly/types.h.
type NetworkTCPFlowControlEventCode uint8

const (
	CodeFlowControlEventZeroWindow = NetworkTCPFlowControlEventCode(StatsTcpFlowControlEventFlowControlEventZeroWindow)
)

type NetworkIoDirectionType string

const (
	DirectionReceive  NetworkIoDirectionType = "receive"
	DirectionTransmit NetworkIoDirectionType = "transmit"
)

// NetworkIoDirectionCode aliases the bpf2go-generated constants derived from
// enum network_io_direction in bpf/statsolly/types.h.
type NetworkIoDirectionCode uint8

const (
	CodeDirectionReceive  = NetworkIoDirectionCode(StatsNetworkIoDirectionDirectionReceive)
	CodeDirectionTransmit = NetworkIoDirectionCode(StatsNetworkIoDirectionDirectionTransmit)
)

// Stat contains accumulated metrics from a stat, with extra metadata
// that is added from the user space
// REMINDER: any attribute here must be also added to the functions StatGetters
// in pkg/internal/statsolly/ebpf/stat_getters.go and getDefinitions in
// pkg/export/attributes/attr_defs.go
type Stat struct {
	Type                    StatType                 `json:"type"`
	TCPRtt                  *TCPRtt                  `json:"-"`
	TCPFailedConnection     *TCPFailedConnection     `json:"-"`
	TCPSuccessfulConnection *TCPSuccessfulConnection `json:"-"`
	TCPClosedConnection     *TCPClosedConnection     `json:"-"`
	TCPRetransmit           bool                     `json:"-"`
	TCPRetransmitType       uint8                    `json:"-"`
	TCPIo                   *TCPIo                   `json:"-"`
	TCPFlowControl          *TCPFlowControl          `json:"-"`
	TCPCongestion           *TCPCongestion           `json:"-"`
	DNSLookup               *DNSLookup               `json:"-"`
	SocketTraffic           *SocketTraffic           `json:"-"`
	// Owner is the process of the socket of the TCP stats
	Owner SockOwner `json:"-"`
	// Count is how many events a counter stat stands for (TCP connections, retransmits, zero
	// window probes), 0 for one: the TCP stats read from the socket traffic rows count several
	Count uint64 `json:"count,omitempty"`
	// Processes are the process and container of each side, when one of their attributes is selected
	Processes *procmeta.Pair `json:"-"`
	// ServerPort is the port of the server side of the connection, whichever side reports it:
	// 0 when it is not known which side is the server
	ServerPort uint16 `json:"-"`
	// SameHost tells whether the remote socket is on this host: only the socket traffic reader
	// looks it up
	SameHost bool `json:"-"`

	// Attrs of the flow record: source/destination, OBI IP, etc...
	CommonAttrs pipe.CommonAttrs
}

// ServerPortOf returns the port of the server side of a connection seen from the socket with
// the given handshake role: its own port on the server, the remote one on the client
func ServerPortOf(role uint8, srcPort, dstPort uint16) uint16 {
	switch NetworkTCPHandshakeRoleCode(role) {
	case CodeRoleServer:
		return srcPort
	case CodeRoleClient:
		return dstPort
	default:
		return 0
	}
}

type TCPRtt struct {
	SrttUs uint32 `json:"srtt_us"`
	Role   uint8  `json:"role"`
	// Merged are the RTTs of the other connections merged into this stat by the connection
	// rollup: each one is still recorded
	Merged []uint32 `json:"-"`
}

type TCPFailedConnection struct {
	Reason uint8 `json:"reason"`
	Role   uint8 `json:"role"`
}

type TCPSuccessfulConnection struct {
	Role uint8 `json:"role"`
}

type TCPClosedConnection struct {
	Role uint8 `json:"role"`
}

type TCPFlowControl struct {
	Event uint8 `json:"event"`
	Role  uint8 `json:"role"`
}

// TCPCongestion carries the increase of the kernel's per-socket congestion counters
// since the previous event for the same socket.
type TCPCongestion struct {
	DeliveredCE uint32 `json:"delivered_ce"`
	ReordSeen   uint32 `json:"reord_seen"`
	RcvOOOPack  uint32 `json:"rcv_ooopack"`
	Role        uint8  `json:"role"`
}

// DNSLookup is a DNS question with its answer, or without an answer after the timeout.
type DNSLookup struct {
	Duration time.Duration `json:"duration"`
	// Merged holds the durations of the other lookups with the same client, server, question
	// and result, merged into this stat during the same second: each one is still recorded.
	Merged  []time.Duration `json:"-"`
	RCode   uint16          `json:"rcode"`
	Timeout bool            `json:"timeout"`
	QName   string          `json:"qname"`
	QType   uint16          `json:"qtype"`
}

// SockOwner is the process of the local socket of a TCP stat, and the process of the remote
// socket when it is on this host. Its fields are zero when unknown, or when no process or
// container attribute of the TCP stats is selected.
type SockOwner struct {
	Pid         uint32
	NetNS       uint32
	ExecName    string
	CgroupID    uint64
	DstPid      uint32
	DstExecName string
	DstCgroupID uint64
}

// SocketTraffic is the traffic of a socket in one direction since the previous read
// of the socket traffic map.
type SocketTraffic struct {
	// Transport is the IP protocol number: syscall.IPPROTO_TCP or syscall.IPPROTO_UDP
	Transport uint8  `json:"transport"`
	Direction uint8  `json:"direction"`
	Role      uint8  `json:"role"`
	Pid       uint32 `json:"pid"`
	Bytes     uint64 `json:"bytes"`
	Packets   uint64 `json:"packets"`
	// DstPid is the process of the remote socket when it is on this host, 0 otherwise
	DstPid uint32 `json:"dst_pid"`
	// ExecName and CgroupID are the executable name and the cgroup of the process, kept by the
	// kernel for the processes that end before their row is read. Dst* are those of the remote
	// process.
	ExecName    string `json:"exec_name"`
	CgroupID    uint64 `json:"-"`
	DstExecName string `json:"-"`
	DstCgroupID uint64 `json:"-"`
	// NetNS is the network namespace of the local socket
	NetNS uint32 `json:"-"`
}

type TCPIo struct {
	Direction uint8  `json:"direction"`
	Bytes     uint64 `json:"bytes"`
}

// Conn mirrors connection_info_t from bpf/common/connection_info.h.
type Conn struct {
	_      structs.HostLayout
	S_addr [16]uint8 //nolint:revive,staticcheck
	D_addr [16]uint8 //nolint:revive,staticcheck
	S_port uint16    //nolint:revive,staticcheck
	D_port uint16    //nolint:revive,staticcheck
}

type StatsTCPRtt struct {
	_      structs.HostLayout
	Flags  uint8
	Role   uint8
	Pad    [2]uint8
	SrttUs uint32
	Conn
	Owner StatsSockOwnerT
}

type StatsTCPFailedConnection struct {
	_      structs.HostLayout
	Flags  uint8
	Reason uint8
	Role   uint8
	Pad    [1]uint8
	Conn
	Owner StatsSockOwnerT
}

type StatsTCPSuccessfulConnection struct {
	_     structs.HostLayout
	Flags uint8
	Role  uint8
	Pad   [2]uint8
	Conn
	Owner StatsSockOwnerT
}

type StatsTCPClosedConnection struct {
	_     structs.HostLayout
	Flags uint8
	Role  uint8
	Pad   [2]uint8
	Conn
	Owner StatsSockOwnerT
}

type StatsTCPRetransmit struct {
	_     structs.HostLayout
	Flags uint8
	Type  uint8
	Pad   [2]uint8
	Conn
	Owner StatsSockOwnerT
}

type StatsTCPFlowControl struct {
	_     structs.HostLayout
	Flags uint8
	Event uint8
	Role  uint8
	Pad   [1]uint8
	Conn
	Owner StatsSockOwnerT
}

// TCPCongVals mirrors tcp_cong_vals_t from bpf/statsolly/maps/tcp_cong_last.h.
type TCPCongVals struct {
	_           structs.HostLayout
	DeliveredCE uint32
	ReordSeen   uint32
	RcvOOOPack  uint32
}

type StatsTCPCongestion struct {
	_     structs.HostLayout
	Flags uint8
	Role  uint8
	Pad   [2]uint8
	Delta TCPCongVals
	Conn
	Owner StatsSockOwnerT
}

type StatsTCPIo struct {
	_         structs.HostLayout
	Flags     uint8
	Direction uint8
	Count     uint8
	Pad       [1]uint8
	Bytes     [TCPIoBatchSize]uint32
	Conn
	Owner StatsSockOwnerT
}

// StatsDNSPacket mirrors dns_packet_t from bpf/statsolly/sock_dns.c.
type StatsDNSPacket struct {
	_       structs.HostLayout
	Flags   uint8
	L4Proto uint8
	Len     uint16
	Conn
	TS  uint64
	Buf [DNSPacketBufSize]uint8
}

// DNSPacketBufSize mirrors k_dns_packet_buf_size in bpf/statsolly/sock_dns.c.
const DNSPacketBufSize = 272

// TCPIoBatchSize mirrors k_tcp_io_batch_size in bpf/statsolly/types.h.
const TCPIoBatchSize = 10

// CString is the string of a kernel buffer, up to its terminating zero
func CString(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// tcpRowFeatures are the TCP stat metrics that the socket traffic rows hold: all but the failed
// connections, which stay events
const tcpRowFeatures = export.FeatureStatsTCPRtt | export.FeatureStatsTCPSuccessfulConnections |
	export.FeatureStatsTCPClosedConnections | export.FeatureStatsTCPRetransmits | export.FeatureStatsTCPIo |
	export.FeatureStatsTCPFlowControl | export.FeatureStatsTCPCongestion

// TCPMetricsFromRows tells whether the TCP stat metrics are read from the socket traffic rows
// (stats.socket_traffic.tcp_metrics) instead of one event per TCP event
func TCPMetricsFromRows(features *export.Features, cfg *config.SocketTrafficConfig) bool {
	return cfg.TCPMetrics && *features&tcpRowFeatures != 0
}

// Events is how many events a counter stat stands for
func (s *Stat) Events() uint64 {
	return max(s.Count, 1)
}
