// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rtlog() *slog.Logger {
	return slog.With("component", "stat.RingBufTracer")
}

// RingBufTracer reads stat events from an eBPF ring buffer, batches them, and
// forwards batches to the pipeline using the shared ForwardRingbuf infrastructure.
type RingBufTracer struct {
	statsMap *ciliumebpf.Map
	cfg      *config.EBPFTracer
	forward  func(context.Context, *msg.Queue[[]*ebpf.Stat])
	// owners is nil when no destination process attribute of the TCP stats is selected
	owners *remoteOwners
}

// NewRingBufTracer reads the stat events of statsMap. When endpointOwners is not nil, it also
// finds the process of the remote socket of each TCP stat on this host.
func NewRingBufTracer(statsMap, endpointOwners *ciliumebpf.Map, cfg *config.EBPFTracer) *RingBufTracer {
	parse := parseStat
	var owners *remoteOwners
	if endpointOwners != nil {
		owners = newRemoteOwners(endpointOwners)
		parse = func(record *ringbuf.Record) (*ebpf.Stat, bool, error) {
			stat, ignore, err := parseStat(record)
			if err == nil {
				owners.find(stat)
			}
			return stat, ignore, err
		}
	}
	return &RingBufTracer{
		statsMap: statsMap,
		cfg:      cfg,
		forward:  ebpfcommon.ForwardRingbuf(cfg, statsMap, parse, nil, rtlog(), nil),
		owners:   owners,
	}
}

func (m *RingBufTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		if m.owners != nil {
			go m.owners.expireEvery(ctx, remoteOwnersCacheTTL)
		}
		m.forward(ctx, out)
	}
}

func parseStat(record *ringbuf.Record) (*ebpf.Stat, bool, error) {
	stat, err := handleStatEvent(record)
	if err != nil {
		return nil, false, err
	}
	return &stat, false, nil
}

func handleStatEvent(record *ringbuf.Record) (ebpf.Stat, error) {
	if record == nil || len(record.RawSample) == 0 {
		return ebpf.Stat{}, errors.New("empty stats event")
	}

	eventType := ebpf.StatType(record.RawSample[0])
	switch eventType {
	case ebpf.StatTypeTCPRtt:
		return readTCPRttIntoStat(record)
	case ebpf.StatTypeTCPFailedConnection:
		return readTCPFailedConnectionsIntoStat(record)
	case ebpf.StatTypeTCPSuccessfulConnection:
		return readTCPSuccessfulConnectionsIntoStat(record)
	case ebpf.StatTypeTCPClosedConnection:
		return readTCPClosedConnectionsIntoStat(record)
	case ebpf.StatTypeTCPRetransmit:
		return readTCPRetransmitIntoStat(record)
	case ebpf.StatTypeTCPIo:
		return readTCPIoIntoStat(record)
	case ebpf.StatTypeTCPFlowControl:
		return readTCPFlowControlIntoStat(record)
	case ebpf.StatTypeTCPCongestion:
		return readTCPCongestionIntoStat(record)
	default:
		return ebpf.Stat{}, fmt.Errorf("unknown stats event [type %d]", uint8(eventType))
	}
}

func connToCommonAttrs(conn ebpf.Conn) pipe.CommonAttrs {
	if conn.S_port == 0 && conn.D_port == 0 {
		return pipe.CommonAttrs{}
	}
	return pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(conn.S_addr),
		DstAddr: pipe.IPAddr(conn.D_addr),
		SrcPort: conn.S_port,
		DstPort: conn.D_port,
	}
}

func sockOwner(o ebpf.StatsSockOwnerT) ebpf.SockOwner {
	return ebpf.SockOwner{
		Pid:      o.Pid,
		NetNS:    o.Netns,
		ExecName: ebpf.CString(o.ExeName[:]),
		CgroupID: uint64(o.CgroupIdHi)<<32 | uint64(o.CgroupIdLo),
	}
}

func readTCPRttIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPRtt](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPRtt,
		TCPRtt: &ebpf.TCPRtt{
			SrttUs: event.SrttUs,
			Role:   event.Role,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
		ServerPort:  ebpf.ServerPortOf(event.Role, event.S_port, event.D_port),
		Owner:       sockOwner(event.Owner),
	}, nil
}

func readTCPFailedConnectionsIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPFailedConnection](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPFailedConnection,
		TCPFailedConnection: &ebpf.TCPFailedConnection{
			Reason: event.Reason,
			Role:   event.Role,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
		ServerPort:  ebpf.ServerPortOf(event.Role, event.S_port, event.D_port),
		Owner:       sockOwner(event.Owner),
	}, nil
}

func readTCPSuccessfulConnectionsIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPSuccessfulConnection](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPSuccessfulConnection,
		TCPSuccessfulConnection: &ebpf.TCPSuccessfulConnection{
			Role: event.Role,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
		ServerPort:  ebpf.ServerPortOf(event.Role, event.S_port, event.D_port),
		Owner:       sockOwner(event.Owner),
	}, nil
}

func readTCPClosedConnectionsIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPClosedConnection](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPClosedConnection,
		TCPClosedConnection: &ebpf.TCPClosedConnection{
			Role: event.Role,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
		ServerPort:  ebpf.ServerPortOf(event.Role, event.S_port, event.D_port),
		Owner:       sockOwner(event.Owner),
	}, nil
}

func readTCPRetransmitIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPRetransmit](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type:              ebpf.StatTypeTCPRetransmit,
		TCPRetransmit:     true,
		TCPRetransmitType: event.Type,
		CommonAttrs:       connToCommonAttrs(event.Conn),
		Owner:             sockOwner(event.Owner),
	}, nil
}

func readTCPIoIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPIo](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	var total uint64
	for _, b := range event.Bytes[:min(int(event.Count), ebpf.TCPIoBatchSize)] {
		total += uint64(b)
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPIo,
		TCPIo: &ebpf.TCPIo{
			Direction: event.Direction,
			Bytes:     total,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
		Owner:       sockOwner(event.Owner),
	}, nil
}

func readTCPFlowControlIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPFlowControl](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPFlowControl,
		TCPFlowControl: &ebpf.TCPFlowControl{
			Event: event.Event,
			Role:  event.Role,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
		ServerPort:  ebpf.ServerPortOf(event.Role, event.S_port, event.D_port),
		Owner:       sockOwner(event.Owner),
	}, nil
}

func readTCPCongestionIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPCongestion](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPCongestion,
		TCPCongestion: &ebpf.TCPCongestion{
			DeliveredCE: event.Delta.DeliveredCE,
			ReordSeen:   event.Delta.ReordSeen,
			RcvOOOPack:  event.Delta.RcvOOOPack,
			Role:        event.Role,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
		ServerPort:  ebpf.ServerPortOf(event.Role, event.S_port, event.D_port),
		Owner:       sockOwner(event.Owner),
	}, nil
}
