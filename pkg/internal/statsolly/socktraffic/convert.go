// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// appendStats appends one stat per direction with traffic in the delta: a row counts both
// directions of the socket, and network.io.direction is a metric attribute.
func appendStats(stats []*ebpf.Stat, k *key, r *row, delta totals) []*ebpf.Stat {
	for _, d := range []struct {
		direction ebpf.NetworkIoDirectionCode
		bytes     uint64
		packets   uint64
	}{
		{ebpf.CodeDirectionTransmit, delta.txBytes, delta.txPackets},
		{ebpf.CodeDirectionReceive, delta.rxBytes, delta.rxPackets},
	} {
		if d.bytes == 0 && d.packets == 0 {
			continue
		}
		stats = append(stats, &ebpf.Stat{
			Type: ebpf.StatTypeSocketTraffic,
			SocketTraffic: &ebpf.SocketTraffic{
				Transport: k.Protocol,
				Direction: uint8(d.direction),
				Role:      uint8(r.Role),
				Pid:       r.Pid,
				NetNS:     k.Netns,
				ExecName:  ebpf.CString(r.ExeName[:]),
				CgroupID:  r.CgroupId,
				Bytes:     d.bytes,
				Packets:   d.packets,
			},
			CommonAttrs: pipe.CommonAttrs{
				SrcAddr: pipe.IPAddr(k.Conn.S_addr),
				DstAddr: pipe.IPAddr(k.Conn.D_addr),
				SrcPort: k.Conn.S_port,
				DstPort: k.Conn.D_port,
			},
		})
	}
	return stats
}
