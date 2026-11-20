// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package inbound

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func addr(ip string) pipe.IPAddr {
	var a pipe.IPAddr
	copy(a[:], net.ParseIP(ip).To16())
	return a
}

// trafficStat is a socket traffic stat of a pod at 10.4.1.7, the local side
func trafficStat(role ebpf.NetworkTCPHandshakeRoleCode, remote string) *ebpf.Stat {
	s := &ebpf.Stat{
		Type:          ebpf.StatTypeSocketTraffic,
		SocketTraffic: &ebpf.SocketTraffic{Role: uint8(role)},
	}
	s.CommonAttrs.SrcAddr, s.CommonAttrs.DstAddr = addr("10.4.1.7"), addr(remote)
	s.CommonAttrs.SrcPort, s.CommonAttrs.DstPort = 443, 50000
	s.CommonAttrs.Metadata = map[attr.Name]string{}
	return s
}

func attrValue(t *testing.T, s *ebpf.Stat, name attr.Name) string {
	t.Helper()
	getter, ok := ebpf.StatStringGetters(name)
	require.True(t, ok)
	return getter(s)
}

func TestCollapse(t *testing.T) {
	server, client := ebpf.CodeRoleServer, ebpf.CodeRoleClient

	azure := trafficStat(server, "10.224.0.5")
	azure.CommonAttrs.Metadata[attr.K8sDstName] = "aks-node-1"
	azure.NAT = &ebpf.NAT{
		Pre:  ebpf.Endpoints{SrcAddr: addr("20.50.1.1"), DstAddr: addr("1.2.3.4"), SrcPort: 443, DstPort: 50000},
		Post: ebpf.Endpoints{SrcAddr: addr("10.4.1.7"), DstAddr: addr("10.224.0.5"), SrcPort: 443, DstPort: 50000},
	}
	payments := trafficStat(server, "10.4.3.8")
	payments.CommonAttrs.Metadata[attr.K8sDstName] = "payments-7d9f"
	nodeWithPublicIP := trafficStat(server, "34.1.2.3")
	nodeWithPublicIP.CommonAttrs.Metadata[attr.K8sDstName] = "gke-node-2"

	for _, tt := range []struct {
		name                string
		stat                *ebpf.Stat
		wantDst, wantPreNAT string
	}{
		{"internet client of a server", trafficStat(server, "1.2.3.4"), "external", ""},
		{"public address before a SNAT", azure, "10.224.0.5", "external"},
		{"pod to pod", payments, "10.4.3.8", ""},
		{"client of a public server", trafficStat(client, "52.95.110.1"), "52.95.110.1", ""},
		{"VPC client of a server", trafficStat(server, "10.20.5.9"), "10.20.5.9", ""},
		{"shared address space client", trafficStat(server, "100.64.3.2"), "100.64.3.2", ""},
		{"loopback client", trafficStat(server, "127.0.0.1"), "127.0.0.1", ""},
		{"IPv4 in IPv6 form", trafficStat(server, "::ffff:1.2.3.4"), "external", ""},
		{"IPv6 internet client", trafficStat(server, "2001:db8::1"), "external", ""},
		{"IPv6 link-local client", trafficStat(server, "fe80::1"), "fe80::1", ""},
		{"Kubernetes object with a public address", nodeWithPublicIP, "34.1.2.3", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			collapse(tt.stat)
			assert.Equal(t, tt.wantDst, attrValue(t, tt.stat, attr.DstAddress))
			if tt.wantDst == ebpf.ExternalAddress {
				assert.Equal(t, ebpf.ExternalAddress, tt.stat.CommonAttrs.DstName)
			}
			if tt.stat.NAT != nil {
				assert.Equal(t, tt.wantPreNAT, attrValue(t, tt.stat, attr.DstPreNATAddress))
				assert.Equal(t, "20.50.1.1", attrValue(t, tt.stat, attr.SrcPreNATAddress), "the address the client dialed")
			}
		})
	}
}

func TestCollapseTCPStat(t *testing.T) {
	s := &ebpf.Stat{Type: ebpf.StatTypeTCPRtt, TCPRtt: &ebpf.TCPRtt{Role: uint8(ebpf.CodeRoleServer)}}
	s.CommonAttrs.DstAddr = addr("1.2.3.4")
	collapse(s)
	assert.Equal(t, ebpf.ExternalAddress, attrValue(t, s, attr.DstAddress))
}

func TestCollapseProvider(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		in := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
		out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
		outCh := out.Subscribe()
		run, err := CollapseProvider(enabled, in, out)(t.Context())
		require.NoError(t, err)
		go run(t.Context())

		in.Send([]*ebpf.Stat{trafficStat(ebpf.CodeRoleServer, "1.2.3.4")})
		stats := testutil.ReadChannel(t, outCh, timeout)
		require.Len(t, stats, 1)
		assert.Equal(t, enabled, stats[0].DstExternal)
	}
}
