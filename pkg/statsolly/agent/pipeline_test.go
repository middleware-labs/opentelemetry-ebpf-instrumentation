// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const timeout = 5 * time.Second

func TestFilter(t *testing.T) {
	ctx := t.Context()

	registry := prometheus.NewRegistry()
	promServer := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	t.Cleanup(promServer.Close)

	stats := Stats{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		cfg: &obi.Config{
			Prometheus: prom.PrometheusConfig{
				Registry: registry,
				Path:     "/metrics",
				TTL:      time.Hour,
			},
			Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureStatsTCPRtt | export.FeatureStatsTCPFailedConnections | export.FeatureStatsTCPRetransmits | export.FeatureStatsTCPIo | export.FeatureStatsTCPSuccessfulConnections | export.FeatureStatsTCPFlowControl | export.FeatureStatsTCPCongestion | export.FeatureStatsTCPClosedConnections | export.FeatureStatsDNSLookups | export.FeatureStatsSocketBytes | export.FeatureStatsSocketPackets},
			Attributes: obi.Attributes{Select: attributes.Selection{
				attributes.StatTCPRtt.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port"},
				},
				attributes.StatTCPFailedConnections.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "reason"},
				},
				attributes.StatTCPSuccessfulConnections.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "network_tcp_handshake_role"},
				},
				attributes.StatTCPClosedConnections.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "network_tcp_handshake_role"},
				},
				attributes.StatTCPRetransmits.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port"},
				},
				attributes.StatTCPIo.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "network_io_direction"},
				},
				attributes.StatTCPFlowControlEvents.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "network_tcp_flow_control_event", "network_tcp_handshake_role"},
				},
				attributes.StatTCPECNCEPackets.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "network_tcp_handshake_role"},
				},
				attributes.StatTCPReorderingEvents.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port"},
				},
				attributes.StatTCPOutOfOrderPackets.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port"},
				},
				attributes.StatDNSLookupDuration.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "error_type", "dns_question_name", "dns_question_type"},
				},
				attributes.StatSocketBytes.Section: attributes.InclusionLists{
					Include: []string{"dst_port", "network_transport", "network_io_direction", "network_connection_role"},
				},
				attributes.StatSocketPackets.Section: attributes.InclusionLists{
					Include: []string{"dst_port", "network_transport", "network_io_direction", "network_connection_role"},
				},
			}},
		},
	}

	ringBuf := make(chan []*ebpf.Stat, 10)
	// override eBPF stat fetchers
	newRingBufTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			for i := range ringBuf {
				out.SendCtx(ctx, i)
			}
		}
	}

	dnsLookups := make(chan []*ebpf.Stat, 10)
	newDNSTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			for i := range dnsLookups {
				out.SendCtx(ctx, i)
			}
		}
	}

	socketTraffic := make(chan []*ebpf.Stat, 10)
	newSocketTrafficReader = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			for i := range socketTraffic {
				out.SendCtx(ctx, i)
			}
		}
	}

	runner, err := stats.buildPipeline(ctx)
	require.NoError(t, err)

	go runner.Start(ctx)

	ringBuf <- []*ebpf.Stat{
		fakeRecord(123, 456),
		fakeRecord(789, 1011),
		fakeRecord(333, 444),
	}
	ringBuf <- []*ebpf.Stat{
		fakeRecord(1213, 1415),
		fakeRecord(3333, 8080),
	}

	ringBuf <- []*ebpf.Stat{
		fakeFailedConnRecord(555, 666, uint8(ebpf.CodeConnectionRefused)),
		fakeFailedConnRecord(777, 888, uint8(ebpf.CodeTimedOut)),
	}

	ringBuf <- []*ebpf.Stat{
		fakeSuccessfulConnRecord(444, 999, uint8(ebpf.CodeRoleClient)),
	}

	ringBuf <- []*ebpf.Stat{
		fakeRetransmitRecord(777, 888),
	}

	ringBuf <- []*ebpf.Stat{
		fakeIoRecord(100, 200, uint8(ebpf.CodeDirectionTransmit), 1500),
		fakeIoRecord(100, 200, uint8(ebpf.CodeDirectionReceive), 2000),
	}

	ringBuf <- []*ebpf.Stat{
		fakeFlowControlRecord(300, 400, uint8(ebpf.CodeRoleClient)),
		fakeFlowControlRecord(300, 400, uint8(ebpf.CodeRoleClient)),
	}

	// reordering never increases: its zero deltas must not create a series
	ringBuf <- []*ebpf.Stat{
		fakeCongestionRecord(500, 600, ebpf.TCPCongestion{DeliveredCE: 3, RcvOOOPack: 2, Role: uint8(ebpf.CodeRoleServer)}),
		fakeCongestionRecord(500, 600, ebpf.TCPCongestion{DeliveredCE: 1, Role: uint8(ebpf.CodeRoleServer)}),
	}

	ringBuf <- []*ebpf.Stat{
		fakeClosedConnRecord(700, 800, uint8(ebpf.CodeRoleClient)),
		fakeClosedConnRecord(700, 800, uint8(ebpf.CodeRoleClient)),
		fakeClosedConnRecord(800, 700, uint8(ebpf.CodeRoleServer)),
	}

	// the TCP stats read from the rows count several events, and the rolled-up RTTs are each recorded
	rowSuccessful := fakeSuccessfulConnRecord(444, 999, uint8(ebpf.CodeRoleClient))
	rowSuccessful.Count = 2
	rowRetransmits := fakeRetransmitRecord(777, 888)
	rowRetransmits.Count = 4
	rowRtt := fakeRecord(123, 456)
	rowRtt.TCPRtt.Merged = []uint32{200, 300}
	socketTraffic <- []*ebpf.Stat{rowSuccessful, rowRetransmits, rowRtt}

	// a TCP close only adds packets: its zero bytes must not create a series
	socketTraffic <- []*ebpf.Stat{
		fakeSocketTrafficRecord(80, ebpf.SocketTraffic{Transport: syscall.IPPROTO_TCP, Direction: uint8(ebpf.CodeDirectionTransmit), Role: uint8(ebpf.CodeRoleClient), Bytes: 76, Packets: 2}),
		fakeSocketTrafficRecord(80, ebpf.SocketTraffic{Transport: syscall.IPPROTO_TCP, Direction: uint8(ebpf.CodeDirectionReceive), Role: uint8(ebpf.CodeRoleClient), Bytes: 853, Packets: 3}),
		fakeSocketTrafficRecord(80, ebpf.SocketTraffic{Transport: syscall.IPPROTO_TCP, Direction: uint8(ebpf.CodeDirectionTransmit), Role: uint8(ebpf.CodeRoleClient), Packets: 1}),
		fakeSocketTrafficRecord(53, ebpf.SocketTraffic{Transport: syscall.IPPROTO_UDP, Direction: uint8(ebpf.CodeDirectionTransmit), Role: uint8(ebpf.CodeRoleClient), Bytes: 40, Packets: 1}),
	}

	dnsLookups <- []*ebpf.Stat{
		fakeDNSLookupRecord(&ebpf.DNSLookup{Duration: 20 * time.Millisecond, QName: "example.com", QType: 1}),
		fakeDNSLookupRecord(&ebpf.DNSLookup{Duration: 30 * time.Millisecond, RCode: 3, QName: "nope.invalid", QType: 28}),
		fakeDNSLookupRecord(&ebpf.DNSLookup{Duration: 30 * time.Millisecond, RCode: 3, QName: "nope.invalid", QType: 28}),
		fakeDNSLookupRecord(&ebpf.DNSLookup{Duration: 5 * time.Second, Timeout: true, QName: "example.com", QType: 1}),
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		allMetrics, err := promtest.Scrape(promServer.URL)
		require.NoError(ct, err)

		// Filter for only the metrics you want to verify
		var filtered []promtest.ScrapedMetric
		for _, m := range allMetrics {
			switch m.Name {
			case "obi_stat_tcp_rtt_seconds_count",
				"obi_stat_tcp_failed_connections_total",
				"obi_stat_tcp_successful_connections_total",
				"obi_stat_tcp_closed_connections_total",
				"obi_stat_tcp_retransmits_total",
				"obi_stat_tcp_io_bytes_total",
				"obi_stat_tcp_flow_control_events_total",
				"obi_stat_tcp_ecn_ce_packets_total",
				"obi_stat_tcp_reordering_events_total",
				"obi_stat_tcp_out_of_order_packets_total",
				"obi_stat_dns_lookup_duration_seconds_count",
				"obi_stat_bytes_total",
				"obi_stat_packets_total",
				"promhttp_metric_handler_errors_total":
				// Reset values to 0 if you don't care about the specific count,
				// or keep them if you want to verify the Value: 1 seen in your logs.
				filtered = append(filtered, m)
			}
		}

		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "1011", "src_port": "789"}},
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "1415", "src_port": "1213"}},
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "444", "src_port": "333"}},
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 4, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "456", "src_port": "123"}},
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "8080", "src_port": "3333"}},
			{Name: "obi_stat_tcp_failed_connections_total", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "666", "src_port": "555", "reason": "refused"}},
			{Name: "obi_stat_tcp_failed_connections_total", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "888", "src_port": "777", "reason": "timed-out"}},
			{Name: "obi_stat_tcp_successful_connections_total", Value: 3, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "999", "src_port": "444", "network_tcp_handshake_role": "client"}},
			{Name: "obi_stat_tcp_closed_connections_total", Value: 2, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "800", "src_port": "700", "network_tcp_handshake_role": "client"}},
			{Name: "obi_stat_tcp_closed_connections_total", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "700", "src_port": "800", "network_tcp_handshake_role": "server"}},
			{Name: "obi_stat_tcp_retransmits_total", Value: 5, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "888", "src_port": "777"}},
			{Name: "obi_stat_tcp_io_bytes_total", Value: 1500, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "200", "src_port": "100", "network_io_direction": "transmit"}},
			{Name: "obi_stat_tcp_io_bytes_total", Value: 2000, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "200", "src_port": "100", "network_io_direction": "receive"}},
			{Name: "obi_stat_tcp_flow_control_events_total", Value: 2, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "400", "src_port": "300", "network_tcp_flow_control_event": "zero_window", "network_tcp_handshake_role": "client"}},
			{Name: "obi_stat_tcp_ecn_ce_packets_total", Value: 4, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "600", "src_port": "500", "network_tcp_handshake_role": "server"}},
			{Name: "obi_stat_tcp_out_of_order_packets_total", Value: 2, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "600", "src_port": "500"}},
			{Name: "obi_stat_dns_lookup_duration_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "error_type": "", "dns_question_name": "example.com", "dns_question_type": "A"}},
			{Name: "obi_stat_dns_lookup_duration_seconds_count", Value: 2, Labels: map[string]string{"obi_ip": "1.2.3.4", "error_type": "NXDomain", "dns_question_name": "nope.invalid", "dns_question_type": "AAAA"}},
			{Name: "obi_stat_dns_lookup_duration_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "error_type": "timeout", "dns_question_name": "example.com", "dns_question_type": "A"}},
			{Name: "obi_stat_bytes_total", Value: 76, Labels: map[string]string{"dst_port": "80", "network_transport": "tcp", "network_io_direction": "transmit", "network_connection_role": "client"}},
			{Name: "obi_stat_bytes_total", Value: 853, Labels: map[string]string{"dst_port": "80", "network_transport": "tcp", "network_io_direction": "receive", "network_connection_role": "client"}},
			{Name: "obi_stat_bytes_total", Value: 40, Labels: map[string]string{"dst_port": "53", "network_transport": "udp", "network_io_direction": "transmit", "network_connection_role": "client"}},
			{Name: "obi_stat_packets_total", Value: 3, Labels: map[string]string{"dst_port": "80", "network_transport": "tcp", "network_io_direction": "transmit", "network_connection_role": "client"}},
			{Name: "obi_stat_packets_total", Value: 3, Labels: map[string]string{"dst_port": "80", "network_transport": "tcp", "network_io_direction": "receive", "network_connection_role": "client"}},
			{Name: "obi_stat_packets_total", Value: 1, Labels: map[string]string{"dst_port": "53", "network_transport": "udp", "network_io_direction": "transmit", "network_connection_role": "client"}},
			{Name: "promhttp_metric_handler_errors_total", Value: 0, Labels: map[string]string{"cause": "encoding"}},
			{Name: "promhttp_metric_handler_errors_total", Value: 0, Labels: map[string]string{"cause": "gathering"}},
		}, filtered)
	}, timeout, 100*time.Millisecond)
}

func fakeRecord(srcPort, dstPort uint16) *ebpf.Stat {
	return &ebpf.Stat{
		TCPRtt: &ebpf.TCPRtt{
			SrttUs: 100,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeFailedConnRecord(srcPort, dstPort uint16, reason uint8) *ebpf.Stat {
	return &ebpf.Stat{
		TCPFailedConnection: &ebpf.TCPFailedConnection{
			Reason: reason,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeSuccessfulConnRecord(srcPort, dstPort uint16, role uint8) *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeTCPSuccessfulConnection,
		TCPSuccessfulConnection: &ebpf.TCPSuccessfulConnection{
			Role: role,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeClosedConnRecord(srcPort, dstPort uint16, role uint8) *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeTCPClosedConnection,
		TCPClosedConnection: &ebpf.TCPClosedConnection{
			Role: role,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeRetransmitRecord(srcPort, dstPort uint16) *ebpf.Stat {
	return &ebpf.Stat{
		TCPRetransmit: true,
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeIoRecord(srcPort, dstPort uint16, direction uint8, bytes uint32) *ebpf.Stat {
	return &ebpf.Stat{
		TCPIo: &ebpf.TCPIo{
			Direction: direction,
			Bytes:     uint64(bytes),
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeFlowControlRecord(srcPort, dstPort uint16, role uint8) *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeTCPFlowControl,
		TCPFlowControl: &ebpf.TCPFlowControl{
			Event: uint8(ebpf.CodeFlowControlEventZeroWindow),
			Role:  role,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeCongestionRecord(srcPort, dstPort uint16, delta ebpf.TCPCongestion) *ebpf.Stat {
	return &ebpf.Stat{
		Type:          ebpf.StatTypeTCPCongestion,
		TCPCongestion: &delta,
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeDNSLookupRecord(lookup *ebpf.DNSLookup) *ebpf.Stat {
	return &ebpf.Stat{
		Type:      ebpf.StatTypeDNSLookup,
		DNSLookup: lookup,
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: 40000,
			DstPort: 53,
		},
	}
}

func fakeSocketTrafficRecord(dstPort uint16, traffic ebpf.SocketTraffic) *ebpf.Stat {
	return &ebpf.Stat{
		Type:          ebpf.StatTypeSocketTraffic,
		SocketTraffic: &traffic,
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: 40000,
			DstPort: dstPort,
		},
	}
}

func TestProcessAttrsSelected(t *testing.T) {
	selecting := func(features export.Features, section attributes.Section, include ...string) *obi.Config {
		return &obi.Config{
			Metrics:    perapp.GlobalMetricsConfig{Features: features},
			Attributes: obi.Attributes{Select: attributes.Selection{section: attributes.InclusionLists{Include: include}}},
		}
	}
	type sides struct{ src, dst bool }
	selected := func(cfg *obi.Config, metrics func(*export.Features) []statMetric) sides {
		src, dst := processAttrsSelected(cfg, metrics(&cfg.Metrics.Features))
		return sides{src, dst}
	}

	cfg := selecting(export.FeatureStats, attributes.StatTCPRetransmits.Section, "src.process.executable.name")
	assert.Equal(t, sides{src: true}, selected(cfg, tcpStatMetrics))
	assert.Equal(t, sides{}, selected(cfg, socketTrafficMetrics))

	cfg = selecting(export.FeatureStats, attributes.StatTCPReorderingEvents.Section, "dst.container.name")
	assert.Equal(t, sides{dst: true}, selected(cfg, tcpStatMetrics))

	cfg = selecting(export.FeatureStatsTCPIo, attributes.StatTCPRtt.Section, "src.container.id")
	assert.Equal(t, sides{}, selected(cfg, tcpStatMetrics), "the metric is not enabled")

	cfg = selecting(export.FeatureStatsSocketBytes, attributes.StatSocketBytes.Section, "*")
	assert.Equal(t, sides{src: true, dst: true}, selected(cfg, socketTrafficMetrics))
	assert.Equal(t, sides{}, selected(cfg, tcpStatMetrics))
}

func TestAttrSelected(t *testing.T) {
	selecting := func(features export.Features, section attributes.Section, include ...string) *obi.Config {
		return &obi.Config{
			Metrics:    perapp.GlobalMetricsConfig{Features: features},
			Attributes: obi.Attributes{Select: attributes.Selection{section: attributes.InclusionLists{Include: include}}},
		}
	}

	cfg := selecting(export.FeatureStats, attributes.StatTCPIo.Section, "server.port")
	assert.True(t, attrSelected(cfg, rowMetrics(&cfg.Metrics.Features, true), attr.ServerPort))
	assert.False(t, attrSelected(cfg, rowMetrics(&cfg.Metrics.Features, false), attr.ServerPort),
		"the TCP stats are events")

	cfg = selecting(export.FeatureStatsSocketBytes, attributes.StatSocketBytes.Section, "server.port")
	assert.True(t, attrSelected(cfg, rowMetrics(&cfg.Metrics.Features, false), attr.ServerPort))

	cfg = selecting(export.FeatureStatsSocketBytes, attributes.StatSocketBytes.Section, "dst.port")
	assert.False(t, attrSelected(cfg, rowMetrics(&cfg.Metrics.Features, false), attr.ServerPort))

	cfg = selecting(export.FeatureStatsSocketBytes, attributes.StatSocketBytes.Section, "network.connection.role")
	assert.True(t, attrSelected(cfg, socketTrafficMetrics(&cfg.Metrics.Features), attr.NetworkConnectionRole))
	assert.False(t, attrSelected(cfg, socketTrafficMetrics(&cfg.Metrics.Features), attr.ServerPort))

	cfg = selecting(export.FeatureStats, attributes.StatTCPRtt.Section, "network.peer.same_host")
	assert.True(t, sameHostSelected(cfg, true))
	assert.False(t, sameHostSelected(cfg, false), "the TCP stats are events")
}

func TestStatProcesses(t *testing.T) {
	tcp := &ebpf.Stat{Owner: ebpf.SockOwner{Pid: 1, ExecName: "curl", CgroupID: 2, DstPid: 3, DstExecName: "nginx", DstCgroupID: 4}}
	src, dst := statProcesses(true, true)(tcp)
	assert.Equal(t, uint32(1), src.Pid)
	assert.Equal(t, "nginx", dst.ExecName)

	traffic := &ebpf.Stat{SocketTraffic: &ebpf.SocketTraffic{Pid: 5, DstPid: 6}}
	src, dst = statProcesses(false, true)(traffic)
	assert.Zero(t, src.Pid, "the source side is not selected")
	assert.Equal(t, uint32(6), dst.Pid)
}
