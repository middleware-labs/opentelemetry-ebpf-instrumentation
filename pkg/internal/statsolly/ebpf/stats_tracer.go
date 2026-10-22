// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

type probe struct {
	name    string
	program *ebpf.Program
	enabled bool
}

// Program names
const (
	progObiStatsKprobeTCPCloseSrtt                        = "obi_stats_kprobe_tcp_close_srtt"
	progObiStatsKprobeTCPCloseIoFlush                     = "obi_stats_kprobe_tcp_close_io_flush"
	progObiStatsTpInetSockSetStateConnRole                = "obi_stats_tp_inet_sock_set_state_conn_role"
	progObiStatsTpInetSockSetStateTCPFailedConnection     = "obi_stats_tp_inet_sock_set_state_tcp_failed_connection"
	progObiStatsTpInetSockSetStateTCPSuccessfulConnection = "obi_stats_tp_inet_sock_set_state_tcp_successful_connection"
	progObiStatsTpInetSockSetStateTCPClosedConnection     = "obi_stats_tp_inet_sock_set_state_tcp_closed_connection"
	progObiStatsRawTpTCPRetransmitSkb                     = "obi_stats_raw_tp_tcp_retransmit_skb"
	progObiStatsKprobeTCPSendmsg                          = "obi_stats_kprobe_tcp_sendmsg"
	progObiStatsKretprobeTCPSendmsg                       = "obi_stats_kretprobe_tcp_sendmsg"
	progObiStatsKprobeTCPCleanupRbuf                      = "obi_stats_kprobe_tcp_cleanup_rbuf"
	progObiStatsKprobeTCPSendProbe0                       = "obi_stats_kprobe_tcp_send_probe0"
	progObiStatsKprobeTCPSendmsgCongestion                = "obi_stats_kprobe_tcp_sendmsg_congestion"
	progObiStatsKprobeTCPCleanupRbufCongestion            = "obi_stats_kprobe_tcp_cleanup_rbuf_congestion"
	progObiStatsKprobeTCPCloseCongestion                  = "obi_stats_kprobe_tcp_close_congestion"
	progObiStatsSocketDNS                                 = "obi_stats_socket_dns"
	progObiStatsKprobeTCPSendmsgTraffic                   = "obi_stats_kprobe_tcp_sendmsg_traffic"
	progObiStatsKretprobeTCPSendmsgTraffic                = "obi_stats_kretprobe_tcp_sendmsg_traffic"
	progObiStatsKprobeTCPCleanupRbufTraffic               = "obi_stats_kprobe_tcp_cleanup_rbuf_traffic"
	progObiStatsKprobeTCPCloseTraffic                     = "obi_stats_kprobe_tcp_close_traffic"
	progObiStatsKretprobeIPMakeSkbTraffic                 = "obi_stats_kretprobe_ip_make_skb_traffic"
	progObiStatsKretprobeIP6MakeSkbTraffic                = "obi_stats_kretprobe_ip6_make_skb_traffic"
	progObiStatsKprobeSkbConsumeUDPTraffic                = "obi_stats_kprobe_skb_consume_udp_traffic"
	progObiStatsKprobeUDPSendmsgTraffic                   = "obi_stats_kprobe_udp_sendmsg_traffic"
	progObiStatsKprobeUDPv6SendmsgTraffic                 = "obi_stats_kprobe_udpv6_sendmsg_traffic"
	progObiStatsKprobeTCPSendpageTraffic                  = "obi_stats_kprobe_tcp_sendpage_traffic"
	progObiStatsKretprobeTCPSendpageTraffic               = "obi_stats_kretprobe_tcp_sendpage_traffic"
	progObiStatsKprobeUDPDestroySockTraffic               = "obi_stats_kprobe_udp_destroy_sock_traffic"
	progObiStatsKprobeUDPv6DestroySockTraffic             = "obi_stats_kprobe_udpv6_destroy_sock_traffic"
	progObiStatsKprobeInetBindTraffic                     = "obi_stats_kprobe_inet_bind_traffic"
	progObiStatsKretprobeInetBindTraffic                  = "obi_stats_kretprobe_inet_bind_traffic"
	progObiStatsKprobeInet6BindTraffic                    = "obi_stats_kprobe_inet6_bind_traffic"
	progObiStatsKretprobeInet6BindTraffic                 = "obi_stats_kretprobe_inet6_bind_traffic"
	progObiStatsTpInetSockSetStateSockOwner               = "obi_stats_tp_inet_sock_set_state_sock_owner"
	progObiStatsKprobeTCPSendmsgOwner                     = "obi_stats_kprobe_tcp_sendmsg_owner"
	progObiStatsKprobeTCPCleanupRbufOwner                 = "obi_stats_kprobe_tcp_cleanup_rbuf_owner"
	progObiStatsKprobeTCPCloseOwner                       = "obi_stats_kprobe_tcp_close_owner"
	progObiStatsKprobeInetCskListenStartOwner             = "obi_stats_kprobe_inet_csk_listen_start_owner"
	progObiStatsTpInetSockSetStateTCPRow                  = "obi_stats_tp_inet_sock_set_state_tcp_row"
	progObiStatsRawTpTCPRetransmitSkbRow                  = "obi_stats_raw_tp_tcp_retransmit_skb_row"
	progObiStatsKprobeTCPSendProbe0Row                    = "obi_stats_kprobe_tcp_send_probe0_row"
	progObiStatsKprobeInetCskDestroySockRow               = "obi_stats_kprobe_inet_csk_destroy_sock_row"
	progObiStatsKprobeTCPDisconnectRow                    = "obi_stats_kprobe_tcp_disconnect_row"
)

// socketTrafficRetprobeMaxActive is how many calls of a socket traffic kretprobe function can
// be tracked at once, Datadog's DefaultKProbeMaxActive. The kernel default (2 per CPU) misses
// the bytes of the calls beyond it, e.g. threads sleeping in tcp_sendmsg for socket memory.
const socketTrafficRetprobeMaxActive = 128

// congestionMinInterval is the minimum time between two congestion events of the same socket.
// Counter increases in between are not lost: they are sent with the next event or at close.
const congestionMinInterval = time.Second

// Hook point names, grouped by attach type.
const (
	// Kprobes: kernel function names.
	KprobeTCPClose       = "tcp_close"
	KprobeTCPSendMsg     = "tcp_sendmsg"
	KprobeTCPCleanupRbuf = "tcp_cleanup_rbuf"
	KprobeTCPSendProbe0  = "tcp_send_probe0"
	KprobeIPMakeSkb      = "ip_make_skb"
	KprobeIP6MakeSkb     = "ip6_make_skb"
	KprobeSkbConsumeUDP  = "skb_consume_udp"
	KprobeTCPSendpage    = "tcp_sendpage"
	KprobeUDPDestroySock = "udp_destroy_sock"
	KprobeUDPSendmsg     = "udp_sendmsg"
	// udpv6_destroy_sock, udpv6_sendmsg, inet6_bind and ip6_make_skb are missing when IPv6 is
	// disabled or not loaded
	KprobeUDPv6DestroySock   = "udpv6_destroy_sock"
	KprobeUDPv6Sendmsg       = "udpv6_sendmsg"
	KprobeInetBind           = "inet_bind"
	KprobeInet6Bind          = "inet6_bind"
	KprobeInetCskListenStart = "inet_csk_listen_start"
	KprobeInetCskDestroySock = "inet_csk_destroy_sock"
	KprobeTCPDisconnect      = "tcp_disconnect"

	// Tracepoints: group/name, are validated by TestTracepointConstantFormat
	TracepointInetSockSetState = "sock/inet_sock_set_state"

	// Raw tracepoints: name only (no group prefix).
	RawTracepointTCPRetransmitSkb = "tcp_retransmit_skb"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type stat_type -type tcp_fail_reason -type tcp_handshake_role -type tcp_retransmit_type -type tcp_flow_control_event -type network_io_direction -type tcp_io_t -type tcp_rtt_t -type tcp_failed_connection_t -type tcp_retransmit_t -type tcp_successful_connection_t -type tcp_closed_connection_t -type tcp_flow_control_t -type tcp_congestion_t -type tcp_cong_vals_t -type dns_packet_t -type socket_traffic_key_t -type socket_traffic_t -type socket_traffic_closed_t -type socket_traffic_drop -type sock_owner_t -type endpoint_key_t -type endpoint_owner_t -target $BPF_TARGETS Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer
	// sockOwners is true when the TCP stat events carry the process of their socket
	sockOwners bool
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

// NewStatsFetcher loads and attaches the stats programs. With sockOwners, the TCP stat events
// carry the process of their socket: a process or container attribute of the TCP stats is selected.
// seedUDPPorts adds to the udp_port_bindings map the UDP ports bound before OBI started.
func NewStatsFetcher(
	cfg *config.EBPFTracer,
	features *export.Features,
	selectorCfg *attributes.SelectorConfig,
	socketTraffic *config.SocketTrafficConfig,
	sockOwners bool,
	seedUDPPorts func(bindings *ebpf.Map) error,
) (*StatsFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := StatsObjects{}
	spec, err := LoadStats()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// UndefinedGroup is intentional: we only need to check NetworkTCPHandshakeRole,
	// which is a direct metric attribute.
	attrSel, err := attributes.NewAttrSelector(attributes.UndefinedGroup, selectorCfg)
	if err != nil {
		return nil, fmt.Errorf("creating attr selector: %w", err)
	}

	// In the row mode, the TCP stat metrics but the failed connections are read from the
	// socket traffic rows: their event programs are off
	tcpRows := TCPMetricsFromRows(features, socketTraffic)
	events := features
	if tcpRows {
		eventFeatures := *features &^ tcpRowFeatures
		events = &eventFeatures
	}

	// OR across all consumer metrics: a single shared probe writes sock_role for all of them,
	// so the probe is needed if any metric has the attribute enabled.
	// Note: tcp successful connection probe derives role from oldstate and never reads sock_role
	// server.port is the local or the remote port depending on the role
	selectsRole := func(metric attributes.Name, roleAttr attr.Name) bool {
		selected := attrSel.For(metric)
		return slices.Contains(selected, roleAttr) || slices.Contains(selected, attr.ServerPort)
	}
	connRoleAttrSelected := selectsRole(attributes.StatTCPRtt, attr.NetworkTCPHandshakeRole) ||
		selectsRole(attributes.StatTCPFailedConnections, attr.NetworkTCPHandshakeRole) ||
		selectsRole(attributes.StatTCPClosedConnections, attr.NetworkTCPHandshakeRole) ||
		selectsRole(attributes.StatTCPFlowControlEvents, attr.NetworkTCPHandshakeRole) ||
		selectsRole(attributes.StatTCPECNCEPackets, attr.NetworkTCPHandshakeRole) ||
		selectsRole(attributes.StatTCPReorderingEvents, attr.NetworkTCPHandshakeRole) ||
		selectsRole(attributes.StatTCPOutOfOrderPackets, attr.NetworkTCPHandshakeRole)

	socketTrafficTCP := (features.StatsSocketTraffic() && socketTraffic.TCP()) || tcpRows
	socketTrafficUDP := features.StatsSocketTraffic() && socketTraffic.UDP()
	// the socket traffic rows take the TCP role from sock_role and the UDP role from udp_port_bindings
	// the connection rollup needs the role too: it tells which port is the client's
	socketTrafficRoleSelected := (features.StatsSocketBytes() && selectsRole(attributes.StatSocketBytes, attr.NetworkConnectionRole)) ||
		(features.StatsSocketPackets() && selectsRole(attributes.StatSocketPackets, attr.NetworkConnectionRole)) ||
		socketTraffic.ConnectionRollup
	udpRoleUsed := socketTrafficUDP && socketTrafficRoleSelected

	connRoleUsed := ((events.StatsTCPFailedConnections() || events.StatsTCPClosedConnections() || events.StatsTCPRtt() ||
		events.StatsTCPFlowControl() || events.StatsTCPCongestion()) && connRoleAttrSelected) ||
		(socketTrafficTCP && socketTrafficRoleSelected)

	var toDisable []string
	if !events.StatsTCPFailedConnections() {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateTCPFailedConnection)
	}
	if !events.StatsTCPSuccessfulConnections() {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateTCPSuccessfulConnection)
	}
	if !events.StatsTCPClosedConnections() {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateTCPClosedConnection)
	}
	if !connRoleUsed {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateConnRole)
	}
	if !events.StatsTCPRtt() {
		toDisable = append(toDisable, progObiStatsKprobeTCPCloseSrtt)
	}
	if !events.StatsTCPRetransmits() {
		toDisable = append(toDisable, progObiStatsRawTpTCPRetransmitSkb)
	}
	if !events.StatsTCPIo() {
		toDisable = append(toDisable, progObiStatsKprobeTCPSendmsg, progObiStatsKretprobeTCPSendmsg, progObiStatsKprobeTCPCleanupRbuf, progObiStatsKprobeTCPCloseIoFlush)
	}
	if !events.StatsTCPFlowControl() {
		toDisable = append(toDisable, progObiStatsKprobeTCPSendProbe0)
	}
	if !events.StatsTCPCongestion() {
		toDisable = append(toDisable, progObiStatsKprobeTCPSendmsgCongestion, progObiStatsKprobeTCPCleanupRbufCongestion, progObiStatsKprobeTCPCloseCongestion)
	}

	if !features.StatsDNSLookups() {
		toDisable = append(toDisable, progObiStatsSocketDNS)
		// a ring buffer can't be empty: keep the smallest size when nothing writes to it
		spec.Maps[StatsMapStatsDnsEvents].MaxEntries = uint32(os.Getpagesize())
	}

	if !socketTrafficTCP {
		toDisable = append(toDisable, progObiStatsKprobeTCPSendmsgTraffic, progObiStatsKretprobeTCPSendmsgTraffic,
			progObiStatsKprobeTCPSendpageTraffic, progObiStatsKretprobeTCPSendpageTraffic,
			progObiStatsKprobeTCPCleanupRbufTraffic, progObiStatsKprobeTCPCloseTraffic)
	}
	if !socketTrafficUDP {
		toDisable = append(toDisable, progObiStatsKretprobeIPMakeSkbTraffic, progObiStatsKretprobeIP6MakeSkbTraffic,
			progObiStatsKprobeSkbConsumeUDPTraffic, progObiStatsKprobeUDPDestroySockTraffic, progObiStatsKprobeUDPv6DestroySockTraffic,
			progObiStatsKprobeUDPSendmsgTraffic, progObiStatsKprobeUDPv6SendmsgTraffic)
	}
	if !udpRoleUsed {
		toDisable = append(toDisable, progObiStatsKprobeInetBindTraffic, progObiStatsKretprobeInetBindTraffic,
			progObiStatsKprobeInet6BindTraffic, progObiStatsKretprobeInet6BindTraffic)
	}
	sizeSocketTrafficMaps(spec, socketTraffic.MaxEntries, socketTrafficTCP, socketTrafficUDP, udpRoleUsed)

	if !tcpRows {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateTCPRow,
			progObiStatsRawTpTCPRetransmitSkbRow, progObiStatsKprobeTCPSendProbe0Row, progObiStatsKprobeInetCskDestroySockRow,
			progObiStatsKprobeTCPDisconnectRow)
	}

	if !sockOwners {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateSockOwner,
			progObiStatsKprobeTCPSendmsgOwner, progObiStatsKprobeTCPCleanupRbufOwner,
			progObiStatsKprobeTCPCloseOwner, progObiStatsKprobeInetCskListenStartOwner)
		spec.Maps[StatsMapSockOwner].MaxEntries = 1
		spec.Maps[StatsMapEndpointOwner].MaxEntries = 1
	}

	if err := fixupSpec(spec, toDisable); err != nil {
		return nil, fmt.Errorf("fixing up BPF spec: %w", err)
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	if err := ebpfconvenience.LoadSpec(spec, &objects, map[string]any{
		"g_bpf_debug":                      cfg.BpfDebug,
		"stats_wakeup_data_bytes":          uint32(cfg.StatsWakeupDataBytes),
		"stats_congestion_min_interval_ns": uint64(congestionMinInterval),
		"stats_sock_owner_enabled":         sockOwners,
		"stats_tcp_metrics_enabled":        tcpRows,
	}, sharedMaps, &mu, "", nil); err != nil {
		return nil, fmt.Errorf("loading stats eBPF spec: %w", err)
	}

	var closables []io.Closer

	// kprobes
	for _, k := range []probe{
		{
			name:    KprobeTCPClose,
			program: objects.ObiStatsKprobeTcpCloseSrtt,
			enabled: events.StatsTCPRtt(),
		},
		{
			name:    KprobeTCPClose,
			program: objects.ObiStatsKprobeTcpCloseIoFlush,
			enabled: events.StatsTCPIo(),
		},
		{
			name:    KprobeTCPSendMsg,
			program: objects.ObiStatsKprobeTcpSendmsg,
			enabled: events.StatsTCPIo(),
		},
		{
			name:    KprobeTCPCleanupRbuf,
			program: objects.ObiStatsKprobeTcpCleanupRbuf,
			enabled: events.StatsTCPIo(),
		},
		{
			name:    KprobeTCPSendMsg,
			program: objects.ObiStatsKprobeTcpSendmsgCongestion,
			enabled: events.StatsTCPCongestion(),
		},
		{
			name:    KprobeTCPCleanupRbuf,
			program: objects.ObiStatsKprobeTcpCleanupRbufCongestion,
			enabled: events.StatsTCPCongestion(),
		},
		{
			name:    KprobeTCPClose,
			program: objects.ObiStatsKprobeTcpCloseCongestion,
			enabled: events.StatsTCPCongestion(),
		},
		{
			name:    KprobeTCPSendMsg,
			program: objects.ObiStatsKprobeTcpSendmsgOwner,
			enabled: sockOwners,
		},
		{
			name:    KprobeTCPCleanupRbuf,
			program: objects.ObiStatsKprobeTcpCleanupRbufOwner,
			enabled: sockOwners,
		},
		{
			name:    KprobeInetCskListenStart,
			program: objects.ObiStatsKprobeInetCskListenStartOwner,
			enabled: sockOwners,
		},
		// after the tcp_close programs that read sock_owner
		{
			name:    KprobeTCPClose,
			program: objects.ObiStatsKprobeTcpCloseOwner,
			enabled: sockOwners,
		},
	} {
		if !k.enabled {
			continue
		}

		l, err := kprobe.Attach(k.name, k.program, false)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed kprobe attachment %s: %w", k.name, err)
		}
		closables = append(closables, l)
	}

	// optional kprobes: a missing kernel symbol only disables that metric
	for _, k := range []probe{
		{
			name:    KprobeTCPSendProbe0,
			program: objects.ObiStatsKprobeTcpSendProbe0,
			enabled: events.StatsTCPFlowControl(),
		},
		{
			name:    KprobeTCPSendProbe0,
			program: objects.ObiStatsKprobeTcpSendProbe0Row,
			enabled: tcpRows && features.StatsTCPFlowControl(),
		},
		{
			name:    KprobeInetCskDestroySock,
			program: objects.ObiStatsKprobeInetCskDestroySockRow,
			enabled: tcpRows,
		},
		{
			name:    KprobeTCPDisconnect,
			program: objects.ObiStatsKprobeTcpDisconnectRow,
			enabled: tcpRows,
		},
	} {
		if !k.enabled {
			continue
		}

		l, err := kprobe.Attach(k.name, k.program, false)
		if err != nil {
			tlog.Warn("optional kprobe not attached, metric disabled", "kprobe", k.name, "error", err)
			continue
		}
		closables = append(closables, l)
	}

	// kretprobes
	for _, k := range []probe{
		{
			name:    KprobeTCPSendMsg,
			program: objects.ObiStatsKretprobeTcpSendmsg,
			enabled: events.StatsTCPIo(),
		},
	} {
		if !k.enabled {
			continue
		}
		l, err := kprobe.Attach(k.name, k.program, true)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed kretprobe attachment %s: %w", k.name, err)
		}
		closables = append(closables, l)
	}

	// the bind probes, then the ports bound before OBI started, then the probes that create the
	// rows: no bind is missed, and no row takes its role before its port is known
	bindLinks, err := attachSocketTrafficProbes(tlog, udpBindProbes(&objects, udpRoleUsed))
	closables = append(closables, bindLinks...)
	if err != nil {
		closeAll(closables)
		return nil, err
	}
	if udpRoleUsed {
		if err := seedUDPPorts(objects.UdpPortBindings); err != nil {
			tlog.Warn("can't read the UDP ports bound before OBI started: their sockets are reported as clients", "error", err)
		}
	}

	socketTrafficLinks, err := attachSocketTrafficProbes(tlog,
		socketTrafficProbes(&objects, socketTrafficTCP, socketTrafficUDP))
	closables = append(closables, socketTrafficLinks...)
	if err != nil {
		closeAll(closables)
		return nil, err
	}

	// tracepoints
	for _, t := range inetSockSetStateProbes(&objects, events, connRoleUsed, sockOwners, tcpRows) {
		if !t.enabled {
			continue
		}

		group, tp, _ := strings.Cut(t.name, "/")
		l, err := link.Tracepoint(group, tp, t.program, nil)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed tracepoint attachment %s: %w", t.name, err)
		}
		closables = append(closables, l)
	}

	// raw tracepoints
	for _, t := range []probe{
		{
			name:    RawTracepointTCPRetransmitSkb,
			program: objects.ObiStatsRawTpTcpRetransmitSkb,
			enabled: events.StatsTCPRetransmits(),
		},
		{
			name:    RawTracepointTCPRetransmitSkb,
			program: objects.ObiStatsRawTpTcpRetransmitSkbRow,
			enabled: tcpRows && features.StatsTCPRetransmits(),
		},
	} {
		if !t.enabled {
			continue
		}
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    t.name,
			Program: t.program,
		})
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed raw tracepoint attachment %s: %w", t.name, err)
		}
		closables = append(closables, l)
	}

	if features.StatsDNSLookups() {
		sock, err := attachSocketFilter(objects.ObiStatsSocketDns)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed socket filter attachment %s: %w", progObiStatsSocketDNS, err)
		}
		closables = append(closables, sock)
	}

	return &StatsFetcher{
		log:        tlog,
		objects:    &objects,
		closables:  closables,
		sockOwners: sockOwners,
	}, nil
}

func closeAll(closables []io.Closer) {
	for _, c := range closables {
		if c != nil {
			c.Close()
		}
	}
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	m.log.Debug("unregistering eBPF objects")

	var errs []error
	for _, c := range m.closables {
		if c != nil {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}

// StatsEventsMap returns the ring buffer map for stats events.
// The caller (ForwardRingbuf) is responsible for creating and closing the reader.
func (m *StatsFetcher) StatsEventsMap() *ebpf.Map {
	return m.objects.StatsEvents
}

// StatsDNSEventsMap returns the ring buffer map for the DNS packets.
func (m *StatsFetcher) StatsDNSEventsMap() *ebpf.Map {
	return m.objects.StatsDnsEvents
}

// SocketTrafficMap returns the map with the bytes and packets of each socket.
func (m *StatsFetcher) SocketTrafficMap() *ebpf.Map {
	return m.objects.SocketTraffic
}

// SocketTrafficClosedMap returns the ring buffer with the final row of each closed socket.
func (m *StatsFetcher) SocketTrafficClosedMap() *ebpf.Map {
	return m.objects.SocketTrafficClosed
}

// SocketTrafficDropsMap returns the per-CPU socket traffic drop counters, indexed by socket_traffic_drop.
func (m *StatsFetcher) SocketTrafficDropsMap() *ebpf.Map {
	return m.objects.SocketTrafficDrops
}

// EndpointOwnerMap returns the map with the process of each local TCP address. It is nil when
// the TCP stat events do not carry the process of their socket.
func (m *StatsFetcher) EndpointOwnerMap() *ebpf.Map {
	if !m.sockOwners {
		return nil
	}
	return m.objects.EndpointOwner
}

func (m *StatsFetcher) DebugEventsMap() *ebpf.Map {
	return m.objects.DebugEvents
}

// attachSocketFilter opens a raw socket that receives all the packets of OBI's network
// namespace and attaches the program to it. The socket is bound to the packets only after
// the filter is attached, so it never queues any packet that the filter did not see.
func attachSocketFilter(prog *ebpf.Program) (io.Closer, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening raw socket: %w", err)
	}
	sock := os.NewFile(uintptr(fd), "stats_dns_socket")

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD()); err != nil {
		sock.Close()
		return nil, fmt.Errorf("attaching socket filter: %w", err)
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL)}); err != nil {
		sock.Close()
		return nil, fmt.Errorf("binding raw socket: %w", err)
	}
	return sock, nil
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}

// sizeSocketTrafficMaps sets the size of the socket traffic maps from the configuration.
// Hash maps are preallocated, so the maps that no enabled program uses keep a single entry.
func sizeSocketTrafficMaps(spec *ebpf.CollectionSpec, maxEntries uint32, tcp, udp, udpRole bool) {
	if tcp || udp {
		spec.Maps[StatsMapSocketTraffic].MaxEntries = maxEntries
	} else {
		spec.Maps[StatsMapSocketTraffic].MaxEntries = 1
		// a ring buffer can't be empty: keep the smallest size when nothing writes to it
		spec.Maps[StatsMapSocketTrafficClosed].MaxEntries = uint32(os.Getpagesize())
	}
	if !tcp {
		spec.Maps[StatsMapSocketTrafficSendmsgSock].MaxEntries = 1
	}
	if !udp {
		spec.Maps[StatsMapSocketTrafficUdpDport].MaxEntries = 1
	}
	if !udpRole {
		spec.Maps[StatsMapUdpPortBindings].MaxEntries = 1
		spec.Maps[StatsMapSocketTrafficBindSock].MaxEntries = 1
	}
}

// socketTrafficProbe is a kprobe or kretprobe of the socket traffic metrics
type socketTrafficProbe struct {
	probe
	retprobe bool
	// an optional probe is skipped when its kernel function is missing
	optional bool
}

// udpBindProbes count the bound UDP ports, for the role of the UDP rows
func udpBindProbes(objects *StatsObjects, udpRole bool) []socketTrafficProbe {
	return []socketTrafficProbe{
		{probe: probe{name: KprobeInetBind, program: objects.ObiStatsKprobeInetBindTraffic, enabled: udpRole}},
		{probe: probe{name: KprobeInetBind, program: objects.ObiStatsKretprobeInetBindTraffic, enabled: udpRole}, retprobe: true},
		{probe: probe{name: KprobeInet6Bind, program: objects.ObiStatsKprobeInet6BindTraffic, enabled: udpRole}, optional: true},
		{probe: probe{name: KprobeInet6Bind, program: objects.ObiStatsKretprobeInet6BindTraffic, enabled: udpRole}, retprobe: true, optional: true},
	}
}

func socketTrafficProbes(objects *StatsObjects, tcp, udp bool) []socketTrafficProbe {
	return []socketTrafficProbe{
		{probe: probe{name: KprobeTCPSendMsg, program: objects.ObiStatsKprobeTcpSendmsgTraffic, enabled: tcp}},
		{probe: probe{name: KprobeTCPSendMsg, program: objects.ObiStatsKretprobeTcpSendmsgTraffic, enabled: tcp}, retprobe: true},
		// tcp_sendpage only exists before kernel 6.5, where sendfile() and splice() use it
		{probe: probe{name: KprobeTCPSendpage, program: objects.ObiStatsKprobeTcpSendpageTraffic, enabled: tcp}, optional: true},
		{probe: probe{name: KprobeTCPSendpage, program: objects.ObiStatsKretprobeTcpSendpageTraffic, enabled: tcp}, retprobe: true, optional: true},
		{probe: probe{name: KprobeTCPCleanupRbuf, program: objects.ObiStatsKprobeTcpCleanupRbufTraffic, enabled: tcp}},
		{probe: probe{name: KprobeTCPClose, program: objects.ObiStatsKprobeTcpCloseTraffic, enabled: tcp}},

		// the destination port of the unconnected sockets, for the ip_make_skb kretprobes
		{probe: probe{name: KprobeUDPSendmsg, program: objects.ObiStatsKprobeUdpSendmsgTraffic, enabled: udp}},
		{probe: probe{name: KprobeUDPv6Sendmsg, program: objects.ObiStatsKprobeUdpv6SendmsgTraffic, enabled: udp}, optional: true},
		{probe: probe{name: KprobeIPMakeSkb, program: objects.ObiStatsKretprobeIpMakeSkbTraffic, enabled: udp}, retprobe: true},
		{probe: probe{name: KprobeIP6MakeSkb, program: objects.ObiStatsKretprobeIp6MakeSkbTraffic, enabled: udp}, retprobe: true, optional: true},
		{probe: probe{name: KprobeSkbConsumeUDP, program: objects.ObiStatsKprobeSkbConsumeUdpTraffic, enabled: udp}},
		{probe: probe{name: KprobeUDPDestroySock, program: objects.ObiStatsKprobeUdpDestroySockTraffic, enabled: udp}},
		{probe: probe{name: KprobeUDPv6DestroySock, program: objects.ObiStatsKprobeUdpv6DestroySockTraffic, enabled: udp}, optional: true},
	}
}

// attachSocketTrafficProbes returns the links attached before any error, for the caller to close.
func attachSocketTrafficProbes(log *slog.Logger, probes []socketTrafficProbe) ([]io.Closer, error) {
	var links []io.Closer
	for _, p := range probes {
		if !p.enabled {
			continue
		}

		var l io.Closer
		var err error
		if p.retprobe {
			l, err = kprobe.AttachRetMaxActive(p.name, p.program, socketTrafficRetprobeMaxActive)
		} else {
			l, err = kprobe.Attach(p.name, p.program, false)
		}
		if err != nil {
			if p.optional {
				log.Debug("optional socket traffic probe not attached", "function", p.name, "retprobe", p.retprobe, "error", err)
				continue
			}
			return links, fmt.Errorf("failed socket traffic probe attachment %s: %w", p.name, err)
		}
		links = append(links, l)
	}
	return links, nil
}

// fixupSpec replaces disabled programs with no-op stubs before loading,
// preventing unused eBPF code from being loaded into the kernel.
func fixupSpec(spec *ebpf.CollectionSpec, toDisable []string) error {
	for _, name := range toDisable {
		prog := spec.Programs[name]
		if prog == nil {
			return fmt.Errorf("unknown program name %s", name)
		}
		spec.Programs[name] = &ebpf.ProgramSpec{
			Name:         "stats_dummy",
			Type:         prog.Type,
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			License:      "Dual MIT/GPL",
		}
	}
	return nil
}

// inetSockSetStateProbes returns the inet_sock_set_state programs in attach order.
// ObiStatsTpInetSockSetStateTcpFailedConnection, ObiStatsTpInetSockSetStateTcpClosedConnection
// (or any other probes that use role) must be attached before ObiStatsTpInetSockSetStateConnRole.
// They attach to the same tracepoint and BPF programs run FIFO:
// the probes read sock_role first, conn_role deletes it after.
// Swapping the order would cause tcp_failed_conn or any other probes
// to see NULL on the same TCP_CLOSE event that conn_role is cleaning up.
func inetSockSetStateProbes(objects *StatsObjects, features *export.Features, connRoleUsed, sockOwners, tcpRows bool) []probe {
	return []probe{
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateTcpRow,
			enabled: tcpRows,
		},
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateTcpSuccessfulConnection,
			enabled: features.StatsTCPSuccessfulConnections(),
		},
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateTcpFailedConnection,
			enabled: features.StatsTCPFailedConnections(),
		},
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateTcpClosedConnection,
			enabled: features.StatsTCPClosedConnections(),
		},
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateConnRole,
			enabled: connRoleUsed,
		},
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateSockOwner,
			enabled: sockOwners,
		},
	}
}
