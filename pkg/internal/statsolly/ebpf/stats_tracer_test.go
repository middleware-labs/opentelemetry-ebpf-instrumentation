// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/export"
)

func TestFixupSpec(t *testing.T) {
	const origKpName = "real_kp"
	const origTpName = "real_tp"
	const origConnRoleName = "real_conn_role"
	const origSuccessTpName = "real_success_tp"
	const origClosedTpName = "real_closed_tp"
	const origSendProbe0Name = "real_send_probe0"
	const origSendmsgCongestionName = "real_sendmsg_congestion"
	const origCleanupRbufCongestionName = "real_cleanup_rbuf_congestion"
	const origCloseCongestionName = "real_close_congestion"
	const origSocketDNSName = "real_socket_dns"

	const origSendmsgName = "real_sendmsg"
	const origRetprobeSendmsgName = "real_retprobe_sendmsg"
	const origCleanupRbufName = "real_cleanup_rbuf"
	const origCloseIoFlushName = "real_close_io_flush"
	const origRetransmitName = "real_retransmit"

	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiStatsKprobeTCPCloseSrtt:                        {Name: origKpName, Type: ebpf.Kprobe},
				progObiStatsTpInetSockSetStateTCPFailedConnection:     {Name: origTpName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateConnRole:                {Name: origConnRoleName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: {Name: origSuccessTpName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateTCPClosedConnection:     {Name: origClosedTpName, Type: ebpf.TracePoint},
				progObiStatsKprobeTCPSendmsg:                          {Name: origSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKretprobeTCPSendmsg:                       {Name: origRetprobeSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCleanupRbuf:                      {Name: origCleanupRbufName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCloseIoFlush:                     {Name: origCloseIoFlushName, Type: ebpf.Kprobe},
				progObiStatsRawTpTCPRetransmitSkb:                     {Name: origRetransmitName, Type: ebpf.RawTracepoint},
				progObiStatsKprobeTCPSendProbe0:                       {Name: origSendProbe0Name, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPSendmsgCongestion:                {Name: origSendmsgCongestionName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCleanupRbufCongestion:            {Name: origCleanupRbufCongestionName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCloseCongestion:                  {Name: origCloseCongestionName, Type: ebpf.Kprobe},
				progObiStatsSocketDNS:                                 {Name: origSocketDNSName, Type: ebpf.SocketFilter},
			},
		}
	}

	tests := []struct {
		name      string
		toDisable []string
		want      map[string]string
	}{
		{
			name:      "disable nothing",
			toDisable: nil,
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                        origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection:     origTpName,
				progObiStatsTpInetSockSetStateConnRole:                origConnRoleName,
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: origSuccessTpName,
				progObiStatsTpInetSockSetStateTCPClosedConnection:     origClosedTpName,
				progObiStatsKprobeTCPSendmsg:                          origSendmsgName,
				progObiStatsKretprobeTCPSendmsg:                       origRetprobeSendmsgName,
				progObiStatsKprobeTCPCleanupRbuf:                      origCleanupRbufName,
				progObiStatsKprobeTCPCloseIoFlush:                     origCloseIoFlushName,
				progObiStatsRawTpTCPRetransmitSkb:                     origRetransmitName,
				progObiStatsKprobeTCPSendProbe0:                       origSendProbe0Name,
				progObiStatsKprobeTCPSendmsgCongestion:                origSendmsgCongestionName,
				progObiStatsKprobeTCPCleanupRbufCongestion:            origCleanupRbufCongestionName,
				progObiStatsKprobeTCPCloseCongestion:                  origCloseCongestionName,
			},
		},
		{
			// Regression: stats_tcp_io standalone (no stats_tcp_rtt) must still attach
			// the io_flush probe on tcp_close to avoid losing the final incomplete batch.
			name:      "disable srtt only",
			toDisable: []string{progObiStatsKprobeTCPCloseSrtt},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
				progObiStatsKprobeTCPCloseIoFlush:                 origCloseIoFlushName,
				progObiStatsKprobeTCPSendmsg:                      origSendmsgName,
				progObiStatsKretprobeTCPSendmsg:                   origRetprobeSendmsgName,
				progObiStatsKprobeTCPCleanupRbuf:                  origCleanupRbufName,
				progObiStatsRawTpTCPRetransmitSkb:                 origRetransmitName,
			},
		},
		{
			name:      "disable retransmits only",
			toDisable: []string{progObiStatsRawTpTCPRetransmitSkb},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
				progObiStatsRawTpTCPRetransmitSkb:                 "stats_dummy",
			},
		},
		{
			name:      "disable failed conn only",
			toDisable: []string{progObiStatsTpInetSockSetStateTCPFailedConnection},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
			},
		},
		{
			name:      "disable successful conn only",
			toDisable: []string{progObiStatsTpInetSockSetStateTCPSuccessfulConnection},
			want: map[string]string{
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection:     origTpName,
				progObiStatsTpInetSockSetStateConnRole:                origConnRoleName,
			},
		},
		{
			name:      "disable closed conn only",
			toDisable: []string{progObiStatsTpInetSockSetStateTCPClosedConnection},
			want: map[string]string{
				progObiStatsTpInetSockSetStateTCPClosedConnection:     "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection:     origTpName,
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: origSuccessTpName,
				progObiStatsTpInetSockSetStateConnRole:                origConnRoleName,
			},
		},
		{
			name:      "disable dns lookups only",
			toDisable: []string{progObiStatsSocketDNS},
			want: map[string]string{
				progObiStatsSocketDNS:                             "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
			},
		},
		{
			name:      "disable flow control only",
			toDisable: []string{progObiStatsKprobeTCPSendProbe0},
			want: map[string]string{
				progObiStatsKprobeTCPSendProbe0:   "stats_dummy",
				progObiStatsKprobeTCPCloseSrtt:    origKpName,
				progObiStatsRawTpTCPRetransmitSkb: origRetransmitName,
			},
		},
		{
			// the congestion programs share hooks with the io and srtt programs, which must stay loaded
			name: "disable congestion only",
			toDisable: []string{
				progObiStatsKprobeTCPSendmsgCongestion,
				progObiStatsKprobeTCPCleanupRbufCongestion,
				progObiStatsKprobeTCPCloseCongestion,
			},
			want: map[string]string{
				progObiStatsKprobeTCPSendmsgCongestion:     "stats_dummy",
				progObiStatsKprobeTCPCleanupRbufCongestion: "stats_dummy",
				progObiStatsKprobeTCPCloseCongestion:       "stats_dummy",
				progObiStatsKprobeTCPSendmsg:               origSendmsgName,
				progObiStatsKprobeTCPCleanupRbuf:           origCleanupRbufName,
				progObiStatsKprobeTCPCloseSrtt:             origKpName,
				progObiStatsKprobeTCPCloseIoFlush:          origCloseIoFlushName,
			},
		},
		{
			name:      "disable conn role only",
			toDisable: []string{progObiStatsTpInetSockSetStateConnRole},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            "stats_dummy",
			},
		},
		{
			name:      "disable io programs",
			toDisable: []string{progObiStatsKprobeTCPSendmsg, progObiStatsKretprobeTCPSendmsg, progObiStatsKprobeTCPCleanupRbuf, progObiStatsKprobeTCPCloseIoFlush},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:    origKpName,
				progObiStatsKprobeTCPSendmsg:      "stats_dummy",
				progObiStatsKretprobeTCPSendmsg:   "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:  "stats_dummy",
				progObiStatsKprobeTCPCloseIoFlush: "stats_dummy",
			},
		},
		{
			name: "disable all",
			toDisable: []string{
				progObiStatsKprobeTCPCloseSrtt,
				progObiStatsTpInetSockSetStateTCPFailedConnection,
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection,
				progObiStatsTpInetSockSetStateTCPClosedConnection,
				progObiStatsTpInetSockSetStateConnRole,
				progObiStatsKprobeTCPSendmsg,
				progObiStatsKretprobeTCPSendmsg,
				progObiStatsKprobeTCPCleanupRbuf,
				progObiStatsKprobeTCPCloseIoFlush,
				progObiStatsRawTpTCPRetransmitSkb,
				progObiStatsKprobeTCPSendProbe0,
				progObiStatsKprobeTCPSendmsgCongestion,
				progObiStatsKprobeTCPCleanupRbufCongestion,
				progObiStatsKprobeTCPCloseCongestion,
			},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                        "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection:     "stats_dummy",
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateTCPClosedConnection:     "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:                "stats_dummy",
				progObiStatsKprobeTCPSendmsg:                          "stats_dummy",
				progObiStatsKretprobeTCPSendmsg:                       "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:                      "stats_dummy",
				progObiStatsKprobeTCPCloseIoFlush:                     "stats_dummy",
				progObiStatsRawTpTCPRetransmitSkb:                     "stats_dummy",
				progObiStatsKprobeTCPSendProbe0:                       "stats_dummy",
				progObiStatsKprobeTCPSendmsgCongestion:                "stats_dummy",
				progObiStatsKprobeTCPCleanupRbufCongestion:            "stats_dummy",
				progObiStatsKprobeTCPCloseCongestion:                  "stats_dummy",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := makeSpec()
			if err := fixupSpec(spec, tc.toDisable); err != nil {
				t.Fatalf("fixupSpec: %v", err)
			}
			for prog, wantName := range tc.want {
				if got := spec.Programs[prog].Name; got != wantName {
					t.Errorf("program %s: got %q, want %q", prog, got, wantName)
				}
			}
		})
	}
}

func TestFixupSpecUnknownProgram(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			progObiStatsKprobeTCPCloseSrtt: {Name: "real_kp", Type: ebpf.Kprobe},
		},
	}
	if err := fixupSpec(spec, []string{"nonexistent_prog"}); err == nil {
		t.Error("expected error for unknown program name, got nil")
	}
}

// TestTracepointConstantFormat validates that all tracepoint constants are in group/name format.
// When adding a new tracepoint constant, add it to the hooks slice below.
func TestTracepointConstantFormat(t *testing.T) {
	hooks := []string{
		TracepointInetSockSetState,
	}
	for _, hook := range hooks {
		if _, _, ok := strings.Cut(hook, "/"); !ok {
			t.Errorf("tracepoint constant %q is not in group/name format", hook)
		}
	}
}

// TestInetSockSetStateProbesOrder checks that every probe reading sock_role and sock_owner is
// attached before conn_role and sock_owner, which delete the entries on the same TCP_CLOSE event.
func TestInetSockSetStateProbesOrder(t *testing.T) {
	objects := &StatsObjects{StatsPrograms: StatsPrograms{
		ObiStatsTpInetSockSetStateTcpSuccessfulConnection: &ebpf.Program{},
		ObiStatsTpInetSockSetStateTcpFailedConnection:     &ebpf.Program{},
		ObiStatsTpInetSockSetStateTcpClosedConnection:     &ebpf.Program{},
		ObiStatsTpInetSockSetStateConnRole:                &ebpf.Program{},
		ObiStatsTpInetSockSetStateSockOwner:               &ebpf.Program{},
	}}
	features := export.FeatureStats

	position := map[*ebpf.Program]int{}
	for i, p := range inetSockSetStateProbes(objects, &features, true, true, true) {
		assert.Equal(t, TracepointInetSockSetState, p.name)
		assert.True(t, p.enabled)
		position[p.program] = i
	}

	connRole := position[objects.ObiStatsTpInetSockSetStateConnRole]
	assert.Less(t, position[objects.ObiStatsTpInetSockSetStateTcpFailedConnection], connRole)
	assert.Less(t, position[objects.ObiStatsTpInetSockSetStateTcpClosedConnection], connRole)

	// sock_owner is deleted on the same TCP_CLOSE event too
	sockOwner := position[objects.ObiStatsTpInetSockSetStateSockOwner]
	assert.Less(t, position[objects.ObiStatsTpInetSockSetStateTcpFailedConnection], sockOwner)
	assert.Less(t, position[objects.ObiStatsTpInetSockSetStateTcpClosedConnection], sockOwner)
}

func TestInetSockSetStateProbesClosedFeature(t *testing.T) {
	objects := &StatsObjects{StatsPrograms: StatsPrograms{
		ObiStatsTpInetSockSetStateTcpClosedConnection: &ebpf.Program{},
	}}
	closedEnabled := func(features export.Features) bool {
		for _, p := range inetSockSetStateProbes(objects, &features, false, false, false) {
			if p.program == objects.ObiStatsTpInetSockSetStateTcpClosedConnection {
				return p.enabled
			}
		}
		return false
	}

	assert.True(t, closedEnabled(export.FeatureStats))
	assert.True(t, closedEnabled(export.FeatureStatsTCPClosedConnections))
	assert.False(t, closedEnabled(export.FeatureStatsTCPFailedConnections))
}

func TestStatsSpecDNSSocketFilter(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)

	require.Contains(t, spec.Programs, progObiStatsSocketDNS)
	assert.Equal(t, ebpf.SocketFilter, spec.Programs[progObiStatsSocketDNS].Type)
	require.Contains(t, spec.Maps, StatsMapStatsDnsEvents)
	assert.Equal(t, ebpf.RingBuf, spec.Maps[StatsMapStatsDnsEvents].Type)

	// when the feature is disabled, the stub keeps the program type
	require.NoError(t, fixupSpec(spec, []string{progObiStatsSocketDNS}))
	assert.Equal(t, ebpf.SocketFilter, spec.Programs[progObiStatsSocketDNS].Type)
	assert.Equal(t, "stats_dummy", spec.Programs[progObiStatsSocketDNS].Name)
}

func TestHtons(t *testing.T) {
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, htons(unix.ETH_P_ALL))
	assert.Equal(t, []byte{0x00, 0x03}, b, "network byte order")
}

func TestSizeSocketTrafficMaps(t *testing.T) {
	type sizes struct{ traffic, closed, sendmsg, bindings, bind, udpDport uint32 }
	sizeFor := func(tcp, udp, udpRole bool) sizes {
		spec, err := LoadStats()
		require.NoError(t, err)
		sizeSocketTrafficMaps(spec, 1000, tcp, udp, udpRole)
		return sizes{
			traffic:  spec.Maps[StatsMapSocketTraffic].MaxEntries,
			closed:   spec.Maps[StatsMapSocketTrafficClosed].MaxEntries,
			sendmsg:  spec.Maps[StatsMapSocketTrafficSendmsgSock].MaxEntries,
			bindings: spec.Maps[StatsMapUdpPortBindings].MaxEntries,
			bind:     spec.Maps[StatsMapSocketTrafficBindSock].MaxEntries,
			udpDport: spec.Maps[StatsMapSocketTrafficUdpDport].MaxEntries,
		}
	}
	page := uint32(os.Getpagesize())

	// hash maps are preallocated: the unused ones keep a single entry
	assert.Equal(t, sizes{traffic: 1, closed: page, sendmsg: 1, bindings: 1, bind: 1, udpDport: 1}, sizeFor(false, false, false))

	tcp := sizeFor(true, false, false)
	assert.Equal(t, uint32(1000), tcp.traffic)
	assert.Greater(t, tcp.closed, page)
	assert.Greater(t, tcp.sendmsg, uint32(1))
	assert.Equal(t, uint32(1), tcp.bindings)
	assert.Equal(t, uint32(1), tcp.udpDport)

	udp := sizeFor(false, true, true)
	assert.Equal(t, uint32(1000), udp.traffic)
	assert.Equal(t, uint32(1), udp.sendmsg)
	assert.Greater(t, udp.udpDport, uint32(1))
	assert.Greater(t, udp.bindings, uint32(1))
	assert.Greater(t, udp.bind, uint32(1))
}

func TestStatsSpecSocketTrafficPrograms(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)

	for _, name := range []string{
		progObiStatsKprobeTCPSendmsgTraffic,
		progObiStatsKretprobeTCPSendmsgTraffic,
		progObiStatsKprobeTCPCleanupRbufTraffic,
		progObiStatsKprobeTCPCloseTraffic,
		progObiStatsKretprobeIPMakeSkbTraffic,
		progObiStatsKretprobeIP6MakeSkbTraffic,
		progObiStatsKprobeSkbConsumeUDPTraffic,
		progObiStatsKprobeUDPSendmsgTraffic,
		progObiStatsKprobeUDPv6SendmsgTraffic,
		progObiStatsKprobeTCPSendpageTraffic,
		progObiStatsKretprobeTCPSendpageTraffic,
		progObiStatsKprobeUDPDestroySockTraffic,
		progObiStatsKprobeUDPv6DestroySockTraffic,
		progObiStatsKprobeInetBindTraffic,
		progObiStatsKretprobeInetBindTraffic,
		progObiStatsKprobeInet6BindTraffic,
		progObiStatsKretprobeInet6BindTraffic,
	} {
		require.Contains(t, spec.Programs, name)
		assert.Equal(t, ebpf.Kprobe, spec.Programs[name].Type, name)
	}
	// a plain hash: a full map fails the insert instead of evicting unread rows
	assert.Equal(t, ebpf.Hash, spec.Maps[StatsMapSocketTraffic].Type)
	assert.Equal(t, ebpf.RingBuf, spec.Maps[StatsMapSocketTrafficClosed].Type)
	assert.Equal(t, ebpf.PerCPUArray, spec.Maps[StatsMapSocketTrafficDrops].Type)
	assert.Equal(t, uint32(StatsSocketTrafficDropK_socketTrafficDropCount), spec.Maps[StatsMapSocketTrafficDrops].MaxEntries)
	assert.Equal(t, ebpf.Hash, spec.Maps[StatsMapUdpPortBindings].Type)
}

func TestSocketTrafficOptionalProbes(t *testing.T) {
	optional := map[string]bool{}
	for _, p := range append(udpBindProbes(&StatsObjects{}, true), socketTrafficProbes(&StatsObjects{}, true, true)...) {
		assert.True(t, p.enabled)
		if p.optional {
			optional[p.name] = true
		}
	}
	// missing on kernels >= 6.5, or without IPv6
	assert.Equal(t, map[string]bool{
		KprobeTCPSendpage:      true,
		KprobeIP6MakeSkb:       true,
		KprobeUDPv6DestroySock: true,
		KprobeUDPv6Sendmsg:     true,
		KprobeInet6Bind:        true,
	}, optional)

	for _, p := range udpBindProbes(&StatsObjects{}, false) {
		assert.False(t, p.enabled, "the bind probes only run for the UDP role")
	}
}
