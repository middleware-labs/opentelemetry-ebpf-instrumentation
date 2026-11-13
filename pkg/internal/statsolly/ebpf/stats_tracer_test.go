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

	const origSendmsgName = "real_sendmsg"
	const origRetprobeSendmsgName = "real_retprobe_sendmsg"
	const origCleanupRbufName = "real_cleanup_rbuf"
	const origCloseIoFlushName = "real_close_io_flush"
	const origDestroySockName = "real_destroy_sock"
	const origRetransmitName = "real_retransmit"
	const origSendResetName = "real_send_reset"
	const origReceiveResetName = "real_receive_reset"

	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiStatsKprobeTCPCloseSrtt:                        {Name: origKpName, Type: ebpf.Kprobe},
				progObiStatsTpInetSockSetStateTCPFailedConnection:     {Name: origTpName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateConnRole:                {Name: origConnRoleName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: {Name: origSuccessTpName, Type: ebpf.TracePoint},
				progObiStatsKprobeTCPSendmsg:                          {Name: origSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKretprobeTCPSendmsg:                       {Name: origRetprobeSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCleanupRbuf:                      {Name: origCleanupRbufName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCloseIoFlush:                     {Name: origCloseIoFlushName, Type: ebpf.Kprobe},
				progObiStatsTpTCPDestroySock:                          {Name: origDestroySockName, Type: ebpf.TracePoint},
				progObiStatsRawTpTCPRetransmitSkb:                     {Name: origRetransmitName, Type: ebpf.RawTracepoint},
				progObiStatsRawTpTCPSendReset:                         {Name: origSendResetName, Type: ebpf.RawTracepoint},
				progObiStatsRawTpTCPReceiveReset:                      {Name: origReceiveResetName, Type: ebpf.RawTracepoint},
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
				progObiStatsKprobeTCPSendmsg:                          origSendmsgName,
				progObiStatsKretprobeTCPSendmsg:                       origRetprobeSendmsgName,
				progObiStatsKprobeTCPCleanupRbuf:                      origCleanupRbufName,
				progObiStatsKprobeTCPCloseIoFlush:                     origCloseIoFlushName,
				progObiStatsTpTCPDestroySock:                          origDestroySockName,
				progObiStatsRawTpTCPRetransmitSkb:                     origRetransmitName,
				progObiStatsRawTpTCPSendReset:                         origSendResetName,
				progObiStatsRawTpTCPReceiveReset:                      origReceiveResetName,
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
			name:      "disable resets only",
			toDisable: []string{progObiStatsRawTpTCPSendReset, progObiStatsRawTpTCPReceiveReset},
			want: map[string]string{
				progObiStatsRawTpTCPSendReset:     "stats_dummy",
				progObiStatsRawTpTCPReceiveReset:  "stats_dummy",
				progObiStatsRawTpTCPRetransmitSkb: origRetransmitName,
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
				progObiStatsTpInetSockSetStateConnRole,
				progObiStatsKprobeTCPSendmsg,
				progObiStatsKretprobeTCPSendmsg,
				progObiStatsKprobeTCPCleanupRbuf,
				progObiStatsKprobeTCPCloseIoFlush,
				progObiStatsTpTCPDestroySock,
				progObiStatsRawTpTCPRetransmitSkb,
				progObiStatsRawTpTCPSendReset,
				progObiStatsRawTpTCPReceiveReset,
			},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                        "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection:     "stats_dummy",
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:                "stats_dummy",
				progObiStatsKprobeTCPSendmsg:                          "stats_dummy",
				progObiStatsKretprobeTCPSendmsg:                       "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:                      "stats_dummy",
				progObiStatsKprobeTCPCloseIoFlush:                     "stats_dummy",
				progObiStatsTpTCPDestroySock:                          "stats_dummy",
				progObiStatsRawTpTCPRetransmitSkb:                     "stats_dummy",
				progObiStatsRawTpTCPSendReset:                         "stats_dummy",
				progObiStatsRawTpTCPReceiveReset:                      "stats_dummy",
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
		TracepointTCPDestroySock,
	}
	for _, hook := range hooks {
		if _, _, ok := strings.Cut(hook, "/"); !ok {
			t.Errorf("tracepoint constant %q is not in group/name format", hook)
		}
	}
}

// TestInetSockSetStateProbesOrder checks the attach order of the programs that share sock_role and
// sock_owner: the TCP row program reads sock_owner before the sock_owner program deletes it on the
// same TCP_CLOSE event, and the sock_role delete is attached before the program that writes it.
func TestInetSockSetStateProbesOrder(t *testing.T) {
	objects := &StatsObjects{StatsPrograms: StatsPrograms{
		ObiStatsTpInetSockSetStateTcpRow:                  &ebpf.Program{},
		ObiStatsTpInetSockSetStateTcpSuccessfulConnection: &ebpf.Program{},
		ObiStatsTpInetSockSetStateTcpFailedConnection:     &ebpf.Program{},
		ObiStatsTpTcpDestroySock:                          &ebpf.Program{},
		ObiStatsTpInetSockSetStateConnRole:                &ebpf.Program{},
		ObiStatsTpInetSockSetStateSockOwner:               &ebpf.Program{},
	}}
	features := export.FeatureStats

	position := map[*ebpf.Program]int{}
	for i, p := range inetSockSetStateProbes(objects, &features, true, true, true) {
		assert.True(t, p.enabled)
		position[p.program] = i
	}

	assert.Less(t, position[objects.ObiStatsTpTcpDestroySock], position[objects.ObiStatsTpInetSockSetStateConnRole])
	assert.Less(t, position[objects.ObiStatsTpInetSockSetStateTcpRow], position[objects.ObiStatsTpInetSockSetStateSockOwner])
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
	for _, p := range append(udpBindProbes(&StatsObjects{}, true), socketTrafficProbes(&StatsObjects{}, true, true, true)...) {
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
