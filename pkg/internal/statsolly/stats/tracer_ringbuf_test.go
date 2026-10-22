// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const traceLoopTestTimeout = time.Second

const (
	wireSizeTCPRtt                  = 76
	wireSizeTCPFailedConnection     = 72
	wireSizeTCPSuccessfulConnection = 72
	wireSizeTCPRetransmit           = 72
	wireSizeTCPIo                   = 112
	wireSizeTCPFlowControl          = 72
	wireSizeTCPCongestion           = 84
	wireSizeTCPClosedConnection     = 72

	wireFlagsOffset          = 0
	wireRttRoleOffset        = 1
	wireRttValueOffset       = 4
	wireRttConnOffset        = 8
	wireFailedReasonOffset   = 1
	wireFailedRoleOffset     = 2
	wireFailedConnOffset     = 4
	wireSuccessfulRoleOffset = 1
	wireSuccessfulConnOffset = 4
	wireClosedRoleOffset     = 1
	wireClosedConnOffset     = 4
	wireRetransmitTypeOffset = 1
	wireRetransmitConnOffset = 4
	wireTCPIoDirectionOffset = 1
	wireTCPIoCountOffset     = 2
	wireTCPIoBytesOffset     = 4
	wireTCPIoConnOffset      = 44
	wireFlowControlEvtOffset = 1
	wireFlowControlRole      = 2
	wireFlowControlConn      = 4
	wireCongestionRole       = 1
	wireCongestionCEOffset   = 4
	wireCongestionReordOff   = 8
	wireCongestionOOOOffset  = 12
	wireCongestionConn       = 16
	wireConnSrcAddrOffset    = 0
	wireConnDstAddrOffset    = 16
	wireConnSrcPortOffset    = 32
	wireConnDstPortOffset    = 34
)

func TestStatsEventWireSizes(t *testing.T) {
	assert.Equal(t, uintptr(wireSizeTCPRtt), unsafe.Sizeof(ebpf.StatsTCPRtt{}))
	assert.Equal(t, uintptr(wireSizeTCPFailedConnection), unsafe.Sizeof(ebpf.StatsTCPFailedConnection{}))
	assert.Equal(t, uintptr(wireSizeTCPSuccessfulConnection), unsafe.Sizeof(ebpf.StatsTCPSuccessfulConnection{}))
	assert.Equal(t, uintptr(wireSizeTCPRetransmit), unsafe.Sizeof(ebpf.StatsTCPRetransmit{}))
	assert.Equal(t, uintptr(wireSizeTCPIo), unsafe.Sizeof(ebpf.StatsTCPIo{}))
	assert.Equal(t, uintptr(wireSizeTCPFlowControl), unsafe.Sizeof(ebpf.StatsTCPFlowControl{}))
	assert.Equal(t, uintptr(wireSizeTCPCongestion), unsafe.Sizeof(ebpf.StatsTCPCongestion{}))
	assert.Equal(t, uintptr(wireSizeTCPClosedConnection), unsafe.Sizeof(ebpf.StatsTCPClosedConnection{}))
}

func TestParseStatDecodesEveryEventType(t *testing.T) {
	ipv4Conn := ebpf.Conn{
		S_addr: testIP("192.0.2.1"),
		D_addr: testIP("198.51.100.2"),
		S_port: 43123,
		D_port: 443,
	}
	ipv6Conn := ebpf.Conn{
		S_addr: testIP("2001:db8::1"),
		D_addr: testIP("2001:db8::2"),
		S_port: 32000,
		D_port: 8080,
	}
	oneZeroPortConn := ebpf.Conn{
		S_addr: testIP("203.0.113.10"),
		D_addr: testIP("203.0.113.20"),
		D_port: 8443,
	}
	rttRaw := newWireStat(ebpf.StatTypeTCPRtt, wireSizeTCPRtt, wireRttConnOffset, ipv4Conn)
	rttRaw[wireRttRoleOffset] = uint8(ebpf.CodeRoleServer)
	rttRaw[2], rttRaw[3] = 0xa1, 0xa2
	binary.NativeEndian.PutUint32(rttRaw[wireRttValueOffset:], 12500)
	failedRaw := newWireStat(
		ebpf.StatTypeTCPFailedConnection,
		wireSizeTCPFailedConnection,
		wireFailedConnOffset,
		ipv6Conn,
	)
	failedRaw[wireFailedReasonOffset] = uint8(ebpf.CodeConnectionRefused)
	failedRaw[wireFailedRoleOffset] = uint8(ebpf.CodeRoleClient)
	failedRaw[3] = 0xb1
	successfulRaw := newWireStat(
		ebpf.StatTypeTCPSuccessfulConnection,
		wireSizeTCPSuccessfulConnection,
		wireSuccessfulConnOffset,
		ipv4Conn,
	)
	successfulRaw[wireSuccessfulRoleOffset] = uint8(ebpf.CodeRoleServer)
	successfulRaw[2], successfulRaw[3] = 0xe1, 0xe2
	closedRaw := newWireStat(
		ebpf.StatTypeTCPClosedConnection,
		wireSizeTCPClosedConnection,
		wireClosedConnOffset,
		ipv6Conn,
	)
	closedRaw[wireClosedRoleOffset] = uint8(ebpf.CodeRoleClient)
	closedRaw[2], closedRaw[3] = 0xe3, 0xe4
	retransmitRaw := newWireStat(
		ebpf.StatTypeTCPRetransmit,
		wireSizeTCPRetransmit,
		wireRetransmitConnOffset,
		oneZeroPortConn,
	)
	retransmitRaw[wireRetransmitTypeOffset] = uint8(ebpf.CodeRetransmitTimeout)
	retransmitRaw[2], retransmitRaw[3] = 0xc2, 0xc3
	tcpIoRaw := newWireStat(ebpf.StatTypeTCPIo, wireSizeTCPIo, wireTCPIoConnOffset, ipv4Conn)
	tcpIoRaw[wireTCPIoDirectionOffset] = uint8(ebpf.CodeDirectionTransmit)
	tcpIoRaw[wireTCPIoCountOffset], tcpIoRaw[3] = 3, 0xd1
	putWireBytes(tcpIoRaw, [ebpf.TCPIoBatchSize]uint32{100, 200, 300, 400})
	flowControlRaw := newWireStat(ebpf.StatTypeTCPFlowControl, wireSizeTCPFlowControl, wireFlowControlConn, ipv4Conn)
	flowControlRaw[wireFlowControlEvtOffset] = uint8(ebpf.CodeFlowControlEventZeroWindow)
	flowControlRaw[wireFlowControlRole] = uint8(ebpf.CodeRoleClient)
	flowControlRaw[3] = 0xf1
	congestionRaw := newWireStat(ebpf.StatTypeTCPCongestion, wireSizeTCPCongestion, wireCongestionConn, ipv4Conn)
	congestionRaw[wireCongestionRole] = uint8(ebpf.CodeRoleServer)
	congestionRaw[2], congestionRaw[3] = 0xe1, 0xe2
	binary.NativeEndian.PutUint32(congestionRaw[wireCongestionCEOffset:], 3)
	binary.NativeEndian.PutUint32(congestionRaw[wireCongestionReordOff:], 5)
	binary.NativeEndian.PutUint32(congestionRaw[wireCongestionOOOOffset:], 7)

	tests := []struct {
		name string
		raw  []byte
		want *ebpf.Stat
	}{
		{
			name: "TCP RTT with IPv4 addresses",
			raw:  rttRaw,
			want: &ebpf.Stat{
				Type: ebpf.StatTypeTCPRtt,
				TCPRtt: &ebpf.TCPRtt{
					SrttUs: 12500,
					Role:   uint8(ebpf.CodeRoleServer),
				},
				CommonAttrs: commonAttrs(ipv4Conn),
				ServerPort:  43123, // the server reports its own port,
			},
		},
		{
			name: "failed connection with IPv6 addresses",
			raw:  failedRaw,
			want: &ebpf.Stat{
				Type: ebpf.StatTypeTCPFailedConnection,
				TCPFailedConnection: &ebpf.TCPFailedConnection{
					Reason: uint8(ebpf.CodeConnectionRefused),
					Role:   uint8(ebpf.CodeRoleClient),
				},
				CommonAttrs: commonAttrs(ipv6Conn),
				ServerPort:  8080, // the client reports the remote port,
			},
		},
		{
			name: "successful connection with IPv4 addresses",
			raw:  successfulRaw,
			want: &ebpf.Stat{
				Type: ebpf.StatTypeTCPSuccessfulConnection,
				TCPSuccessfulConnection: &ebpf.TCPSuccessfulConnection{
					Role: uint8(ebpf.CodeRoleServer),
				},
				CommonAttrs: commonAttrs(ipv4Conn),
				ServerPort:  43123,
			},
		},
		{
			name: "closed connection with IPv6 addresses",
			raw:  closedRaw,
			want: &ebpf.Stat{
				Type: ebpf.StatTypeTCPClosedConnection,
				TCPClosedConnection: &ebpf.TCPClosedConnection{
					Role: uint8(ebpf.CodeRoleClient),
				},
				CommonAttrs: commonAttrs(ipv6Conn),
				ServerPort:  8080,
			},
		},
		{
			name: "TCP retransmit with one zero port",
			raw:  retransmitRaw,
			want: &ebpf.Stat{
				Type:              ebpf.StatTypeTCPRetransmit,
				TCPRetransmit:     true,
				TCPRetransmitType: uint8(ebpf.CodeRetransmitTimeout),
				CommonAttrs:       commonAttrs(oneZeroPortConn),
			},
		},
		{
			name: "TCP I/O",
			raw:  tcpIoRaw,
			want: &ebpf.Stat{
				Type: ebpf.StatTypeTCPIo,
				TCPIo: &ebpf.TCPIo{
					Direction: uint8(ebpf.CodeDirectionTransmit),
					Bytes:     600,
				},
				CommonAttrs: commonAttrs(ipv4Conn),
			},
		},
		{
			name: "TCP zero-window probe",
			raw:  flowControlRaw,
			want: &ebpf.Stat{
				Type: ebpf.StatTypeTCPFlowControl,
				TCPFlowControl: &ebpf.TCPFlowControl{
					Event: uint8(ebpf.CodeFlowControlEventZeroWindow),
					Role:  uint8(ebpf.CodeRoleClient),
				},
				CommonAttrs: commonAttrs(ipv4Conn),
				ServerPort:  443,
			},
		},
		{
			name: "TCP congestion",
			raw:  congestionRaw,
			want: &ebpf.Stat{
				Type: ebpf.StatTypeTCPCongestion,
				TCPCongestion: &ebpf.TCPCongestion{
					DeliveredCE: 3,
					ReordSeen:   5,
					RcvOOOPack:  7,
					Role:        uint8(ebpf.CodeRoleServer),
				},
				CommonAttrs: commonAttrs(ipv4Conn),
				ServerPort:  43123,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ignore, err := parseStat(&ringbuf.Record{RawSample: tt.raw})

			require.NoError(t, err)
			assert.False(t, ignore)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseStatRejectsMalformedRecords(t *testing.T) {
	tests := []struct {
		name   string
		record *ringbuf.Record
	}{
		{name: "nil record"},
		{name: "nil sample", record: &ringbuf.Record{}},
		{name: "empty sample", record: &ringbuf.Record{RawSample: []byte{}}},
		{name: "zero tag", record: &ringbuf.Record{RawSample: []byte{0}}},
		{name: "unknown tag", record: &ringbuf.Record{RawSample: []byte{255}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ignore, err := parseStat(tt.record)

			require.Error(t, err)
			assert.False(t, ignore)
			assert.Nil(t, got)
		})
	}
}

func TestParseStatRejectsEveryTruncatedEventLength(t *testing.T) {
	for _, tt := range minimalWireStats() {
		for length := 1; length < len(tt.raw); length++ {
			t.Run(fmt.Sprintf("%s/length_%d", tt.name, length), func(t *testing.T) {
				got, ignore, err := parseStat(&ringbuf.Record{RawSample: tt.raw[:length]})

				require.Error(t, err)
				assert.False(t, ignore)
				assert.Nil(t, got)
			})
		}
	}
}

func TestConnToCommonAttrsDropsUnspecifiedConnection(t *testing.T) {
	conn := ebpf.Conn{
		S_addr: testIP("192.0.2.10"),
		D_addr: testIP("2001:db8::10"),
	}

	assert.Equal(t, pipe.CommonAttrs{}, connToCommonAttrs(conn))
}

func TestParseTCPIoBoundsBatchCount(t *testing.T) {
	bytesByCall := [ebpf.TCPIoBatchSize]uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	tests := []struct {
		count uint8
		want  uint64
	}{
		{count: 0, want: 0},
		{count: 1, want: 1},
		{count: ebpf.TCPIoBatchSize - 1, want: 45},
		{count: ebpf.TCPIoBatchSize, want: 55},
		{count: ebpf.TCPIoBatchSize + 1, want: 55},
		{count: 255, want: 55},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("count_%d", tt.count), func(t *testing.T) {
			raw := newWireStat(ebpf.StatTypeTCPIo, wireSizeTCPIo, wireTCPIoConnOffset, ebpf.Conn{})
			raw[wireTCPIoCountOffset] = tt.count
			putWireBytes(raw, bytesByCall)
			got, ignore, err := parseStat(&ringbuf.Record{RawSample: raw})

			require.NoError(t, err)
			assert.False(t, ignore)
			require.NotNil(t, got)
			require.NotNil(t, got.TCPIo)
			assert.Equal(t, tt.want, got.TCPIo.Bytes)
		})
	}
}

func TestNewRingBufTracerInitializesForwarder(t *testing.T) {
	tracer := NewRingBufTracer(nil, nil, nil)

	assert.NotNil(t, tracer.forward)
}

func TestTraceLoopForwardsOutputAndClosesOnCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), traceLoopTestTimeout)
	defer cancel()

	want := []*ebpf.Stat{{Type: ebpf.StatTypeTCPRetransmit, TCPRetransmit: true}}
	tracer := &RingBufTracer{
		forward: func(ctx context.Context, out *msg.Queue[[]*ebpf.Stat]) {
			out.SendCtx(ctx, want)
			<-ctx.Done()
		},
	}
	out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(1))
	output := out.Subscribe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tracer.TraceLoop(out)(ctx)
	}()

	select {
	case got := <-output:
		assert.Equal(t, want, got)
	case <-ctx.Done():
		t.Fatal("timed out waiting for trace output")
	}

	cancel()
	shutdownCtx, stopWaiting := context.WithTimeout(t.Context(), traceLoopTestTimeout)
	defer stopWaiting()
	select {
	case <-done:
	case <-shutdownCtx.Done():
		t.Fatal("timed out waiting for trace loop cancellation")
	}

	_, ok := <-output
	assert.False(t, ok, "output channel remains open after the trace loop exits")
}

func FuzzParseStat(f *testing.F) {
	seeds := [][]byte{nil, {}, {0}, {255}}
	for _, stat := range minimalWireStats() {
		seeds = append(seeds, stat.raw[:1], stat.raw[:len(stat.raw)-1], stat.raw)
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("parseStat panicked for %d bytes: %v", len(raw), recovered)
			}
		}()

		got, _, err := parseStat(&ringbuf.Record{RawSample: raw})
		if err != nil {
			assert.Nil(t, got)
		}
	})
}

func testIP(value string) [net.IPv6len]uint8 {
	var result [net.IPv6len]uint8
	copy(result[:], net.ParseIP(value).To16())
	return result
}

func commonAttrs(conn ebpf.Conn) pipe.CommonAttrs {
	return pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(conn.S_addr),
		DstAddr: pipe.IPAddr(conn.D_addr),
		SrcPort: conn.S_port,
		DstPort: conn.D_port,
	}
}

func minimalWireStats() []struct {
	name string
	raw  []byte
} {
	return []struct {
		name string
		raw  []byte
	}{
		{"TCP RTT", newWireStat(ebpf.StatTypeTCPRtt, wireSizeTCPRtt, wireRttConnOffset, ebpf.Conn{})},
		{"failed connection", newWireStat(ebpf.StatTypeTCPFailedConnection, wireSizeTCPFailedConnection, wireFailedConnOffset, ebpf.Conn{})},
		{"successful connection", newWireStat(ebpf.StatTypeTCPSuccessfulConnection, wireSizeTCPSuccessfulConnection, wireSuccessfulConnOffset, ebpf.Conn{})},
		{"TCP retransmit", newWireStat(ebpf.StatTypeTCPRetransmit, wireSizeTCPRetransmit, wireRetransmitConnOffset, ebpf.Conn{})},
		{"TCP I/O", newWireStat(ebpf.StatTypeTCPIo, wireSizeTCPIo, wireTCPIoConnOffset, ebpf.Conn{})},
		{"TCP flow control", newWireStat(ebpf.StatTypeTCPFlowControl, wireSizeTCPFlowControl, wireFlowControlConn, ebpf.Conn{})},
		{"TCP congestion", newWireStat(ebpf.StatTypeTCPCongestion, wireSizeTCPCongestion, wireCongestionConn, ebpf.Conn{})},
		{"closed connection", newWireStat(ebpf.StatTypeTCPClosedConnection, wireSizeTCPClosedConnection, wireClosedConnOffset, ebpf.Conn{})},
	}
}

func newWireStat(statType ebpf.StatType, size, connOffset int, conn ebpf.Conn) []byte {
	raw := make([]byte, size)
	raw[wireFlagsOffset] = uint8(statType)
	copy(raw[connOffset+wireConnSrcAddrOffset:], conn.S_addr[:])
	copy(raw[connOffset+wireConnDstAddrOffset:], conn.D_addr[:])
	binary.NativeEndian.PutUint16(raw[connOffset+wireConnSrcPortOffset:], conn.S_port)
	binary.NativeEndian.PutUint16(raw[connOffset+wireConnDstPortOffset:], conn.D_port)
	return raw
}

func putWireBytes(raw []byte, values [ebpf.TCPIoBatchSize]uint32) {
	for i, value := range values {
		binary.NativeEndian.PutUint32(raw[wireTCPIoBytesOffset+i*4:], value)
	}
}

func TestParseStatDecodesTheSocketOwner(t *testing.T) {
	conn := ebpf.Conn{S_addr: testIP("10.0.0.1"), D_addr: testIP("10.0.0.2"), S_port: 40000, D_port: 80}
	raw := newWireStat(ebpf.StatTypeTCPRtt, wireSizeTCPRtt, wireRttConnOffset, conn)
	owner := raw[wireSizeTCPRtt-int(unsafe.Sizeof(ebpf.StatsSockOwnerT{})):]
	binary.NativeEndian.PutUint32(owner[0:], 4242)
	binary.NativeEndian.PutUint32(owner[4:], 4026531840)
	binary.NativeEndian.PutUint32(owner[8:], 0x5)
	binary.NativeEndian.PutUint32(owner[12:], 0x1)
	copy(owner[16:], "curl")

	stat, _, err := parseStat(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)
	assert.Equal(t, ebpf.SockOwner{Pid: 4242, NetNS: 4026531840, ExecName: "curl", CgroupID: 1<<32 | 5}, stat.Owner)
}
