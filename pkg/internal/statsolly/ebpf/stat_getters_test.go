// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

func TestNetworkTCPRetransmitTypeGetter(t *testing.T) {
	getter, ok := StatGetters(attr.NetworkTCPRetransmitType)
	require.True(t, ok)

	tests := []struct {
		code uint8
		want NetworkTCPRetransmitType
	}{
		{code: uint8(CodeRetransmitOther), want: RetransmitOther},
		{code: uint8(CodeRetransmitFast), want: RetransmitFast},
		{code: uint8(CodeRetransmitTimeout), want: RetransmitTimeout},
		{code: 99, want: RetransmitOther},
	}
	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			kv := getter(&Stat{Type: StatTypeTCPRetransmit, TCPRetransmit: true, TCPRetransmitType: tt.code})
			assert.Equal(t, string(attr.NetworkTCPRetransmitType), string(kv.Key))
			assert.Equal(t, string(tt.want), kv.Value.AsString())
		})
	}
}

func TestNetworkTCPFlowControlEventGetter(t *testing.T) {
	getter, ok := StatGetters(attr.NetworkTCPFlowControlEvent)
	require.True(t, ok)

	tests := []struct {
		name string
		stat *Stat
		want NetworkTCPFlowControlEventType
	}{
		{
			name: "zero window",
			stat: &Stat{Type: StatTypeTCPFlowControl, TCPFlowControl: &TCPFlowControl{Event: uint8(CodeFlowControlEventZeroWindow)}},
			want: FlowControlEventZeroWindow,
		},
		{
			name: "unknown code",
			stat: &Stat{Type: StatTypeTCPFlowControl, TCPFlowControl: &TCPFlowControl{Event: 99}},
			want: FlowControlEventUnknown,
		},
		{
			name: "not a flow control stat",
			stat: &Stat{Type: StatTypeTCPRetransmit, TCPRetransmit: true},
			want: FlowControlEventUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv := getter(tt.stat)
			assert.Equal(t, string(attr.NetworkTCPFlowControlEvent), string(kv.Key))
			assert.Equal(t, string(tt.want), kv.Value.AsString())
		})
	}
}

func TestNetworkTCPHandshakeRoleGetterClosedConnection(t *testing.T) {
	getter, ok := StatGetters(attr.NetworkTCPHandshakeRole)
	require.True(t, ok)

	tests := []struct {
		code uint8
		want NetworkTCPHandshakeRoleType
	}{
		{code: uint8(CodeRoleClient), want: RoleClient},
		{code: uint8(CodeRoleServer), want: RoleServer},
		{code: uint8(CodeRoleUnknown), want: RoleUnknown},
	}
	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			kv := getter(&Stat{Type: StatTypeTCPClosedConnection, TCPClosedConnection: &TCPClosedConnection{Role: tt.code}})
			assert.Equal(t, string(attr.NetworkTCPHandshakeRole), string(kv.Key))
			assert.Equal(t, string(tt.want), kv.Value.AsString())
		})
	}
}

func TestServerPort(t *testing.T) {
	assert.Equal(t, uint16(5432), ServerPortOf(uint8(CodeRoleClient), 41001, 5432), "the client's remote port")
	assert.Equal(t, uint16(5432), ServerPortOf(uint8(CodeRoleServer), 5432, 41001), "the server's own port")
	assert.Zero(t, ServerPortOf(uint8(CodeRoleUnknown), 5432, 41001))

	getter, ok := StatGetters(attr.ServerPort)
	require.True(t, ok)
	kv := getter(&Stat{ServerPort: 5432, CommonAttrs: pipe.CommonAttrs{SrcPort: 41001, DstPort: 5432}})
	assert.Equal(t, string(attr.ServerPort), string(kv.Key))
	assert.Equal(t, int64(5432), kv.Value.AsInt64())
}

func TestDNSLookupGetters(t *testing.T) {
	errorType, ok := StatGetters(attr.ErrorType)
	require.True(t, ok)
	questionName, ok := StatGetters(attr.DNSQuestionName)
	require.True(t, ok)
	questionType, ok := StatGetters(attr.DNSQuestionType)
	require.True(t, ok)

	tests := []struct {
		name          string
		stat          *Stat
		wantErrorType string
		wantName      string
		wantType      string
	}{
		{
			name:          "answered",
			stat:          &Stat{Type: StatTypeDNSLookup, DNSLookup: &DNSLookup{QName: "example.com", QType: 28}},
			wantErrorType: "",
			wantName:      "example.com",
			wantType:      "AAAA",
		},
		{
			name:          "error answer",
			stat:          &Stat{Type: StatTypeDNSLookup, DNSLookup: &DNSLookup{RCode: 3, QName: "nope.invalid", QType: 1}},
			wantErrorType: "NXDomain",
			wantName:      "nope.invalid",
			wantType:      "A",
		},
		{
			name:          "timeout",
			stat:          &Stat{Type: StatTypeDNSLookup, DNSLookup: &DNSLookup{Timeout: true, QName: "example.com", QType: 33}},
			wantErrorType: DNSTimeoutErrorType,
			wantName:      "example.com",
			wantType:      "SRV",
		},
		{
			name: "not a DNS lookup",
			stat: &Stat{Type: StatTypeTCPRetransmit, TCPRetransmit: true},
		},
	}
	errorTypeLabel, ok := StatStringGetters(attr.ErrorType)
	require.True(t, ok)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErrorType == "" {
				assert.False(t, errorType(tt.stat).Valid(), "error.type is omitted, not sent empty")
			} else {
				assert.Equal(t, attribute.String(string(attr.ErrorType), tt.wantErrorType), errorType(tt.stat))
			}
			assert.Equal(t, tt.wantErrorType, errorTypeLabel(tt.stat), "an omitted attribute is an empty Prometheus label")

			assert.Equal(t, tt.wantName, questionName(tt.stat).Value.AsString())
			assert.Equal(t, tt.wantType, questionType(tt.stat).Value.AsString())
			assert.Equal(t, string(attr.DNSQuestionName), string(questionName(tt.stat).Key))
			assert.Equal(t, string(attr.DNSQuestionType), string(questionType(tt.stat).Key))
		})
	}
}

func TestSocketTrafficGetters(t *testing.T) {
	transport, ok := StatGetters(attr.NetworkTransport)
	require.True(t, ok)
	direction, ok := StatGetters(attr.NetworkIoDirection)
	require.True(t, ok)
	role, ok := StatGetters(attr.NetworkConnectionRole)
	require.True(t, ok)

	tcp := &Stat{Type: StatTypeSocketTraffic, SocketTraffic: &SocketTraffic{
		Transport: syscall.IPPROTO_TCP,
		Direction: uint8(CodeDirectionReceive),
		Role:      uint8(CodeRoleServer),
	}}
	assert.Equal(t, attribute.String(string(attr.NetworkTransport), "tcp"), transport(tcp))
	assert.Equal(t, attribute.String(string(attr.NetworkIoDirection), "receive"), direction(tcp))
	assert.Equal(t, attribute.String(string(attr.NetworkConnectionRole), "server"), role(tcp))

	udp := &Stat{Type: StatTypeSocketTraffic, SocketTraffic: &SocketTraffic{
		Transport: syscall.IPPROTO_UDP,
		Direction: uint8(CodeDirectionTransmit),
		Role:      uint8(CodeRoleClient),
	}}
	assert.Equal(t, attribute.String(string(attr.NetworkTransport), "udp"), transport(udp))
	assert.Equal(t, attribute.String(string(attr.NetworkIoDirection), "transmit"), direction(udp))
	assert.Equal(t, attribute.String(string(attr.NetworkConnectionRole), "client"), role(udp))
}
