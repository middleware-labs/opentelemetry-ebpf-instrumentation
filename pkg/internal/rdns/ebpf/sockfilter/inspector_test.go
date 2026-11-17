// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sockfilter

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/rdns/store"
)

// responseRecord wraps a DNS message as the socket filter submits it to the ring buffer
func responseRecord(msg []byte) *ringbuf.Record {
	raw := make([]byte, unsafe.Sizeof(BpfRdnsResponseT{}))
	binary.NativeEndian.PutUint16(raw, uint16(len(msg)))
	copy(raw[unsafe.Offsetof(BpfRdnsResponseT{}.Buf):], msg)
	return &ringbuf.Record{RawSample: raw}
}

func TestHandleDNSMessage(t *testing.T) {
	aData := []byte{192, 0, 2, 1}
	aaaaData := []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	tests := []struct {
		name    string
		message []byte
		want    *store.DNSEntry
	}{{
		name:    "A",
		message: compressedResponse(typeA, typeA, aData),
		want:    &store.DNSEntry{HostName: "example.com", IPs: []string{"192.0.2.1"}},
	}, {
		name:    "AAAA",
		message: compressedResponse(typeAAAA, typeAAAA, aaaaData),
		want:    &store.DNSEntry{HostName: "example.com", IPs: []string{"2001:db8::1"}},
	}, {
		name:    "mixed case name",
		message: bytes.Replace(compressedResponse(typeA, typeA, aData), []byte("example"), []byte("ExAmPlE"), 1),
		want:    &store.DNSEntry{HostName: "example.com", IPs: []string{"192.0.2.1"}},
	}, {
		name:    "CNAME target compressed against the question",
		message: cnameResponse(),
		want:    &store.DNSEntry{HostName: "www.wikipedia.org", IPs: []string{"192.0.2.1"}},
	}, {
		name:    "CNAME only",
		message: compressedResponse(typeA, typeCNAME, []byte{3, 'w', 'w', 'w', 0xc0, 0x0c}),
	}, {
		name:    "A with an IPv6 sized address",
		message: compressedResponse(typeA, typeA, aaaaData),
	}, {
		name:    "AAAA with an IPv4 sized address",
		message: compressedResponse(typeAAAA, typeAAAA, aData),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, handleDNSMessage(tt.message))
		})
	}
}

func TestResponseMessage(t *testing.T) {
	msg := compressedResponse(typeA, typeA, []byte{192, 0, 2, 1})

	t.Run("returns the copied bytes only", func(t *testing.T) {
		assert.Equal(t, msg, responseMessage(responseRecord(msg).RawSample))
	})

	t.Run("record shorter than its header", func(t *testing.T) {
		assert.Nil(t, responseMessage([]byte{1}))
	})

	t.Run("length beyond the record", func(t *testing.T) {
		raw := responseRecord(msg).RawSample
		binary.NativeEndian.PutUint16(raw, uint16(len(raw)))
		assert.Nil(t, responseMessage(raw))
	})

	t.Run("a message filling the buffer", func(t *testing.T) {
		full := make([]byte, len(BpfRdnsResponseT{}.Buf))
		copy(full, msg)
		got := responseMessage(responseRecord(full).RawSample)
		require.Len(t, got, len(full))
	})
}
