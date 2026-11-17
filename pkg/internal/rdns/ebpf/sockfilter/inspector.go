// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sockfilter // import "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/sockfilter"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/rdns/store"
)

// the socket filter only wakes the reader up when many responses are waiting: the reader reads
// the others at least this often, so they are stored before the connections they precede
const pollInterval = 100 * time.Millisecond

func log() *slog.Logger {
	return slog.With("component", "sockfilter.DNSPacketInspector")
}

// storage backend for DNS IP-->Hostnames relation
type storage interface {
	Store(*store.DNSEntry)
	GetHostnames(ip string) ([]string, error)
}

// StartDNSPacketInspector in a backgound goroutine. The returned channel is closed
// once the inspector has stopped and closed its socket.
func StartDNSPacketInspector(ctx context.Context, storage storage, ebpfCfg *config.EBPFTracer) (<-chan struct{}, error) {
	tracer, err := newTracer(ebpfCfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating DNS socket tracer: %w", err)
	}

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		tracerLoop(ctx, storage, tracer)
	}()

	return stopped, nil
}

func tracerLoop(ctx context.Context, storage storage, tracer *tracer) {
	defer tracer.Close()

	log := log()

	log.Debug("listening to packet resolver")

	record := ringbuf.Record{}

	// the socket sees a response once per interface that it crosses, usually back to back
	var previous []byte

	for {
		select {
		case <-ctx.Done():
			log.Debug("context cancelled, exiting..")
			return
		default:
		}

		// the idea here is to avoid copying 'record' when passing it to a
		// channel - this allows its allocated memory to be reused by
		// subsequent ReadInto() calls, allowing the record data to be parsed
		// in place by parseDNSMessage()
		tracer.ringbuf.SetDeadline(time.Now().Add(pollInterval))
		err := tracer.ringbuf.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Debug("ringbuf closed, exiting..")
				return
			} else if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Error("reading from ringbuf", "error", err)
			}
			continue
		}

		msg := responseMessage(record.RawSample)
		if bytes.Equal(msg, previous) {
			continue
		}
		previous = append(previous[:0], msg...)

		entry := handleDNSMessage(msg)

		if entry != nil {
			log.Debug("received DNS entry", "host", entry.HostName, "ips", entry.IPs)
			storage.Store(entry)
		}
	}
}

func handleDNSMessage(msg []byte) *store.DNSEntry {
	dnsMessage := parseDNSMessage(msg)

	if dnsMessage == nil || len(dnsMessage.questions) == 0 {
		return nil
	}

	entry := store.DNSEntry{
		// names are case-insensitive, and some resolvers randomize the case of the queries
		HostName: strings.ToLower(dnsMessage.questions[0].qName),
		IPs:      make([]string, 0, len(dnsMessage.answers)),
	}

	for _, answer := range dnsMessage.answers {
		if ip := answerIP(answer); ip != nil {
			entry.IPs = append(entry.IPs, ip.String())
		}
	}

	if len(entry.IPs) == 0 {
		return nil
	}

	return &entry
}

// responseMessage returns the DNS message of an rdns_response_t record,
// or nil when the record is malformed.
func responseMessage(raw []byte) []byte {
	msgOffset := int(unsafe.Offsetof(BpfRdnsResponseT{}.Buf))
	if len(raw) < msgOffset {
		return nil
	}

	msgLen := int(binary.NativeEndian.Uint16(raw))
	msg := raw[msgOffset:]
	if msgLen > len(msg) {
		return nil
	}
	return msg[:msgLen]
}

// answerIP returns the address of an A or AAAA answer, or nil for any other answer
func answerIP(answer *record) net.IP {
	switch {
	case answer.typ == uint16(dnsparser.TypeA) && len(answer.data) == net.IPv4len,
		answer.typ == uint16(dnsparser.TypeAAAA) && len(answer.data) == net.IPv6len:
		return net.IP(answer.data)
	default:
		return nil
	}
}
