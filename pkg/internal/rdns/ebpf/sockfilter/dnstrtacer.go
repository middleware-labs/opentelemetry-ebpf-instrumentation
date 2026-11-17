// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sockfilter // import "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/sockfilter"

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	convenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/netns"
)

const (
	// the process whose network namespace is the host's
	hostPID = 1

	socketName = "rdns_socket"
)

// tracer represents the main structure for DNS response tracking.
type tracer struct {
	bpfObjects *BpfObjects
	socket     io.Closer
	ringbuf    *ringbuf.Reader
}

func (t *tracer) Close() error {
	var errs []error
	if t.socket != nil {
		errs = append(errs, t.socket.Close())
		t.socket = nil
	}

	if t.ringbuf != nil {
		errs = append(errs, t.ringbuf.Close())
		t.ringbuf = nil
	}

	if t.bpfObjects != nil {
		errs = append(errs, t.bpfObjects.Close())
		t.bpfObjects = nil
	}

	return errors.Join(errs...)
}

// newTracer creates and initializes a new DNS response tracer.
// It loads the BPF program, attaches it to a raw socket, and sets up the ring buffer.
// Returns an error if any step fails.
func newTracer(ebpfCfg *config.EBPFTracer) (*tracer, error) {
	objects := BpfObjects{}
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	convenience.SetupMapSizes(spec, ebpfCfg.MapsConfig.GlobalScaleFactor)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	if err := convenience.LoadSpec(spec, &objects, nil, sharedMaps, &mu, "", nil); err != nil {
		return nil, err
	}

	tracer := tracer{bpfObjects: &objects}

	tracer.socket, err = attachToHostNetNS(objects.ObiRdnsSocketDns)
	if err != nil {
		_ = tracer.Close()
		return nil, fmt.Errorf("attaching DNS socket filter: %w", err)
	}

	tracer.ringbuf, err = ringbuf.NewReader(objects.RdnsResponses)
	if err != nil {
		_ = tracer.Close()
		return nil, fmt.Errorf("creating ringbuffer reader: %w", err)
	}
	return &tracer, nil
}

// attachToHostNetNS opens the socket in the host network namespace, where it sees the DNS
// responses of the host and of every container and pod while they cross the host side of their
// virtual interfaces. It falls back to OBI's own namespace when OBI can't enter the host's.
func attachToHostNetNS(prog *ebpf.Program) (io.Closer, error) {
	var sock io.Closer
	err := netns.WithNetNS(hostPID, func() error {
		var err error
		sock, err = convenience.AttachSocketFilter(prog, socketName)
		return err
	})
	if err == nil {
		return sock, nil
	}

	// the namespace can fail to restore after the socket was opened
	if sock != nil {
		sock.Close()
	}

	log().Warn("can't open the DNS socket in the host network namespace."+
		" Only the DNS responses of OBI's own network namespace will be inspected", "error", err)
	return convenience.AttachSocketFilter(prog, socketName)
}
