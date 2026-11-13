// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nat // import "go.opentelemetry.io/obi/pkg/internal/statsolly/nat"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
)

const (
	// ciliumMapsDir is where Cilium pins its maps: OBI needs /sys/fs/bpf mounted
	ciliumMapsDir = "/sys/fs/bpf/tc/globals"
	// ciliumBackendsInterval is how often the load balancer backends are read, Datadog's
	ciliumBackendsInterval = 10 * time.Second

	// the flags of the conntrack entries of the services, from cilium/pkg/maps/ctmap
	ciliumTupleOut     = 0
	ciliumTupleService = 4
)

// ciliumTupleKey4 is the key of the Cilium conntrack maps, from cilium/pkg/maps/ctmap. The
// ports are in network byte order.
type ciliumTupleKey4 struct {
	DestAddr   [net.IPv4len]byte
	SourceAddr [net.IPv4len]byte
	SourcePort uint16
	DestPort   uint16
	NextHeader uint8
	Flags      uint8
}

// ciliumCtEntry is the value of the Cilium conntrack maps
type ciliumCtEntry struct {
	Reserved0        uint64
	BackendID        uint64
	Packets          uint64
	Bytes            uint64
	Lifetime         uint32
	Flags            uint16
	RevNAT           uint16
	IfIndex          uint16
	TxFlagsSeen      uint8
	RxFlagsSeen      uint8
	SourceSecurityID uint32
	LastTxReport     uint32
	LastRxReport     uint32
}

// ciliumBackend4 is the value of the Cilium load balancer backends map (v3). The port is in
// network byte order.
type ciliumBackend4 struct {
	Address   [net.IPv4len]byte
	Port      uint16
	Proto     uint8
	Flags     uint8
	ClusterID uint16
	Zone      uint8
	Pad       uint8
}

type ciliumBackend struct {
	addr [net.IPv6len]byte
	port uint16
}

// ciliumLB finds the backend of the connections to the services of the Cilium load balancer,
// like Datadog's Cilium conntracker: Cilium translates them in eBPF, without conntrack. IPv4
// only, like Datadog.
type ciliumLB struct {
	log          *slog.Logger
	ctTCP, ctUDP *ciliumebpf.Map
	backendsMap  *ciliumebpf.Map
	mu           sync.Mutex
	backendsByID map[uint32]ciliumBackend
}

// newCiliumLB returns nil without Cilium
func newCiliumLB() (*ciliumLB, error) {
	ctTCP, err := loadCiliumMap("cilium_ct4_global")
	if ctTCP == nil {
		return nil, err
	}
	ctUDP, err := loadCiliumMap("cilium_ct_any4_global")
	if ctUDP == nil {
		ctTCP.Close()
		return nil, err
	}
	backends, err := loadCiliumMap("cilium_lb4_backends_v3")
	if backends == nil {
		ctTCP.Close()
		ctUDP.Close()
		return nil, err
	}

	lb := &ciliumLB{
		log:          slog.With("component", "nat.ciliumLB"),
		ctTCP:        ctTCP,
		ctUDP:        ctUDP,
		backendsMap:  backends,
		backendsByID: map[uint32]ciliumBackend{},
	}
	lb.updateBackends()
	return lb, nil
}

// loadCiliumMap returns nil without error when the map does not exist
func loadCiliumMap(name string) (*ciliumebpf.Map, error) {
	path := filepath.Join(ciliumMapsDir, name)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	m, err := ciliumebpf.LoadPinnedMap(path, &ciliumebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("loading the pinned Cilium map %s: %w", path, err)
	}
	return m, nil
}

// run reads the backends until ctx is done, then closes the maps
func (lb *ciliumLB) run(ctx context.Context) {
	ticker := time.NewTicker(ciliumBackendsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			lb.ctTCP.Close()
			lb.ctUDP.Close()
			lb.backendsMap.Close()
			return
		case <-ticker.C:
			lb.updateBackends()
		}
	}
}

func (lb *ciliumLB) updateBackends() {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	var id uint32
	var b ciliumBackend4
	it := lb.backendsMap.Iterate()
	for it.Next(&id, &b) {
		lb.backendsByID[id] = ciliumBackend{
			addr: [net.IPv6len]byte(net.IP(b.Address[:]).To16()),
			port: ntohs(b.Port),
		}
	}
	if err := it.Err(); err != nil {
		lb.log.Debug("error reading the Cilium load balancer backends", "error", err)
	}
}

// lookup finds the backend of a client connection to a service: its reply direction
func (lb *ciliumLB) lookup(k *key) (translation, bool) {
	src, dst := net.IP(k.Conn.S_addr[:]), net.IP(k.Conn.D_addr[:])
	if src.To4() == nil || dst.To4() == nil || dst.IsLoopback() {
		return translation{}, false
	}

	ct := lb.ctTCP
	if k.Protocol == syscall.IPPROTO_UDP {
		ct = lb.ctUDP
	}
	tuple := ciliumTupleKey4{
		DestAddr:   [net.IPv4len]byte(dst.To4()),
		SourceAddr: [net.IPv4len]byte(src.To4()),
		SourcePort: htons(k.Conn.S_port),
		DestPort:   htons(k.Conn.D_port),
		NextHeader: k.Protocol,
		Flags:      ciliumTupleOut | ciliumTupleService,
	}
	var entry ciliumCtEntry
	if err := ct.Lookup(&tuple, &entry); err != nil {
		return translation{}, false
	}

	lb.mu.Lock()
	backend, ok := lb.backendsByID[uint32(entry.BackendID)]
	lb.mu.Unlock()
	if !ok || (backend.addr == k.Conn.D_addr && backend.port == k.Conn.D_port) {
		return translation{}, false
	}
	// the reply comes from the backend to the client socket
	tr := translation{IsReply: 1}
	tr.Conn.S_addr, tr.Conn.S_port = backend.addr, backend.port
	tr.Conn.D_addr, tr.Conn.D_port = k.Conn.S_addr, k.Conn.S_port
	return tr, true
}

func ntohs(n uint16) uint16 {
	b := binary.NativeEndian.AppendUint16(nil, n)
	return binary.BigEndian.Uint16(b)
}

func htons(n uint16) uint16 {
	b := binary.BigEndian.AppendUint16(nil, n)
	return binary.NativeEndian.Uint16(b)
}
