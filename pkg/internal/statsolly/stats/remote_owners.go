// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// remoteOwnersCacheTTL is how long the process of a local address is reused: the address of a
// server is looked up for each of its connections
const remoteOwnersCacheTTL = time.Second

// endpointLookup is the lookup of a local address in the endpoint_owner map
type endpointLookup func(key *ebpf.StatsEndpointKeyT, owner *ebpf.StatsEndpointOwnerT) error

// remoteOwner is the process of a local address
type remoteOwner struct {
	pid      uint32
	execName string
	cgroupID uint64
}

// remoteOwners finds the process of the remote socket of the TCP stats whose remote socket is
// on this host. The local addresses of the stats teach it most of them: both ends of a
// connection on this host send stats. The others are read from the endpoint_owner map, where the
// kernel records the process of each local address. It is not safe for concurrent use, except
// expireEvery.
type remoteOwners struct {
	lookup  endpointLookup
	cache   map[ebpf.StatsEndpointKeyT]remoteOwner
	expired atomic.Bool
}

func newRemoteOwners(endpointOwners *ciliumebpf.Map) *remoteOwners {
	return &remoteOwners{
		lookup: func(key *ebpf.StatsEndpointKeyT, owner *ebpf.StatsEndpointOwnerT) error {
			return endpointOwners.Lookup(key, owner)
		},
		cache: map[ebpf.StatsEndpointKeyT]remoteOwner{},
	}
}

// expireEvery empties the cache every period, without reading the clock for each stat
func (r *remoteOwners) expireEvery(ctx context.Context, period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.expired.Store(true)
		}
	}
}

func (r *remoteOwners) find(s *ebpf.Stat) {
	if r.expired.Load() {
		r.expired.Store(false)
		clear(r.cache)
	}
	if s.Owner.Pid != 0 && s.CommonAttrs.SrcPort != 0 {
		r.cache[endpointKey(&s.CommonAttrs.SrcAddr, s.CommonAttrs.SrcPort, s.Owner.NetNS)] = remoteOwner{
			pid: s.Owner.Pid, execName: s.Owner.ExecName, cgroupID: s.Owner.CgroupID,
		}
	}
	if s.CommonAttrs.DstPort == 0 {
		return
	}
	// a remote loopback address is in the namespace of the local socket
	owner := r.cached(endpointKey(&s.CommonAttrs.DstAddr, s.CommonAttrs.DstPort, s.Owner.NetNS))
	s.Owner.DstPid, s.Owner.DstExecName, s.Owner.DstCgroupID = owner.pid, owner.execName, owner.cgroupID
}

// endpointKey is the endpoint_owner key of a local address: the loopback addresses exist in
// every network namespace
func endpointKey(addr *pipe.IPAddr, port uint16, netns uint32) ebpf.StatsEndpointKeyT {
	key := ebpf.StatsEndpointKeyT{Addr: *addr, Port: port}
	if net.IP(key.Addr[:]).IsLoopback() {
		key.Netns = netns
	}
	return key
}

// cached returns the process of a local address, zero when it is not a local address
func (r *remoteOwners) cached(key ebpf.StatsEndpointKeyT) remoteOwner {
	if owner, ok := r.cache[key]; ok {
		return owner
	}
	var endpoint ebpf.StatsEndpointOwnerT
	var owner remoteOwner
	if err := r.lookup(&key, &endpoint); err == nil {
		owner = remoteOwner{
			pid:      endpoint.Owner.Pid,
			execName: ebpf.CString(endpoint.Owner.ExeName[:]),
			cgroupID: uint64(endpoint.Owner.CgroupIdHi)<<32 | uint64(endpoint.Owner.CgroupIdLo),
		}
	}
	r.cache[key] = owner
	return owner
}
