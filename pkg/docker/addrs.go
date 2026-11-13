// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker // import "go.opentelemetry.io/obi/pkg/docker"

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	mobycontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// addrsRefresh is how often the containers are listed, like Datadog's LocalResolver pulls them
const addrsRefresh = 10 * time.Second

// Addr is an address a container serves: one of its IPs with one of its declared ports
type Addr struct {
	IP   netip.Addr
	Port uint16
	// Proto is "tcp", "udp" or "sctp"
	Proto string
}

// AddrIndex finds the container serving a local address, like Datadog's LocalResolver
// (addrToCtrID): from the IPs of the running containers and their declared ports, the exposed
// or published ones. It knows the container, not its process.
type AddrIndex struct {
	store *ContainerStore
	addrs atomic.Pointer[map[Addr]ContainerID]
}

// NewAddrIndex needs an enabled store: see ContainerStore.IsEnabled
func NewAddrIndex(store *ContainerStore) *AddrIndex {
	return &AddrIndex{store: store}
}

// Run lists the containers every addrsRefresh until ctx is done
func (i *AddrIndex) Run(ctx context.Context) {
	ticker := time.NewTicker(addrsRefresh)
	defer ticker.Stop()
	for {
		i.refresh(ctx)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// refresh keeps the previous addresses when the containers can't be listed
func (i *AddrIndex) refresh(ctx context.Context) {
	list, err := i.store.docker.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		i.store.log.Debug("failed to list the docker containers", "error", err)
		return
	}
	addrs := containerAddrs(list.Items)
	i.addrs.Store(&addrs)
}

// containerAddrs are the IPs × the declared ports of each container, like Datadog's
// computeContainerAddrs. A container without IP (host network) or port has none.
func containerAddrs(containers []mobycontainer.Summary) map[Addr]ContainerID {
	addrs := map[Addr]ContainerID{}
	for c := range containers {
		ctr := &containers[c]
		if ctr.NetworkSettings == nil {
			continue
		}
		for _, endpoint := range ctr.NetworkSettings.Networks {
			if endpoint == nil || !endpoint.IPAddress.IsValid() || endpoint.IPAddress.IsLoopback() {
				continue
			}
			for _, port := range ctr.Ports {
				addr := Addr{IP: endpoint.IPAddress.Unmap(), Port: port.PrivatePort, Proto: port.Type}
				addrs[addr] = ContainerID(ctr.ID)
			}
		}
	}
	return addrs
}

// ContainerID returns the container serving an address, when it is a local container
func (i *AddrIndex) ContainerID(addr Addr) (ContainerID, bool) {
	addrs := i.addrs.Load()
	if addrs == nil {
		return "", false
	}
	addr.IP = addr.IP.Unmap()
	id, ok := (*addrs)[addr]
	return id, ok
}
