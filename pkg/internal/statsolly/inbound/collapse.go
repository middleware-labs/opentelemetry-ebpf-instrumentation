// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package inbound reports the public addresses of the clients of the servers of this host as one
// address.
package inbound // import "go.opentelemetry.io/obi/pkg/internal/statsolly/inbound"

import (
	"context"
	"net"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// sharedAddressSpace is the carrier-grade NAT range of RFC 6598, which some clouds use inside
// their networks
var sharedAddressSpace = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// CollapseProvider reports the public address of the remote side of the connections that this
// host serves as ebpf.ExternalAddress, when enabled: else each client on the internet is its
// own series. It must run before the decorator that names the remote side by its address.
func CollapseProvider(enabled bool, input, output *msg.Queue[[]*ebpf.Stat]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !enabled {
			return swarm.Bypass(input, output)
		}
		in := input.Subscribe(msg.SubscriberName("inbound.Collapse"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(stats []*ebpf.Stat) {
				for _, s := range stats {
					collapse(s)
				}
				output.Send(stats)
			})
		}, nil
	}
}

// collapse marks the public addresses of the client of a server stat. The address before NAT is
// checked on its own: a SNAT, like the one of a cloud load balancer, can keep the client address
// there only.
func collapse(s *ebpf.Stat) {
	if !s.Server() {
		return
	}
	if s.CommonAttrs.Metadata[attr.K8sDstName] == "" && public(s.Endpoints().DstAddr) {
		s.DstExternal = true
		s.CommonAttrs.DstName = ebpf.ExternalAddress
	}
	if s.NAT != nil && public(s.NAT.Pre.DstAddr) {
		s.DstPreNATExternal = true
	}
}

// public tells whether an address is a public unicast one, IPv4 or IPv6
func public(addr pipe.IPAddr) bool {
	ip := addr.IP()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !sharedAddressSpace.Contains(ip)
}
