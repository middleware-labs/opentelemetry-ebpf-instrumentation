// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	containerTypes "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
)

func summary(id string, ips []string, ports ...containerTypes.PortSummary) containerTypes.Summary {
	networks := map[string]*network.EndpointSettings{}
	for i, ip := range ips {
		networks["net"+string(rune('a'+i))] = &network.EndpointSettings{IPAddress: netip.MustParseAddr(ip)}
	}
	return containerTypes.Summary{
		ID: id, Ports: ports, NetworkSettings: &containerTypes.NetworkSettingsSummary{Networks: networks},
	}
}

func TestAddrIndex(t *testing.T) {
	mock := &mockDockerClient{listResult: client.ContainerListResult{Items: []containerTypes.Summary{
		// a DNS server on two networks
		summary("coredns", []string{"172.29.0.53", "172.30.0.53"},
			containerTypes.PortSummary{PrivatePort: 53, Type: "udp"},
			containerTypes.PortSummary{PrivatePort: 53, Type: "tcp"}),
		// no declared port
		summary("client", []string{"172.29.0.20"}),
		// host network: no IP
		summary("host", nil, containerTypes.PortSummary{PrivatePort: 80, Type: "tcp"}),
	}}}
	index := NewAddrIndex(&ContainerStore{docker: mock, log: cmlog()})
	dnsServer := Addr{IP: netip.MustParseAddr("172.29.0.53"), Port: 53, Proto: "udp"}

	_, found := index.ContainerID(dnsServer)
	assert.False(t, found, "the containers are not listed yet")

	index.refresh(context.Background())
	for _, addr := range []Addr{
		dnsServer,
		{IP: netip.MustParseAddr("172.30.0.53"), Port: 53, Proto: "tcp"},
		{IP: netip.MustParseAddr("::ffff:172.29.0.53"), Port: 53, Proto: "udp"},
	} {
		id, found := index.ContainerID(addr)
		assert.True(t, found, addr)
		assert.Equal(t, ContainerID("coredns"), id, addr)
	}
	for _, addr := range []Addr{
		{IP: netip.MustParseAddr("172.29.0.53"), Port: 5353, Proto: "udp"},
		{IP: netip.MustParseAddr("172.29.0.20"), Port: 40000, Proto: "udp"},
		{IP: netip.MustParseAddr("8.8.8.8"), Port: 53, Proto: "udp"},
	} {
		_, found := index.ContainerID(addr)
		assert.False(t, found, addr)
	}

	mock.listErr = errors.New("docker is restarting")
	index.refresh(context.Background())
	_, found = index.ContainerID(dnsServer)
	assert.True(t, found, "the previous containers are kept")

	mock.listResult, mock.listErr = client.ContainerListResult{}, nil
	index.refresh(context.Background())
	_, found = index.ContainerID(dnsServer)
	assert.False(t, found, "the container stopped")
}
