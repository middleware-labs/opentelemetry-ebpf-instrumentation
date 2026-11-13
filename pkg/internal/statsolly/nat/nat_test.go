// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nat

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

const (
	rootNetns      = 4026531840
	containerNetns = 4026532001
)

func tuple(protocol uint8, netns uint32, src string, srcPort uint16, dst string, dstPort uint16) key {
	k := key{Netns: netns, Protocol: protocol}
	copy(k.Conn.S_addr[:], net.ParseIP(src).To16())
	copy(k.Conn.D_addr[:], net.ParseIP(dst).To16())
	k.Conn.S_port, k.Conn.D_port = srcPort, dstPort
	return k
}

func endpoints(src string, srcPort uint16, dst string, dstPort uint16) ebpf.Endpoints {
	e := ebpf.Endpoints{SrcPort: srcPort, DstPort: dstPort}
	copy(e.SrcAddr[:], net.ParseIP(src).To16())
	copy(e.DstAddr[:], net.ParseIP(dst).To16())
	return e
}

// fakeConntrack has the NAT-ed entries by both their directions, like the nat_translations map
type fakeConntrack map[key]translation

func (f fakeConntrack) lookup(k *key) (translation, bool) {
	tr, ok := f[*k]
	return tr, ok
}

func (f fakeConntrack) add(orig, reply *key) {
	f[*orig] = translation{Conn: reply.Conn, IsReply: 1}
	f[*reply] = translation{Conn: orig.Conn}
}

func TestNATOfTheClientAndTheServer(t *testing.T) {
	conntrack := fakeConntrack{}
	tracker := &Tracker{rootNetns: rootNetns, conntrack: conntrack}

	// a container client masqueraded to the host address, in the root network namespace
	orig := tuple(syscall.IPPROTO_TCP, rootNetns, "172.29.0.20", 40000, "10.66.1.164", 80)
	reply := tuple(syscall.IPPROTO_TCP, rootNetns, "10.66.1.164", 80, "139.59.42.32", 40000)
	conntrack.add(&orig, &reply)
	client := tuple(syscall.IPPROTO_TCP, containerNetns, "172.29.0.20", 40000, "10.66.1.164", 80)
	assert.Equal(t, &ebpf.NAT{
		Pre:  endpoints("172.29.0.20", 40000, "10.66.1.164", 80),
		Post: endpoints("139.59.42.32", 40000, "10.66.1.164", 80),
	}, tracker.NAT(&client, true), "the client socket has the addresses before NAT")

	// a service translated to its backend: the backend socket has the addresses after NAT
	orig = tuple(syscall.IPPROTO_UDP, rootNetns, "10.244.0.5", 50000, "10.96.0.10", 53)
	reply = tuple(syscall.IPPROTO_UDP, rootNetns, "10.244.1.7", 8053, "10.244.0.5", 50000)
	conntrack.add(&orig, &reply)
	backend := tuple(syscall.IPPROTO_UDP, containerNetns, "10.244.1.7", 8053, "10.244.0.5", 50000)
	assert.Equal(t, &ebpf.NAT{
		Pre:  endpoints("10.96.0.10", 53, "10.244.0.5", 50000),
		Post: endpoints("10.244.1.7", 8053, "10.244.0.5", 50000),
	}, tracker.NAT(&backend, false), "the server socket finds the service address of its client")

	noNAT := tuple(syscall.IPPROTO_TCP, rootNetns, "10.0.0.1", 40001, "10.0.0.2", 80)
	assert.Nil(t, tracker.NAT(&noNAT, true))
}

func TestNATOfTheSocketNetworkNamespace(t *testing.T) {
	conntrack := fakeConntrack{}
	tracker := &Tracker{rootNetns: rootNetns, conntrack: conntrack}

	// a NAT rule of the container's own network namespace
	orig := tuple(syscall.IPPROTO_TCP, containerNetns, "127.0.0.1", 40000, "127.0.0.1", 8080)
	reply := tuple(syscall.IPPROTO_TCP, containerNetns, "10.1.0.4", 80, "127.0.0.1", 40000)
	conntrack.add(&orig, &reply)
	n := tracker.NAT(&orig, true)
	require.NotNil(t, n)
	assert.Equal(t, endpoints("127.0.0.1", 40000, "10.1.0.4", 80), n.Post)

	other := orig
	other.Netns = containerNetns + 1
	assert.Nil(t, tracker.NAT(&other, true), "another network namespace")
}

func TestNATWithoutConntrack(t *testing.T) {
	tracker := &Tracker{rootNetns: rootNetns}
	k := tuple(syscall.IPPROTO_TCP, rootNetns, "10.0.0.1", 40001, "10.0.0.2", 80)
	assert.Nil(t, tracker.NAT(&k, true))
}

func TestIsNAT(t *testing.T) {
	orig := tuple(syscall.IPPROTO_TCP, rootNetns, "10.0.0.1", 40001, "10.0.0.2", 80)
	reply := tuple(syscall.IPPROTO_TCP, rootNetns, "10.0.0.2", 80, "10.0.0.1", 40001)
	assert.False(t, isNAT(&orig, &reply), "the reply is the original reversed")

	reply.Conn.S_port = 8080
	assert.True(t, isNAT(&orig, &reply), "the port of the server is translated")

	reply = tuple(syscall.IPPROTO_TCP, rootNetns, "10.0.0.2", 80, "192.168.1.1", 40001)
	assert.True(t, isNAT(&orig, &reply), "the address of the client is translated")
}
