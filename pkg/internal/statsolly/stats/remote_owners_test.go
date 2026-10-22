// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func TestRemoteOwners(t *testing.T) {
	const hostNS, containerNS = 4026531840, 4026532500
	endpoints := map[ebpf.StatsEndpointKeyT]ebpf.StatsSockOwnerT{
		{Addr: testIP("172.17.0.5"), Port: 8080}:                    {Pid: 100, CgroupIdLo: 7, ExeName: [16]uint8{'n', 'g', 'i', 'n', 'x'}},
		{Addr: testIP("127.0.0.1"), Port: 6379, Netns: containerNS}: {Pid: 200, ExeName: [16]uint8{'r', 'e', 'd', 'i', 's'}},
	}
	lookups := 0
	r := &remoteOwners{
		lookup: func(key *ebpf.StatsEndpointKeyT, endpoint *ebpf.StatsEndpointOwnerT) error {
			lookups++
			o, ok := endpoints[*key]
			if !ok {
				return errors.New("not found")
			}
			*endpoint = ebpf.StatsEndpointOwnerT{Owner: o, RecordedNs: 1}
			return nil
		},
		cache: map[ebpf.StatsEndpointKeyT]remoteOwner{},
	}
	stat := func(dst string, port uint16, netns uint32) *ebpf.Stat {
		return &ebpf.Stat{
			CommonAttrs: pipe.CommonAttrs{DstAddr: testIP(dst), DstPort: port},
			Owner:       ebpf.SockOwner{Pid: 1, NetNS: netns},
		}
	}

	s := stat("172.17.0.5", 8080, containerNS)
	r.find(s)
	assert.Equal(t, ebpf.SockOwner{Pid: 1, NetNS: containerNS, DstPid: 100, DstExecName: "nginx", DstCgroupID: 7}, s.Owner)

	s = stat("127.0.0.1", 6379, containerNS)
	r.find(s)
	assert.Equal(t, uint32(200), s.Owner.DstPid, "a loopback address in the namespace of the local socket")
	s = stat("127.0.0.1", 6379, hostNS)
	r.find(s)
	assert.Zero(t, s.Owner.DstPid, "the same loopback address in another namespace")

	s = stat("8.8.8.8", 53, hostNS)
	r.find(s)
	assert.Zero(t, s.Owner.DstPid, "not a local address")

	// the lookups are reused for a second
	lookups = 0
	r.find(stat("172.17.0.5", 8080, hostNS))
	r.find(stat("8.8.8.8", 53, hostNS))
	assert.Zero(t, lookups)
	r.expired.Store(true)
	r.find(stat("172.17.0.5", 8080, hostNS))
	assert.Equal(t, 1, lookups, "looked up again after the expiry")
}

func TestRemoteOwnersLearnFromTheStats(t *testing.T) {
	lookups := 0
	r := &remoteOwners{
		lookup: func(*ebpf.StatsEndpointKeyT, *ebpf.StatsEndpointOwnerT) error {
			lookups++
			return errors.New("not found")
		},
		cache: map[ebpf.StatsEndpointKeyT]remoteOwner{},
	}
	// a client stat teaches its local address: the stats of the server side don't look it up
	client := &ebpf.Stat{
		CommonAttrs: pipe.CommonAttrs{SrcAddr: testIP("127.0.0.1"), SrcPort: 40000, DstAddr: testIP("127.0.0.1"), DstPort: 80},
		Owner:       ebpf.SockOwner{Pid: 10, NetNS: 1, ExecName: "curl", CgroupID: 3},
	}
	r.find(client)
	server := &ebpf.Stat{
		CommonAttrs: pipe.CommonAttrs{SrcAddr: testIP("127.0.0.1"), SrcPort: 80, DstAddr: testIP("127.0.0.1"), DstPort: 40000},
		Owner:       ebpf.SockOwner{Pid: 20, NetNS: 1, ExecName: "nginx"},
	}
	r.find(server)
	assert.Equal(t, ebpf.SockOwner{Pid: 20, NetNS: 1, ExecName: "nginx", DstPid: 10, DstExecName: "curl", DstCgroupID: 3}, server.Owner)
	assert.Equal(t, 1, lookups, "only the server address of the first client stat was looked up")
	r.find(client)
	assert.Equal(t, uint32(20), client.Owner.DstPid, "learned from the server stat")
	assert.Equal(t, 1, lookups)
}
