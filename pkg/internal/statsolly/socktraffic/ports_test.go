// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const udpHeader = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"

func writeProcess(t *testing.T, procRoot, pid, netnsLink, udp, udp6 string) {
	t.Helper()
	pidDir := filepath.Join(procRoot, pid)
	require.NoError(t, os.MkdirAll(filepath.Join(pidDir, "ns"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(pidDir, "net"), 0o755))
	require.NoError(t, os.Symlink(netnsLink, filepath.Join(pidDir, "ns", "net")))
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "net", "udp"), []byte(udpHeader+udp), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "net", "udp6"), []byte(udpHeader+udp6), 0o644))
}

func TestBoundUDPPorts(t *testing.T) {
	procRoot := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "sys", "net", "ipv4"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(procRoot, "sys", "net", "ipv4", "ip_local_port_range"), []byte("32768\t60999\n"), 0o644))

	writeProcess(t, procRoot, "1", "net:[100]",
		// DNS server on 53 (twice, e.g. two addresses), a connected client (state 01) and
		// an unconnected client on an ephemeral port
		"  1: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 1 2 0 0\n"+
			"  2: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 2 2 0 0\n"+
			"  3: 0100007F:9C40 0100007F:0035 01 00000000:00000000 00:00000000 00000000  1000        0 3 2 0 0\n"+
			"  4: 00000000:8235 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 4 2 0 0\n",
		"  5: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 5 2 0 0\n")
	// same network namespace: not read again
	writeProcess(t, procRoot, "2", "net:[100]",
		"  1: 00000000:0BB8 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 6 2 0 0\n", "")
	// another network namespace
	writeProcess(t, procRoot, "3", "net:[200]",
		"  1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 7 2 0 0\n", "")
	// not a process
	require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "self"), 0o755))

	ports, err := boundUDPPorts(procRoot)
	require.NoError(t, err)
	assert.Equal(t, map[portKey]uint32{
		{Netns: 100, Port: 53}:   2,
		{Netns: 100, Port: 5353}: 1,
		{Netns: 200, Port: 53}:   1,
	}, ports)
}

func TestEphemeralPortRangeDefault(t *testing.T) {
	low, high := ephemeralPortRange(t.TempDir())
	assert.Equal(t, uint16(defaultEphemeralLow), low)
	assert.Equal(t, uint16(defaultEphemeralHigh), high)
}
