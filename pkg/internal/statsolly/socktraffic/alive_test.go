// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// procNetAddr prints an address like the kernel does in /proc/net/tcp{,6}: 32-bit words
// in host byte order
func procNetAddr(ip net.IP) string {
	raw := ip.To4()
	if raw == nil {
		raw = ip.To16()
	}
	var sb strings.Builder
	for i := 0; i < len(raw); i += 4 {
		fmt.Fprintf(&sb, "%08X", binary.NativeEndian.Uint32(raw[i:]))
	}
	return sb.String()
}

func procNetLine(local net.IP, localPort uint16, remote net.IP, remotePort uint16) string {
	return fmt.Sprintf("   0: %s:%04X %s:%04X 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1",
		procNetAddr(local), localPort, procNetAddr(remote), remotePort)
}

func procNetListenLine(local net.IP, localPort uint16) string {
	return fmt.Sprintf("   1: %s:%04X %s:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1",
		procNetAddr(local), localPort, procNetAddr(net.IPv4zero))
}

// writeProcNet writes /proc/<pid>/net/<file> with the header and the given lines
func writeProcNet(t *testing.T, procRoot string, pid uint32, file string, lines ...string) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(int(pid)), "net")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		strings.Join(lines, "\n") + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644))
}

func tcpConnKey(local string, localPort uint16, remote string, remotePort uint16) key {
	k := key{Protocol: syscall.IPPROTO_TCP}
	copy(k.Conn.S_addr[:], net.ParseIP(local).To16())
	copy(k.Conn.D_addr[:], net.ParseIP(remote).To16())
	k.Conn.S_port = localPort
	k.Conn.D_port = remotePort
	return k
}

func TestParseProcNetEndpoint(t *testing.T) {
	addr, port, ok := parseProcNetEndpoint(procNetAddr(net.ParseIP("10.0.0.1")) + ":1F90")
	require.True(t, ok)
	assert.Equal(t, net.ParseIP("10.0.0.1").To16(), net.IP(addr[:]))
	assert.Equal(t, uint16(8080), port)

	addr, port, ok = parseProcNetEndpoint(procNetAddr(net.ParseIP("2001:db8::1")) + ":0050")
	require.True(t, ok)
	assert.Equal(t, net.ParseIP("2001:db8::1"), net.IP(addr[:]))
	assert.Equal(t, uint16(80), port)

	// a dual-stack socket shows IPv4 clients IPv4-mapped in tcp6
	addr, _, ok = parseProcNetEndpoint(procNetAddr(net.ParseIP("::ffff:10.0.0.2")) + ":0050")
	require.True(t, ok)
	assert.Equal(t, net.ParseIP("10.0.0.2").To16(), net.IP(addr[:]))

	for _, bad := range []string{"", "0100007F", "0100007F:XYZ", "01007F:0050", "ZZ00007F:0050"} {
		_, _, ok := parseProcNetEndpoint(bad)
		assert.False(t, ok, bad)
	}
}

func TestTCPSocketsIsOpen(t *testing.T) {
	procRoot := t.TempDir()
	writeProcNet(t, procRoot, 100, "tcp", procNetLine(net.ParseIP("10.0.0.1"), 40000, net.ParseIP("10.0.0.2"), 80))
	writeProcNet(t, procRoot, 100, "tcp6",
		procNetLine(net.ParseIP("::ffff:10.0.0.1"), 8080, net.ParseIP("::ffff:10.0.0.3"), 50000))

	s := newTCPSockets(procRoot)
	open4 := tcpConnKey("10.0.0.1", 40000, "10.0.0.2", 80)
	open6 := tcpConnKey("10.0.0.1", 8080, "10.0.0.3", 50000)
	closed := tcpConnKey("10.0.0.1", 40001, "10.0.0.2", 80)

	assert.True(t, s.isOpen(&open4, 100))
	assert.True(t, s.isOpen(&open6, 100))
	assert.False(t, s.isOpen(&closed, 100))

	// the process ended: like Datadog, its connections are not open
	otherNetns := open4
	otherNetns.Netns = 2
	assert.False(t, s.isOpen(&otherNetns, 200))

	// the connections of a network namespace are read once per map read
	require.NoError(t, os.RemoveAll(filepath.Join(procRoot, "100")))
	assert.True(t, s.isOpen(&open4, 100))
	s.reset()
	assert.False(t, s.isOpen(&open4, 100))
}

func TestTCPSocketsIsListening(t *testing.T) {
	procRoot := t.TempDir()
	writeProcNet(t, procRoot, 100, "tcp",
		procNetListenLine(net.ParseIP("0.0.0.0"), 5432),
		procNetLine(net.ParseIP("10.0.0.2"), 5432, net.ParseIP("10.0.0.1"), 41001))
	writeProcNet(t, procRoot, 100, "tcp6", procNetListenLine(net.ParseIP("::"), 8080))

	s := newTCPSockets(procRoot)
	server := tcpConnKey("10.0.0.2", 5432, "10.0.0.1", 41001)
	listening, known := s.isListening(&server, 100)
	assert.True(t, known)
	assert.True(t, listening)
	assert.True(t, s.isOpen(&server, 100), "a listening socket does not hide the connections")

	server6 := tcpConnKey("10.0.0.2", 8080, "10.0.0.3", 50000)
	listening, _ = s.isListening(&server6, 100)
	assert.True(t, listening)

	client := tcpConnKey("10.0.0.2", 41002, "10.0.0.9", 443)
	listening, known = s.isListening(&client, 100)
	assert.True(t, known)
	assert.False(t, listening)

	gone := server
	gone.Netns = 2
	_, known = s.isListening(&gone, 200)
	assert.False(t, known, "the process ended")
}
