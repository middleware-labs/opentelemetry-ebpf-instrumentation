// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tcpConn is a TCP connection as the socket_traffic keys hold it: IPv6 or IPv4-mapped
// addresses, ports in host byte order.
type tcpConn struct {
	local, remote         [16]byte
	localPort, remotePort uint16
}

// tcpSockets tells whether the connection of an idle TCP row is still open, so a long-lived
// idle connection keeps its row and its packet totals are not counted again. Datadog checks
// that the process is alive and that conntrack still has the connection
// (pkg/network/tracer/tracer.go connectionExpired); here the process's
// /proc/<pid>/net/tcp{,6} replaces conntrack, which OBI does not use.
type tcpSockets struct {
	procRoot string
	// the TCP sockets per network namespace, read at most once per map read
	netns map[uint32]*netnsSockets
}

type netnsSockets struct {
	open map[tcpConn]struct{}
	// listening are the local ports of the listening sockets
	listening map[uint16]struct{}
}

func newTCPSockets(procRoot string) *tcpSockets {
	return &tcpSockets{procRoot: procRoot, netns: map[uint32]*netnsSockets{}}
}

// reset forgets the connections read before, at the start of each map read
func (s *tcpSockets) reset() {
	clear(s.netns)
}

// sockets returns the TCP sockets of the network namespace of a row, read from the /proc of its
// process. It fails when the process ended.
func (s *tcpSockets) sockets(k *key, pid uint32) (*netnsSockets, bool) {
	sockets, ok := s.netns[k.Netns]
	if !ok {
		var err error
		if sockets, err = readTCPSockets(filepath.Join(s.procRoot, strconv.Itoa(int(pid)), "net")); err != nil {
			return nil, false
		}
		s.netns[k.Netns] = sockets
	}
	return sockets, true
}

// isOpen returns false when the process of the row ended, like Datadog, or when its network
// namespace no longer has the connection.
func (s *tcpSockets) isOpen(k *key, pid uint32) bool {
	sockets, ok := s.sockets(k, pid)
	if !ok {
		return false
	}
	_, ok = sockets.open[tcpConn{
		local:      k.Conn.S_addr,
		remote:     k.Conn.D_addr,
		localPort:  k.Conn.S_port,
		remotePort: k.Conn.D_port,
	}]
	return ok
}

// isListening tells whether the local port of a row is listening in its network namespace,
// like Datadog's port_bindings: the row is then the server side. known is false when the
// sockets of its process can't be read.
func (s *tcpSockets) isListening(k *key, pid uint32) (listening, known bool) {
	sockets, ok := s.sockets(k, pid)
	if !ok {
		return false, false
	}
	_, listening = sockets.listening[k.Conn.S_port]
	return listening, true
}

// readTCPSockets reads the TCP sockets of tcp and tcp6 in a /proc/<pid>/net directory. It
// fails when the process ended.
func readTCPSockets(netDir string) (*netnsSockets, error) {
	sockets := &netnsSockets{open: map[tcpConn]struct{}{}, listening: map[uint16]struct{}{}}
	for _, file := range []string{"tcp", "tcp6"} {
		err := addTCPSockets(sockets, filepath.Join(netDir, file))
		// tcp6 is missing when IPv6 is disabled
		if err != nil && (file == "tcp" || !os.IsNotExist(err)) {
			return nil, err
		}
	}
	return sockets, nil
}

// tcpListenState is TCP_LISTEN as /proc/net/tcp{,6} prints it
const tcpListenState = "0A"

func addTCPSockets(sockets *netnsSockets, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // header
	for scanner.Scan() {
		// "sl local_address rem_address st ...", e.g. "0: 0100007F:1F90 0100007F:D431 01 ..."
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		var conn tcpConn
		var okLocal, okRemote bool
		conn.local, conn.localPort, okLocal = parseProcNetEndpoint(fields[1])
		conn.remote, conn.remotePort, okRemote = parseProcNetEndpoint(fields[2])
		switch {
		case !okLocal || !okRemote:
		case fields[3] == tcpListenState:
			sockets.listening[conn.localPort] = struct{}{}
		default:
			sockets.open[conn] = struct{}{}
		}
	}
	return scanner.Err()
}

// parseProcNetEndpoint parses "ADDR:PORT" of /proc/net/tcp{,6}. The kernel prints the address
// as 32-bit words in host byte order; IPv4 addresses are returned IPv4-mapped.
func parseProcNetEndpoint(endpoint string) ([16]byte, uint16, bool) {
	var addr [16]byte
	addrHex, portHex, ok := strings.Cut(endpoint, ":")
	if !ok {
		return addr, 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return addr, 0, false
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return addr, 0, false
	}

	switch len(raw) {
	case 4:
		addr[10], addr[11] = 0xff, 0xff
		binary.NativeEndian.PutUint32(addr[12:], binary.BigEndian.Uint32(raw))
	case 16:
		for i := 0; i < len(raw); i += 4 {
			binary.NativeEndian.PutUint32(addr[i:], binary.BigEndian.Uint32(raw[i:]))
		}
	default:
		return addr, 0, false
	}
	return addr, uint16(port), true
}
