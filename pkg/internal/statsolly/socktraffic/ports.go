// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

type portKey = ebpf.StatsSockPortNs

// udpStateUnconnected is the state of /proc/<pid>/net/udp for a socket with a local port
// and no remote (TCP_CLOSE): a server socket.
const udpStateUnconnected = "07"

// Linux defaults, used when ip_local_port_range can't be read
const (
	defaultEphemeralLow  = 32768
	defaultEphemeralHigh = 60999
)

// SeedUDPPortBindings adds to the udp_port_bindings map the UDP ports bound before OBI
// started, like Datadog's initializePortBindingMaps. It must run after the bind probes are
// attached, so no bind is missed, and before the probes that create the rows, so no row takes
// the client role of a server port. The ports already in the map are kept.
func SeedUDPPortBindings(bindings *ciliumebpf.Map, procRoot string) error {
	ports, err := boundUDPPorts(procRoot)
	if err != nil {
		return err
	}
	for k, count := range ports {
		if err := bindings.Update(&k, &count, ciliumebpf.UpdateNoExist); err != nil &&
			!errors.Is(err, ciliumebpf.ErrKeyExist) {
			return fmt.Errorf("adding UDP port %d of netns %d: %w", k.Port, k.Netns, err)
		}
	}
	return nil
}

// boundUDPPorts reads /proc/<pid>/net/udp and udp6 of one process per network namespace.
// /proc/net/udp would only show OBI's own namespace. The inode of /proc/<pid>/ns/net is
// the netns value of the kernel probes.
func boundUDPPorts(procRoot string) (map[portKey]uint32, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", procRoot, err)
	}
	low, high := ephemeralPortRange(procRoot)

	ports := map[portKey]uint32{}
	readNetns := map[uint32]struct{}{}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		pidDir := filepath.Join(procRoot, entry.Name())
		netns, err := netnsInode(pidDir)
		if err != nil {
			// the process ended or is not readable
			continue
		}
		if _, ok := readNetns[netns]; ok {
			continue
		}
		readNetns[netns] = struct{}{}

		for _, file := range []string{"udp", "udp6"} {
			addUnconnectedUDPPorts(ports, netns, filepath.Join(pidDir, "net", file), low, high)
		}
	}
	return ports, nil
}

// netnsInode parses the "net:[4026531840]" link of /proc/<pid>/ns/net
func netnsInode(pidDir string) (uint32, error) {
	link, err := os.Readlink(filepath.Join(pidDir, "ns", "net"))
	if err != nil {
		return 0, err
	}
	inode, ok := strings.CutPrefix(link, "net:[")
	if !ok {
		return 0, fmt.Errorf("unexpected netns link %q", link)
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(inode, "]"), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unexpected netns link %q: %w", link, err)
	}
	return uint32(n), nil
}

// addUnconnectedUDPPorts counts the local ports of the unconnected sockets of a
// /proc/<pid>/net/udp{,6} file, skipping the ephemeral ports of the clients
func addUnconnectedUDPPorts(ports map[portKey]uint32, netns uint32, path string, low, high uint16) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // header
	for scanner.Scan() {
		// "sl local_address rem_address st ...", e.g. "0: 00000000:0035 00000000:0000 07 ..."
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != udpStateUnconnected {
			continue
		}
		_, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || (uint16(port) >= low && uint16(port) <= high) {
			continue
		}
		ports[portKey{Netns: netns, Port: uint16(port)}]++
	}
}

func ephemeralPortRange(procRoot string) (uint16, uint16) {
	content, err := os.ReadFile(filepath.Join(procRoot, "sys", "net", "ipv4", "ip_local_port_range"))
	if err != nil {
		return defaultEphemeralLow, defaultEphemeralHigh
	}
	fields := strings.Fields(string(content))
	if len(fields) != 2 {
		return defaultEphemeralLow, defaultEphemeralHigh
	}
	low, errLow := strconv.ParseUint(fields[0], 10, 16)
	high, errHigh := strconv.ParseUint(fields[1], 10, 16)
	if errLow != nil || errHigh != nil {
		return defaultEphemeralLow, defaultEphemeralHigh
	}
	return uint16(low), uint16(high)
}
