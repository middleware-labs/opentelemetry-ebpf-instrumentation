// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfconvenience // import "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// AttachSocketFilter opens a raw socket that receives all the packets of the calling thread's
// network namespace and attaches the program to it. The socket is bound to the packets only after
// the filter is attached, so it never queues any packet that the filter did not see.
func AttachSocketFilter(prog *ebpf.Program, name string) (io.Closer, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening raw socket: %w", err)
	}
	sock := os.NewFile(uintptr(fd), name)

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD()); err != nil {
		sock.Close()
		return nil, fmt.Errorf("attaching socket filter: %w", err)
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL)}); err != nil {
		sock.Close()
		return nil, fmt.Errorf("binding raw socket: %w", err)
	}
	return sock, nil
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}
