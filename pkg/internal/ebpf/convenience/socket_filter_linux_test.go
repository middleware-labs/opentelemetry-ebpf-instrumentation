// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfconvenience

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestHtons(t *testing.T) {
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, htons(unix.ETH_P_ALL))
	assert.Equal(t, []byte{0x00, 0x03}, b, "network byte order")
}
