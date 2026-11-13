// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic

import (
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func tcpKey(port uint16) key {
	k := key{Protocol: syscall.IPPROTO_TCP}
	k.Conn.S_port = port
	return k
}

func udpKey(port uint16) key {
	k := key{Protocol: syscall.IPPROTO_UDP}
	k.Conn.S_port = port
	return k
}

func TestDeltaFirstTimeIsWholeValue(t *testing.T) {
	d := newDeltaTracker()
	k := tcpKey(1)

	// a short connection seen only through its close event
	assert.Equal(t, totals{txBytes: 76, rxBytes: 853, txPackets: 5, rxPackets: 4},
		d.closed(&k, totals{txBytes: 76, rxBytes: 853, txPackets: 5, rxPackets: 4}, 0))
	assert.Empty(t, d.entries)
}

func TestDeltaKeepAliveIsNotCountedTwice(t *testing.T) {
	d := newDeltaTracker()
	k := tcpKey(1)

	assert.Equal(t, totals{txBytes: 100, txPackets: 3}, d.update(&k, totals{txBytes: 100, txPackets: 3}, 0))
	// idle across reads: no increase
	assert.Equal(t, totals{}, d.update(&k, totals{txBytes: 100, txPackets: 3}, time.Second))
	assert.Equal(t, totals{}, d.update(&k, totals{txBytes: 100, txPackets: 3}, 2*time.Second))
	assert.Equal(t, totals{txBytes: 50, txPackets: 1}, d.update(&k, totals{txBytes: 150, txPackets: 4}, 3*time.Second))
	assert.Equal(t, totals{rxBytes: 10, rxPackets: 2}, d.closed(&k, totals{txBytes: 150, rxBytes: 10, txPackets: 4, rxPackets: 2}, 4*time.Second))
	assert.Zero(t, d.underflows)
}

func TestDeltaUnderflowIsClamped(t *testing.T) {
	d := newDeltaTracker()
	k := tcpKey(1)

	d.update(&k, totals{txBytes: 100, txPackets: 30}, 0)
	// another socket with the same addresses: its packet total is lower
	assert.Equal(t, totals{txBytes: 20}, d.update(&k, totals{txBytes: 120, txPackets: 2}, time.Second))
	assert.Equal(t, uint64(1), d.underflows)
	assert.Equal(t, totals{txPackets: 3}, d.update(&k, totals{txBytes: 120, txPackets: 5}, 2*time.Second))
}

func TestDeltaOpenSince(t *testing.T) {
	d := newDeltaTracker()
	k := tcpKey(1)

	d.markOpen(&k, time.Minute)
	assert.False(t, d.openSince(&k, 0), "unknown keys are never open")

	d.update(&k, totals{txBytes: 1}, time.Minute)
	assert.False(t, d.openSince(&k, 0), "not checked yet")
	d.markOpen(&k, 2*time.Minute)
	assert.True(t, d.openSince(&k, time.Minute))
	assert.False(t, d.openSince(&k, 2*time.Minute))
}

func TestDeltaPrune(t *testing.T) {
	d := newDeltaTracker()
	old, recent := tcpKey(1), tcpKey(2)
	d.update(&old, totals{txBytes: 1}, time.Minute)
	d.update(&recent, totals{txBytes: 1}, 20*time.Minute)

	d.prune(10 * time.Minute)
	assert.NotContains(t, d.entries, old)
	assert.Contains(t, d.entries, recent)
}
