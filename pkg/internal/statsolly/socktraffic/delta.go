// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"time"
)

// totals are the counters of a socket_traffic row
type totals struct {
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
	// the TCP stat metrics, when they are read from the rows
	established    uint64
	retransFast    uint64
	retransTimeout uint64
	retransOther   uint64
	zeroWindow     uint64
	deliveredCE    uint64
	reordSeen      uint64
	rcvOOOPack     uint64
}

func rowTotals(r *row) totals {
	return totals{
		txBytes: r.TxBytes, rxBytes: r.RxBytes, txPackets: r.TxPackets, rxPackets: r.RxPackets,
		established: uint64(r.Established), retransFast: uint64(r.RetransFast),
		retransTimeout: uint64(r.RetransTimeout), retransOther: uint64(r.RetransOther),
		zeroWindow: uint64(r.ZeroWindowProbes), deliveredCE: uint64(r.DeliveredCe),
		reordSeen: uint64(r.ReordSeen), rcvOOOPack: uint64(r.RcvOoopack),
	}
}

// any tells whether some counter increased
func (t *totals) any() bool {
	return *t != totals{}
}

type deltaEntry struct {
	last     totals
	lastSeen time.Duration
	// openAt is when an idle TCP row was last found with its connection still open, 0 if never
	openAt time.Duration
}

// deltaTracker turns the totals of the socket_traffic rows into increases, like Datadog's
// connection state (pkg/network/state.go).
type deltaTracker struct {
	entries map[key]*deltaEntry
	// underflows counts the totals that went down: the socket was replaced by another one
	// with the same addresses
	underflows uint64
}

func newDeltaTracker() *deltaTracker {
	return &deltaTracker{entries: map[key]*deltaEntry{}}
}

// update returns the increase since the previous call for the same key. The first time,
// the whole value is the increase: a row is created at the first send or receive of its
// socket, so this counts the short connections that open and close between two reads.
// The TCP packets of a connection opened before OBI started are counted once, from the
// start of the connection, as Datadog does.
func (d *deltaTracker) update(k *key, now totals, at time.Duration) totals {
	e, ok := d.entries[*k]
	if !ok {
		d.entries[*k] = &deltaEntry{last: now, lastSeen: at}
		return now
	}

	underflow := false
	sub := func(now, last uint64) uint64 {
		if now < last {
			underflow = true
			return 0
		}
		return now - last
	}
	delta := totals{
		txBytes:        sub(now.txBytes, e.last.txBytes),
		rxBytes:        sub(now.rxBytes, e.last.rxBytes),
		txPackets:      sub(now.txPackets, e.last.txPackets),
		rxPackets:      sub(now.rxPackets, e.last.rxPackets),
		established:    sub(now.established, e.last.established),
		retransFast:    sub(now.retransFast, e.last.retransFast),
		retransTimeout: sub(now.retransTimeout, e.last.retransTimeout),
		retransOther:   sub(now.retransOther, e.last.retransOther),
		zeroWindow:     sub(now.zeroWindow, e.last.zeroWindow),
		deliveredCE:    sub(now.deliveredCE, e.last.deliveredCE),
		reordSeen:      sub(now.reordSeen, e.last.reordSeen),
		rcvOOOPack:     sub(now.rcvOOOPack, e.last.rcvOOOPack),
	}
	if underflow {
		d.underflows++
	}
	e.last = now
	e.lastSeen = at
	return delta
}

// closed returns the last increase of a closed socket and forgets it.
func (d *deltaTracker) closed(k *key, final totals, at time.Duration) totals {
	delta := d.update(k, final, at)
	delete(d.entries, *k)
	return delta
}

// markOpen records that the connection of an idle TCP row is still open
func (d *deltaTracker) markOpen(k *key, at time.Duration) {
	if e, ok := d.entries[*k]; ok {
		e.openAt = at
	}
}

// openSince reports whether the connection of an idle TCP row was found open after the given time
func (d *deltaTracker) openSince(k *key, since time.Duration) bool {
	e, ok := d.entries[*k]
	return ok && e.openAt != 0 && e.openAt > since
}

// prune forgets the keys last seen before the given time. It is a safety net: the keys are
// forgotten when their socket closes or their row is deleted.
func (d *deltaTracker) prune(before time.Duration) {
	for k, e := range d.entries {
		if e.lastSeen < before {
			delete(d.entries, k)
		}
	}
}
