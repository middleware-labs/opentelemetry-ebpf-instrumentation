// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expire // import "go.opentelemetry.io/obi/pkg/export/expire"

import (
	"encoding/binary"
	"hash/maphash"
	"slices"
	"strconv"
	"sync"
	"time"
)

type Clock func() time.Time

// ExpiryMap stores elements in a synchronized map, and removes them if they haven't been
// accessed/updated for a given time period
type ExpiryMap[T any] struct {
	clock Clock
	mt    sync.RWMutex
	ttl   time.Duration
	seed  maphash.Seed
	// entries by the hash of their label values. The entries whose label values have the same
	// hash share a bucket, so a hash collision never merges two entries.
	entries map[uint64][]*entry[T]
}

type entry[T any] struct {
	lastAccess  time.Time
	labelValues []string
	val         T
}

// NewExpiryMap creates an expiry map given a Clock implementation and a TTL.
// Its labeled instances are dropped if they haven't been updated during the
// last timeout period
func NewExpiryMap[T any](clock Clock, ttl time.Duration) *ExpiryMap[T] {
	em := &ExpiryMap[T]{
		ttl:     ttl,
		seed:    maphash.MakeSeed(),
		entries: map[uint64][]*entry[T]{},
		clock:   clock,
	}
	return em
}

// GetOrCreate returns the stored object for the given slice of label
// values. If that combination of
// label values is accessed for the first time, a new instance is created.
// If not, a cached copy is returned and the "last access" cache time is updated.
// The caller can reuse lbls after the call.
func (ex *ExpiryMap[T]) GetOrCreate(lbls []string, instancer func() T) T {
	now := ex.clock()

	h := ex.labelsHash(lbls)
	ex.mt.RLock()
	e, _ := find(ex.entries[h], lbls)
	ex.mt.RUnlock()
	if e != nil {
		ex.mt.Lock()
		e.lastAccess = now
		ex.mt.Unlock()
		return e.val
	}

	ex.mt.Lock()
	defer ex.mt.Unlock()
	// another call can have created it since the read lock
	if e, _ := find(ex.entries[h], lbls); e != nil {
		e.lastAccess = now
		return e.val
	}
	instance := instancer()
	ex.entries[h] = append(ex.entries[h], &entry[T]{
		labelValues: slices.Clone(lbls),
		lastAccess:  now,
		val:         instance,
	})
	return instance
}

// Delete removes and returns the entry for the label values.
func (ex *ExpiryMap[T]) Delete(lbls []string) (T, bool) {
	h := ex.labelsHash(lbls)
	ex.mt.Lock()
	defer ex.mt.Unlock()

	e, i := find(ex.entries[h], lbls)
	if e == nil {
		var zero T
		return zero, false
	}
	bucket := slices.Delete(ex.entries[h], i, i+1)
	if len(bucket) == 0 {
		delete(ex.entries, h)
	} else {
		ex.entries[h] = bucket
	}
	return e.val, true
}

// DeleteExpired entries and return their label set
func (ex *ExpiryMap[T]) DeleteExpired() []T {
	// If TTL is 0, disable expiration completely
	if ex.ttl == 0 {
		return nil
	}

	var delEntries []T
	ex.mt.Lock()
	defer ex.mt.Unlock()
	now := ex.clock()
	for h, bucket := range ex.entries {
		kept := bucket[:0]
		for _, e := range bucket {
			if now.Sub(e.lastAccess) > ex.ttl {
				delEntries = append(delEntries, e.val)
			} else {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(ex.entries, h)
			continue
		}
		clear(bucket[len(kept):])
		ex.entries[h] = kept
	}
	return delEntries
}

// DeleteAll cleans the map and returns a slice with its deleted elements
func (ex *ExpiryMap[T]) DeleteAll() []T {
	ex.mt.Lock()
	defer ex.mt.Unlock()
	entries := make([]T, 0, len(ex.entries))
	for _, bucket := range ex.entries {
		for _, e := range bucket {
			entries = append(entries, e.val)
		}
	}
	clear(ex.entries)
	return entries
}

// All returns an array with all the stored entries. It might contain expired entries
// if DeleteExpired is not invoked before it.
// TODO: use https://tip.golang.org/wiki/RangefuncExperiment when available
func (ex *ExpiryMap[T]) All() []T {
	ex.mt.RLock()
	items := make([]T, 0, len(ex.entries))
	for _, bucket := range ex.entries {
		for _, e := range bucket {
			items = append(items, e.val)
		}
	}
	ex.mt.RUnlock()
	return items
}

// labelsHash hashes label values with the encoding of LabelsKey, so that values containing
// its separator can't be ambiguous
func (ex *ExpiryMap[T]) labelsHash(labels []string) uint64 {
	var h maphash.Hash
	h.SetSeed(ex.seed)
	var length [binary.MaxVarintLen64]byte
	for _, label := range labels {
		_, _ = h.Write(length[:binary.PutUvarint(length[:], uint64(len(label)))])
		_, _ = h.WriteString(label)
	}
	return h.Sum64()
}

// find returns the entry of a bucket with the given label values, and its index
func find[T any](bucket []*entry[T], labels []string) (*entry[T], int) {
	for i, e := range bucket {
		if slices.Equal(e.labelValues, labels) {
			return e, i
		}
	}
	return nil, -1
}

// LabelsKey encodes label values without ambiguity between values.
func LabelsKey(labels []string) string {
	size := 0
	for _, label := range labels {
		size += len(label) + 2
		for length := len(label); length >= 10; length /= 10 {
			size++
		}
	}
	key := make([]byte, 0, size)
	for _, label := range labels {
		key = strconv.AppendInt(key, int64(len(label)), 10)
		key = append(key, ':')
		key = append(key, label...)
	}
	return string(key)
}
