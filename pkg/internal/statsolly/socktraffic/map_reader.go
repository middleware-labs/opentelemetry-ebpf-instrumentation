// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic // import "go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"

import (
	"errors"
	"log/slog"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

const readBatchLen = 1024

type (
	key = ebpf.StatsSocketTrafficKeyT
	row = ebpf.StatsSocketTrafficT
)

type mapIterator interface {
	Next(key, value any) bool
	Err() error
}

// trafficMap extracts the used methods from ebpf.Map, for testing.
type trafficMap[IT mapIterator] interface {
	BatchLookup(cursor *ciliumebpf.MapBatchCursor, keysOut, valuesOut any, opts *ciliumebpf.BatchOptions) (int, error)
	Iterate() IT
	Delete(key any) error
}

// mapReader reads all the rows of the socket_traffic map, without deleting them. It uses
// the batch operations when the kernel supports them, and iterates the map otherwise
// (RHEL8 kernels).
type mapReader[IT mapIterator] struct {
	log       *slog.Logger
	m         trafficMap[IT]
	useLegacy bool
	// chosen is true once the reader implementation is known to work
	chosen bool

	// lookup is not called concurrently, so the batch slices are reused
	keys []key
	rows []row
}

func newMapReader[IT mapIterator](m trafficMap[IT], forcedType config.EBPFMapReader) *mapReader[IT] {
	return &mapReader[IT]{
		log:       slog.With("component", "socktraffic.mapReader"),
		m:         m,
		useLegacy: forcedType == config.MapReaderLegacy,
		chosen:    forcedType != config.MapReaderAuto,
		keys:      make([]key, readBatchLen),
		rows:      make([]row, readBatchLen),
	}
}

// lookup calls fn for each row of the map.
func (r *mapReader[IT]) lookup(fn func(*key, *row)) error {
	if r.useLegacy {
		return r.iterate(fn)
	}

	err := r.batchLookup(fn)
	if !r.chosen {
		if errors.Is(err, ciliumebpf.ErrNotSupported) {
			r.log.Warn("batch map lookup is not supported, falling back to legacy map iteration. This"+
				" is expected in RHEL8-based systems", "error", err)
			r.useLegacy = true
			r.chosen = true
			return r.iterate(fn)
		}
		r.chosen = err == nil
	}
	return err
}

func (r *mapReader[IT]) delete(k *key) error {
	return r.m.Delete(k)
}

func (r *mapReader[IT]) batchLookup(fn func(*key, *row)) error {
	cursor := ciliumebpf.MapBatchCursor{}
	for {
		n, err := r.m.BatchLookup(&cursor, r.keys, r.rows, nil)
		for i := range n {
			fn(&r.keys[i], &r.rows[i])
		}
		if errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			// end of the map
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (r *mapReader[IT]) iterate(fn func(*key, *row)) error {
	var k key
	var v row
	iterator := r.m.Iterate()
	for iterator.Next(&k, &v) {
		fn(&k, &v)
	}
	return iterator.Err()
}
