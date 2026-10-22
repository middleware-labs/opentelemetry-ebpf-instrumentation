// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package socktraffic

import (
	"errors"
	"slices"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
)

// fakeMap holds the rows in insertion order and returns them in batches of batchLen
type fakeMap struct {
	keys       []key
	rows       []row
	batchLen   int
	batchErr   error
	batchCalls int
	// next batch of the read in progress: the fake ignores the cursor
	page int
}

func (f *fakeMap) BatchLookup(_ *ciliumebpf.MapBatchCursor, keysOut, valuesOut any, _ *ciliumebpf.BatchOptions) (int, error) {
	f.batchCalls++
	if f.batchErr != nil {
		return 0, f.batchErr
	}
	from := f.page * f.batchLen
	n := copy(keysOut.([]key), f.keys[min(from, len(f.keys)):min(from+f.batchLen, len(f.keys))])
	copy(valuesOut.([]row), f.rows[from:from+n])
	f.page++
	if from+n >= len(f.keys) {
		f.page = 0
		return n, ciliumebpf.ErrKeyNotExist
	}
	return n, nil
}

func (f *fakeMap) Iterate() *fakeIterator {
	return &fakeIterator{m: f}
}

func (f *fakeMap) Delete(k any) error {
	i := slices.Index(f.keys, *k.(*key))
	if i < 0 {
		return ciliumebpf.ErrKeyNotExist
	}
	f.keys = slices.Delete(f.keys, i, i+1)
	f.rows = slices.Delete(f.rows, i, i+1)
	return nil
}

func (f *fakeMap) set(k key, r row) {
	if i := slices.Index(f.keys, k); i >= 0 {
		f.rows[i] = r
		return
	}
	f.keys = append(f.keys, k)
	f.rows = append(f.rows, r)
}

type fakeIterator struct {
	m   *fakeMap
	pos int
}

func (it *fakeIterator) Next(k, v any) bool {
	if it.pos >= len(it.m.keys) {
		return false
	}
	*k.(*key) = it.m.keys[it.pos]
	*v.(*row) = it.m.rows[it.pos]
	it.pos++
	return true
}

func (it *fakeIterator) Err() error { return nil }

func newFakeMap(rows int) *fakeMap {
	f := &fakeMap{batchLen: 2}
	for i := range rows {
		k := key{}
		k.Conn.S_port = uint16(i + 1)
		f.set(k, row{TxBytes: uint64(i + 1)})
	}
	return f
}

func readPorts(t *testing.T, r *mapReader[*fakeIterator]) []uint16 {
	t.Helper()
	var ports []uint16
	require.NoError(t, r.lookup(func(k *key, v *row) {
		assert.Equal(t, uint64(k.Conn.S_port), v.TxBytes)
		ports = append(ports, k.Conn.S_port)
	}))
	return ports
}

func TestMapReaderBatchDoesNotDelete(t *testing.T) {
	m := newFakeMap(5)
	r := newMapReader[*fakeIterator](m, config.MapReaderAuto)

	assert.Equal(t, []uint16{1, 2, 3, 4, 5}, readPorts(t, r))
	assert.False(t, r.useLegacy)
	assert.True(t, r.chosen)

	// the rows stay in the map until they are closed or idle
	assert.Equal(t, []uint16{1, 2, 3, 4, 5}, readPorts(t, r))

	require.NoError(t, r.delete(&m.keys[0]))
	assert.Equal(t, []uint16{2, 3, 4, 5}, readPorts(t, r))
}

func TestMapReaderFallsBackToLegacy(t *testing.T) {
	m := newFakeMap(3)
	m.batchErr = ciliumebpf.ErrNotSupported
	r := newMapReader[*fakeIterator](m, config.MapReaderAuto)

	assert.Equal(t, []uint16{1, 2, 3}, readPorts(t, r))
	assert.True(t, r.useLegacy)
	assert.Len(t, m.keys, 3, "iterating must not delete")

	// the batch operation is not tried again
	readPorts(t, r)
	assert.Equal(t, 1, m.batchCalls)
}

func TestMapReaderForcedLegacy(t *testing.T) {
	m := newFakeMap(2)
	r := newMapReader[*fakeIterator](m, config.MapReaderLegacy)

	assert.Equal(t, []uint16{1, 2}, readPorts(t, r))
	assert.Zero(t, m.batchCalls)
}

func TestMapReaderForcedBatchDoesNotFallBack(t *testing.T) {
	m := newFakeMap(2)
	m.batchErr = ciliumebpf.ErrNotSupported
	r := newMapReader[*fakeIterator](m, config.MapReaderBatch)

	require.ErrorIs(t, r.lookup(func(*key, *row) {}), ciliumebpf.ErrNotSupported)
	assert.False(t, r.useLegacy)
}

func TestMapReaderAutoKeepsTryingBatchAfterOtherErrors(t *testing.T) {
	m := newFakeMap(2)
	m.batchErr = errors.New("transient")
	r := newMapReader[*fakeIterator](m, config.MapReaderAuto)

	require.Error(t, r.lookup(func(*key, *row) {}))
	assert.False(t, r.chosen)

	m.batchErr = nil
	assert.Equal(t, []uint16{1, 2}, readPorts(t, r))
	assert.False(t, r.useLegacy)
}
