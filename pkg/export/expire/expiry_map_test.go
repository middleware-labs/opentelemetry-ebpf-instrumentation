// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expire

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpiryMap_DisableExpiration(t *testing.T) {
	// Mock clock that we can control
	now := time.Now()
	clock := func() time.Time { return now }

	// Create expiry map with TTL=0 (should disable expiration)
	em := NewExpiryMap[string](clock, 0)

	// Add some entries
	val1 := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "entry1" })
	val2 := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "entry2" })

	assert.Equal(t, "entry1", val1)
	assert.Equal(t, "entry2", val2)

	// Advance time significantly (would normally cause expiration)
	now = now.Add(10 * time.Hour)

	// Try to delete expired entries - should return empty slice when TTL=0
	expired := em.DeleteExpired()
	assert.Empty(t, expired, "No entries should expire when TTL=0")

	// Verify entries are still there
	val1Again := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "should_not_be_called" })
	val2Again := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "should_not_be_called" })

	assert.Equal(t, "entry1", val1Again)
	assert.Equal(t, "entry2", val2Again)
}

func TestExpiryMap_NormalExpiration(t *testing.T) {
	// Mock clock that we can control
	now := time.Now()
	clock := func() time.Time { return now }

	// Create expiry map with TTL=5 minutes
	em := NewExpiryMap[string](clock, 5*time.Minute)

	// Add some entries
	val1 := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "entry1" })
	val2 := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "entry2" })

	assert.Equal(t, "entry1", val1)
	assert.Equal(t, "entry2", val2)

	// Advance time beyond TTL
	now = now.Add(10 * time.Minute)

	// Delete expired entries - should return the expired entries
	expired := em.DeleteExpired()
	assert.Len(t, expired, 2, "Both entries should expire after 10 minutes with TTL=5 minutes")
	assert.Contains(t, expired, "entry1")
	assert.Contains(t, expired, "entry2")

	// Verify entries are gone - should create new ones
	val1Again := em.GetOrCreate([]string{"label1", "value1"}, func() string { return "new_entry1" })
	val2Again := em.GetOrCreate([]string{"label2", "value2"}, func() string { return "new_entry2" })

	assert.Equal(t, "new_entry1", val1Again)
	assert.Equal(t, "new_entry2", val2Again)
}

func TestExpiryMap_Delete(t *testing.T) {
	em := NewExpiryMap[string](time.Now, time.Minute)
	em.GetOrCreate([]string{"label", "value"}, func() string { return "entry" })

	value, ok := em.Delete([]string{"label", "value"})
	assert.Equal(t, "entry", value)
	assert.True(t, ok)
	_, ok = em.Delete([]string{"label", "value"})
	assert.False(t, ok)
	assert.Empty(t, em.All())
}

func TestExpiryMap_DistinctLabelsWithColons(t *testing.T) {
	em := NewExpiryMap[string](time.Now, time.Minute)

	first := em.GetOrCreate([]string{"checkout:blue", "prod"}, func() string { return "first" })
	second := em.GetOrCreate([]string{"checkout", "blue:prod"}, func() string { return "second" })

	assert.Equal(t, "first", first)
	assert.Equal(t, "second", second)
	assert.Len(t, em.All(), 2)
}

func TestExpiryMap_GetOrCreateKeepsItsLabels(t *testing.T) {
	em := NewExpiryMap[string](time.Now, time.Minute)
	// a buffer that the caller reuses for its next labels
	labels := []string{"service", "checkout"}
	em.GetOrCreate(labels, func() string { return "checkout" })
	labels[1] = "orders"

	assert.Equal(t, "checkout", em.GetOrCreate([]string{"service", "checkout"}, func() string { return "new" }))
	assert.Equal(t, "orders", em.GetOrCreate(labels, func() string { return "orders" }))
	assert.Len(t, em.All(), 2)
}

func TestExpiryMap_SharedHash(t *testing.T) {
	now := time.Unix(100, 0)
	em := NewExpiryMap[string](func() time.Time { return now }, time.Minute)
	// two label sets whose hashes collide share a bucket
	first, second := []string{"first"}, []string{"second"}
	h := em.labelsHash(first)
	em.entries[h] = []*entry[string]{
		{labelValues: first, lastAccess: now, val: "first"},
		{labelValues: second, lastAccess: now.Add(-2 * time.Minute), val: "second"},
	}
	find := func(lbls []string) string {
		e, _ := find(em.entries[h], lbls)
		if e == nil {
			return ""
		}
		return e.val
	}
	assert.Equal(t, "first", find(first))
	assert.Equal(t, "second", find(second))

	assert.Equal(t, []string{"second"}, em.DeleteExpired())
	assert.Equal(t, []string{"first"}, em.All())

	em.entries[h] = append(em.entries[h], &entry[string]{labelValues: second, lastAccess: now, val: "second"})
	value, ok := em.Delete(first)
	assert.True(t, ok)
	assert.Equal(t, "first", value)
	assert.Equal(t, "second", find(second), "the other entry of the bucket stays")
}

func TestExpiryMap_DeleteRemovesAnEmptyBucket(t *testing.T) {
	em := NewExpiryMap[string](time.Now, time.Minute)
	em.GetOrCreate([]string{"label"}, func() string { return "entry" })

	_, ok := em.Delete([]string{"label"})
	assert.True(t, ok)
	assert.Empty(t, em.entries)
}

func BenchmarkExpiryMap_GetOrCreateExisting(b *testing.B) {
	em := NewExpiryMap[string](time.Now, time.Minute)
	labels := make([]string, 80)
	for i := range labels {
		labels[i] = "attribute.name.or.value"
	}
	em.GetOrCreate(labels, func() string { return "entry" })

	b.ReportAllocs()
	for b.Loop() {
		em.GetOrCreate(labels, func() string { return "entry" })
	}
}
