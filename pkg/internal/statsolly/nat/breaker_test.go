// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nat

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCircuitBreaker(t *testing.T) {
	start := time.Unix(1000, 0)
	b := newCircuitBreaker(100, 3*time.Second, start)

	assert.False(t, b.tick(1000, start.Add(time.Second)), "the rate is measured every interval")
	assert.True(t, b.tick(0, start.Add(3*time.Second)), "1000 events in 3s: 333/s at the start")
	assert.InDelta(t, 333, b.rate, 1)

	b.reset(start)
	assert.False(t, b.tick(240, start.Add(3*time.Second)), "80/s")
	// a burst over the limit is smoothed with the previous rate
	assert.False(t, b.tick(450, start.Add(6*time.Second)), "150/s: 0.2*150 + 0.8*80 = 94/s")
	assert.True(t, b.tick(1200, start.Add(9*time.Second)), "400/s: 0.2*400 + 0.8*94 = 155/s")
}
