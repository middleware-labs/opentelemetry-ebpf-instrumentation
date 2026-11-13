// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package timing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKernelTimeConvertsMonotonicToWallClock(t *testing.T) {
	// Only the scheduling gap between two clock readings has to fit in here
	// (measured worst case ~15µs); the rest is headroom for a CPU-throttled
	// CI runner.
	const tolerance = 100 * time.Millisecond

	// a timestamp taken right now must map back to right now
	require.WithinDuration(t, time.Now(), KernelTime(uint64(MonoTimeNow())), tolerance)

	// and an older timestamp must map further into the past, by the same
	// amount it is older (this is what catches a flipped sign)
	mono := MonoTimeNow()
	recent := KernelTime(uint64(mono))
	older := KernelTime(uint64(mono - time.Minute))
	require.WithinDuration(t, recent.Add(-time.Minute), older, tolerance)
}

func TestMonoClockFollowsMonoTimeNow(t *testing.T) {
	clock := MonoClock()
	time.Sleep(20 * time.Millisecond)
	// only the gap between the two readings separates them
	require.InDelta(t, float64(MonoTimeNow()), float64(clock()), float64(5*time.Millisecond))
}
