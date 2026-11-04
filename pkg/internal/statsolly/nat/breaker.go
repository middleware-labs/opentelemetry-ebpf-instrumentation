// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nat // import "go.opentelemetry.io/obi/pkg/internal/statsolly/nat"

import "time"

// ewmaWeight is the weight of the last interval in the event rate, Datadog's: a lower weight
// smooths the bursts more
const ewmaWeight = 0.2

// circuitBreaker trips when the rate of the events goes over a limit, like Datadog's netlink
// CircuitBreaker: the rate is an exponentially weighted average, updated every interval.
type circuitBreaker struct {
	limit    float64
	interval time.Duration
	count    int
	rate     float64
	last     time.Time
}

func newCircuitBreaker(limit float64, interval time.Duration, now time.Time) *circuitBreaker {
	return &circuitBreaker{limit: limit, interval: interval, last: now}
}

// tick counts n events, and tells whether the rate is over the limit
func (b *circuitBreaker) tick(n int, now time.Time) bool {
	b.count += n
	elapsed := now.Sub(b.last)
	if elapsed < b.interval {
		return false
	}

	current := float64(b.count) / elapsed.Seconds()
	if b.rate == 0 {
		// not smoothed at the start, to trip on a rate that starts over the limit
		b.rate = current
	} else {
		b.rate = ewmaWeight*current + (1-ewmaWeight)*b.rate
	}
	b.count, b.last = 0, now
	return b.rate > b.limit
}

func (b *circuitBreaker) reset(now time.Time) {
	b.count, b.rate, b.last = 0, 0, now
}
