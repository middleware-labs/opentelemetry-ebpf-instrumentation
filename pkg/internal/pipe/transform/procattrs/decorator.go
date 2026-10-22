// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package procattrs adds the process and the container of each side to the network metrics.
package procattrs // import "go.opentelemetry.io/obi/pkg/internal/pipe/transform/procattrs"

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/procmeta"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func log() *slog.Logger { return slog.With("component", "procattrs.Decorator") }

// pairsTTL is how long the attributes of a pair of processes are reused before they are looked
// up again: like procmeta's own cache, a reused PID gets its new process after this time
const pairsTTL = 5 * time.Second

// DecoratorProvider gives each item the process and container of its source and destination
// processes. getProcs returns a zero Process for an unknown side. The items of the same pair of
// processes share one read-only procmeta.Pair, like the process spans of OpenTelemetry's network
// reducer: each pair is looked up once per pairsTTL. It is bypassed when newResolver is nil: no
// process or container attribute is selected.
func DecoratorProvider[T any](
	newResolver func(ctx context.Context) (*procmeta.Resolver, error),
	getProcs func(T) (src, dst procmeta.Process),
	setPair func(T, *procmeta.Pair),
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if newResolver == nil {
			return swarm.Bypass(input, output)
		}
		resolver, err := newResolver(ctx)
		if err != nil {
			return nil, err
		}
		pairs := newPairCache(resolver)
		in := input.Subscribe(msg.SubscriberName("procattrs.Decorator"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, log().Debug, func(items []T) {
				pairs.expire(time.Now())
				for _, item := range items {
					setPair(item, pairs.get(getProcs(item)))
				}
				output.Send(items)
			})
		}, nil
	}
}

type pairKey struct {
	src, dst procmeta.Process
}

// pairCache keeps the procmeta.Pair of each pair of processes. It is not safe for concurrent use.
type pairCache struct {
	resolver *procmeta.Resolver
	pairs    map[pairKey]*procmeta.Pair
	from     time.Time
}

func newPairCache(resolver *procmeta.Resolver) *pairCache {
	return &pairCache{resolver: resolver, pairs: map[pairKey]*procmeta.Pair{}}
}

// expire forgets all the pairs every pairsTTL
func (c *pairCache) expire(now time.Time) {
	if now.Sub(c.from) < pairsTTL {
		return
	}
	clear(c.pairs)
	c.from = now
}

// get returns the shared Pair of two processes, nil when both are unknown
func (c *pairCache) get(src, dst procmeta.Process) *procmeta.Pair {
	if src.Pid == 0 && dst.Pid == 0 {
		return nil
	}
	key := pairKey{src: src, dst: dst}
	if p, ok := c.pairs[key]; ok {
		return p
	}
	p := &procmeta.Pair{Src: c.resolver.Info(src), Dst: c.resolver.Info(dst)}
	c.pairs[key] = p
	return p
}
