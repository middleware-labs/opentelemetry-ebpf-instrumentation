// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procattrs

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/procmeta"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type item struct {
	src, dst uint32
	pair     *procmeta.Pair
}

func getProcs(i *item) (procmeta.Process, procmeta.Process) {
	return procmeta.Process{Pid: i.src, ExecName: "p" + strconv.Itoa(int(i.src))},
		procmeta.Process{Pid: i.dst, ExecName: "p" + strconv.Itoa(int(i.dst))}
}

func setPair(i *item, p *procmeta.Pair) { i.pair = p }

func TestPairCacheSharesThePairOfTheSameProcesses(t *testing.T) {
	// a /proc without the PIDs: the names come from the kernel
	c := newPairCache(procmeta.NewResolver(t.TempDir(), procmeta.Sources{}))
	now := time.Unix(1000, 0)
	c.expire(now)

	a := c.get(getProcs(&item{src: 1, dst: 2}))
	b := c.get(getProcs(&item{src: 1, dst: 2}))
	assert.Same(t, a, b, "the same processes share one pair")
	assert.Equal(t, procmeta.Pair{Src: procmeta.Info{ExecName: "p1"}, Dst: procmeta.Info{ExecName: "p2"}}, *a)
	assert.NotSame(t, a, c.get(getProcs(&item{src: 2, dst: 1})))
	assert.Nil(t, c.get(procmeta.Process{}, procmeta.Process{}), "both unknown")

	c.expire(now.Add(pairsTTL / 2))
	assert.Same(t, a, c.get(getProcs(&item{src: 1, dst: 2})))
	c.expire(now.Add(pairsTTL))
	assert.NotSame(t, a, c.get(getProcs(&item{src: 1, dst: 2})), "looked up again after pairsTTL")
}

func TestDecoratorProvider(t *testing.T) {
	procRoot := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "self"), 0o755))
	newResolver := func(_ context.Context) (*procmeta.Resolver, error) {
		return procmeta.NewResolver(procRoot, procmeta.Sources{}), nil
	}
	input := msg.NewQueue[[]*item](msg.ChannelBufferLen(1))
	output := msg.NewQueue[[]*item](msg.ChannelBufferLen(1))
	run, err := DecoratorProvider(newResolver, getProcs, setPair, input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go run(t.Context())
	input.Send([]*item{{src: 1, dst: 2}, {src: 1, dst: 2}, {}})
	select {
	case got := <-out:
		require.Len(t, got, 3)
		assert.Equal(t, "p1", got[0].pair.Src.ExecName)
		assert.Same(t, got[0].pair, got[1].pair)
		assert.Nil(t, got[2].pair)
	case <-time.After(5 * time.Second):
		t.Fatal("the decorator did not forward the items")
	}
}

func TestDecoratorProviderBypassedWithoutAttributes(t *testing.T) {
	input := msg.NewQueue[[]*item](msg.ChannelBufferLen(1))
	output := msg.NewQueue[[]*item](msg.ChannelBufferLen(1))
	run, err := DecoratorProvider(nil, getProcs, setPair, input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go run(t.Context())
	input.Send([]*item{{src: 1}})
	select {
	case got := <-out:
		require.Len(t, got, 1)
		assert.Nil(t, got[0].pair)
	case <-time.After(5 * time.Second):
		t.Fatal("the bypass did not forward the items")
	}
}
