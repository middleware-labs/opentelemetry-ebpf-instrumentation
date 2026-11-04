// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package nat // import "go.opentelemetry.io/obi/pkg/internal/statsolly/nat"

import (
	"context"
	"errors"
)

var errUnsupported = errors.New("conntrack is only supported on Linux")

type netlinkConntrack struct{}

func newNetlinkConntrack(uint32) (*netlinkConntrack, error) {
	return nil, errUnsupported
}

func (*netlinkConntrack) lookup(*key) (translation, bool) {
	return translation{}, false
}

func (*netlinkConntrack) run(context.Context) {}

func dumpConntrack(uint32, func(orig, reply *key)) error {
	return errUnsupported
}
