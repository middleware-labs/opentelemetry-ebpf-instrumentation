// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package netns // import "go.opentelemetry.io/obi/pkg/internal/netns"

func WithNetNS(_ int, fn func() error) error {
	return fn()
}

func IsIsolated(_ int) (bool, error) {
	return false, nil
}

func Inode(_ int) (uint64, error) {
	return 0, nil
}
