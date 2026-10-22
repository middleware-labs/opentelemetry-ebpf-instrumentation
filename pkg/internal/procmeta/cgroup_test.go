// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procmeta

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Sys().(*syscall.Stat_t).Ino
}

func TestCgroupIndex(t *testing.T) {
	procRoot := t.TempDir()
	localCgroupRoot = filepath.Join(procRoot, "missing")
	assert.Nil(t, NewCgroupIndex(procRoot), "no cgroup v2 tree")

	root := filepath.Join(procRoot, "1", "root", "sys", "fs", "cgroup")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644))
	docker := strings.Repeat("a", 64)
	kube := strings.Repeat("b", 64)
	dockerDir := filepath.Join(root, "system.slice", "docker-"+docker+".scope")
	kubeDir := filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod1234.slice", "cri-containerd-"+kube+".scope")
	userDir := filepath.Join(root, "user.slice", "user-1000.slice")
	for _, dir := range []string{dockerDir, kubeDir, userDir} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}

	c := NewCgroupIndex(procRoot)
	require.NotNil(t, c)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	assert.Equal(t, docker, c.ContainerID(inode(t, dockerDir)))
	assert.Equal(t, kube, c.ContainerID(inode(t, kubeDir)))
	assert.Equal(t, kube, c.ContainerID(inode(t, kubeDir)|7<<32), "the inode generation of kernels before 5.5")
	assert.Empty(t, c.ContainerID(inode(t, userDir)), "not a container")

	// a new container is only found after minWalkInterval
	newContainer := strings.Repeat("c", 64)
	newDir := filepath.Join(root, "system.slice", "docker-"+newContainer+".scope")
	require.NoError(t, os.MkdirAll(newDir, 0o755))
	assert.Empty(t, c.ContainerID(inode(t, newDir)))
	now = now.Add(minWalkInterval)
	assert.Equal(t, newContainer, c.ContainerID(inode(t, newDir)))
}
