// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procmeta // import "go.opentelemetry.io/obi/pkg/internal/procmeta"

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
)

// minWalkInterval limits how often the cgroup tree is walked again for an unknown cgroup ID
const minWalkInterval = 10 * time.Second

// localCgroupRoot is OBI's own view of the cgroup tree, when it is not under /proc/1/root
var localCgroupRoot = "/sys/fs/cgroup"

// CgroupIndex finds the container of a cgroup ID, as bpf_get_current_cgroup_id returns it: the
// inode of the cgroup v2 directory. It walks the host cgroup tree again on a miss. It is not
// safe for concurrent use.
type CgroupIndex struct {
	root     string
	ids      map[uint64]string
	lastWalk time.Time
	now      func() time.Time
}

// NewCgroupIndex returns nil without a cgroup v2 tree: cgroup v1 IDs are not the inodes. The host
// tree is read through /proc/1/root when OBI runs in a container with its own cgroup namespace.
func NewCgroupIndex(procRoot string) *CgroupIndex {
	for _, root := range []string{filepath.Join(procRoot, "1", "root", "sys", "fs", "cgroup"), localCgroupRoot} {
		if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err == nil {
			return &CgroupIndex{root: root, ids: map[uint64]string{}, now: time.Now}
		}
	}
	return nil
}

// ContainerID returns the container ID of a cgroup ID, "" when it is not a container cgroup
func (c *CgroupIndex) ContainerID(cgroupID uint64) string {
	if cid, ok := c.lookup(cgroupID); ok {
		return cid
	}
	if now := c.now(); now.Sub(c.lastWalk) >= minWalkInterval {
		c.lastWalk = now
		c.walk()
	}
	cid, _ := c.lookup(cgroupID)
	return cid
}

// lookup also tries the low 32 bits: before kernel 5.5, the cgroup ID has the inode generation
// in its high 32 bits
func (c *CgroupIndex) lookup(cgroupID uint64) (string, bool) {
	if cid, ok := c.ids[cgroupID]; ok {
		return cid, true
	}
	cid, ok := c.ids[cgroupID&0xffffffff]
	return cid, ok
}

// walk indexes the inodes of the cgroups of containers, forgetting the removed ones
func (c *CgroupIndex) walk() {
	ids := map[uint64]string{}
	_ = filepath.WalkDir(c.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		cid, ok := container.IDFromCgroupPath("/" + strings.TrimPrefix(path, c.root+"/"))
		if !ok {
			return nil
		}
		if info, err := d.Info(); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				ids[st.Ino] = cid
			}
		}
		return nil
	})
	c.ids = ids
}
