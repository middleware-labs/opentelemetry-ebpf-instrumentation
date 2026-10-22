// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procmeta

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProc writes /proc/<pid>/{stat,comm,exe} under root
func fakeProc(t *testing.T, root string, pid uint32, startTime int, exe, comm string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(int(pid)))
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	// the command name can contain spaces and parentheses
	stat := fmt.Sprintf("%d (%s) S 1 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 %d 1000 100", pid, comm, startTime)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644))
	if exe != "" {
		require.NoError(t, os.Symlink(exe, filepath.Join(dir, "exe")))
	}
}

type fakeSources struct {
	containers map[uint32]string
	cgroups    map[uint64]string
	kubeNames  map[string]string
	docker     map[string][2]string
	dockerHits int
}

func (f *fakeSources) sources() Sources {
	return Sources{
		ContainerID:         func(pid uint32) (string, error) { return f.containers[pid], nil },
		ContainerIDByCgroup: func(id uint64) string { return f.cgroups[id] },
		KubeContainerName:   func(cid string) string { return f.kubeNames[cid] },
		Docker: func(cid string) (string, string, bool) {
			f.dockerHits++
			d, ok := f.docker[cid]
			return d[0], d[1], ok
		},
	}
}

func testResolver(t *testing.T, src *fakeSources) (*Resolver, string, *time.Time) {
	t.Helper()
	root := t.TempDir()
	now := time.Unix(1000, 0)
	r := NewResolver(root, src.sources())
	r.now = func() time.Time { return now }
	return r, root, &now
}

func TestResolverProcessAndContainer(t *testing.T) {
	src := &fakeSources{
		containers: map[uint32]string{100: "c-kube", 200: "c-docker"},
		kubeNames:  map[string]string{"c-kube": "orders"},
		docker:     map[string][2]string{"c-docker": {"web", "myrepo/web:1.4"}},
	}
	r, root, _ := testResolver(t, src)
	fakeProc(t, root, 100, 50, "/usr/local/bin/python3.12", "python3")
	fakeProc(t, root, 200, 60, "/usr/sbin/nginx (deleted)", "nginx")
	fakeProc(t, root, 300, 70, "", "kworker/0:1 (x)")

	assert.Equal(t, Info{ExecName: "python3.12", ContainerID: "c-kube", ContainerName: "orders"}, r.Info(Process{Pid: 100}))
	assert.Equal(t, Info{ExecName: "nginx", ContainerID: "c-docker", ContainerName: "web", ImageName: "myrepo/web", ImageTag: "1.4"}, r.Info(Process{Pid: 200}))
	assert.Equal(t, Info{ExecName: "kworker/0:1 (x)"}, r.Info(Process{Pid: 300}), "no exe link: the command name, no container")
	assert.Equal(t, Info{}, r.Info(Process{Pid: 0}))
	assert.Equal(t, Info{}, r.Info(Process{Pid: 999}), "a process that is not visible")
}

func TestResolverPIDReuse(t *testing.T) {
	src := &fakeSources{containers: map[uint32]string{}}
	r, root, now := testResolver(t, src)
	fakeProc(t, root, 100, 50, "/bin/curl", "curl")
	assert.Equal(t, "curl", r.Info(Process{Pid: 100}).ExecName)

	// the process ends: its last stats keep its name
	require.NoError(t, os.RemoveAll(filepath.Join(root, "100")))
	*now = now.Add(recheckAfter)
	assert.Equal(t, "curl", r.Info(Process{Pid: 100}).ExecName)

	// another process gets the PID: it is found after recheckAfter
	fakeProc(t, root, 100, 90, "/usr/bin/redis-server", "redis-server")
	assert.Equal(t, "curl", r.Info(Process{Pid: 100}).ExecName, "still trusted until recheckAfter")
	*now = now.Add(recheckAfter)
	assert.Equal(t, "redis-server", r.Info(Process{Pid: 100}).ExecName)
}

func TestResolverForgetsUnusedPIDs(t *testing.T) {
	src := &fakeSources{}
	r, root, now := testResolver(t, src)
	fakeProc(t, root, 100, 50, "/bin/a", "a")
	fakeProc(t, root, 200, 50, "/bin/b", "b")
	r.Info(Process{Pid: 100})
	r.Info(Process{Pid: 200})

	*now = now.Add(unusedTTL / 2)
	r.Info(Process{Pid: 200})
	*now = now.Add(unusedTTL/2 + time.Minute)
	r.Info(Process{Pid: 200})
	assert.NotContains(t, r.pids, uint32(100))
	assert.Contains(t, r.pids, uint32(200))
}

func TestSplitImage(t *testing.T) {
	for image, want := range map[string][2]string{
		"nginx":                                {"nginx", ""},
		"nginx:1.27":                           {"nginx", "1.27"},
		"myrepo/orders:1.4":                    {"myrepo/orders", "1.4"},
		"registry:5000/org/app":                {"registry:5000/org/app", ""},
		"registry:5000/org/app:2.0@sha256:abc": {"registry:5000/org/app", "2.0"},
		"org/app@sha256:abc":                   {"org/app", ""},
		"":                                     {"", ""},
	} {
		name, tag := SplitImage(image)
		assert.Equal(t, want, [2]string{name, tag}, image)
	}
}

func TestResolverProcessThatEndedBeforeTheLookup(t *testing.T) {
	src := &fakeSources{
		cgroups:   map[uint64]string{77: "c-cron"},
		kubeNames: map[string]string{"c-cron": "nightly-report"},
		docker:    map[string][2]string{"c-cron": {"", "myrepo/report:3"}},
	}
	r, _, _ := testResolver(t, src)

	// a short-lived client: no /proc/<pid> any more, the kernel kept its name and cgroup
	assert.Equal(t, Info{
		ExecName: "curl", ContainerID: "c-cron", ContainerName: "nightly-report", ImageName: "myrepo/report", ImageTag: "3",
	}, r.Info(Process{Pid: 4242, ExecName: "curl", CgroupID: 77}))
	assert.Equal(t, Info{ExecName: "wget"}, r.Info(Process{Pid: 4243, ExecName: "wget", CgroupID: 99}), "not a container cgroup")
}

func TestResolverCachesTheContainers(t *testing.T) {
	src := &fakeSources{
		containers: map[uint32]string{100: "c-web", 101: "c-web", 102: "c-new"},
		docker:     map[string][2]string{"c-web": {"web", "nginx:1.27"}},
	}
	r, root, now := testResolver(t, src)
	fakeProc(t, root, 100, 50, "/usr/sbin/nginx", "nginx")
	fakeProc(t, root, 101, 51, "/usr/sbin/nginx", "nginx")
	fakeProc(t, root, 102, 52, "/app/server", "server")

	assert.Equal(t, "web", r.Info(Process{Pid: 100}).ContainerName)
	assert.Equal(t, "web", r.Info(Process{Pid: 101}).ContainerName)
	assert.Equal(t, 1, src.dockerHits, "one lookup per container")

	// a container not found yet is looked up again after recheckAfter
	assert.Empty(t, r.Info(Process{Pid: 102}).ContainerName)
	src.docker["c-new"] = [2]string{"api", "api:2"}
	assert.Empty(t, r.Info(Process{Pid: 102}).ContainerName)
	*now = now.Add(recheckAfter)
	assert.Equal(t, "api", r.Info(Process{Pid: 102}).ContainerName)
}
