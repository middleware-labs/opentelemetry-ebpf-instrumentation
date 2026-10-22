// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package procmeta finds the process and the container of a PID, for the network metrics.
package procmeta // import "go.opentelemetry.io/obi/pkg/internal/procmeta"

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Process is what the kernel kept about the process of a socket: its name and cgroup are still
// known when it ended before it was looked up (short-lived clients)
type Process struct {
	Pid uint32
	// ExecName is the base name of the executable, truncated to 15 characters
	ExecName string
	CgroupID uint64
}

// Info is what the network metrics report about the process of a socket
type Info struct {
	ExecName      string
	ContainerID   string
	ContainerName string
	ImageName     string
	ImageTag      string
}

// Pair is the process and container of both sides of a socket. It is shared by the items of
// the same processes: read-only.
type Pair struct {
	Src, Dst Info
}

const (
	// recheckAfter is how long a cached PID is trusted before its start time is read again:
	// a PID reused by a new process gets its own Info after at most this time. A container
	// whose name was not found is looked up again after this time too.
	recheckAfter = 5 * time.Second
	// unusedTTL forgets the PIDs, cgroups and containers that no metric asked for during this time
	unusedTTL = 5 * time.Minute
)

// Sources are the lookups of the container of a process. A nil source is skipped.
type Sources struct {
	// ContainerID returns the container ID of a running process, from its cgroup
	ContainerID func(pid uint32) (string, error)
	// ContainerIDByCgroup returns the container ID of a cgroup ID, for the processes that ended
	ContainerIDByCgroup func(cgroupID uint64) string
	// KubeContainerName returns the container name of a container ID, from the Kubernetes pods
	KubeContainerName func(containerID string) string
	// Docker returns the container name and image of a container ID, from the Docker API
	Docker func(containerID string) (name, image string, ok bool)
}

type pidEntry struct {
	execName    string
	containerID string
	startTime   string
	checked     time.Time
	used        time.Time
}

type cgroupEntry struct {
	containerID string
	used        time.Time
}

type containerEntry struct {
	info    Info
	checked time.Time
	used    time.Time
}

// Resolver caches the Info of the PIDs. It is not safe for concurrent use.
type Resolver struct {
	procRoot   string
	sources    Sources
	now        func() time.Time
	pids       map[uint32]*pidEntry
	cgroups    map[uint64]*cgroupEntry
	containers map[string]*containerEntry
	lastPrune  time.Time
}

func NewResolver(procRoot string, sources Sources) *Resolver {
	return &Resolver{
		procRoot: procRoot, sources: sources, now: time.Now,
		pids: map[uint32]*pidEntry{}, cgroups: map[uint64]*cgroupEntry{}, containers: map[string]*containerEntry{},
	}
}

// Info returns the process and container of a socket's process. When the process ended before
// it was looked up, its name and container come from what the kernel kept. It is empty for an
// unknown process (PID 0).
func (r *Resolver) Info(p Process) Info {
	if p.Pid == 0 {
		return Info{}
	}
	now := r.now()
	r.prune(now)

	pid := r.pidInfo(p.Pid, now)
	execName, containerID := pid.execName, pid.containerID
	if execName == "" {
		execName = p.ExecName
	}
	if containerID == "" && p.CgroupID != 0 {
		containerID = r.cgroupContainerID(p.CgroupID, now)
	}
	info := r.containerInfo(containerID, now)
	info.ExecName = execName
	return info
}

// pidInfo returns the executable and container ID of a running PID. They are empty for a
// process that ended before it was looked up, or when /proc/<pid> is not visible (OBI without
// hostPID).
func (r *Resolver) pidInfo(pid uint32, now time.Time) *pidEntry {
	e, ok := r.pids[pid]
	if ok && now.Sub(e.checked) < recheckAfter {
		e.used = now
		return e
	}

	startTime := r.startTime(pid)
	// the same process, or one that ended: its last stats keep what was found while it ran
	if ok && (startTime == e.startTime || startTime == "") {
		e.checked, e.used = now, now
		return e
	}
	// a new PID, or a PID reused by another process
	e = &pidEntry{startTime: startTime, checked: now, used: now}
	if startTime != "" {
		e.execName = r.execName(pid)
		if r.sources.ContainerID != nil {
			e.containerID, _ = r.sources.ContainerID(pid)
		}
	}
	r.pids[pid] = e
	return e
}

func (r *Resolver) cgroupContainerID(cgroupID uint64, now time.Time) string {
	if c, ok := r.cgroups[cgroupID]; ok {
		c.used = now
		return c.containerID
	}
	var containerID string
	if r.sources.ContainerIDByCgroup != nil {
		containerID = r.sources.ContainerIDByCgroup(cgroupID)
	}
	r.cgroups[cgroupID] = &cgroupEntry{containerID: containerID, used: now}
	return containerID
}

// containerInfo returns the name and image of a container. Their lookups don't need its
// processes, which can end in the meantime.
func (r *Resolver) containerInfo(containerID string, now time.Time) Info {
	if containerID == "" {
		return Info{}
	}
	c, ok := r.containers[containerID]
	if ok && (c.info.ContainerName != "" || now.Sub(c.checked) < recheckAfter) {
		c.used = now
		return c.info
	}
	info := Info{ContainerID: containerID}
	if r.sources.KubeContainerName != nil {
		info.ContainerName = r.sources.KubeContainerName(containerID)
	}
	if r.sources.Docker != nil {
		if name, image, ok := r.sources.Docker(containerID); ok {
			if info.ContainerName == "" {
				info.ContainerName = name
			}
			info.ImageName, info.ImageTag = SplitImage(image)
		}
	}
	r.containers[containerID] = &containerEntry{info: info, checked: now, used: now}
	return info
}

// execName is the base name of the executable, like OBI's process.executable.name. The
// command name is used when the executable link can't be read (kernel threads, permissions).
func (r *Resolver) execName(pid uint32) string {
	dir := filepath.Join(r.procRoot, strconv.FormatUint(uint64(pid), 10))
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil && exe != "" {
		return filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	}
	comm, err := os.ReadFile(filepath.Join(dir, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}

// startTime is field 22 of /proc/<pid>/stat, the process start time: with the PID, it
// identifies a process. It is "" when the process ended.
func (r *Resolver) startTime(pid uint32) string {
	stat, err := os.ReadFile(filepath.Join(r.procRoot, strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return ""
	}
	// the command name, field 2, is in parentheses and can contain spaces
	s := string(stat)
	end := strings.LastIndexByte(s, ')')
	if end < 0 {
		return ""
	}
	fields := strings.Fields(s[end+1:])
	const startTimeField = 22 - 3 // fields[0] is field 3
	if len(fields) <= startTimeField {
		return ""
	}
	return fields[startTimeField]
}

// prune forgets what was not used for unusedTTL, at most once per minute
func (r *Resolver) prune(now time.Time) {
	if now.Sub(r.lastPrune) < time.Minute {
		return
	}
	r.lastPrune = now
	for pid, e := range r.pids {
		if now.Sub(e.used) > unusedTTL {
			delete(r.pids, pid)
		}
	}
	for id, c := range r.cgroups {
		if now.Sub(c.used) > unusedTTL {
			delete(r.cgroups, id)
		}
	}
	for id, c := range r.containers {
		if now.Sub(c.used) > unusedTTL {
			delete(r.containers, id)
		}
	}
}

// SplitImage splits an image reference into its name and tag:
// "registry:5000/org/app:1.4@sha256:ab…" → "registry:5000/org/app", "1.4".
func SplitImage(image string) (name, tag string) {
	name, _, _ = strings.Cut(image, "@")
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		return name[:i], name[i+1:]
	}
	return name, ""
}
