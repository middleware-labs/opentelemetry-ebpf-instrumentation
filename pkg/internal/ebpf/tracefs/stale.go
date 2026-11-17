// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tracefs // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const groupNamePrefix = "obi"

// GroupPrefix is the prefix of the tracefs event groups of this process: obi_<pid>. The PID
// tells RemoveStale which groups were left by a process that no longer runs.
func GroupPrefix() string {
	return fmt.Sprintf("%s_%d", groupNamePrefix, os.Getpid())
}

var removeStaleOnce sync.Once

// RemoveStale deletes, once per process, the kprobe and uprobe events that OBI processes which no
// longer run left in tracefs. Unlike the probes attached through perf_event_open, tracefs events
// outlive the process that created them when it can't remove them itself: SIGKILL, OOM, crash.
func RemoveStale() {
	removeStaleOnce.Do(func() {
		root, err := findTraceFS()
		if err != nil {
			return
		}
		if removed := removeStale(root, processExists); removed > 0 {
			slog.Info("removed tracefs probe events left by OBI processes that no longer run", "events", removed)
		}
	})
}

func removeStale(root string, exists func(pid int) bool) int {
	removed := 0
	for _, kind := range []ProbeType{Kprobe, Uprobe} {
		eventsFile := filepath.Join(root, string(kind)+"_events")
		events, err := os.ReadFile(eventsFile)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(events), "\n") {
			group, name, ok := parseEventLine(line)
			if !ok {
				continue
			}
			pid, ok := groupPID(group)
			if !ok || exists(pid) {
				continue
			}
			// the kernel refuses (EBUSY) to delete an event that is still in use, e.g. by an OBI
			// in another PID namespace whose PID looks unused from here
			if writeTraceFSCommand(eventsFile, fmt.Sprintf("-:%s/%s", group, name)) == nil {
				removed++
			}
		}
	}
	return removed
}

// parseEventLine returns the group and the name of a kprobe_events or uprobe_events line,
// e.g. "r128:obi_42_0123456789abcdef/tcp_sendmsg tcp_sendmsg".
func parseEventLine(line string) (group, name string, ok bool) {
	definition, _, _ := strings.Cut(line, " ")
	_, id, found := strings.Cut(definition, ":")
	if !found {
		return "", "", false
	}
	group, name, ok = strings.Cut(id, "/")
	return group, name, ok && group != "" && name != ""
}

// groupPID returns the PID of a group named by GroupPrefix: obi_<pid>_<random>.
func groupPID(group string) (int, bool) {
	rest, ok := strings.CutPrefix(group, groupNamePrefix+"_")
	if !ok {
		return 0, false
	}
	pidText, random, ok := strings.Cut(rest, "_")
	if !ok || random == "" {
		return 0, false
	}
	pid, err := strconv.Atoi(pidText)
	return pid, err == nil && pid > 0
}

func processExists(pid int) bool {
	return !errors.Is(unix.Kill(pid, 0), unix.ESRCH)
}
