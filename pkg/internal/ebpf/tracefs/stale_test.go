// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tracefs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupPrefix(t *testing.T) {
	assert.Equal(t, fmt.Sprintf("obi_%d", os.Getpid()), GroupPrefix())

	pid, ok := groupPID(GroupPrefix() + "_0123456789abcdef")
	require.True(t, ok)
	assert.Equal(t, os.Getpid(), pid)
}

func TestParseEventLine(t *testing.T) {
	for line, want := range map[string][2]string{
		"r128:obi_42_0123456789abcdef/tcp_sendmsg tcp_sendmsg":  {"obi_42_0123456789abcdef", "tcp_sendmsg"},
		"p:obi_42_0123456789abcdef/probe_0 /usr/bin/app:0x1234": {"obi_42_0123456789abcdef", "probe_0"},
	} {
		group, name, ok := parseEventLine(line)
		require.True(t, ok, line)
		assert.Equal(t, want, [2]string{group, name}, line)
	}

	for _, line := range []string{"", "garbage", "p:/name target", "p:group/ target"} {
		_, _, ok := parseEventLine(line)
		assert.False(t, ok, line)
	}
}

func TestGroupPID(t *testing.T) {
	for _, group := range []string{
		"ebpf_0123456789abcdef",  // cilium/ebpf's default prefix
		"obi_0123456789abcdef",   // no PID
		"obi_42",                 // no random part
		"obi_x42_0123456789abcd", // PID isn't a number
		"obi_0_0123456789abcdef", // no process has PID 0
		"kprobes_42_abcd",        // another tool
	} {
		_, ok := groupPID(group)
		assert.False(t, ok, group)
	}
}

func TestRemoveStale(t *testing.T) {
	root := t.TempDir()
	const (
		running = "obi_100_00000000000000aa"
		gone    = "obi_200_00000000000000bb"
	)
	kprobes := strings.Join([]string{
		"r128:" + running + "/tcp_sendmsg tcp_sendmsg",
		"r128:" + gone + "/tcp_sendmsg tcp_sendmsg",
		"r128:" + gone + "/inet_bind inet_bind",
		"r128:ebpf_00000000000000cc/tcp_sendmsg tcp_sendmsg",
		"r512:kprobes/r_tcp_sendmsg_net_300 tcp_sendmsg",
		"",
	}, "\n")
	uprobes := "p:" + gone + "/probe_0 /usr/bin/app:0x1234\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "kprobe_events"), []byte(kprobes), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "uprobe_events"), []byte(uprobes), 0o600))

	exists := func(pid int) bool { return pid == 100 }
	assert.Equal(t, 3, removeStale(root, exists))

	// writing to a plain file appends the commands that tracefs would execute
	kprobesAfter, err := os.ReadFile(filepath.Join(root, "kprobe_events"))
	require.NoError(t, err)
	assert.Equal(t, kprobes+"-:"+gone+"/tcp_sendmsg"+"-:"+gone+"/inet_bind", string(kprobesAfter))

	uprobesAfter, err := os.ReadFile(filepath.Join(root, "uprobe_events"))
	require.NoError(t, err)
	assert.Equal(t, uprobes+"-:"+gone+"/probe_0", string(uprobesAfter))
}

func TestRemoveStaleWithoutTraceFS(t *testing.T) {
	assert.Zero(t, removeStale(t.TempDir(), func(int) bool { return false }))
}

func TestProcessExists(t *testing.T) {
	assert.True(t, processExists(os.Getpid()))
	assert.True(t, processExists(1), "PID 1 exists even when it can't be signaled")
}
