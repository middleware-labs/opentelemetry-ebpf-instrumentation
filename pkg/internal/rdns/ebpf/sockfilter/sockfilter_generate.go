// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sockfilter // import "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/sockfilter"

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type rdns_response_t -target $BPF_TARGETS Bpf ../../../../../bpf/rdns/rdns_sock.c -- -I../../../../../bpf
