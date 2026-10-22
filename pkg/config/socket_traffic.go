// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"slices"
	"time"
)

// Socket traffic protocols
const (
	SocketTrafficTCP = "tcp"
	SocketTrafficUDP = "udp"
)

// SocketTrafficConfig configures the bytes and packets counted at the TCP and UDP sockets.
type SocketTrafficConfig struct {
	// Protocols whose sockets are counted. Accepted values: tcp, udp.
	// The UDP hooks run once per datagram: leaving udp out avoids their cost on busy DNS servers.
	Protocols []string `yaml:"protocols" env:"OTEL_EBPF_STATS_SOCKET_TRAFFIC_PROTOCOLS" envSeparator:"," validate:"min=1,dive,oneof=tcp udp"`
	// ReadInterval is how often the counters are read from the kernel. It should not be
	// longer than the metrics export interval.
	ReadInterval time.Duration `yaml:"read_interval" env:"OTEL_EBPF_STATS_SOCKET_TRAFFIC_READ_INTERVAL" validate:"gt=0"`
	// MaxEntries is the number of open sockets with traffic that can be counted at once. It is
	// scaled by the eBPF maps global scale factor, like the other maps.
	MaxEntries uint32 `yaml:"max_entries" env:"OTEL_EBPF_STATS_SOCKET_TRAFFIC_MAX_ENTRIES" validate:"gt=0"`
	// ConnectionRollup merges the closed connections that only differ by the client's ephemeral
	// port before they are exported, like Datadog's connection rollup. Many short connections
	// then cost a few stats per read interval instead of one per connection. The rolled-up
	// port is reported as 0.
	ConnectionRollup bool `yaml:"connection_rollup" env:"OTEL_EBPF_STATS_SOCKET_TRAFFIC_CONNECTION_ROLLUP"`
	// TCPMetrics reads the obi.stat.tcp.* metrics from the TCP rows, every read interval and
	// at close, like Datadog's connection stats, instead of one event per TCP event. Their cost
	// then grows with the connections, not with the events. The failed connections stay events.
	TCPMetrics bool `yaml:"tcp_metrics" env:"OTEL_EBPF_STATS_SOCKET_TRAFFIC_TCP_METRICS"`
}

func (c *SocketTrafficConfig) TCP() bool {
	return slices.Contains(c.Protocols, SocketTrafficTCP)
}

func (c *SocketTrafficConfig) UDP() bool {
	return slices.Contains(c.Protocols, SocketTrafficUDP)
}
