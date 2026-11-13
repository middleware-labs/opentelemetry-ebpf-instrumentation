# Socket traffic reader

The socket traffic reader collects the Cloud Network Monitoring metrics: one row per TCP
connection or UDP socket and peer in a kernel hash map, read by user space every
`read_interval`, like Datadog's `conn_stats`. It is the fork's main addition to OBI. See
[README.md](README.md) for the rules of the fork.

[devdocs/metrics.md](../metrics.md) documents its behaviour in detail (sections "Socket bytes and
packets", "TCP stats from the connection rows" and "Process and container of the TCP stats").
This page is the map of the code.

## Two flows

| | Event flow (upstream) | Reader flow (fork) |
|---|---|---|
| Kernel | `tp_tcp.c`, `k_tcp.c`: one `stats_events` ring buffer event per TCP event | `k_socket_traffic.c`: counters in the `socket_traffic` row of each connection |
| User space | `stats/tracer_ringbuf.go` | `socktraffic/` reader, every `read_interval` |
| Enabled by | the `stats_tcp_*` features | `stats_socket_bytes`, `stats_socket_packets`, or `stats.socket_traffic.tcp_metrics: true` |
| Metrics | upstream's: RTT, failed, successful, retransmits, I/O, resets | `obi.stat.bytes`, `obi.stat.packets`, and with `tcp_metrics` all the `obi.stat.tcp.*` metrics except resets, including the fork-only closed connections, flow control and congestion metrics |
| Process, container, NAT, same host, server port | no | yes |

With `tcp_metrics: true`, `NewStatsFetcher` turns off the event programs of the TCP metrics that
the rows hold (`tcpRowFeatures` in `pkg/internal/statsolly/ebpf/stat.go`): the two flows never
count the same metric. `stats_tcp_resets` (upstream) has no row counter, so its event programs
stay on.

## Kernel side

All in `bpf/statsolly/`, compiled into the single `stats.c` object (bpf2go type `Stats`).

| File | Content |
|---|---|
| `k_socket_traffic.c` | The reader's programs: TCP and UDP send/receive, the TCP state changes (row creation, failures), retransmits, zero window probes, loss/recovery, accept, close and destroy, and the `inet_bind` probes for the UDP role |
| `k_sock_owner.c` | Keeps the process of each TCP socket (`sock_owner`) and of each local address (`endpoint_owner`), for rows updated in softirq or timers |
| `k_nat.c` | conntrack kprobes that fill `nat_translations` |
| `sock_dns.c` | Socket filter for the DNS lookups (`stats_dns_events` ring buffer) |
| `tcp_failure.h` | Failed connection rule of the rows. Same logic as upstream's `tp_tcp.c`, kept separate so `tp_tcp.c` stays upstream's |
| `tcp_counters.h` | `tcp_cong_vals_t`, reading the congestion totals, retransmit type |
| `inet_sock_set_state.h` | TCP check that works on RHEL 8 (the tracepoint's `protocol` field is a `u8` there) |
| `sock_netns.h`, `ringbuf_flags.h`, `exe_name.h` | Small helpers |
| `maps/socket_traffic*.h`, `maps/sock_owner.h`, `maps/nat_translations.h`, `maps/udp_port_bindings.h`, `maps/stats_dns_events.h` | The reader's maps |

Main maps:

| Map | Type | Content |
|---|---|---|
| `socket_traffic` | hash, `stats.socket_traffic.max_entries` (default 65536) | One row per connection: key `socket_traffic_key_t` (5-tuple, netns, protocol), value `socket_traffic_t` (totals, process, TCP counters) |
| `socket_traffic_closed` | ring buffer | Final row of each closed socket |
| `socket_traffic_drops` | per-CPU array | Rows not inserted (map full) or close events lost |
| `socket_traffic_retransmit`, `socket_traffic_sendmsg_sock`, `socket_traffic_udp_dport`, `socket_traffic_bind_sock` | LRU | Per-call state between a kprobe and its kretprobe |
| `sock_owner`, `endpoint_owner` | hash | Process of a socket, and of a local address |
| `udp_port_bindings` | hash | Bound UDP ports: a socket bound to its port is the server |

What the reader shares with upstream: the `sock_role` map, which upstream's
`obi_stats_tp_inet_sock_set_state_conn_role` writes and `obi_stats_tp_tcp_destroy_sock` deletes,
and upstream helpers such as `parse_sock_info()` and `failed_connection_role()`.

Load-time constants set by `NewStatsFetcher`: `stats_tcp_metrics_enabled`,
`stats_tcp_failures_enabled`, `stats_sock_owner_enabled`, and upstream's
`stats_wakeup_data_bytes`.

Attach order matters on `inet_sock_set_state`, where the programs run in attach order:
`obi_stats_tp_inet_sock_set_state_tcp_row` reads `sock_owner` on `TCP_CLOSE`, so it is attached
before `obi_stats_tp_inet_sock_set_state_sock_owner`, which deletes it. `inetSockSetStateProbes`
in `stats_tracer.go` holds the order, and `TestInetSockSetStateProbesOrder` checks it.

## User space

| Path | Content |
|---|---|
| `pkg/internal/statsolly/ebpf/stats_tracer.go` | Loads the object, chooses the programs from the features (`toDisable`), sizes the maps, attaches the probes |
| `pkg/internal/statsolly/ebpf/stat.go`, `stat_getters.go` | `Stat` and its attribute getters, shared by both flows |
| `pkg/internal/statsolly/socktraffic/` | The reader: map reads (`map_reader.go`), increases since the last read (`delta.go`), rows to stats (`convert.go`, `tcp_stats.go`), connection rollup (`rollup.go`), same-host peers (`peers.go`), connection role of old connections (`ports.go`), idle rows (`alive.go`) |
| `pkg/internal/statsolly/nat/` | NAT translations, from the conntrack probes or netlink |
| `pkg/internal/statsolly/dns/` | Matches DNS questions and answers |
| `pkg/statsolly/agent/agent.go`, `pipeline.go` | Builds the tracers and the pipeline. The ring buffer tracer, the DNS tracer and the reader all send to `ebpfStats`, and stop with `readerCtx` so the pipeline can drain |
| `pkg/export/otel/metrics_stats.go`, `pkg/export/prom/prom_stats.go` | Exporters, both flows |
| `pkg/export/attributes/metric.go`, `attr_defs.go`, `names/attrs.go` | Metric and attribute definitions |
| `pkg/export/feature.go` | Features: `FeatureStats`, `FeatureStatsTCPRowOnly`, `FeatureStatsSocketTraffic`, `FeatureAnyStats` |
| `pkg/config/socket_traffic.go`, `pkg/obi/stats_cfg.go` | v1 config `stats.socket_traffic` |
| `internal/config/schema/network.go`, `internal/config/convert/` | v2 config `capture.network.stats.socket_traffic` and v1/v2 conversion |

## Configuration

```yaml
metrics:
  features: [stats_socket_bytes, stats_socket_packets, stats_tcp_rtt, stats_tcp_closed_connections]
stats:
  socket_traffic:
    protocols: [tcp, udp]   # default both
    read_interval: 10s      # default 10s, not longer than the export interval
    max_entries: 65536      # default 65536
    connection_rollup: true # merge the closed connections that only differ by the client port
    tcp_metrics: true       # read the obi.stat.tcp.* metrics from the rows
```

## Adding a metric to the reader

1. Add the counter to `socket_traffic_t` (`bpf/statsolly/maps/socket_traffic.h`) and update it in
   `k_socket_traffic.c`. Do not touch `tp_tcp.c` or `k_tcp.c`.
2. If the metric needs a new stat type or enum, add it at the end of `bpf/statsolly/types.h`, and
   add an `unused` line for a new enum in `stats.c` and a `-type` in the `go:generate` line of
   `stats_tracer.go`. An enum that no struct field or global uses is missing from BTF, and bpf2go
   then fails with `looking up type ...: not found`.
3. Add the feature in `pkg/export/feature.go`, in `FeatureStatsTCPRowOnly` if it is TCP, and to
   `FeatureMapper`. Add it to `validateStatsTCPRowFeatures` (`pkg/obi/config.go`) and to the v2
   feature names (`internal/config/convert/export.go`, `import.go`,
   `cmd/check-config-v2-parity/main.go`, `devdocs/config/version-2.0/`).
4. Emit the stat in `socktraffic/tcp_stats.go` (`Emit`, `EmitFor`, `appendTCPStats`), add it to
   `tcpRowFeatures` (`stat.go`) and to the metric lists of `pkg/statsolly/agent/agent.go`.
5. Define the metric and its attributes (`pkg/export/attributes/`), record it in both exporters,
   and add getters for new attributes in `stat_getters.go`.
6. Add the metric to the telemetry schema (`schemas/obi/groups/stats/`), then run
   `make generate-schema-docs`, `make generate-config-schema` and `make lint-schema`.
7. Document it in [devdocs/metrics.md](../metrics.md).

## Looking at the maps on a host

```sh
sudo bpftool map show | grep -A2 socket_traffic
sudo bpftool map dump id <id> | head -60   # the socket_traffic hash map
```

Kernel object names are cut to 15 characters, so several maps show as `socket_traffic_`: use the
map ID, from the type and sizes. Ring buffers cannot be dumped. IDs change at each restart.

## Tests

- Unit tests: `go test ./pkg/internal/statsolly/... ./pkg/statsolly/... ./pkg/export/... ./pkg/obi/...`
- eBPF verifier: `TestBPFVerifierWithConstants/statsolly`, see
  [upstream-sync.md](upstream-sync.md#validate).
- Integration (Docker): `internal/test/integration/docker-compose-go-stat-metrics.yml` and
  `suites_stat_test.go`.
