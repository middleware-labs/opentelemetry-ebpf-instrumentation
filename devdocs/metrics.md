# OBI metrics

> The full list of metrics OBI exports — names in OTel and Prometheus form, types, units, descriptions, and per-metric attribute defaults — lives in the user-facing OBI docs: <https://opentelemetry.io/docs/zero-code/obi/metrics/>.
>
> This document is the **developer-internal companion** to that page: it explains how each component's pipeline turns eBPF events into the metrics listed there, where to edit when adding a new one, and the attribute-group composition behind each metric's label set.

## Table Of Contents

- [NetO11y](#neto11y)
- [AppO11y](#appo11y)
- [StatsO11y](#statso11y)
- [General notes](#general-notes)

Each component has its own pipeline, described in the [pipeline-map doc](pipeline-map.md). In short, each component has its own maps, events, and a set of userspace nodes that add, modify, and export the data obtained from eBPF probes.

## NetO11y

**NetO11y** uses eBPF probes attached at the [TC level in ingress and egress](../bpf/netolly/flows.c) as well as a [socket/filter](../bpf/netolly/flows_sock.c).

The event we're interested in on the kernel side is called `flow_record_t` and on the userspace side is called `NetFlowRecordT`, which is read by a dedicated ringbuffer (exclusive to **NetO11y**) and will be treated as an `ebpf.Record` (defined in [pkg/internal/netolly/ebpf/record.go](../pkg/internal/netolly/ebpf/record.go)) field from there on.

The `ebpf.Record` contains accumulated metrics from a flow, with additional metadata added from the user space. It is the structure that passes all the pipeline nodes to the metric exporters.

The `Attrs` field contains various attributes that can be added to the flow record. In particular, any attributes here must also be added to the `RecordGetters` functions in [pkg/internal/netolly/ebpf/record_getters.go](../pkg/internal/netolly/ebpf/record_getters.go) and `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go). For each metric, other ad hoc attributes are defined (such as `networkCIDR` or `networkInterZoneCIDR`).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), `networkAttributes` and `networkKubeAttributes` are defined. These are `AttrReportGroup` structures that define groups of attributes allowed by a given metric, whether we're in a k8s environment or not. Note that not all attributes are set to true by default and if you want to enable them, you can do so during configuration using the `attributes` field, which allows you to configure the decoration of some extra attributes that will be added to each metric. Example:

```
attributes:
  select:
    obi_network_flow_bytes:
      include:
      - obi.ip
      - src.address
      - dst.address
      ...
```

In the following methods:

- `newMetricsExporter` in [pkg/export/otel/metrics_net.go](../pkg/export/otel/metrics_net.go) for OTEL
- `newNetReporter` in [pkg/export/prom/prom_net.go](../pkg/export/prom/prom_net.go) for Prometheus

the actual metrics are created using the names defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with the attributes defined and added in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

### Add a new network metric

To add a new network metric, follow these guidelines:

1. If new fields are needed on the flow record, extend `flow_record_t` on the eBPF side and the `NetFlowRecordT` / `ebpf.Record` structs on the userspace side.
2. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go), wrapping it in `metric(...)` and setting its `Section`, `OTEL`, `Unit` and `Type`. Never set `Prom` by hand: it is derived from the other three.
3. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `networkAttributes`, `networkKubeAttributes`) and any ad-hoc attributes it needs.
4. If new attributes are introduced, add the matching getters in [pkg/internal/netolly/ebpf/record_getters.go](../pkg/internal/netolly/ebpf/record_getters.go).
5. If the metric is gated by its own feature flag, add the feature bit and its accessor in [pkg/export/feature.go](../pkg/export/feature.go), register the flag name in `FeatureMapper`, and include it in `AnyNetwork()` so it activates the network pipeline. Then run `make generate-config-schema` to refresh the config JSON schema and docs.
6. Wire up the metric in the exporters, gating it behind the feature predicate added in step 5 where applicable: `newMetricsExporter` in [pkg/export/otel/metrics_net.go](../pkg/export/otel/metrics_net.go) for OTEL, and `newNetReporter` in [pkg/export/prom/prom_net.go](../pkg/export/prom/prom_net.go) for Prometheus.
7. Register the metric in the schema registry: add the metric to the `metrics:` list in [schemas/obi/groups/network/metrics.yaml](../schemas/obi/groups/network/metrics.yaml).

## AppO11y

**AppO11y** is the component that handles all application-level tasks and generates traces and metrics. Unlike NetO11y, it uses different types of eBPF probes (such as `uprobe`, `kprobe/kretprobe`) and introduces the concept of a `tracer`, which is the component responsible for tracing a given type of application. Specifically, we can divide tracers into two categories: `gotracer` and `generictracer`.

It also has three common tracers:

- `tpinjector`: handles context propagation via both HTTP headers (sk_msg) and TCP options (BPF_SOCK_OPS)
- `logenricher`: handles trace-log correlation
- `gputracer`: handles GPU (CUDA) instrumentation

These tracers are loaded for any tracer group.

That said, let's focus on the metrics.

In **AppO11y**, the `request.Span` (defined in [pkg/appolly/app/request/span.go](../pkg/appolly/app/request/span.go)) struct is populated with all the necessary information and passes through all the nodes of the pipeline, from reading the necessary data from the eBPF maps to exporting the metrics/traces.

In particular, any attribute here must also be added to the functions `SpanOTELGetters`, `SpanPromGetters` in [pkg/appolly/app/request/span_getters_providers.go](../pkg/appolly/app/request/span_getters_providers.go) and `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go) some `AttrReportGroup` type structures are defined for application metrics in both the k8s and non-k8s environment: `appAttributes` and `appKubeAttributes`. Here too, ad hoc attributes such as `httpCommon`, `httpClientInfo`, and so on are added for each metric. There are attributes that default to true and others to false, but which can be enabled by the user during configuration.

In the following methods:

- `setupOtelMeters` in [pkg/export/otel/metrics.go](../pkg/export/otel/metrics.go) for OTEL
- `newReporter` in [pkg/export/prom/prom.go](../pkg/export/prom/prom.go) for Prometheus

the actual metrics are created using the names defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with the attributes defined and added in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

### Add a new application metric

To add a new application metric, follow these guidelines:

1. If new fields are needed on the span, extend `request.Span` in [pkg/appolly/app/request/span.go](../pkg/appolly/app/request/span.go) and populate them in the relevant tracer.
2. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go), wrapping it in `metric(...)` and setting its `Section`, `OTEL`, `Unit` and `Type`. Never set `Prom` by hand: it is derived from the other three.
3. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `appAttributes`, `appKubeAttributes`, `httpCommon`, `httpClientInfo`) and any ad-hoc attributes.
4. If new attributes are introduced, add them to `SpanOTELGetters` and `SpanPromGetters` in [pkg/appolly/app/request/span_getters_providers.go](../pkg/appolly/app/request/span_getters_providers.go).
5. Wire up the metric in the exporters: `setupOtelMeters` in [pkg/export/otel/metrics.go](../pkg/export/otel/metrics.go) for OTEL, and `newReporter` in [pkg/export/prom/prom.go](../pkg/export/prom/prom.go) for Prometheus.
6. Don't forget to clean each `Expirer` in [`cleanupAllMetricsInstances()`](../pkg/export/otel/metrics.go).
7. Declare the metric and any new attribute in the schema registry, following [Adding telemetry](../schemas/obi/README.md#adding-telemetry): import an upstream metric OBI emits unchanged, or add it to the `metrics:` list of the domain's `metrics.yaml` with every attribute from step 3. Run `make lint-schema` and `make generate-schema-docs`.
8. Cover the metric in an integration suite whose compose file runs weaver, so live-check validates what is emitted.

## StatsO11y

**StatsO11y** is the component responsible for calculating statistical metrics — for example, TCP RTT or failed-connection counts — across all applications running on a node, regardless of which PID triggered the event. The probes live in [bpf/statsolly](../bpf/statsolly/).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go) some `AttrReportGroup` type structures are defined for stat metrics in both the k8s and non-k8s environment: `statsAttributes` and `statsKubeAttributes`. Here too, ad hoc attributes can be added for each metric. There are attributes that default to true and others to false, but which can be enabled by the user during configuration.

### BPF program naming convention

Every statsolly BPF program follows the pattern `obi_stats_{probe_type}_{kernel_func}[_{purpose}]`, where `purpose` is only appended when two or more probes share the same hook point (e.g. `tcp_close_srtt` vs `tcp_close_io_flush`).

### Add a new stat metric

To add a new metric, follow these guidelines:

1. Decide on the hook point where you want to attach the eBPF probe. For example, you can use a kprobe on the `tcp_close` function to retrieve `srtt_us`.
2. Add a unique flag that indicates an event related to the metric you want to calculate in [bpf/statsolly/types.h](../bpf/statsolly/types.h) and the corresponding Go constant in [stat.go](../pkg/internal/statsolly/ebpf/stat.go), for example, `k_event_stat_tcp_rtt` and `StatTypeTCPRtt`.
3. Add the eBPF probe to the [bpf/statsolly](../bpf/statsolly/) folder, following the naming convention above. The metric will be calculated and sent to userspace using the `stats_events` ringbuffer.
4. Add the metric's feature bit and accessor in [pkg/export/feature.go](../pkg/export/feature.go), register the flag name in `FeatureMapper`, and include it in the `FeatureStats` aggregate if it should be part of the umbrella `stats` feature. Then run `make generate-config-schema` to refresh the config JSON schema and docs.
5. Wire the probe into [stats_tracer.go](../pkg/internal/statsolly/ebpf/stats_tracer.go):
    - add a program name constant (e.g. `progObiStatsKprobeTCPCloseSrtt`) matching the C symbol;
    - add a hook-point constant (kernel function name for kprobes, `group/name` for tracepoints);
    - add an entry to the appropriate `kprobes`/`kretprobes`/`tracepoints`/`raw tracepoints` slice inside `NewStatsFetcher`, with `enabled` driven by the `features.StatsXxx()` predicate added in step 4. Disabled probes are replaced with a no-op stub before loading, preventing unused eBPF code from being loaded into the kernel.
6. In the [tracer_ringbuf.go](../pkg/internal/statsolly/stats/tracer_ringbuf.go), simply add a function that handles that metric. This function will convert the event to a `ebpf.Stat`.
7. Then, modify the `Stat` struct accordingly, by adding a data structure containing all the necessary fields. For example `TCPRtt` struct.
8. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go), wrapping it in `metric(...)` and setting its `Section`, `OTEL`, `Unit` and `Type`. Never set `Prom` by hand: it is derived from the other three.
9. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `statsAttributes`, `statsKubeAttributes`) and any ad-hoc attributes it needs.
10. If new attributes are introduced, add the matching getters to `StatGetters` in [pkg/internal/statsolly/ebpf/stat_getters.go](../pkg/internal/statsolly/ebpf/stat_getters.go).
11. Wire up the metric in the exporters. Each exporter owns one observe-method per stat type (e.g. `observeTCPRtt`, `observeTCPFailedConnections`) that translates the `ebpf.Stat` into a given observation, with its attribute set resolved through the attribute selector's `For` method:

    - `newStatsReporter` in [pkg/export/prom/prom_stats.go](../pkg/export/prom/prom_stats.go) for Prometheus
    - `newStatMetricsExporter` in [pkg/export/otel/metrics_stats.go](../pkg/export/otel/metrics_stats.go) for OTEL

12. Register the metric in the schema registry: add the metric to the `metrics:` list in [schemas/obi/groups/stats/metrics.yaml](../schemas/obi/groups/stats/metrics.yaml).

### DNS lookups

`obi.stat.dns.lookup.duration` (feature `stats_dns_lookups`) does not follow the steps above, because its events are packets, not metrics. It is opt-in: the `stats` group does not include it, because its socket filter adds a cost to every packet of the host. It works like this:

- The `obi_stats_socket_dns` socket filter in [bpf/statsolly/sock_dns.c](../bpf/statsolly/sock_dns.c) is attached to a raw `AF_PACKET` socket, so it sees every packet of OBI's network namespace, from all the processes. It forwards the UDP and TCP port 53 packets to their own ring buffer, `stats_dns_events`, and returns 0 so the socket never queues any packet. DNS over TCP is read without reassembly, like Datadog: only the messages that start a TCP segment are read, and a question only counts when it is sent to port 53 and an answer when it comes from it, so a later segment of a long answer is never taken for a question.
- [dns_tracer.go](../pkg/internal/statsolly/stats/dns_tracer.go) reads that ring buffer and feeds the packets to the matcher in [pkg/internal/statsolly/dns](../pkg/internal/statsolly/dns/), which turns a question and its answer, or a question without answer after 5 seconds, into one `ebpf.Stat`. The source is the client and the destination is the DNS server.
- The same lookup can cross several interfaces of the namespace, with different addresses before and after NAT. A copy of a question with the same client (address, port, DNS ID and question) is the same question, which covers DNAT. A copy with the same server (address, DNS ID and question) within 10 ms is the same question too, which covers SNAT. The first copy decides the client and the latency start, the latest copy the server. Answers match by the client.
- Timeouts are decided with the kernel time of the newest DNS packet read. The clock is only used when the ring buffer is empty, so answers that are still waiting there never become false timeouts.
- Lookups to loopback DNS servers (e.g. systemd-resolved at `127.0.0.53`) are not counted: their forwarded lookup to the upstream server is.

The internal metrics `obi.stats.dns.dropped.questions`, `obi.stats.dns.server_key.merges` and `obi.stats.dns.reader.lag` show when the lookups are not exact.

### Socket bytes and packets

`obi.stat.bytes` (feature `stats_socket_bytes`) and `obi.stat.packets` (feature `stats_socket_packets`) count the traffic of each TCP connection and UDP socket where the application sends and reads it, like Datadog CNM. They are opt-in: the `stats` group does not include them. They follow the row lifecycle of Datadog's `conn_stats`:

- The probes in [bpf/statsolly/k_socket_traffic.c](../bpf/statsolly/k_socket_traffic.c) keep one row per socket in the `socket_traffic` hash map, with totals: bytes and UDP datagrams only grow, TCP packets are the socket's `segs_out` / `segs_in`. TCP bytes come from `tcp_sendmsg`, `tcp_sendpage` (`sendfile()` and `splice()` before kernel 6.5) and `tcp_cleanup_rbuf`; UDP bytes and datagrams from `ip_make_skb` / `ip6_make_skb` (sent) and `skb_consume_udp` (received). `stats.socket_traffic.protocols` selects which of the TCP and UDP probes are attached.
- When a socket closes (`tcp_close`, `udp_destroy_sock`, `udpv6_destroy_sock`), its row is deleted and sent once through the `socket_traffic_closed` ring buffer. The row is deleted before the event is sent, so user space never reads it again after the event.
- The reader in [pkg/internal/statsolly/socktraffic](../pkg/internal/statsolly/socktraffic/) reads the map every `stats.socket_traffic.read_interval` (default `10s`) without deleting the rows, and reads the close events in between, in the same goroutine. It reports the increase of each total since the previous read: the first time a row is seen, its whole totals, so the connections that open and close between two reads are counted. The read interval should not be longer than the metrics export interval.
- Rows without traffic for 2 minutes (TCP) or 30 seconds (UDP) are reported and deleted by the reader, like Datadog's connection timeouts. They catch the lost close events and the unconnected UDP sockets, which have one row per remote.
- `network.connection.role` (off by default) is `client` or `server`. TCP takes it from `sock_role` (the handshake). UDP takes it from `udp_port_bindings`, filled by the `inet_bind` / `inet6_bind` probes and, at start, from `/proc/<pid>/net/udp{,6}` of one process per network namespace, like Datadog: a socket bound to its local port is the `server`. The ports are read after the bind probes are attached and before the probes that create the rows, so a row never takes the `client` role of a server port bound before OBI started. Like Datadog's `fixIncomingConnectionDirection` and `fixOutgoingConnectionDirection`, the reader then corrects the UDP role from the ports: a `server` row with an ephemeral local port is a `client` when its remote port is below 1024, or not ephemeral on this host; a `client` row with a non-ephemeral local port and an ephemeral remote port on this host is a `server`. "On this host" is `network.peer.same_host`, so these rows are handled after the rest of the map read. The connection rollup takes the corrected role. A TCP connection opened before OBI started has no handshake role: its side is the `server` when its local port is listening, as for `server.port` below, and stays `unknown` when its process has ended. The role probes only run when the attribute is selected.
- The process and container of each side (all off by default): `src.process.executable.name`, `src.container.name`, `src.container.image.name`, `src.container.image.tag`, `src.container.id`, and the same with `dst.`. `src` is the local socket: the kernel stores the PID, the executable name (16 bytes) and the cgroup ID of the process that created each row, so the processes that end before their row is read (short-lived clients) are still named; their container comes from the cgroup ID (the inode of their cgroup v2 directory). `dst` is filled only when the remote socket is on the same host: the reader matches the remote address with the local address of the other rows, and the closed connections then wait for the next read. [pkg/internal/procmeta](../pkg/internal/procmeta/) turns a PID into the base name of `/proc/<pid>/exe`, the container ID from `/proc/<pid>/cgroup`, and a container ID into the container name from the Kubernetes pod or Docker, and the image from Docker (not from Kubernetes yet). A process that ended keeps what was found while it ran. The decorator is bypassed when none of these attributes is selected.
- `network.peer.same_host` (off by default) is `true` when the remote socket is on this host, like Datadog's `IntraHost` (`determineConnectionIntraHost`): the remote address, port and transport are the local side of another row (the network namespace is kept for loopback addresses, as for `dst` above), or both addresses are the same or loopback. The rows without process count too. Like `dst`, the closed connections then wait for the remote socket to be read. Without NAT: a connection to a Kubernetes service or a published Docker port is `false`. The TCP stats read from the events (`tcp_metrics: false`) report `false`.
- Internal metrics: `obi.stats.socket_traffic.drops` (send and receive calls not counted because the map was full: raise `stats.socket_traffic.max_entries`), `obi.stats.socket_traffic.close_drops` (close events lost: the row is reported later), `obi.stats.socket_traffic.underflows` (a total went down because the socket was replaced by another one with the same addresses) and `obi.stats.socket_traffic.rows`.

For TCP bytes, prefer `obi.stat.bytes{network.transport="tcp"}` to `obi.stat.tcp.io`: it counts the same values without an event per 10 calls. Enabling both `stats_tcp_io` and `stats_socket_bytes` attaches two programs to `tcp_sendmsg` and `tcp_cleanup_rbuf`.

Known limits, the same as Datadog's: traffic with no local socket (forwarded packets), ICMP and header bytes are not counted; the segments sent after `tcp_close` (e.g. the FIN) are not counted on the closing side; the first TCP packet count of a connection opened before OBI started includes its earlier packets, once; UDP `sendfile()` before kernel 6.5 (`udp_sendpage`) is not counted; a UDP client that binds a fixed port is a `server`; the TCP role of a connection established before OBI started comes from its listening ports, and is `unknown` when its process has ended; the transmit points of an unconnected UDP socket have `dst.port` `0`.

### TCP stats from the connection rows

With `stats.socket_traffic.tcp_metrics: true` (default `false`), the `obi.stat.tcp.*` metrics except `obi.stat.tcp.failed.connections` are read from the TCP rows of the socket traffic map, like Datadog's connection stats (`conn_stats` + `tcp_stats`), instead of one ring buffer event per TCP event. Their cost then grows with the connections per read interval, not with the events: no event per I/O batch, retransmit, zero window probe or congestion change.

- The row holds the TCP counters next to the bytes: `established` (`TCP_SYN_SENT`/`TCP_SYN_RECV` → `TCP_ESTABLISHED`, where the row is created, so the connections without data are counted too), `retrans_fast/timeout/other` (`tcp_retransmit_skb`: the retransmitted segments, `tcp_skb_pcount(skb)`, like Datadog and the kernel's `TcpRetransSegs`; the retransmit events count one per call), `zero_window_probes` (`tcp_send_probe0`), and the latest `srtt_us` and the `delivered_ce`, `reord_seen`, `rcv_ooopack` socket totals, read at each send, receive and close, like Datadog's `handle_tcp_stats`.
- The reader sends the increases with `Stat.Count`, and the connection rollup merges them (the RTTs of the merged connections are all recorded). The process and container come from the row.
- Rows created in softirq or timers take their process from `sock_owner` when a process attribute is selected. A row created after the application closed its socket (a late retransmit) counts from the socket totals of that moment, and is sent at `inet_csk_destroy_sock`. A connection that the listener never accepted is sent at `tcp_disconnect`, before its addresses are cleared.
- The close events are read by their own goroutine into a buffer, like Datadog's closed connections channel, so the ring buffer keeps draining while the map is read. With a `dst.*` process attribute, a closed connection is sent at its close when the remote socket is known, else looked up again every second and at the next map reads.
- `server.port` (opt-in) is the port of the server side whichever side reports: the remote port on the client, the local one on the server, from the handshake role, like the network flows' `server.port`. A connection opened before OBI started has no role: like Datadog's `port_bindings`, its side is the server when its local port is listening (`/proc/<pid>/net/tcp{,6}`, read once per network namespace and map read). The rows use the same role for `network.tcp.handshake.role` and `network.connection.role` when one of them is selected; the events keep `unknown`. Selecting it loads the role probe like `network.tcp.handshake.role`. Unlike `src.port`/`dst.port`, it never holds the client's ephemeral port, so open connections do not add series. With the events (`tcp_metrics: false`), `obi.stat.tcp.io` and `obi.stat.tcp.retransmits` report 0: their events have no role.
- A closed row counts every connection established on it: a new connection with the same addresses (a reused port) can take the row over before the previous one's close, which is then not sent.
- Differences with the events: the RTT is one sample per connection per read with activity, and one at close; the closed connections are the established ones (the failed attempts are only in `obi.stat.tcp.failed.connections`, like Datadog); the values arrive every `read_interval`; connections share the row map (`max_entries`).

### Process and container of the TCP stats

The TCP stat metrics (`obi.stat.tcp.*`) take the same process and container attributes, all off by default. Many of their events run where the current task is not the application (softirq, timers: handshakes, retransmits, zero window probes), so the kernel keeps the process of each socket, like Datadog's `tcp_ongoing_connect_pid`, in [bpf/statsolly/maps/sock_owner.h](../bpf/statsolly/maps/sock_owner.h):

- `sock_owner`, by `struct sock *`: written by `connect()` (`TCP_SYN_SENT`), else by the first send or receive of the socket (`tcp_sendmsg`, `tcp_cleanup_rbuf`), deleted at `TCP_CLOSE`, and at `tcp_close` for a socket already closed. Each entry keeps the remote address and port, and the local port once known: like Datadog keys `tcp_ongoing_connect_pid` by the socket and its tuple, an entry only names the same connection. A `struct sock` is reused by new sockets, and the delete of a closed one can be missed: the kernel skips a tracing program that fires while another one runs on the same CPU.
- `endpoint_owner`, by local address and port: the listeners (`inet_csk_listen_start`, also the listen of MPTCP, the default of Go listeners), and the local address of each connection when it is established. A new server connection takes the process of its local address or of its listener, the newer of the two (a restarted server), until the application uses it.

Each TCP stat event carries the PID, executable name and cgroup ID of its socket, and the network namespace. For `dst`, the ring buffer reader looks up the remote address in `endpoint_owner` (a loopback address in the namespace of the local socket), with a cache of one second. The probes run and the maps are sized only when one of these attributes is selected for an enabled TCP stat metric; otherwise the events carry zeros.

Known limits: the server side of a connection accepted before its server used any socket since OBI started (a server started before OBI) has no process; a socket handed to another process keeps the process that connected it or used it first, like Datadog; `dst` is only filled for the remote sockets on the same host, without NAT.

### Known limitations

#### `src.port` may be reported as `0`

The `src.port` attribute (disabled by default) can be `0` in metrics whose probes fire near socket teardown: specifically `obi_stat_tcp_rtt_seconds` and `obi_stat_tcp_failed_connections_total`. Metrics measured while the socket is still active (retransmits) are not affected. The root cause is a kernel-side race between the application's `close()` path and RST processing.

When a socket **receives** a RST and is orphaned (`SOCK_DEAD` set), the kernel calls:

```
tcp_done()
  └── inet_csk_destroy_sock()
        └── inet_put_port()  <-- zeroes skc_num (the source port)
```

This happens outside the application's `close()` call. By the time `parse_sock_info` in [bpf/common/sockaddr.h](../bpf/common/sockaddr.h) reads `skc_num`, it is already `0`.

The RST **sender** is not affected because it goes through the normal application `close()` path where the port is still valid at probe time.

StatsO11y probes fire at different points relative to `inet_put_port()`, so the behaviour is not uniform across metrics. For example, `obi_kprobe_tcp_close_srtt` (kprobe on `tcp_close`) may still observe a valid port in some RST-receiver scenarios, while `obi_tracepoint_inet_sock_set_state` (tracepoint on `inet_sock_set_state`) consistently sees `0`. Metrics with `src_port="0"` still carry useful signal — `dst_port`, `src_address`, `dst_address`, `reason`, and `network_tcp_handshake_role` remain valid.

### Performance considerations

Some stat metrics attach to kernel functions that are called very frequently (e.g. `tcp_sendmsg`, `tcp_cleanup_rbuf` for TCP IO). These probes add a small overhead on every call, so the aggregate cost is proportional to the rate of TCP sends/receives on the node. Consider:

- If you need RTT, failed connections, or retransmits **without** TCP IO overhead, enable those individually (`stats_tcp_rtt`, `stats_tcp_failed_connections`, `stats_tcp_successful_connections`, `stats_tcp_closed_connections`, `stats_tcp_retransmits`, `stats_tcp_flow_control`) instead of using the `stats` aggregate feature — `stats` includes `stats_tcp_io`, which fires on every `tcp_sendmsg` and `tcp_cleanup_rbuf` call.
- `stats_tcp_congestion` also runs on every `tcp_sendmsg` and `tcp_cleanup_rbuf` call, but only reads three `tcp_sock` counters and does one map lookup. A socket enters the `tcp_cong_last` map only after its ECN CE, reordering or out-of-order counter becomes non-zero, and sends at most one event per second (plus one at close).
- `stats_dns_lookups` is not part of `stats` and must be enabled explicitly. It runs its socket filter for every packet of OBI's network namespace, in both directions. Non-DNS packets exit after reading the protocol and the UDP or TCP ports, but the kernel clones every outgoing packet for the raw socket before the filter runs, like for `tcpdump`. This costs about 0.5 µs per packet, whatever the filter does, which can lower the packet rate of small-packet traffic by about 10%.
- The `stats_events` ring buffer and the per-metric eBPF maps (e.g. `tcp_io_accum`) have default size limits; on nodes with a very large number of concurrent connections these can be resized via the `ebpf.*` configuration knobs if events start being dropped.

### Final notes

We decided to create a component separate from **AppO11y** and **NetO11y**, focusing only on **statistical metrics** calculated for all applications running on the node. This is because statistical metrics are important if correlated to all applications, and also because some hook points can cause unreliable PID calculations and lead to false positives.

The user can then filter the metrics in userspace using appropriate filters or even the collector.

## General notes

Span Metrics, Service Graph Metrics and the info metrics carry no `Section`, because user-provided attribute selection is disabled for them: they are very specific metrics with an opinionated format. They are still declared once — span metrics in [metric_spanmetrics.go](../pkg/export/attributes/metric_spanmetrics.go), service graph in [metric_service_graph.go](../pkg/export/attributes/metric_service_graph.go), the `target.info` family in [metric_internal.go](../pkg/export/attributes/metric_internal.go) — so that both exporters read the same definition — the `OTEL` exporter takes `.OTEL` and `.Unit`, the `Prometheus` exporter takes the `.Prom` name derived from them. Do not add a new metric of this kind as a literal in either exporter.

Resource attributes exported through Prometheus `target_info` / `traces_target_info` (named `target.info` / `traces.target.info` on the OTLP path) and the corresponding OTLP resources can be filtered with `attributes.select.resource`. By default, detected resource attributes are preserved. For example:

```yaml
attributes:
  select:
    resource:
      exclude:
        - cloud.account.id
        - cloud.resource_id
        - host.image.id
        - host.type
        - k8s.pod.name
```

**Note**: a metric is defined using the `Name` type, which carries the metric's `Section`, its `OTEL` name, `Unit` and instrument `Type`, plus the `Prom` name derived from those. Subsequently, that metric can be a counter, gauge, or other type.
