# OBI TCP stats: retransmit type, zero-window probes, congestion

Three changes to OBI's TCP stats on this branch, plus a script to test them end to end.

| Change | Metric | New attribute / values |
|---|---|---|
| Retransmit cause | `obi.stat.tcp.retransmits` (existing) | `network.tcp.retransmit.type` = `timeout`, `fast`, `other` (on by default) |
| Zero-window probes | `obi.stat.tcp.flow_control.events` (new, feature `stats_tcp_flow_control`, part of `stats`) | `network.tcp.flow_control.event` = `zero_window` (on by default); `network.tcp.handshake.role` (off by default) |
| Congestion | `obi.stat.tcp.ecn.ce.packets`, `obi.stat.tcp.reordering.events`, `obi.stat.tcp.out_of_order.packets` (new, feature `stats_tcp_congestion`, part of `stats`) | `network.tcp.handshake.role` (off by default) |

Plans: `datadog-agent/cnm-docs/OBI_RETRANSMIT_TYPE_ATTRIBUTE_PLAN.md`,
`datadog-agent/cnm-docs/OBI_FLOW_CONTROL_ZERO_WINDOW_PLAN.md` and
`datadog-agent/cnm-docs/OBI_TCP_CONGESTION_IMPLEMENTATION_PLAN.md`.

## How they work

**Retransmit type.** The existing `tcp_retransmit_skb` raw tracepoint now also reads the
socket's congestion state (`icsk_ca_state`) and stores it in a spare padding byte of the event,
so the event size is unchanged:

| Kernel state | Set by | Value |
|---|---|---|
| `TCP_CA_Loss` | retransmission timer expired | `timeout` |
| `TCP_CA_Recovery` | duplicate ACKs / SACK | `fast` |
| anything else | e.g. tail loss probes | `other` |

Summing over the attribute gives exactly the old total, so existing dashboards keep working.

**Zero-window probes.** A new kprobe on `tcp_send_probe0` sends one ring-buffer event per
zero-window probe. One event = one probe, the same as Datadog's `tcp_probe0_count` and the
kernel's `TcpExtTCPWinProbe`. `src` is the blocked sender, `dst` is the receiver that is not
reading. The kprobe is optional: if the kernel lacks the symbol, OBI logs a warning and only this
metric is disabled.

**Congestion.** The kernel keeps three totals per socket in `tcp_sock`; OBI reads them and sends
the increase:

| Kernel field | Metric | Prometheus name | Datadog equivalent |
|---|---|---|---|
| `delivered_ce` | `obi.stat.tcp.ecn.ce.packets` | `obi_stat_tcp_ecn_ce_packets_total` | `tcp_delivered_ce` |
| `reord_seen` | `obi.stat.tcp.reordering.events` | `obi_stat_tcp_reordering_events_total` | `tcp_reord_seen` |
| `rcv_ooopack` | `obi.stat.tcp.out_of_order.packets` | `obi_stat_tcp_out_of_order_packets_total` | `tcp_rcv_ooo_pack` |

- Three new kprobes on `tcp_sendmsg`, `tcp_cleanup_rbuf` and `tcp_close` read the counters. They
  are separate programs from the `stats_tcp_io` ones on the same functions.
- A socket enters the `tcp_cong_last` LRU map (`1 << 14`) only once one of its counters is
  non-zero. Healthy sockets cost three reads and one lookup, with no map write and no event.
- One event carries all three increases. A socket sends at most one event per second; increases
  in between are carried to the next event. `tcp_close` always sends what is left and removes the
  socket from the map.
- The last-sent values move only after a successful ring-buffer reserve, so a full ring buffer
  delays a delta instead of losing it. Each failed reserve adds 1 to the per-CPU
  `tcp_cong_drops` map.
- `delivered_ce` is non-zero only on connections that negotiated ECN. Linux's default
  `net.ipv4.tcp_ecn = 2` doesn't request ECN, so in most environments this metric stays at 0.
- The exporters skip zero increases, so a metric that never moved has no series.

Two parts of the plan were changed:

- **No `congestion_min_interval` setting.** The one-second limit is the Go constant
  `congestionMinInterval` in `stats_tracer.go`, passed to the kernel as
  `stats_congestion_min_interval_ns`. Config v1 is frozen (`devdocs/config/version-2.0/config-v2.md`),
  so a user setting would have to be added to config v2.
- **No `obi_stats_tcp_congestion_ringbuf_drops_total` internal metric.** The `tcp_cong_drops` map is
  there, but the internal-metrics reporter isn't wired to it. During a load test, read it with
  `sudo bpftool map dump name tcp_cong_drops` (add up the per-CPU values).

## Test script

Everything is in `test-retransmit-type.sh` at the repo root. Running it with no argument prints
the step list.

| Step | Command | Where |
|---|---|---|
| 1. Install clang 19 tools and `iperf3` | `./test-retransmit-type.sh tools` | once (uses sudo) |
| 2. Regenerate eBPF bindings, build `bin/obi` | `./test-retransmit-type.sh build` | |
| 3. clang-format, clang-tidy, targeted tests, `make verify` | `./test-retransmit-type.sh verify` | |
| 4. Run OBI as root, Prometheus on `:9400` | `./test-retransmit-type.sh obi` | terminal A, Ctrl-C to stop |
| 5. Force retransmits, compare with the kernel | `./test-retransmit-type.sh traffic` | terminal B (uses sudo) |
| 6. Stall a receiver, compare zero-window probes | `./test-retransmit-type.sh zerowindow` | terminal B (no sudo) |
| 7. Reorder and ECN-mark traffic, compare with the kernel | `./test-retransmit-type.sh congestion` | terminal B (uses sudo) |
| 8. Show the current metrics | `./test-retransmit-type.sh metrics` | |
| Load the stats programs into this kernel's verifier | `./test-retransmit-type.sh verifier` | uses sudo |
| Undo the qdisc and `tcp_ecn` changes, stop the test server | `./test-retransmit-type.sh cleanup` | if a run gets interrupted |

After a code change, the quick re-check is `build`, then `obi` in terminal A, then `traffic`,
`zerowindow` and/or `congestion` in terminal B.

Notes:

- You don't type `sudo` for `obi`, `traffic`, `congestion` and `cleanup`; they re-run themselves
  with it.
- Ports can be changed with `PROM_PORT=…`, `IPERF_PORT=…` and `ZW_PORT=…`.
- `obi` enables `stats_tcp_retransmits,stats_tcp_flow_control,stats_tcp_congestion`.
- `traffic` runs `iperf3` over loopback: 15 s at 5% packet loss (mostly `fast`), then 20 s with
  three 3 s blackouts (`timeout`). It prints the kernel's `nstat` counters and how much each OBI
  type grew during the run. The loss rule is removed on exit, even if the step fails.
- `zerowindow` opens a loopback connection whose receiver has a 4 KiB buffer and stops reading
  twice for 15 s. It prints OBI's `zero_window` count next to the kernel's `TcpExtTCPWinProbe`.
- `congestion` runs `iperf3` over loopback twice for 20 s. The first run reorders 25% of packets,
  for out-of-order and reordering. The second sets `net.ipv4.tcp_ecn=1` and runs on a 50 Mbit/s
  `tbf` link with `fq_codel ecn`, which marks packets CE instead of dropping them. It prints the
  kernel's `nstat` counters next to OBI's increase for each metric. The qdisc and the old
  `tcp_ecn` value are restored on exit.
- `verifier` loads every statsolly program into the running kernel with both values of each
  load-time constant. This is the local version of the plan's step 4.5. The full kernel matrix
  is `make run-bpf-verifier-vm`.
- OBI drops a series it hasn't updated for a while, so `metrics` may show nothing for loopback
  some minutes after a test. That's why `traffic` and `zerowindow` report the change over their
  own run instead of running totals.

## Results so far (kernel 7.0.0-34)

**Retransmit type** (`traffic`):

```
obi_stat_tcp_retransmits_total{src_address="127.0.0.1",dst_address="127.0.0.1",network_tcp_retransmit_type="fast"}    1742
obi_stat_tcp_retransmits_total{src_address="127.0.0.1",dst_address="127.0.0.1",network_tcp_retransmit_type="timeout"}  257
obi_stat_tcp_retransmits_total{src_address="127.0.0.1",dst_address="127.0.0.1",network_tcp_retransmit_type="other"}     72
```

The 5% loss phase was almost all `fast`; `timeout` jumped during the blackouts. Real outbound
connections that never got a reply also showed up as `timeout`.

**Zero-window probes** (`zerowindow`):

```
OBI zero_window events (loopback)  13
kernel TcpExtTCPWinProbe (all)     13
```

**Congestion** (`congestion`):

| Metric | OBI (loopback) | Kernel (`nstat`, all interfaces) |
|---|---|---|
| `ecn_ce_packets` | 1933 | `TcpExtTCPDeliveredCE` 1933 |
| `reordering_events` | 2541 | `TcpExtTCPSACKReorder` 1918 + `TcpExtTCPTSReorder` 633 = 2551 |
| `out_of_order_packets` | 1498 | `TcpExtTCPOFOQueue` 1313 |

CE is an exact match and reordering is within 0.4%. Out-of-order is higher because the kernel
adds 1 to `TCPOFOQueue` per queued buffer, but adds the buffer's segment count (`gso_segs`) to
`rcv_ooopack`, which is what OBI and Datadog's `tcp_rcv_ooo_pack` read. With OBI running normally,
all three programs passed the verifier on kernel 7.0 and attached. Out-of-order and reordering
also showed up on real internet connections.

**Checks:** clang-format 19 and clang-tidy 19 are clean; the affected Go packages, config
conversion, schema and config-doc checks pass. `make verify` with both changes passed lint and
all test packages except one timing-sensitive test per run, each unrelated to these changes and
passing when re-run alone:

| Run | Failed test | Re-run alone |
|---|---|---|
| retransmit change | `TestBlockedClients` (`pkg/kube/kubecache/envtest`) | passed 3/3 |
| both changes | `TestMetrics_InternalInstrumentation` (`pkg/export/otel`, span metrics exporter) | passed 5/5 with `-race`; whole package passes with `-race` |

## Running `make verify` without freezing the machine

`make verify` runs `golangci-lint` over the whole repo and `go test -race ./... -coverpkg=./...`,
which is heavy on CPU, memory and disk. Run it at low priority with fewer parallel packages:

```bash
nice -n 19 ionice -c3 env GOFLAGS=-p=4 make verify
```

While iterating, test only the touched packages instead:

```bash
go test ./pkg/internal/statsolly/... ./pkg/statsolly/... ./pkg/export/... ./internal/config/...
```

## Files changed

- **eBPF:** `bpf/statsolly/types.h`, `tp_tcp.c` (retransmit type), `k_tcp.c` (zero-window kprobe,
  congestion kprobes), `stats.c`, new `maps/tcp_cong_last.h` and `maps/tcp_cong_drops.h`
- **Tracer and decoding:** `pkg/internal/statsolly/ebpf/{stats_tracer,stat,stat_getters}.go`,
  `pkg/internal/statsolly/stats/tracer_ringbuf.go`
- **Metric, attributes, feature flag:** `pkg/export/attributes/{metric,attr_defs}.go`,
  `pkg/export/attributes/names/attrs.go`, `pkg/export/feature.go`
- **Exporters:** `pkg/export/otel/metrics_stats.go`, `pkg/export/prom/prom_stats.go`
- **Config v2:** `internal/config/convert/{export,import}.go`, `cmd/check-config-v2-parity/main.go`,
  `devdocs/config/version-2.0/*`
- **Schema and docs:** `schemas/obi/groups/stats/{registry,metrics}.yaml`; regenerated
  `site/docs/*` and `devdocs/config/{CONFIG.md,config-schema.json}`; `devdocs/metrics.md`
- **Tests:** `tracer_ringbuf_test.go`, `stats_tracer_test.go`, new `stat_getters_test.go`,
  `pipeline_test.go`, `metric_test.go`, config convert tests, the statsolly constant in
  `pkg/internal/ebpf/verifier/bpf_verifier_test.go`

Adding the `stats_tcp_flow_control` and `stats_tcp_congestion` feature bits shifts the bits after
them, so the generated `metrics.features` default in `CONFIG.md` changes from 1536 to 6144. The
enabled defaults are the same; the template commit `6ad4e67e7` had the same churn.

`test-retransmit-type.sh` and this file are not tracked by git, so they won't be committed unless
you add them.
