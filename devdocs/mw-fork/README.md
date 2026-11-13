# Middleware fork of OBI

This repository is Middleware's fork of OpenTelemetry eBPF Instrumentation (OBI):
`middleware-labs/opentelemetry-ebpf-instrumentation`. The `upstream` remote is
`open-telemetry/opentelemetry-ebpf-instrumentation`.

The fork adds Cloud Network Monitoring (CNM), Datadog-like per-connection network metrics, to
OBI's stats pipeline (`statsolly`). Everything else is upstream OBI.

Read these before changing the stats code or syncing with upstream:

- [socket-traffic-reader.md](socket-traffic-reader.md): how the CNM metrics are collected, in the
  kernel and in user space, and how to add a metric.
- [upstream-sync.md](upstream-sync.md): how to merge `upstream/main` into the fork, and the
  conflicts and pitfalls seen so far.

## Branches

| Branch | Content |
|---|---|
| `network-performance-monitoring` | The CNM work. mw-agent pins a commit of it. |
| `network-performance-monitoring-sync` | The CNM work merged with `upstream/main` (merge of 2026-11-13). |
| `main` | Mirror of upstream `main`. |

## Rules for changes in this fork

1. **The CNM metrics come from the socket traffic reader only.** The default stats flow (one
   ring buffer event per TCP event) stays exactly upstream's. Do not add CNM metrics, attributes
   or fields to upstream's event programs (`bpf/statsolly/tp_tcp.c`, `bpf/statsolly/k_tcp.c`) or
   to the event decoder (`pkg/internal/statsolly/stats/tracer_ringbuf.go`).
2. **Keep upstream files unchanged where possible.** Put new eBPF code, maps and helpers in new
   files. The only upstream eBPF files the fork changes are `bpf/statsolly/stats.c` (includes and
   `unused` enum lines) and `bpf/statsolly/types.h` (new enums and stat types), and only by
   adding lines. Go files that both flows share (features, attributes, exporters, config) get
   additions next to upstream's code, never rewrites of it.
3. **The fork-only TCP metrics are opt-in and need the rows.** `stats_tcp_closed_connections`,
   `stats_tcp_flow_control` and `stats_tcp_congestion` are in `export.FeatureStatsTCPRowOnly`,
   not in `stats` (`FeatureStats`) or `all` (`FeatureAll`). `Config.validateStatsTCPRowFeatures`
   (`pkg/obi/config.go`) refuses them without `stats.socket_traffic.tcp_metrics: true`.
4. **Never edit generated files**: `*_bpfel.go`, `*_bpfel.o`, `bpf/bpfcore/`. Regenerate them
   (see [upstream-sync.md](upstream-sync.md#validate)).
5. Follow the repository rules in [AGENTS.md](../../AGENTS.md) as well.

## Who uses the fork

### mw-agent

Middleware's agent (`middleware-labs/mw-agent`) runs OBI as an OpenTelemetry Collector receiver
named `obi`:

- The fork is a git submodule at `.obi-src`, pinned to a commit. `go.mod` has
  `replace go.opentelemetry.io/obi => ./.obi-src` (the `require` version is a placeholder).
- The generated eBPF files are gitignored here, so mw-agent runs `make generate-obi`
  (`make -C .obi-src docker-generate`) before building. Its Dockerfiles have a `bpf-generator`
  stage for the same reason.
- The receiver is registered in `init()` of `cmd/host-agent/main.go` and `cmd/kube-agent/main.go`
  through `agent.ExtraReceivers`. CI builds `main.go` alone, so the registration must stay in
  that file.
- The feature flag is `agent-features.cloud-network-monitoring`
  (`MW_AGENT_FEATURES_CLOUD_NETWORK_MONITORING`). When it is on, the agent asks the backend for
  the CNM config with `enable_cloud_network_monitoring=true`.
- mw-agent's `docs/obi-integration.md` and `docs/obi-update.md` describe the setup and how to
  move `.obi-src` to a new commit of this fork.

### Backend config (bifrost)

The backend writes the `obi` receiver config, in
`app/internal/endpoints/agent/ingestion_rules/cloud_network_monitoring.go`:

- Only for mw-agent 2.0.8 and later, on Linux hosts and the Kubernetes DaemonSet, in its own
  `metrics/cnm` pipeline.
- It uses the **v1 config layout**: before upstream PR #3973, a v2 receiver config could not set
  `attributes.select`. The merge of 2026-11-13 brings that PR in, so the backend could move to
  v2 once mw-agent uses a commit that has it.
- It enables the `stats_*` features with `stats.socket_traffic.tcp_metrics: true` and
  `connection_rollup: true`, network flows off, and selects every attribute except `src.port`,
  `dst.port` and the container IDs.
- `attributes.kubernetes.enable` must be a string (`"true"`, `"false"` or `"autodetect"`): the
  Collector config rejects a bool.
- OBI exports the `obi.stat.*` metrics with delta temporality, so the pipeline needs no
  `cumulative_to_delta` processor.

Any change to the fork's config names, features or validation must keep this config valid.
Check it with the fork's `obi config validate --mode=receiver <file>`, which rejects unknown
keys and values.
