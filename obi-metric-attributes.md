# OBI network and stats metrics: resource and metric attributes

Reference for the 14 OBI network and stats metrics, as exported over OTLP.
Source: `pkg/export/attributes/attr_defs.go` (per-metric attributes and defaults),
`pkg/export/otel/metrics_net.go` and `pkg/export/otel/metrics_stats.go` (resource).

Every attribute is one of two kinds:

- **Resource attribute**: sent once per batch, describes who sent the data (the OBI on a node).
  These are the only attributes that bifrost's `ResourceWrapper` sees.
- **Metric attribute** (data point attribute): on every data point, describes what the measurement is about.

## 1. Resource attributes (same for all 14 metrics)

| Attribute | Example | Source | Changes on OBI upgrade |
|---|---|---|---|
| `host.id` | `i-0abc123…` or a machine ID | in priority order: the host ID set in the OBI config, the cloud instance ID when cloud metadata is detected (ECS, EC2, GCP, Azure), the Kubernetes node machine ID, `/etc/machine-id` | no |
| `obi.version` | `v1.0.0` | OBI build | yes |
| `obi.revision` | git commit | OBI build | yes |
| `telemetry.distro.name` | `opentelemetry-ebpf-instrumentation` | constant | no |
| `telemetry.distro.version` | `v1.0.0` | OBI build | yes |

Notes:

- `host.id` passes through the `attributes.select` lists of the `obi.network.*` sections: if a network
  section has an `include:` list, it must contain `host.id`, or `host.id` is dropped from the network
  resource. The `obi.stat.*` sections never filter it. `obi-values-no-ports.yaml` includes it.
- `obi.version` is only set on the network and stats resources, never on application metrics or traces,
  so it identifies OBI network and stats data.
- With the Prometheus exporter there is no resource: these attributes go to `target_info` instead.

## 2. Cloud metadata

OBI detects the node's cloud metadata (EC2, Azure VM, GCP, ECS: `cloud.provider`, `cloud.platform`,
`cloud.region`, `cloud.availability_zone`, `host.type`, …), but the network and stats exporters
only use it for `host.id`. No `cloud.*` attribute is sent with these 14 metrics.
Cloud attributes are added to the application metrics and traces only.

The availability zone is available as metric attributes instead:

| Attribute | Source |
|---|---|
| `src.zone`, `dst.zone` | the `topology.kubernetes.io/zone` label of the Kubernetes node of the source and destination (Kubernetes decoration must be enabled) |

To get `cloud.*` on the resource, the collector that receives the data must add it
(for example with a resource detection processor).

## 3. Metric attribute groups

The per-metric tables below combine these groups. "Default" is what OBI sends without an
`attributes.select` section for the metric.

### Network base (`obi.network.*`)

| Attribute | Default |
|---|---|
| `direction` | on |
| `obi.ip` | off |
| `transport` | off |
| `src.address`, `dst.address` | off |
| `src.port`, `dst.port` | off |
| `src.name`, `dst.name` | off |
| `server.port`, `client.port` | off |
| `src.zone`, `dst.zone` | off |
| `network.type`, `network.protocol.name` | off |
| `iface`, `iface.direction` | off (on when the interface direction feature is enabled) |

### Network CIDR (only when `cidrs` are configured)

| Attribute | Default |
|---|---|
| `src.cidr`, `dst.cidr` | on |

### Network GeoIP (only when GeoIP is configured)

| Attribute | Default |
|---|---|
| `src.country`, `dst.country` | on |
| `src.asn`, `dst.asn` | on |

### Stats base (`obi.stat.*`)

| Attribute | Default |
|---|---|
| `src.address`, `dst.address` | on |
| `obi.ip` | off |
| `src.port`, `dst.port` | off |
| `src.name`, `dst.name` | off |
| `src.zone`, `dst.zone` | off |

### Kubernetes (network and stats, only when Kubernetes decoration is enabled)

| Attribute | Default |
|---|---|
| `k8s.cluster.name` | on |
| `k8s.src.namespace`, `k8s.dst.namespace` | on |
| `k8s.src.owner.name`, `k8s.dst.owner.name` | on |
| `k8s.src.owner.type`, `k8s.dst.owner.type` | on |
| `k8s.src.name`, `k8s.dst.name` (pod or service name) | off |
| `k8s.src.type`, `k8s.dst.type` | off |
| `k8s.src.node.ip`, `k8s.dst.node.ip` | off |
| `k8s.src.node.name`, `k8s.dst.node.name` | off |
| `service.name`, `service.namespace` | off |
| `service.peer.name`, `service.peer.namespace` | off |

The namespace of the source and destination is `k8s.src.namespace` and `k8s.dst.namespace`:
metric attributes, not resource attributes.

## 4. Per metric

"Your file" is what `obi-values-no-ports.yaml` selects. `src.cidr` and `dst.cidr` are listed there,
but they are only sent once `cidrs` are configured.

### Network

| Metric | Attribute groups | Extra attributes | Your file |
|---|---|---|---|
| `obi.network.flow.bytes` | network base, CIDR, GeoIP, Kubernetes | none | `direction`, `transport`, `src.address`, `dst.address`, `src.name`, `dst.name`, `src.cidr`, `dst.cidr`, `obi.ip`, `k8s.cluster.name`, `k8s.src.namespace`, `k8s.src.owner.name`, `k8s.src.owner.type`, `k8s.dst.namespace`, `k8s.dst.owner.name`, `k8s.dst.owner.type` |
| `obi.network.flow.packets` | network base, CIDR, GeoIP, Kubernetes | none | `direction`, `transport`, `src.address`, `dst.address`, `src.name`, `dst.name`, `src.cidr`, `dst.cidr`, `obi.ip`, `k8s.src.owner.name`, `k8s.dst.owner.name` |
| `obi.network.inter.zone.bytes` | same groups, all off by default except `k8s.cluster.name`, `src.zone`, `dst.zone` | none | `k8s.cluster.name`, `src.zone`, `dst.zone` |

### Stats

All stats metrics have the stats base and Kubernetes groups. Your file selects `include: ["*"]` with
`exclude: [src.port, dst.port]`, so they send every attribute below except the ports.

| Metric | Extra attributes (default) |
|---|---|
| `obi.stat.tcp.rtt` | `network.tcp.handshake.role` (off) |
| `obi.stat.tcp.failed.connections` | `reason` (off), `network.tcp.handshake.role` (off) |
| `obi.stat.tcp.successful.connections` | `network.tcp.handshake.role` (off) |
| `obi.stat.tcp.closed.connections` | `network.tcp.handshake.role` (off) |
| `obi.stat.tcp.retransmits` | `network.tcp.retransmit.type` (on) |
| `obi.stat.tcp.io` | `network.io.direction` (on) |
| `obi.stat.tcp.flow_control.events` | `network.tcp.flow_control.event` (on), `network.tcp.handshake.role` (off) |
| `obi.stat.tcp.ecn.ce.packets` | `network.tcp.handshake.role` (off) |
| `obi.stat.tcp.reordering.events` | `network.tcp.handshake.role` (off) |
| `obi.stat.tcp.out_of_order.packets` | `network.tcp.handshake.role` (off) |
| `obi.stat.dns.lookup.duration` | `error.type` (on, omitted when the lookup succeeded), `dns.question.name` (off), `dns.question.type` (off) |

Stats metrics have no CIDR, GeoIP, `direction` or `transport` attributes.

## 5. For bifrost

- Resource identity: detect OBI data by the `obi.version` key, and use `host.id`
  (plus `telemetry.distro.name`) as identity, with `host` as parent.
- Everything in sections 3 and 4, including `k8s.cluster.name`, the namespaces and the zones,
  arrives on the data points (`NumberDataPoint.Attributes()`, `HistogramDataPoint.Attributes()`),
  not on the resource.
