# OBI network metric attributes

Applies to the deployment configured in `obi-values.yaml` (network capture enabled,
Kubernetes metadata enabled, OTLP gRPC export to `mw-agent:9319`).

Source: `pkg/export/attributes/attr_defs.go`, `pkg/export/otel/metrics_net.go`,
`internal/config/convert/import.go`.

## Metric emitted

| Metric | Type | Unit |
|---|---|---|
| `obi.network.flow.bytes` | Counter | bytes |

Not emitted with this config: `obi.network.flow.packets`, `obi.network.inter.zone.bytes`.

## Resource attributes

| Attribute | Description |
|---|---|
| `obi.version` | OBI build version |
| `obi.revision` | OBI build revision |
| `telemetry.distro.name` | Telemetry distribution name |
| `telemetry.distro.version` | Telemetry distribution version |
| `host.id` | Host ID of the node |

## Metric attributes enabled by default

| Attribute | Description | Example |
|---|---|---|
| `direction` | Flow direction | `request` / `response` |
| `k8s.src.owner.name` | Owner of the source pod | `ruby-app` |
| `k8s.src.owner.type` | Owner kind of the source pod | `Deployment` |
| `k8s.src.namespace` | Namespace of the source | `default` |
| `k8s.dst.owner.name` | Owner of the destination pod | `mw-agent` |
| `k8s.dst.owner.type` | Owner kind of the destination pod | `DaemonSet` |
| `k8s.dst.namespace` | Namespace of the destination | `mw-agent-ns` |
| `k8s.cluster.name` | Cluster name | `my-cluster` |

## Metric attributes available but disabled by default

Enable through `attributes.select` (see below).

| Attribute | Description |
|---|---|
| `src.address` | Source IP address |
| `dst.address` | Destination IP address |
| `src.port` | Source port |
| `dst.port` | Destination port |
| `server.port` | Server-side port of the connection |
| `client.port` | Client-side port of the connection |
| `src.name` | Source name (host or pod) |
| `dst.name` | Destination name (host or pod) |
| `transport` | Transport protocol (TCP, UDP) |
| `network.type` | IP version (`ipv4` / `ipv6`) |
| `network.protocol.name` | Application protocol name |
| `src.zone` | Availability zone of the source node |
| `dst.zone` | Availability zone of the destination node |
| `obi.ip` | IP of the OBI instance that captured the flow |
| `k8s.src.name` | Source pod or service name |
| `k8s.src.type` | Source object type (`Pod`, `Service`, `Node`) |
| `k8s.src.node.ip` | IP of the node running the source |
| `k8s.src.node.name` | Name of the node running the source |
| `k8s.dst.name` | Destination pod or service name |
| `k8s.dst.type` | Destination object type (`Pod`, `Service`, `Node`) |
| `k8s.dst.node.ip` | IP of the node running the destination |
| `k8s.dst.node.name` | Name of the node running the destination |
| `service.name` | Source service name |
| `service.namespace` | Source service namespace |
| `service.peer.name` | Destination service name |
| `service.peer.namespace` | Destination service namespace |

## Attributes that need extra configuration

| Attribute | Requires |
|---|---|
| `src.cidr`, `dst.cidr` | `network.capture` CIDR definitions |
| `src.country`, `dst.country`, `src.asn`, `dst.asn` | GeoIP database configuration |
| `iface`, `iface.direction` | Flow deduplication set to `none` |

## Default flow filters (from the Helm chart)

Flows are dropped when `k8s.src.owner.name` or `k8s.dst.owner.name` matches:

```
{kube*,*jaeger-agent*,*prometheus*,*promtail*,*grafana-agent*}
```

## Enabling extra attributes

Example `obi-values.yaml` addition (under `config.data.extensions.obi`):

```yaml
enrich:
  attributes:
    select:
      obi.network.flow:
        include:
          - k8s.src.name
          - k8s.dst.name
          - src.address
          - dst.address
          - dst.port
```
