// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logger"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/internal/procmeta"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/socktraffic"
	stats "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/netip"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// procRoot is read to find the UDP ports bound before OBI started, and whether idle TCP
// connections are still open
const procRoot = "/proc"

func alog() *slog.Logger {
	return slog.With("component", "agent.StatsO11y")
}

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept stats.
type Status int

const (
	StatusNotStarted Status = iota
	StatusStarting
	StatusStarted
	StatusStopping
	StatusStopped
)

func (s Status) String() string {
	switch s {
	case StatusNotStarted:
		return "StatusNotStarted"
	case StatusStarting:
		return "StatusStarting"
	case StatusStarted:
		return "StatusStarted"
	case StatusStopping:
		return "StatusStopping"
	case StatusStopped:
		return "StatusStopped"
	default:
		return "invalid"
	}
}

var errShutdownTimeout = errors.New("graceful shutdown has timed out while waiting for eBPF statsolly to finish")

// Stats reporting agent
type Stats struct {
	cfg     *obi.Config
	ctxInfo *global.ContextInfo
	graph   *swarm.Runner

	// elements used to decorate stats with extra information
	agentIP net.IP

	// stat metrics
	rbTracer *stats.RingBufTracer
	// DNS lookups, nil when the stats_dns_lookups feature is disabled
	dnsTracer *stats.DNSTracer
	// socket bytes and packets, nil when the stats_socket_* features are disabled
	socketTraffic *socktraffic.Reader

	// focuses on TCP/UDP stack internals (kprobes/tracepoints)
	fetcher ebpFetcher

	status Status
}

type ebpFetcher interface {
	io.Closer
	StatsEventsMap() *ciliumebpf.Map
	StatsDNSEventsMap() *ciliumebpf.Map
	SocketTrafficMap() *ciliumebpf.Map
	SocketTrafficClosedMap() *ciliumebpf.Map
	SocketTrafficDropsMap() *ciliumebpf.Map
	EndpointOwnerMap() *ciliumebpf.Map
	DebugEventsMap() *ciliumebpf.Map
}

func StatsAgent(ctxInfo *global.ContextInfo, cfg *obi.Config) (*Stats, error) {
	alog := alog()
	alog.Info("initializing Stats agent")

	var (
		statsFetcher ebpFetcher
		err          error
	)

	alog.Debug("acquiring Agent IP")

	agentIP, err := netip.FetchAgentIP(cfg.Stats.AgentIP, string(cfg.Stats.AgentIPIface), cfg.Stats.AgentIPType)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            cfg.Attributes.Select,
		ExtraGroupAttributesCfg: cfg.Attributes.ExtraGroupAttributes,
	}
	tcpSrc, tcpDst := processAttrsSelected(cfg, tcpStatMetrics(&cfg.Metrics.Features))
	statsFetcher, err = newFetcher(&cfg.EBPF, &cfg.Metrics.Features, selectorCfg, &cfg.Stats.SocketTraffic, tcpSrc || tcpDst)
	if err != nil {
		return nil, err
	}

	return statsAgent(ctxInfo, cfg, statsFetcher, agentIP)
}

func newFetcher(
	cfg *config.EBPFTracer,
	features *export.Features,
	selectorCfg *attributes.SelectorConfig,
	socketTraffic *config.SocketTrafficConfig,
	sockOwners bool,
) (ebpFetcher, error) {
	seedUDPPorts := func(bindings *ciliumebpf.Map) error { return socktraffic.SeedUDPPortBindings(bindings, procRoot) }
	return ebpf.NewStatsFetcher(cfg, features, selectorCfg, socketTraffic, sockOwners, seedUDPPorts)
}

// statsAgent is a private constructor with injectable dependencies, usable for tests
func statsAgent(
	ctxInfo *global.ContextInfo,
	cfg *obi.Config,
	statsFetcher ebpFetcher,
	agentIP net.IP,
) (*Stats, error) {
	var endpointOwners *ciliumebpf.Map
	if _, dst := processAttrsSelected(cfg, tcpStatMetrics(&cfg.Metrics.Features)); dst {
		endpointOwners = statsFetcher.EndpointOwnerMap()
	}
	rbTracer := stats.NewRingBufTracer(statsFetcher.StatsEventsMap(), endpointOwners, &cfg.EBPF)

	var dnsTracer *stats.DNSTracer
	if cfg.Metrics.Features.StatsDNSLookups() {
		dnsTracer = stats.NewDNSTracer(statsFetcher.StatsDNSEventsMap(), &cfg.EBPF, ctxInfo.Metrics, dnsKeepsClientPort(cfg))
	}

	var socketTraffic *socktraffic.Reader
	tcpRows := ebpf.TCPMetricsFromRows(&cfg.Metrics.Features, &cfg.Stats.SocketTraffic)
	if cfg.Metrics.Features.StatsSocketTraffic() || tcpRows {
		warnSlowSocketTrafficReads(cfg)
		emit := socktraffic.EmitFor(&cfg.Metrics.Features, tcpRows)
		emit.ServerPort = attrSelected(cfg, rowMetrics(&cfg.Metrics.Features, tcpRows), attr.ServerPort)
		emit.Role = attrSelected(cfg, socketTrafficMetrics(&cfg.Metrics.Features), attr.NetworkConnectionRole) ||
			tcpRows && attrSelected(cfg, tcpStatMetrics(&cfg.Metrics.Features), attr.NetworkTCPHandshakeRole)
		socketTraffic = socktraffic.NewReader(statsFetcher.SocketTrafficMap(), statsFetcher.SocketTrafficClosedMap(),
			statsFetcher.SocketTrafficDropsMap(), &cfg.EBPF, &cfg.Stats.SocketTraffic, procRoot,
			emit, dstProcessAttrsSelected(cfg, tcpRows) || sameHostSelected(cfg, tcpRows), ctxInfo.Metrics)
	}

	return &Stats{
		ctxInfo:       ctxInfo,
		cfg:           cfg,
		rbTracer:      rbTracer,
		dnsTracer:     dnsTracer,
		socketTraffic: socketTraffic,
		agentIP:       agentIP,
		fetcher:       statsFetcher,
	}, nil
}

var (
	srcProcessAttrs = []attr.Name{
		attr.SrcProcessExecutableName, attr.SrcContainerID, attr.SrcContainerName,
		attr.SrcContainerImageName, attr.SrcContainerImageTag,
	}
	dstProcessAttrs = []attr.Name{
		attr.DstProcessExecutableName, attr.DstContainerID, attr.DstContainerName,
		attr.DstContainerImageName, attr.DstContainerImageTag,
	}
)

// statMetric is a metric of the stats tracer, and whether it is enabled
type statMetric struct {
	enabled bool
	name    attributes.Name
}

// socketTrafficMetrics are the metrics that take the process of a socket from the socket traffic rows
func socketTrafficMetrics(features *export.Features) []statMetric {
	return []statMetric{
		{features.StatsSocketBytes(), attributes.StatSocketBytes},
		{features.StatsSocketPackets(), attributes.StatSocketPackets},
	}
}

// tcpStatMetrics are the metrics that take the process of a socket from the TCP stat events
func tcpStatMetrics(features *export.Features) []statMetric {
	return []statMetric{
		{features.StatsTCPRtt(), attributes.StatTCPRtt},
		{features.StatsTCPFailedConnections(), attributes.StatTCPFailedConnections},
		{features.StatsTCPSuccessfulConnections(), attributes.StatTCPSuccessfulConnections},
		{features.StatsTCPClosedConnections(), attributes.StatTCPClosedConnections},
		{features.StatsTCPRetransmits(), attributes.StatTCPRetransmits},
		{features.StatsTCPIo(), attributes.StatTCPIo},
		{features.StatsTCPFlowControl(), attributes.StatTCPFlowControlEvents},
		{features.StatsTCPCongestion(), attributes.StatTCPECNCEPackets},
		{features.StatsTCPCongestion(), attributes.StatTCPReorderingEvents},
		{features.StatsTCPCongestion(), attributes.StatTCPOutOfOrderPackets},
	}
}

func attrSelector(cfg *obi.Config) (*attributes.AttrSelector, error) {
	return attributes.NewAttrSelector(attributes.UndefinedGroup, &attributes.SelectorConfig{
		SelectionCfg:            cfg.Attributes.Select,
		ExtraGroupAttributesCfg: cfg.Attributes.ExtraGroupAttributes,
	})
}

// attrSelected tells whether one of the enabled metrics has the attribute selected
func attrSelected(cfg *obi.Config, metrics []statMetric, name attr.Name) bool {
	sel, err := attrSelector(cfg)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(metrics, func(m statMetric) bool {
		return m.enabled && slices.Contains(sel.For(m.name), name)
	})
}

// processAttrsSelected tells which sides of the enabled metrics have a process or container
// attribute selected
func processAttrsSelected(cfg *obi.Config, metrics []statMetric) (src, dst bool) {
	sel, err := attrSelector(cfg)
	if err != nil {
		return false, false
	}
	for _, m := range metrics {
		if !m.enabled {
			continue
		}
		selected := sel.For(m.name)
		src = src || slices.ContainsFunc(srcProcessAttrs, func(n attr.Name) bool { return slices.Contains(selected, n) })
		dst = dst || slices.ContainsFunc(dstProcessAttrs, func(n attr.Name) bool { return slices.Contains(selected, n) })
	}
	return src, dst
}

// dstProcessAttrsSelected tells whether the metrics of the socket traffic rows have a dst.*
// process or container attribute selected: with tcpRows, the TCP stat metrics too
func dstProcessAttrsSelected(cfg *obi.Config, tcpRows bool) bool {
	_, dst := processAttrsSelected(cfg, rowMetrics(&cfg.Metrics.Features, tcpRows))
	return dst
}

// sameHostSelected tells whether the metrics of the socket traffic rows have
// network.peer.same_host selected: with tcpRows, the TCP stat metrics too
func sameHostSelected(cfg *obi.Config, tcpRows bool) bool {
	return attrSelected(cfg, rowMetrics(&cfg.Metrics.Features, tcpRows), attr.NetworkPeerSameHost)
}

// rowMetrics are the metrics read from the socket traffic rows: with tcpRows, the TCP stat
// metrics too
func rowMetrics(features *export.Features, tcpRows bool) []statMetric {
	metrics := socketTrafficMetrics(features)
	if tcpRows {
		metrics = append(metrics, tcpStatMetrics(features)...)
	}
	return metrics
}

// processResolver returns how the process decorator finds the process and container of a PID,
// or nil when no process or container attribute is selected
func (s *Stats) processResolver(selected bool) func(ctx context.Context) (*procmeta.Resolver, error) {
	if !selected {
		return nil
	}
	return func(ctx context.Context) (*procmeta.Resolver, error) {
		sources := procmeta.Sources{
			ContainerID: func(pid uint32) (string, error) {
				info, err := container.InfoForPID(app.PID(pid))
				return info.ContainerID, err
			},
		}
		// for the processes that ended before they were looked up
		if cgroups := procmeta.NewCgroupIndex(procRoot); cgroups != nil {
			sources.ContainerIDByCgroup = cgroups.ContainerID
		}
		if informer := s.ctxInfo.K8sInformer; informer != nil && informer.IsKubeEnabled() {
			store, err := informer.Get(ctx)
			if err != nil {
				return nil, fmt.Errorf("process attributes: getting the Kubernetes store: %w", err)
			}
			sources.KubeContainerName = func(cid string) string {
				_, name := store.PodContainerByContainerID(cid)
				return name
			}
		}
		if containers := s.ctxInfo.DockerMetadata; containers != nil && containers.IsEnabled(ctx) {
			sources.Docker = func(cid string) (string, string, bool) {
				meta, ok := containers.ContainerInfoByID(ctx, cid)
				return meta.Name, meta.Image, ok
			}
		}
		return procmeta.NewResolver(procRoot, sources), nil
	}
}

// dnsKeepsClientPort tells whether the DNS lookups need their client port: when it is a
// reported or a filtered attribute. Otherwise the lookups that only differ by it are merged.
func dnsKeepsClientPort(cfg *obi.Config) bool {
	for name := range cfg.Filters.Stats {
		if attr.Name(name).Prom() == attr.SrcPort.Prom() {
			return true
		}
	}
	sel, err := attributes.NewAttrSelector(attributes.UndefinedGroup, &attributes.SelectorConfig{
		SelectionCfg:            cfg.Attributes.Select,
		ExtraGroupAttributesCfg: cfg.Attributes.ExtraGroupAttributes,
	})
	if err != nil {
		return true
	}
	return slices.Contains(sel.For(attributes.StatDNSLookupDuration), attr.SrcPort)
}

// warnSlowSocketTrafficReads warns when the socket traffic is read less often than the
// OTEL metrics are exported: some exports would then miss the traffic of their interval.
func warnSlowSocketTrafficReads(cfg *obi.Config) {
	readInterval := cfg.Stats.SocketTraffic.ReadInterval
	exportInterval := cfg.OTELMetrics.Interval
	if cfg.OTELMetrics.EndpointEnabled() && exportInterval > 0 && readInterval > exportInterval {
		alog().Warn("stats.socket_traffic.read_interval is longer than the OTEL metrics export interval",
			"readInterval", readInterval, "exportInterval", exportInterval)
	}
}

// Run a Stats agent
func (s *Stats) Run(ctx context.Context) error {
	alog := alog()

	s.status = StatusStarting
	alog.Info("starting Stats agent")

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if s.cfg.EBPF.BpfDebug {
		go logger.ReadDebugEventsMap(runCtx, s.fetcher.DebugEventsMap(),
			slog.With("component", "statsolly.BPFDebug"))
	}

	graph, err := s.buildPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	s.graph = graph

	s.graph.Start(ctx, swarm.WithCancelTimeout(tracefs.EffectiveShutdownTimeout(s.cfg.ShutdownTimeout)))
	s.status = StatusStarted

	alog.Info("Stats agent successfully started")

	<-ctx.Done()

	if err := s.stop(); err != nil {
		return fmt.Errorf("failed to stop Stats agent: %w", err)
	}

	return nil
}

func (s *Stats) stop() error {
	alog := alog()

	stopped := make(chan error)
	go func() {
		s.status = StatusStopping
		alog.Info("stopping Stats agent")
		if err := s.fetcher.Close(); err != nil {
			alog.Warn("eBPF resources not correctly closed", "error", err)
		}

		alog.Debug("waiting for all nodes to finish their pending work")

		err := <-s.graph.Done()

		s.status = StatusStopped

		stopped <- err

		close(stopped)

		alog.Info("Stats agent stopped")
	}()

	select {
	case <-time.After(tracefs.EffectiveShutdownTimeout(s.cfg.ShutdownTimeout)):
		return errShutdownTimeout
	case err := <-stopped:
		// err might be nil
		return err
	}
}

func (s *Stats) Status() Status {
	return s.status
}
