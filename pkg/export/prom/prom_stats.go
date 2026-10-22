// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// injectable function reference for testing

// StatsPrometheusConfig for stat metrics just wraps the global prom.StatsPrometheusConfig as provided by the user
type StatsPrometheusConfig struct {
	Config      *PrometheusConfig
	SelectorCfg *attributes.SelectorConfig
	CommonCfg   *perapp.GlobalMetricsConfig
}

// Enabled returns whether the node needs to be activated
func (p StatsPrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.EndpointEnabled() && p.CommonCfg.Features.StatMetrics()
}

type statMetricsReporter struct {
	cfg *PrometheusConfig

	tcpRtt                   *Expirer[prometheus.Histogram]
	tcpFailedConnections     *Expirer[prometheus.Counter]
	tcpRetransmits           *Expirer[prometheus.Counter]
	tcpIo                    *Expirer[prometheus.Counter]
	tcpSuccessfulConnections *Expirer[prometheus.Counter]
	tcpClosedConnections     *Expirer[prometheus.Counter]
	tcpFlowControl           *Expirer[prometheus.Counter]
	tcpECNCEPackets          *Expirer[prometheus.Counter]
	tcpReorderingEvents      *Expirer[prometheus.Counter]
	tcpOutOfOrderPackets     *Expirer[prometheus.Counter]
	dnsLookupDuration        *Expirer[prometheus.Histogram]
	socketBytes              *Expirer[prometheus.Counter]
	socketPackets            *Expirer[prometheus.Counter]

	promConnect *connector.PrometheusManager

	tcpRttAttrs                   []attributes.Field[*ebpf.Stat, string]
	tcpFailedConnectionsAttrs     []attributes.Field[*ebpf.Stat, string]
	tcpRetransmitsAttrs           []attributes.Field[*ebpf.Stat, string]
	tcpIoAttrs                    []attributes.Field[*ebpf.Stat, string]
	tcpSuccessfulConnectionsAttrs []attributes.Field[*ebpf.Stat, string]
	tcpClosedConnectionsAttrs     []attributes.Field[*ebpf.Stat, string]
	tcpFlowControlAttrs           []attributes.Field[*ebpf.Stat, string]
	tcpECNCEPacketsAttrs          []attributes.Field[*ebpf.Stat, string]
	tcpReorderingEventsAttrs      []attributes.Field[*ebpf.Stat, string]
	tcpOutOfOrderPacketsAttrs     []attributes.Field[*ebpf.Stat, string]
	dnsLookupDurationAttrs        []attributes.Field[*ebpf.Stat, string]
	socketBytesAttrs              []attributes.Field[*ebpf.Stat, string]
	socketPacketsAttrs            []attributes.Field[*ebpf.Stat, string]

	input <-chan []*ebpf.Stat
}

func StatsPrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *StatsPrometheusConfig,
	input *msg.Queue[[]*ebpf.Stat],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the swarm library just ignore it.
			return swarm.EmptyRunFunc()
		}
		reporter, err := newStatsReporter(ctxInfo, cfg, input)
		if err != nil {
			return nil, err
		}
		if cfg.Config.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func newStatsReporter(
	ctxInfo *global.ContextInfo,
	cfg *StatsPrometheusConfig,
	input *msg.Queue[[]*ebpf.Stat],
) (*statMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("stats Prometheus exporter attributes enable: %w", err)
	}

	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &statMetricsReporter{
		cfg:         cfg.Config,
		promConnect: ctxInfo.Prometheus,
	}

	var register []prometheus.Collector
	log := slog.With("component", "prom.StatsEndpoint")
	if cfg.CommonCfg.Features.StatsTCPRtt() {
		log.Debug("registering stat tcp rtt metric")

		mr.tcpRttAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPRtt))

		mr.tcpRtt = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatTCPRtt.Prom,
			Help:                            "measures the smoothed TCP RTT as calculated by the kernel in seconds",
			Buckets:                         cfg.Config.Buckets.StatTCPRttHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.tcpRttAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpRtt)
	}

	if cfg.CommonCfg.Features.StatsTCPRetransmits() {
		log.Debug("registering stat tcp retransmits metric")

		mr.tcpRetransmitsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPRetransmits))

		mr.tcpRetransmits = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPRetransmits.Prom,
			Help: "counts the TCP retransmits between 2 endpoints",
		}, labelNames(mr.tcpRetransmitsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpRetransmits)
	}

	if cfg.CommonCfg.Features.StatsTCPIo() {
		log.Debug("registering stat tcp io metric")

		mr.tcpIoAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPIo))

		mr.tcpIo = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPIo.Prom,
			Help: "count bytes transferred at the socket layer",
		}, labelNames(mr.tcpIoAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpIo)
	}

	if cfg.CommonCfg.Features.StatsTCPFailedConnections() {
		log.Debug("registering stat tcp failed connections metric")

		mr.tcpFailedConnectionsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPFailedConnections))

		mr.tcpFailedConnections = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPFailedConnections.Prom,
			Help: "counts the TCP failed connections between 2 endpoints",
		}, labelNames(mr.tcpFailedConnectionsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpFailedConnections)
	}

	if cfg.CommonCfg.Features.StatsTCPSuccessfulConnections() {
		log.Debug("registering stat tcp successful connections metric")

		mr.tcpSuccessfulConnectionsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPSuccessfulConnections))

		mr.tcpSuccessfulConnections = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPSuccessfulConnections.Prom,
			Help: "counts the TCP successful connections between 2 endpoints",
		}, labelNames(mr.tcpSuccessfulConnectionsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpSuccessfulConnections)
	}

	if cfg.CommonCfg.Features.StatsTCPClosedConnections() {
		log.Debug("registering stat tcp closed connections metric")

		mr.tcpClosedConnectionsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPClosedConnections))

		mr.tcpClosedConnections = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPClosedConnections.Prom,
			Help: "counts the TCP connections that were closed between 2 endpoints",
		}, labelNames(mr.tcpClosedConnectionsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpClosedConnections)
	}

	if cfg.CommonCfg.Features.StatsTCPFlowControl() {
		log.Debug("registering stat tcp flow control metric")

		mr.tcpFlowControlAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPFlowControlEvents))

		mr.tcpFlowControl = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPFlowControlEvents.Prom,
			Help: "counts TCP flow-control events; for zero_window, one event is one zero-window probe",
		}, labelNames(mr.tcpFlowControlAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpFlowControl)
	}

	if cfg.CommonCfg.Features.StatsTCPCongestion() {
		log.Debug("registering stat tcp congestion metrics")

		newCounter := func(name attributes.Name, help string) ([]attributes.Field[*ebpf.Stat, string], *Expirer[prometheus.Counter]) {
			attrs := attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(name))
			counter := NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: name.Prom,
				Help: help,
			}, labelNames(attrs)).MetricVec, timeNow, cfg.Config.TTL)
			return attrs, counter
		}

		mr.tcpECNCEPacketsAttrs, mr.tcpECNCEPackets = newCounter(attributes.StatTCPECNCEPackets,
			"counts sent TCP packets that the peer reported as ECN congestion experienced (CE)")
		mr.tcpReorderingEventsAttrs, mr.tcpReorderingEvents = newCounter(attributes.StatTCPReorderingEvents,
			"counts TCP data packet reordering events detected by the sender")
		mr.tcpOutOfOrderPacketsAttrs, mr.tcpOutOfOrderPackets = newCounter(attributes.StatTCPOutOfOrderPackets,
			"counts TCP packets received out of order")

		register = append(register, mr.tcpECNCEPackets, mr.tcpReorderingEvents, mr.tcpOutOfOrderPackets)
	}

	if cfg.CommonCfg.Features.StatsDNSLookups() {
		log.Debug("registering stat dns lookup duration metric")

		mr.dnsLookupDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDNSLookupDuration))

		mr.dnsLookupDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDNSLookupDuration.Prom,
			Help:                            "measures the duration of the DNS lookups of all the processes in seconds, from the question to its answer",
			Buckets:                         cfg.Config.Buckets.DurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.dnsLookupDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.dnsLookupDuration)
	}

	if cfg.CommonCfg.Features.StatsSocketBytes() {
		log.Debug("registering stat socket bytes metric")

		mr.socketBytesAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatSocketBytes))

		mr.socketBytes = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatSocketBytes.Prom,
			Help: "counts the payload bytes sent and read by the applications on their TCP and UDP sockets",
		}, labelNames(mr.socketBytesAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.socketBytes)
	}

	if cfg.CommonCfg.Features.StatsSocketPackets() {
		log.Debug("registering stat socket packets metric")

		mr.socketPacketsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatSocketPackets))

		mr.socketPackets = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatSocketPackets.Prom,
			Help: "counts the TCP segments and UDP datagrams sent and received by the applications' sockets",
		}, labelNames(mr.socketPacketsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.socketPackets)
	}

	if cfg.Config.Registry != nil {
		cfg.Config.Registry.MustRegister(register...)
	} else {
		mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, register...)
	}

	mr.input = input.Subscribe(msg.SubscriberName("prom.StatsReporterInput"))
	return mr, nil
}

func (r *statMetricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *statMetricsReporter) collectMetrics(_ context.Context) {
	for stats := range r.input {
		for _, stat := range stats {
			r.observeTCPRtt(stat)
			r.observeTCPFailedConnections(stat)
			r.observeTCPSuccessfulConnections(stat)
			r.observeTCPClosedConnections(stat)
			r.observeTCPRetransmits(stat)
			r.observeTCPIo(stat)
			r.observeTCPFlowControl(stat)
			r.observeTCPCongestion(stat)
			r.observeDNSLookupDuration(stat)
			r.observeSocketTraffic(stat)
		}
	}
}

func (r *statMetricsReporter) observeTCPRtt(stat *ebpf.Stat) {
	if r.tcpRtt == nil || stat.TCPRtt == nil {
		return
	}
	histogram := r.tcpRtt.WithLabelValues(labelValues(stat, r.tcpRttAttrs)...).Metric
	histogram.Observe(float64(stat.TCPRtt.SrttUs) / 1_000_000.0)
	for _, us := range stat.TCPRtt.Merged {
		histogram.Observe(float64(us) / 1_000_000.0)
	}
}

func (r *statMetricsReporter) observeTCPFailedConnections(stat *ebpf.Stat) {
	if r.tcpFailedConnections == nil || stat.TCPFailedConnection == nil {
		return
	}
	r.tcpFailedConnections.WithLabelValues(labelValues(stat, r.tcpFailedConnectionsAttrs)...).
		Metric.Add(float64(stat.Events()))
}

func (r *statMetricsReporter) observeTCPSuccessfulConnections(stat *ebpf.Stat) {
	if r.tcpSuccessfulConnections == nil || stat.TCPSuccessfulConnection == nil {
		return
	}
	r.tcpSuccessfulConnections.WithLabelValues(labelValues(stat, r.tcpSuccessfulConnectionsAttrs)...).
		Metric.Add(float64(stat.Events()))
}

func (r *statMetricsReporter) observeTCPClosedConnections(stat *ebpf.Stat) {
	if r.tcpClosedConnections == nil || stat.TCPClosedConnection == nil {
		return
	}
	r.tcpClosedConnections.WithLabelValues(labelValues(stat, r.tcpClosedConnectionsAttrs)...).
		Metric.Add(float64(stat.Events()))
}

func (r *statMetricsReporter) observeTCPRetransmits(stat *ebpf.Stat) {
	if r.tcpRetransmits == nil || !stat.TCPRetransmit {
		return
	}
	r.tcpRetransmits.WithLabelValues(labelValues(stat, r.tcpRetransmitsAttrs)...).
		Metric.Add(float64(stat.Events()))
}

func (r *statMetricsReporter) observeTCPIo(stat *ebpf.Stat) {
	if r.tcpIo == nil || stat.TCPIo == nil {
		return
	}
	r.tcpIo.WithLabelValues(labelValues(stat, r.tcpIoAttrs)...).
		Metric.Add(float64(stat.TCPIo.Bytes))
}

func (r *statMetricsReporter) observeTCPFlowControl(stat *ebpf.Stat) {
	if r.tcpFlowControl == nil || stat.TCPFlowControl == nil {
		return
	}
	r.tcpFlowControl.WithLabelValues(labelValues(stat, r.tcpFlowControlAttrs)...).
		Metric.Add(float64(stat.Events()))
}

func (r *statMetricsReporter) observeDNSLookupDuration(stat *ebpf.Stat) {
	if r.dnsLookupDuration == nil || stat.DNSLookup == nil {
		return
	}
	histogram := r.dnsLookupDuration.WithLabelValues(labelValues(stat, r.dnsLookupDurationAttrs)...).Metric
	histogram.Observe(stat.DNSLookup.Duration.Seconds())
	for _, d := range stat.DNSLookup.Merged {
		histogram.Observe(d.Seconds())
	}
}

// observeTCPCongestion adds each counter increase of the event, skipping the ones that did not change.
func (r *statMetricsReporter) observeTCPCongestion(stat *ebpf.Stat) {
	if stat.TCPCongestion == nil {
		return
	}
	for _, c := range []struct {
		expirer *Expirer[prometheus.Counter]
		attrs   []attributes.Field[*ebpf.Stat, string]
		delta   uint32
	}{
		{r.tcpECNCEPackets, r.tcpECNCEPacketsAttrs, stat.TCPCongestion.DeliveredCE},
		{r.tcpReorderingEvents, r.tcpReorderingEventsAttrs, stat.TCPCongestion.ReordSeen},
		{r.tcpOutOfOrderPackets, r.tcpOutOfOrderPacketsAttrs, stat.TCPCongestion.RcvOOOPack},
	} {
		if c.expirer == nil || c.delta == 0 {
			continue
		}
		c.expirer.WithLabelValues(labelValues(stat, c.attrs)...).
			Metric.Add(float64(c.delta))
	}
}

// observeSocketTraffic adds the bytes and packets of the stat, skipping the ones that are zero.
func (r *statMetricsReporter) observeSocketTraffic(stat *ebpf.Stat) {
	if stat.SocketTraffic == nil {
		return
	}
	for _, c := range []struct {
		expirer *Expirer[prometheus.Counter]
		attrs   []attributes.Field[*ebpf.Stat, string]
		value   uint64
	}{
		{r.socketBytes, r.socketBytesAttrs, stat.SocketTraffic.Bytes},
		{r.socketPackets, r.socketPacketsAttrs, stat.SocketTraffic.Packets},
	} {
		if c.expirer == nil || c.value == 0 {
			continue
		}
		c.expirer.WithLabelValues(labelValues(stat, c.attrs)...).
			Metric.Add(float64(c.value))
	}
}
