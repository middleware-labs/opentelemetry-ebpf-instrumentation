// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	metric2 "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const statScopeName = "stats_ebpf_events"

// StatMetricsConfig extends MetricsConfig for Statistical Metrics
type StatMetricsConfig struct {
	Metrics     *otelcfg.MetricsConfig
	CommonCfg   *perapp.GlobalMetricsConfig
	SelectorCfg *attributes.SelectorConfig
}

func (mc *StatMetricsConfig) Enabled() bool {
	return mc.Metrics != nil && mc.Metrics.EndpointEnabled() &&
		mc.CommonCfg.Features.StatMetrics()
}

func smlog() *slog.Logger {
	return slog.With("component", "otel.StatMetricsExporter")
}

// getFilteredStatsResourceAttrs returns resource attributes that can be filtered based on the attribute selector
// for statistical metrics.
func getFilteredStatsResourceAttrs(hostID string, attrSelector attributes.Selection) []attribute.KeyValue {
	baseAttrs := []attribute.KeyValue{
		attribute.String(attr.VendorPrefix+string(attr.VendorVersionSuffix), buildinfo.Version),
		attribute.String(attr.VendorPrefix+string(attr.VendorRevisionSuffix), buildinfo.Revision),
		semconv.TelemetryDistroName(attr.TelemetryDistroName),
		semconv.TelemetryDistroVersion(attr.TelemetryDistroVersion()),
	}

	extraAttrs := []attribute.KeyValue{
		semconv.HostID(hostID),
	}

	return otelcfg.GetFilteredAttributesByPrefix(baseAttrs, attrSelector, extraAttrs, []string{"stats.", attr.VendorPrefix + ".stats"})
}

func createFilteredStatsResource(hostID string, attrSelector attributes.Selection) *resource.Resource {
	attrs := getFilteredStatsResourceAttrs(hostID, attrSelector)
	return resource.NewWithAttributes(attr.OBISchemaURL, attrs...)
}

func newStatMeterProvider(res *resource.Resource, exporter *sdkmetric.Exporter, interval time.Duration, cfg *otelcfg.MetricsConfig) *metric.MeterProvider {
	isExponential := cfg.HistogramAggregation == otelcfg.HistogramAggregationExponential
	if !isExponential && cfg.HistogramAggregation != otelcfg.HistogramAggregationExplicit {
		smlog().Warn("invalid value for histogram aggregation. Accepted values are: "+
			string(otelcfg.HistogramAggregationExponential)+", "+string(otelcfg.HistogramAggregationExplicit)+" (default). Using default",
			"value", cfg.HistogramAggregation)
	}
	return metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval))),
		metric.WithView(statHistogramView(attributes.StatTCPRtt.OTEL, cfg.Buckets.StatTCPRttHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatDNSLookupDuration.OTEL, cfg.Buckets.DurationHistogram, isExponential, cfg.ExponentialHistogram)),
	)
}

func statHistogramView(metricName string, buckets []float64, isExponential bool, expCfg otelcfg.ExponentialHistogramConfig) metric.View {
	return newHistogramView(metricName, statScopeName, buckets, isExponential, expCfg)
}

type statMetricsExporter struct {
	tcpRtt                   *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	tcpFailedConnections     *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpRetransmits           *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpIo                    *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpSuccessfulConnections *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpClosedConnections     *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpFlowControl           *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpECNCEPackets          *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpReorderingEvents      *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpOutOfOrderPackets     *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	dnsLookupDuration        *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	socketBytes              *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	socketPackets            *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	expireTTL                time.Duration
	in                       <-chan []*ebpf.Stat
}

func StatMetricsExporterProvider(
	ctxInfo *global.ContextInfo,
	cfg *StatMetricsConfig,
	input *msg.Queue[[]*ebpf.Stat],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the swarm library just ignore it.
			return swarm.EmptyRunFunc()
		}
		if cfg.SelectorCfg.SelectionCfg == nil {
			cfg.SelectorCfg.SelectionCfg = make(attributes.Selection)
		}
		exporter, err := newStatMetricsExporter(ctx, ctxInfo, cfg, input)
		if err != nil {
			return nil, err
		}
		return exporter.Do, nil
	}
}

func newStatMetricsExporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *StatMetricsConfig,
	input *msg.Queue[[]*ebpf.Stat],
) (*statMetricsExporter, error) {
	log := smlog()
	log.Debug("instantiating stat metrics exporter provider")
	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		log.Error("can't instantiate metrics exporter", "error", err)
		return nil, err
	}
	exporter = instrumentMetricsExporter(ctxInfo.Metrics, exporter)

	resource := createFilteredStatsResource(ctxInfo.NodeMeta.HostID, cfg.SelectorCfg.SelectionCfg)
	provider := newStatMeterProvider(resource, &exporter, cfg.Metrics.Interval, cfg.Metrics)

	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("stats OTEL exporter attributes enable: %w", err)
	}

	ebpfEvents := provider.Meter(statScopeName)

	nme := &statMetricsExporter{
		expireTTL: cfg.Metrics.TTL,
	}

	if cfg.CommonCfg.Features.StatsTCPRtt() {
		log := log.With("metricFamily", "StatsTCPRtt")

		tcpRtt, err := ebpfEvents.Float64Histogram(
			attributes.StatTCPRtt.OTEL,
			metric2.WithUnit(attributes.StatTCPRtt.Unit),
		)
		if err != nil {
			log.Error("creating stats tcp rtt histogram", "error", err)
			return nil, err
		}

		log.Debug("restricting attributes not in this list", "attributes", cfg.SelectorCfg.SelectionCfg)
		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPRtt))

		nme.tcpRtt = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, tcpRtt, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPRetransmits() {
		log := log.With("metricFamily", "StatsTCPRetransmits")

		tcpRetransmits, err := ebpfEvents.Int64Counter(attributes.StatTCPRetransmits.OTEL)
		if err != nil {
			log.Error("creating stats tcp retransmits counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPRetransmits))

		nme.tcpRetransmits = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpRetransmits, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPIo() {
		log := log.With("metricFamily", "StatsTCPIo")

		tcpIo, err := ebpfEvents.Int64Counter(attributes.StatTCPIo.OTEL, metric2.WithUnit(attributes.StatTCPIo.Unit))
		if err != nil {
			log.Error("creating stats tcp io counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPIo))

		nme.tcpIo = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpIo, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPFailedConnections() {
		log := log.With("metricFamily", "StatsTCPFailedConnections")

		tcpFailedConnections, err := ebpfEvents.Int64Counter(attributes.StatTCPFailedConnections.OTEL)
		if err != nil {
			log.Error("creating stats tcp failed connection counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPFailedConnections))

		nme.tcpFailedConnections = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpFailedConnections, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPSuccessfulConnections() {
		log := log.With("metricFamily", "StatsTCPSuccessfulConnections")

		tcpSuccessfulConnections, err := ebpfEvents.Int64Counter(attributes.StatTCPSuccessfulConnections.OTEL)
		if err != nil {
			log.Error("creating stats tcp successful connection counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPSuccessfulConnections))

		nme.tcpSuccessfulConnections = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpSuccessfulConnections, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPClosedConnections() {
		log := log.With("metricFamily", "StatsTCPClosedConnections")

		tcpClosedConnections, err := ebpfEvents.Int64Counter(
			attributes.StatTCPClosedConnections.OTEL,
			metric2.WithUnit(attributes.StatTCPClosedConnections.Unit),
		)
		if err != nil {
			log.Error("creating stats tcp closed connection counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPClosedConnections))

		nme.tcpClosedConnections = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpClosedConnections, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPFlowControl() {
		log := log.With("metricFamily", "StatsTCPFlowControl")

		tcpFlowControl, err := ebpfEvents.Int64Counter(
			attributes.StatTCPFlowControlEvents.OTEL,
			metric2.WithUnit(attributes.StatTCPFlowControlEvents.Unit),
		)
		if err != nil {
			log.Error("creating stats tcp flow control counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPFlowControlEvents))

		nme.tcpFlowControl = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpFlowControl, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPCongestion() {
		log := log.With("metricFamily", "StatsTCPCongestion")

		newCounter := func(name attributes.Name) (*Expirer[*ebpf.Stat, metric2.Int64Counter, int64], error) {
			counter, err := ebpfEvents.Int64Counter(name.OTEL, metric2.WithUnit(name.Unit))
			if err != nil {
				log.Error("creating stats tcp congestion counter", "metric", name.OTEL, "error", err)
				return nil, err
			}
			attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
			return NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, counter, attrs, timeNow, cfg.Metrics.TTL), nil
		}

		if nme.tcpECNCEPackets, err = newCounter(attributes.StatTCPECNCEPackets); err != nil {
			return nil, err
		}
		if nme.tcpReorderingEvents, err = newCounter(attributes.StatTCPReorderingEvents); err != nil {
			return nil, err
		}
		if nme.tcpOutOfOrderPackets, err = newCounter(attributes.StatTCPOutOfOrderPackets); err != nil {
			return nil, err
		}
	}

	if cfg.CommonCfg.Features.StatsDNSLookups() {
		log := log.With("metricFamily", "StatsDNSLookups")

		dnsLookupDuration, err := ebpfEvents.Float64Histogram(
			attributes.StatDNSLookupDuration.OTEL,
			metric2.WithUnit(attributes.StatDNSLookupDuration.Unit),
		)
		if err != nil {
			log.Error("creating stats dns lookup duration histogram", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatDNSLookupDuration))

		nme.dnsLookupDuration = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, dnsLookupDuration, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsSocketTraffic() {
		log := log.With("metricFamily", "StatsSocketTraffic")

		newCounter := func(name attributes.Name) (*Expirer[*ebpf.Stat, metric2.Int64Counter, int64], error) {
			counter, err := ebpfEvents.Int64Counter(name.OTEL, metric2.WithUnit(name.Unit))
			if err != nil {
				log.Error("creating stats socket traffic counter", "metric", name.OTEL, "error", err)
				return nil, err
			}
			attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
			return NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, counter, attrs, timeNow, cfg.Metrics.TTL), nil
		}

		if cfg.CommonCfg.Features.StatsSocketBytes() {
			if nme.socketBytes, err = newCounter(attributes.StatSocketBytes); err != nil {
				return nil, err
			}
		}
		if cfg.CommonCfg.Features.StatsSocketPackets() {
			if nme.socketPackets, err = newCounter(attributes.StatSocketPackets); err != nil {
				return nil, err
			}
		}
	}

	nme.in = input.Subscribe(msg.SubscriberName("otel.StatMetricsExporter"))
	return nme, nil
}

func (me *statMetricsExporter) Do(ctx context.Context) {
	for i := range me.in {
		for _, v := range i {
			if me.tcpRtt != nil && v.TCPRtt != nil {
				tcpRtt, attrs := me.tcpRtt.ForRecord(v)
				tcpRtt.Record(ctx, float64(v.TCPRtt.SrttUs)/1_000_000.0, metric2.WithAttributeSet(attrs))
				for _, us := range v.TCPRtt.Merged {
					tcpRtt.Record(ctx, float64(us)/1_000_000.0, metric2.WithAttributeSet(attrs))
				}
			}
			if me.tcpFailedConnections != nil && v.TCPFailedConnection != nil {
				tcpFailedConnections, attrs := me.tcpFailedConnections.ForRecord(v)
				tcpFailedConnections.Add(ctx, int64(v.Events()), metric2.WithAttributeSet(attrs))
			}
			if me.tcpSuccessfulConnections != nil && v.TCPSuccessfulConnection != nil {
				tcpSuccessfulConnections, attrs := me.tcpSuccessfulConnections.ForRecord(v)
				tcpSuccessfulConnections.Add(ctx, int64(v.Events()), metric2.WithAttributeSet(attrs))
			}
			if me.tcpClosedConnections != nil && v.TCPClosedConnection != nil {
				tcpClosedConnections, attrs := me.tcpClosedConnections.ForRecord(v)
				tcpClosedConnections.Add(ctx, int64(v.Events()), metric2.WithAttributeSet(attrs))
			}
			if me.tcpRetransmits != nil && v.TCPRetransmit {
				tcpRetransmits, attrs := me.tcpRetransmits.ForRecord(v)
				tcpRetransmits.Add(ctx, int64(v.Events()), metric2.WithAttributeSet(attrs))
			}
			if me.tcpIo != nil && v.TCPIo != nil {
				tcpIo, attrs := me.tcpIo.ForRecord(v)
				tcpIo.Add(ctx, int64(v.TCPIo.Bytes), metric2.WithAttributeSet(attrs))
			}
			if me.tcpFlowControl != nil && v.TCPFlowControl != nil {
				tcpFlowControl, attrs := me.tcpFlowControl.ForRecord(v)
				tcpFlowControl.Add(ctx, int64(v.Events()), metric2.WithAttributeSet(attrs))
			}
			if v.TCPCongestion != nil {
				me.recordTCPCongestion(ctx, v)
			}
			if me.dnsLookupDuration != nil && v.DNSLookup != nil {
				dnsLookupDuration, attrs := me.dnsLookupDuration.ForRecord(v)
				dnsLookupDuration.Record(ctx, v.DNSLookup.Duration.Seconds(), metric2.WithAttributeSet(attrs))
				for _, d := range v.DNSLookup.Merged {
					dnsLookupDuration.Record(ctx, d.Seconds(), metric2.WithAttributeSet(attrs))
				}
			}
			if v.SocketTraffic != nil {
				me.recordSocketTraffic(ctx, v)
			}
		}
	}
}

// recordTCPCongestion adds each counter increase of the event, skipping the ones that did not change.
func (me *statMetricsExporter) recordTCPCongestion(ctx context.Context, v *ebpf.Stat) {
	for _, c := range []struct {
		expirer *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
		delta   uint32
	}{
		{me.tcpECNCEPackets, v.TCPCongestion.DeliveredCE},
		{me.tcpReorderingEvents, v.TCPCongestion.ReordSeen},
		{me.tcpOutOfOrderPackets, v.TCPCongestion.RcvOOOPack},
	} {
		if c.expirer == nil || c.delta == 0 {
			continue
		}
		counter, attrs := c.expirer.ForRecord(v)
		counter.Add(ctx, int64(c.delta), metric2.WithAttributeSet(attrs))
	}
}

// recordSocketTraffic adds the bytes and packets of the stat, skipping the ones that are zero.
func (me *statMetricsExporter) recordSocketTraffic(ctx context.Context, v *ebpf.Stat) {
	for _, c := range []struct {
		expirer *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
		value   uint64
	}{
		{me.socketBytes, v.SocketTraffic.Bytes},
		{me.socketPackets, v.SocketTraffic.Packets},
	} {
		if c.expirer == nil || c.value == 0 {
			continue
		}
		counter, attrs := c.expirer.ForRecord(v)
		counter.Add(ctx, int64(c.value), metric2.WithAttributeSet(attrs))
	}
}
