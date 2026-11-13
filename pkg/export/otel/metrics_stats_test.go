// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	otelmetric "go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

var defaultStatRttInstrument = otelmetric.Instrument{
	Name:  attributes.StatTCPRtt.OTEL,
	Scope: instrumentation.Scope{Name: statScopeName},
}

var defaultExpCfg = otelcfg.ExponentialHistogramConfig{MaxSize: 64, MaxScale: 12}

func TestStatHistogramView_ExponentialUsesConfiguredMaxSizeAndScale(t *testing.T) {
	buckets := []float64{0.001, 0.010, 0.100, 1.0}
	view := statHistogramView(attributes.StatTCPRtt.OTEL, buckets, true, defaultExpCfg)

	stream, ok := view(defaultStatRttInstrument)
	require.True(t, ok)

	aggregation, ok := stream.Aggregation.(sdkmetric.AggregationBase2ExponentialHistogram)
	require.True(t, ok)
	assert.Equal(t, int32(64), aggregation.MaxSize)
	assert.Equal(t, int32(12), aggregation.MaxScale)
}

func TestStatHistogramView_ExplicitUsesBuckets(t *testing.T) {
	buckets := []float64{0.001, 0.010, 0.100, 1.0}
	view := statHistogramView(attributes.StatTCPRtt.OTEL, buckets, false, otelcfg.ExponentialHistogramConfig{})

	stream, ok := view(defaultStatRttInstrument)
	require.True(t, ok)

	aggregation, ok := stream.Aggregation.(sdkmetric.AggregationExplicitBucketHistogram)
	require.True(t, ok)
	assert.Equal(t, buckets, aggregation.Boundaries)
}

// cumulativeExporter stands for the OTLP exporters, which default to cumulative
type cumulativeExporter struct {
	sdkmetric.Exporter
	sums       []int64
	counts     []uint64
	sumTempo   metricdata.Temporality
	histoTempo metricdata.Temporality
}

func (e *cumulativeExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (e *cumulativeExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(kind)
}

func (e *cumulativeExporter) ForceFlush(context.Context) error { return nil }

func (e *cumulativeExporter) Shutdown(context.Context) error { return nil }

func (e *cumulativeExporter) Export(_ context.Context, md *metricdata.ResourceMetrics) error {
	for _, scope := range md.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				e.sumTempo = data.Temporality
				e.sums = append(e.sums, data.DataPoints[0].Value)
			case metricdata.Histogram[float64]:
				e.histoTempo = data.Temporality
				e.counts = append(e.counts, data.DataPoints[0].Count)
			}
		}
	}
	return nil
}

func TestDeltaExporter_SendsEachIntervalIncrease(t *testing.T) {
	ctx := t.Context()
	base := &cumulativeExporter{}
	var exporter sdkmetric.Exporter = deltaExporter{base}
	provider := newStatMeterProvider(resource.Empty(), &exporter, time.Hour, &otelcfg.MetricsConfig{
		HistogramAggregation: otelcfg.HistogramAggregationExplicit,
	})
	meter := provider.Meter(statScopeName)
	counter, err := meter.Int64Counter(attributes.StatTCPIo.OTEL)
	require.NoError(t, err)
	histogram, err := meter.Float64Histogram(attributes.StatTCPRtt.OTEL)
	require.NoError(t, err)

	counter.Add(ctx, 100)
	histogram.Record(ctx, 0.1)
	require.NoError(t, provider.ForceFlush(ctx))

	counter.Add(ctx, 5)
	histogram.Record(ctx, 0.1)
	histogram.Record(ctx, 0.2)
	require.NoError(t, provider.ForceFlush(ctx))

	// an interval without measurements sends nothing
	require.NoError(t, provider.ForceFlush(ctx))

	assert.Equal(t, metricdata.DeltaTemporality, base.sumTempo)
	assert.Equal(t, metricdata.DeltaTemporality, base.histoTempo)
	assert.Equal(t, []int64{100, 5}, base.sums)
	assert.Equal(t, []uint64{1, 2}, base.counts)
}

func TestDeltaExporter_KeepsOtherInstrumentsTemporality(t *testing.T) {
	exporter := deltaExporter{&cumulativeExporter{}}

	assert.Equal(t, metricdata.DeltaTemporality, exporter.Temporality(sdkmetric.InstrumentKindCounter))
	assert.Equal(t, metricdata.DeltaTemporality, exporter.Temporality(sdkmetric.InstrumentKindHistogram))
	assert.Equal(t, metricdata.CumulativeTemporality, exporter.Temporality(sdkmetric.InstrumentKindGauge))
	assert.Equal(t, metricdata.CumulativeTemporality, exporter.Temporality(sdkmetric.InstrumentKindUpDownCounter))
}
