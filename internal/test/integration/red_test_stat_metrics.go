// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func testStatMetricsTCPRtt(t *testing.T, port string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		countResults, err := pq.Query(`obi_stat_tcp_rtt_seconds_count{dst_port="` + port + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, countResults)

		// pumba injects a 100ms delay on the testclient, so at least ONE
		// per-connection RTT (sum/count per series) should be >= 100ms.
		// Per-series division avoids dilution from other fast connections
		// (e.g. health checks) that share the same dst_port label. A non-empty
		// response means at least one connection was captured with RTT >= 100ms.
		// Threshold is 90ms rather than 100ms to absorb the +/- 1ms timestamp jitter.
		avgQuery := `(obi_stat_tcp_rtt_seconds_sum{dst_port="` + port + `"} /` +
			` obi_stat_tcp_rtt_seconds_count{dst_port="` + port + `"}) >= 0.09`
		avgResults, err := pq.Query(avgQuery)
		require.NoError(ct, err)
		enoughPromResults(ct, avgResults)
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPRttGo(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsTCP(t, testCaseURL)
			testStatMetricsTCPRtt(t, "8080")
		})
	}
}

func testStatMetricsTCPFailedConnectionsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_failed_connections_total{dst_port="19999",network_tcp_handshake_role="client"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.Positive(ct, totalPromCount(ct, results))

		zeroPortResults, err := pq.Query(`obi_stat_tcp_failed_connections_total{dst_port="19999",src_port="0"}`)
		require.NoError(ct, err)
		assert.Empty(ct, zeroPortResults)
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPSuccessfulConnectionsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		clientResults, err := pq.Query(`obi_stat_tcp_successful_connections_total{dst_port="8080",network_tcp_handshake_role="client"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, clientResults)
		assert.Positive(ct, totalPromCount(ct, clientResults))

		serverResults, err := pq.Query(`obi_stat_tcp_successful_connections_total{src_port="8080",network_tcp_handshake_role="server"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, serverResults)
		assert.Positive(ct, totalPromCount(ct, serverResults))
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPClosedConnectionsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		clientResults, err := pq.Query(`obi_stat_tcp_closed_connections_total{dst_port="8080",network_tcp_handshake_role="client"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, clientResults)
		assert.Positive(ct, totalPromCount(ct, clientResults))

		serverResults, err := pq.Query(`obi_stat_tcp_closed_connections_total{src_port="8080",network_tcp_handshake_role="server"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, serverResults)
		assert.Positive(ct, totalPromCount(ct, serverResults))

		// the kernel releases an auto-assigned source port before the close event fires
		zeroPortResults, err := pq.Query(`obi_stat_tcp_closed_connections_total{dst_port="8080",src_port="0"}`)
		require.NoError(ct, err)
		assert.Empty(ct, zeroPortResults)
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsDNSLookupsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		answered, err := pq.Query(`obi_stat_dns_lookup_duration_seconds_count{dst_port="53",dns_question_name="obi.example.test",dns_question_type="A",error_type=""}`)
		require.NoError(ct, err)
		enoughPromResults(ct, answered)
		assert.Positive(ct, totalPromCount(ct, answered))

		nxdomain, err := pq.Query(`obi_stat_dns_lookup_duration_seconds_count{dst_port="53",dns_question_name="nope.example.test",error_type="NXDomain"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, nxdomain)
		assert.Positive(ct, totalPromCount(ct, nxdomain))

		overTCP, err := pq.Query(`obi_stat_dns_lookup_duration_seconds_count{dst_port="53",dns_question_name="tcp.example.test",error_type=""}`)
		require.NoError(ct, err)
		enoughPromResults(ct, overTCP)
		assert.Positive(ct, totalPromCount(ct, overTCP))

		// every question gets an answer from the test server
		timeouts, err := pq.Query(`obi_stat_dns_lookup_duration_seconds_count{dst_port="53",dns_question_name=~".*example.test",error_type="timeout"}`)
		require.NoError(ct, err)
		assert.Empty(ct, timeouts)
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPRetransmitsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_retransmits_total{dst_port="8081"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.Positive(ct, totalPromCount(ct, results))
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPIoGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"transmit", "receive"} {
		t.Run(direction, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(`obi_stat_tcp_io_bytes_total{dst_port="8080",network_io_direction="` + direction + `"}`)
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				assert.Positive(ct, totalPromCount(ct, results))
			}, testTimeout, 100*time.Millisecond)
		})
	}
}
