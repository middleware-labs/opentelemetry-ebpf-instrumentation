#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
# End-to-end checks for OBI TCP stats changes:
#   - `network.tcp.retransmit.type` on obi.stat.tcp.retransmits (timeout / fast / other)
#   - obi.stat.tcp.flow_control.events{network.tcp.flow_control.event="zero_window"} (one per probe)
#   - obi.stat.tcp.ecn.ce.packets, obi.stat.tcp.reordering.events, obi.stat.tcp.out_of_order.packets
#   - obi.stat.tcp.closed.connections, and the source port of closed / failed connections
#
# Steps (run in this order the first time):
#   1. ./test-retransmit-type.sh tools     install clang/clang-format/clang-tidy 19 + iperf3 (sudo)
#   2. ./test-retransmit-type.sh build     regenerate eBPF bindings (docker) and compile bin/obi
#   3. ./test-retransmit-type.sh verify    clang-format/clang-tidy on changed C, unit tests, `make verify`
#   4. ./test-retransmit-type.sh obi       terminal A: run OBI as root, Prometheus on :9400 (Ctrl-C to stop)
#   5. ./test-retransmit-type.sh traffic   terminal B: force retransmits on loopback (sudo), print OBI vs kernel deltas
#   6. ./test-retransmit-type.sh zerowindow terminal B: stall a loopback receiver, compare probes with TcpExtTCPWinProbe
#   7. ./test-retransmit-type.sh congestion terminal B: reorder + ECN-mark loopback traffic (sudo), compare with nstat
#   8. ./test-retransmit-type.sh closed    terminal B: 100 normal closes, 50 refused, 1 reset (sudo), compare with bpftrace
#   9. ./test-retransmit-type.sh metrics   print the current retransmit, flow-control and congestion series from OBI
#      ./test-retransmit-type.sh verifier  load the statsolly programs into this kernel's verifier (sudo)
#      ./test-retransmit-type.sh cleanup   remove the loopback qdisc, restore tcp_ecn, stop the test iperf3 server (sudo)
#
# Quick re-check after a code change: build -> obi (terminal A) -> traffic / zerowindow / congestion (terminal B).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROM_PORT="${PROM_PORT:-9400}"
IPERF_PORT="${IPERF_PORT:-5299}"
ZW_PORT="${ZW_PORT:-9000}"
OBI_LOG="${OBI_LOG:-/tmp/obi-retransmit-test.log}"
METRIC="obi_stat_tcp_retransmits_total"
FLOW_CONTROL_METRIC="obi_stat_tcp_flow_control_events_total"
CONGESTION_METRICS=(obi_stat_tcp_ecn_ce_packets_total obi_stat_tcp_reordering_events_total
    obi_stat_tcp_out_of_order_packets_total)
TCP_ECN_SAVE="/tmp/obi-congestion-test.tcp_ecn"
CLOSED_PORT="${CLOSED_PORT:-18080}"
REFUSED_PORT=1
CLOSED_METRIC="obi_stat_tcp_closed_connections_total"
FAILED_METRIC="obi_stat_tcp_failed_connections_total"
OBI_CONFIG="/tmp/obi-retransmit-test.yml"
TYPES=(fast timeout other)

need_root() {
    if [[ $EUID -ne 0 ]]; then
        exec sudo --preserve-env=PROM_PORT,IPERF_PORT,OBI_LOG,CLOSED_PORT "$0" "$@"
    fi
}

# Prints "<type> <value>" for loopback retransmits, one line per type (0 when absent).
loopback_counts() {
    local body
    body="$(curl -sf "localhost:${PROM_PORT}/metrics" || true)"
    for t in "${TYPES[@]}"; do
        echo "$t $(sum_series "$body" "$METRIC" "network_tcp_retransmit_type=\"${t}\"")"
    done
}

# Sums the loopback series of a metric whose labels contain the given label="value".
# awk (not grep) so that a missing series yields 0 instead of failing under pipefail.
sum_series() {
    local body=$1 metric=$2 label=$3
    awk -v m="${metric}{" -v l="$label" '
        index($0, m) == 1 && index($0, "dst_address=\"127.0.0.1\"") && index($0, l) { s += $NF }
        END { printf "%d", s }' <<<"$body"
}

cmd_tools() {
    sudo apt-get install -y clang-19 clang-format-19 clang-tidy-19 iperf3
    for t in clang clang-format clang-tidy; do
        command -v "$t" >/dev/null || sudo ln -sf "/usr/bin/${t}-19" "/usr/bin/${t}"
    done
}

cmd_build() {
    cd "$REPO_DIR"
    make docker-generate
    make compile
    ls -la bin/obi
}

cmd_verify() {
    cd "$REPO_DIR"
    echo "### clang-format (fails if the changed C files are not formatted)"
    clang-format --dry-run --Werror bpf/statsolly/tp_tcp.c bpf/statsolly/k_tcp.c bpf/statsolly/types.h \
        bpf/statsolly/maps/tcp_cong_last.h bpf/statsolly/maps/tcp_cong_drops.h

    echo "### clang-tidy"
    (cd bpf && clang-tidy statsolly/tp_tcp.c statsolly/k_tcp.c statsolly/types.h \
        statsolly/maps/tcp_cong_last.h statsolly/maps/tcp_cong_drops.h)

    echo "### targeted unit tests"
    go test -count=1 ./pkg/internal/statsolly/... ./pkg/export/attributes/... \
        ./pkg/export/prom/... ./pkg/statsolly/... ./internal/config/... ./internal/schemacheck/...

    echo "### make verify (lint + full test suite)"
    make verify
}

cmd_obi() {
    need_root obi
    cd "$REPO_DIR"
    [[ -x bin/obi ]] || { echo "bin/obi missing: run '$0 build' first" >&2; exit 1; }
    export OTEL_EBPF_METRICS_FEATURES=stats_tcp_retransmits,stats_tcp_flow_control,stats_tcp_congestion,stats_tcp_closed_connections,stats_tcp_failed_connections
    export OTEL_EBPF_PROMETHEUS_PORT="$PROM_PORT"
    export OTEL_EBPF_STATS_WAKEUP_DATA_BYTES=0
    export OTEL_EBPF_LOG_LEVEL=DEBUG
    # ports and handshake role are opt-in: the closed step filters on them
    cat >"$OBI_CONFIG" <<'YAML'
attributes:
  select:
    obi.stat.tcp.closed.connections:
      include: ["*"]
    obi.stat.tcp.failed.connections:
      include: ["*"]
YAML
    echo "### OBI log: $OBI_LOG  metrics: http://localhost:${PROM_PORT}/metrics"
    ./bin/obi -config "$OBI_CONFIG" 2>&1 | tee "$OBI_LOG"
}

cmd_cleanup() {
    need_root cleanup
    tc qdisc del dev lo root 2>/dev/null || true
    if [[ -f "$TCP_ECN_SAVE" ]]; then
        sysctl -qw "net.ipv4.tcp_ecn=$(cat "$TCP_ECN_SAVE")"
        rm -f "$TCP_ECN_SAVE"
    fi
    pkill -f "iperf3 -s -p ${IPERF_PORT}" 2>/dev/null || true
    pkill -f "http.server --bind 127.0.0.1 ${CLOSED_PORT}" 2>/dev/null || true
}

cmd_traffic() {
    need_root traffic
    curl -sf "localhost:${PROM_PORT}/metrics" >/dev/null ||
        { echo "OBI is not serving on :${PROM_PORT}: start '$0 obi' in another terminal" >&2; exit 1; }

    trap cmd_cleanup EXIT
    declare -A before after
    while read -r t v; do before[$t]=$v; done < <(loopback_counts)
    nstat -n

    iperf3 -s -p "$IPERF_PORT" -D
    sleep 1
    tc qdisc add dev lo root netem loss 5%

    echo "### phase 1: 5% loss for 15s (expect mostly fast)"
    iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -t 15 >/dev/null

    echo "### phase 2: 3 x 3s blackouts during a 20s transfer (expect timeout)"
    iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -t 20 >/dev/null &
    for _ in 1 2 3; do
        sleep 3; tc qdisc change dev lo root netem loss 100%
        sleep 3; tc qdisc change dev lo root netem loss 5%
    done
    wait

    # let OBI flush the last ring-buffer events
    sleep 2

    echo
    echo "### kernel counters (delta for this run, all interfaces)"
    nstat TcpRetransSegs TcpExtTCPFastRetrans TcpExtTCPTimeouts TcpExtTCPLossProbes \
        TcpExtTCPSlowStartRetrans TcpExtTCPLossFailures

    echo
    echo "### OBI loopback retransmits (delta for this run)"
    while read -r t v; do after[$t]=$v; done < <(loopback_counts)
    local total=0
    for t in "${TYPES[@]}"; do
        local d=$((after[$t] - before[$t]))
        total=$((total + d))
        printf "  %-8s %d\n" "$t" "$d"
    done
    printf "  %-8s %d\n" "total" "$total"

    echo
    echo "Expected: fast > 0 and timeout > 0; total close to TcpRetransSegs (OBI counts"
    echo "attempts, so small differences are normal); timeout > TcpExtTCPTimeouts since"
    echo "one timer expiry retransmits several segments."
}

# Prints the summed zero-window probes OBI saw towards the loopback test port's peer.
loopback_zero_window() {
    local body
    body="$(curl -sf "localhost:${PROM_PORT}/metrics" || true)"
    sum_series "$body" "$FLOW_CONTROL_METRIC" 'network_tcp_flow_control_event="zero_window"'
}

kernel_win_probes() {
    nstat -az TcpExtTCPWinProbe | awk '$1 == "TcpExtTCPWinProbe" {print $2}'
}

cmd_zerowindow() {
    curl -sf "localhost:${PROM_PORT}/metrics" >/dev/null ||
        { echo "OBI is not serving on :${PROM_PORT}: start '$0 obi' in another terminal" >&2; exit 1; }

    local obi_before kern_before
    obi_before="$(loopback_zero_window)"
    kern_before="$(kernel_win_probes)"

    echo "### receiver with a 4 KiB buffer stops reading: 2 stalls of 15s each (expect ~5 probes per stall)"
    python3 - "$ZW_PORT" <<'PY'
import socket, sys, threading, time

port = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
srv.bind(("127.0.0.1", port))
srv.listen()

def sender():
    c = socket.create_connection(("127.0.0.1", port))
    try:
        while True:
            c.sendall(b"x" * 65536)
    except OSError:
        pass

threading.Thread(target=sender, daemon=True).start()
conn, _ = srv.accept()
time.sleep(15)               # stall 1: window goes to 0, sender probes
conn.recv(1 << 20)           # read once: window opens briefly
time.sleep(15)               # stall 2
conn.close()
srv.close()
PY

    # let OBI flush the last ring-buffer events
    sleep 2

    local obi_after kern_after
    obi_after="$(loopback_zero_window)"
    kern_after="$(kernel_win_probes)"

    echo
    printf "  %-34s %d\n" "OBI zero_window events (loopback)" "$((obi_after - obi_before))"
    printf "  %-34s %d\n" "kernel TcpExtTCPWinProbe (all)" "$((kern_after - kern_before))"
    echo
    echo "Expected: both > 0 and equal, unless other connections on this host"
    echo "were probing at the same time (the kernel counter is host-wide)."
}

# Prints "<metric> <value>" for the loopback series of each congestion metric (0 when absent).
loopback_congestion() {
    local body
    body="$(curl -sf "localhost:${PROM_PORT}/metrics" || true)"
    for m in "${CONGESTION_METRICS[@]}"; do
        echo "$m $(sum_series "$body" "$m" 'src_address="127.0.0.1"')"
    done
}

cmd_congestion() {
    need_root congestion
    curl -sf "localhost:${PROM_PORT}/metrics" >/dev/null ||
        { echo "OBI is not serving on :${PROM_PORT}: start '$0 obi' in another terminal" >&2; exit 1; }

    trap cmd_cleanup EXIT
    declare -A before after
    while read -r m v; do before[$m]=$v; done < <(loopback_congestion)
    nstat -n

    iperf3 -s -p "$IPERF_PORT" -D
    sleep 1

    echo "### phase 1: reorder 25% of loopback packets for 20s (expect out_of_order and reordering)"
    tc qdisc add dev lo root netem delay 10ms reorder 25% 50%
    iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -t 20 >/dev/null
    tc qdisc del dev lo root
    # the iperf3 server accepts one test at a time and needs a moment to finish the previous one
    sleep 3

    echo "### phase 2: ECN on, slow link with fq_codel marking for 20s (expect ecn_ce)"
    sysctl -n net.ipv4.tcp_ecn >"$TCP_ECN_SAVE"
    sysctl -qw net.ipv4.tcp_ecn=1
    # burst must exceed loopback's 64 KiB packets, or tbf drops them instead of queueing
    tc qdisc add dev lo root handle 1: tbf rate 50mbit burst 256k latency 400ms
    tc qdisc add dev lo parent 1:1 fq_codel ecn
    iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -t 20 -P 8 >/dev/null

    # close the connections (final flush) and let OBI read the last ring-buffer events
    sleep 2

    echo
    echo "### kernel counters (delta for this run, all interfaces)"
    nstat TcpExtTCPDeliveredCE TcpExtTCPOFOQueue TcpExtTCPSACKReorder TcpExtTCPTSReorder TcpExtTCPRenoReorder

    echo
    echo "### OBI loopback congestion metrics (delta for this run)"
    while read -r m v; do after[$m]=$v; done < <(loopback_congestion)
    for m in "${CONGESTION_METRICS[@]}"; do
        printf "  %-42s %d\n" "$m" "$((after[$m] - before[$m]))"
    done

    echo
    echo "Expected: all three > 0. ecn_ce equal to TcpExtTCPDeliveredCE; reordering close to the sum"
    echo "of the *Reorder counters. out_of_order is usually higher than TcpExtTCPOFOQueue: the kernel"
    echo "counts one per queued buffer there, but adds the buffer's segment count to rcv_ooopack."
    echo "Kernel counters are host-wide, so other traffic can add to them."
}

# Sums the series of a metric whose labels contain every given label="value".
sum_labels() {
    local body=$1 metric=$2
    shift 2
    awk -v m="${metric}{" -v labels="$*" '
        BEGIN { n = split(labels, want, " ") }
        index($0, m) == 1 {
            for (i = 1; i <= n; i++) if (!index($0, want[i])) next
            s += $NF
        }
        END { printf "%d", s }' <<<"$body"
}

# Prints "<name> <value>" for each series the closed step checks (0 when absent).
closed_counts() {
    local body cp="dst_port=\"${CLOSED_PORT}\"" sp="src_port=\"${CLOSED_PORT}\"" rp="dst_port=\"${REFUSED_PORT}\""
    body="$(curl -sf "localhost:${PROM_PORT}/metrics" || true)"
    echo "closed_client $(sum_labels "$body" "$CLOSED_METRIC" "$cp" 'network_tcp_handshake_role="client"')"
    echo "closed_server $(sum_labels "$body" "$CLOSED_METRIC" "$sp" 'network_tcp_handshake_role="server"')"
    echo "closed_refused $(sum_labels "$body" "$CLOSED_METRIC" "$rp" 'network_tcp_handshake_role="client"')"
    echo "failed_refused $(sum_labels "$body" "$FAILED_METRIC" "$rp" 'reason="refused"')"
    echo "failed_reset $(sum_labels "$body" "$FAILED_METRIC" "$sp" 'reason="reset"')"
    echo "closed_sport0 $(( $(sum_labels "$body" "$CLOSED_METRIC" "$cp" 'src_port="0"') + \
        $(sum_labels "$body" "$CLOSED_METRIC" "$rp" 'src_port="0"') ))"
    echo "failed_sport0 $(sum_labels "$body" "$FAILED_METRIC" "$rp" 'src_port="0"')"
}

cmd_closed() {
    need_root closed
    curl -sf "localhost:${PROM_PORT}/metrics" >/dev/null ||
        { echo "OBI is not serving on :${PROM_PORT}: start '$0 obi' in another terminal" >&2; exit 1; }

    trap cmd_cleanup EXIT
    python3 -m http.server --bind 127.0.0.1 "$CLOSED_PORT" >/dev/null 2>&1 &
    sleep 2

    # the kernel's own count of the closes the rule should match, for the test ports only
    local bt_out=/tmp/obi-closed-test.bpftrace
    bpftrace -e "tracepoint:sock:inet_sock_set_state
        /args->protocol == 6 && args->newstate == 7 && args->oldstate != 10 && args->oldstate != 7 &&
         (args->sport == ${CLOSED_PORT} || args->dport == ${CLOSED_PORT} || args->dport == ${REFUSED_PORT})/
        { @closed = count(); }" >"$bt_out" 2>&1 &
    local bt=$!
    sleep 3

    declare -A before after
    while read -r k v; do before[$k]=$v; done < <(closed_counts)

    echo "### A) 100 normal closes (FIN)"
    for _ in $(seq 100); do curl -s "http://127.0.0.1:${CLOSED_PORT}/" >/dev/null; done
    echo "### B) 50 refused connects"
    for _ in $(seq 50); do curl -s "http://127.0.0.1:${REFUSED_PORT}/" >/dev/null || true; done
    echo "### C) 1 reset (SO_LINGER 0)"
    python3 -c "import socket, struct, time
s = socket.create_connection(('127.0.0.1', ${CLOSED_PORT}))
time.sleep(0.2)
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
s.close()"

    sleep 3
    while read -r k v; do after[$k]=$v; done < <(closed_counts)
    kill -INT "$bt"
    wait "$bt" || true

    echo
    printf "  %-16s %8s %8s\n" series got want
    local -A want=([closed_client]=101 [closed_server]=101 [closed_refused]=50 [failed_refused]=50
        [failed_reset]="0-1" [closed_sport0]=0 [failed_sport0]=0)
    local obi_total=0
    for k in closed_client closed_server closed_refused failed_refused failed_reset closed_sport0 failed_sport0; do
        printf "  %-16s %8d %8s\n" "$k" "$((after[$k] - before[$k]))" "${want[$k]}"
    done
    for k in closed_client closed_server closed_refused; do
        obi_total=$((obi_total + after[$k] - before[$k]))
    done
    echo
    echo "### OBI closed total vs bpftrace (same rule, same ports)"
    echo "  obi       $obi_total"
    echo "  bpftrace  $(awk '/@closed/ { print $2 }' "$bt_out")"
    echo
    echo "closed_sport0 / failed_sport0 count series with src_port=\"0\": they must stay 0."
}

cmd_verifier() {
    cd "$REPO_DIR"
    # needs root to load programs; build as the user so the Go cache stays user-owned
    go test -c -tags bpf_verifier_tests -o /tmp/obi-bpf-verifier.test ./pkg/internal/ebpf/verifier/
    sudo /tmp/obi-bpf-verifier.test -test.v -test.run 'TestBPFVerifierWithConstants/statsolly'
}

cmd_metrics() {
    local congestion pattern
    congestion="$(IFS='|'; echo "${CONGESTION_METRICS[*]}")"
    pattern="${METRIC}|${FLOW_CONTROL_METRIC}|${congestion}|${CLOSED_METRIC}"
    curl -sf "localhost:${PROM_PORT}/metrics" | grep -E "^(${pattern})" ||
        echo "no retransmit / flow-control / congestion series (is OBI running on :${PROM_PORT}?)"
}

case "${1:-}" in
    tools) cmd_tools ;;
    build) cmd_build ;;
    verify) cmd_verify ;;
    obi) cmd_obi ;;
    traffic) cmd_traffic ;;
    zerowindow) cmd_zerowindow ;;
    congestion) cmd_congestion ;;
    closed) cmd_closed ;;
    verifier) cmd_verifier ;;
    metrics) cmd_metrics ;;
    cleanup) cmd_cleanup ;;
    *)
        awk 'NR == 1 || /Copyright|SPDX/ { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
        exit 1
        ;;
esac
