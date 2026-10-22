#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
# Single-host (loopback) load test for stats_tcp_congestion, following
# datadog-agent/cnm-docs/OBI_TCP_CONGESTION_LOAD_TEST_PLAN.md.
#
# Usage (needs root; re-runs itself with sudo). Stop any other OBI on :9400 first.
#   ./load-test-congestion.sh run        run the scenarios, then print the summary
#   SCENARIOS="C1 C2 C3 C4" ./load-test-congestion.sh run
#                                        cost of stats_tcp_closed_connections under connection churn
#   ./load-test-congestion.sh summary    print the summary of the latest run again
#   ./load-test-congestion.sh cleanup    remove loopback qdiscs, restore sysctls/offloads, stop helpers
#
# Settings (environment):
#   SCENARIOS="S1 S2 ... S11"  scenarios to run (default: all)
#   WARMUP=10 MEASURE=25 REPEATS=1    seconds / repeats; the defaults take about 10 minutes
#                                     longer run (~35 min): WARMUP=30 MEASURE=120
#                                     plan (~7 h): WARMUP=300 MEASURE=600 REPEATS=3
#   QPS=50000 CONNS=1000              healthy HTTP load (S1-S3)
#   BAD_QPS=20000                     HTTP rate for S5-S7
#   BAD_SIZE=32768                    response size for the bad-network HTTP scenarios (S6, S7, S10, S11);
#                                     1 KiB responses fit in one packet and can hardly be reordered
#   EXTREME_CONNS=20000 EXTREME_QPS=5000  (plan: 50000-100000 connections)
#   FORTIO=~/go/bin/fortio            load generator and HTTP server
#
# Differences from the plan (one host instead of two VMs):
#   - fortio replaces wrk2 (client) and nginx (server, /echo?size=1024 = 1 KiB response).
#   - netem/tbf run on lo, so both directions are affected; OBI sees both ends of every connection.
#   - For the bad-network scenarios (S6-S11) GSO/TSO/GRO are turned off on lo. Then the kernel's
#     TcpExtTCPOFOQueue (per queued buffer) and rcv_ooopack (per segment) count the same thing.
#   - congestion_min_interval is a constant (1s) in this build, so S11 only raises the map scale factor.
#   - S12 (kernel matrix) is not run here: use `make run-bpf-verifier-vm`.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_ROOT="${REPO_DIR}/loadtest-results"
SCENARIOS="${SCENARIOS:-S1 S2 S3 S4 S5 S6 S7 S8 S9 S10 S11}"
WARMUP="${WARMUP:-10}"
MEASURE="${MEASURE:-25}"
REPEATS="${REPEATS:-1}"
QPS="${QPS:-50000}"
CONNS="${CONNS:-1000}"
BAD_QPS="${BAD_QPS:-20000}"
BAD_SIZE="${BAD_SIZE:-32768}"
EXTREME_CONNS="${EXTREME_CONNS:-20000}"
EXTREME_QPS="${EXTREME_QPS:-5000}"
FORTIO="${FORTIO:-${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}/go/bin/fortio}"
PROM_PORT=9400
HTTP_PORTS=(18080 18081)
IPERF_PORT=5299
STATE_FILE=/tmp/obi-loadtest.state

STATS_BASE=stats_tcp_rtt,stats_tcp_failed_connections,stats_tcp_successful_connections,stats_tcp_retransmits,stats_tcp_io,stats_tcp_flow_control
STATS_CONG="${STATS_BASE},stats_tcp_congestion"
STATS_CLOSED="${STATS_BASE},stats_tcp_closed_connections"

log() { printf '[%s] %s\n' "$(date +%T)" "$*"; }

need_root() {
    if [[ $EUID -ne 0 ]]; then
        exec sudo --preserve-env=SCENARIOS,WARMUP,MEASURE,REPEATS,QPS,CONNS,BAD_QPS,BAD_SIZE,EXTREME_CONNS,EXTREME_QPS,FORTIO \
            "$0" "$@"
    fi
}

# ---------------------------------------------------------------- host state

save_state() {
    [[ -f "$STATE_FILE" ]] && return
    {
        echo "tcp_ecn=$(sysctl -n net.ipv4.tcp_ecn)"
        echo "bpf_stats=$(sysctl -n kernel.bpf_stats_enabled)"
        echo "somaxconn=$(sysctl -n net.core.somaxconn)"
        echo "port_range=\"$(sysctl -n net.ipv4.ip_local_port_range | tr '\t' ' ')\""
    } >"$STATE_FILE"
}

cmd_cleanup() {
    need_root cleanup
    tc qdisc del dev lo root 2>/dev/null || true
    ethtool -K lo gso on tso on gro on >/dev/null 2>&1 || true
    pkill -f "fortio server -http-port" 2>/dev/null || true
    pkill -f "fortio load" 2>/dev/null || true
    pkill -f "iperf3 -s -p ${IPERF_PORT}" 2>/dev/null || true
    pkill -x obi 2>/dev/null || true
    if [[ -f "$STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
        # shellcheck disable=SC2154 # set by the sourced state file
        sysctl -qw "net.ipv4.tcp_ecn=${tcp_ecn}" "kernel.bpf_stats_enabled=${bpf_stats}" \
            "net.core.somaxconn=${somaxconn}" "net.ipv4.ip_local_port_range=${port_range}"
        rm -f "$STATE_FILE"
    fi
}

net_healthy() {
    tc qdisc del dev lo root 2>/dev/null || true
    ethtool -K lo gso on tso on gro on >/dev/null 2>&1 || true
    sysctl -qw net.ipv4.tcp_ecn="$(sed -n 's/^tcp_ecn=//p' "$STATE_FILE")"
}

net_reorder() {
    net_healthy
    ethtool -K lo gso off tso off gro off >/dev/null
    tc qdisc add dev lo root netem delay 5ms reorder 25% 50%
}

net_ecn() {
    net_healthy
    ethtool -K lo gso off tso off gro off >/dev/null
    sysctl -qw net.ipv4.tcp_ecn=1
    tc qdisc add dev lo root handle 1: tbf rate 200mbit burst 256k latency 400ms
    tc qdisc add dev lo parent 1:1 fq_codel ecn
}

# ---------------------------------------------------------------- OBI

OBI_PID=""

start_obi() { # <none|base|cong|closed> <logfile> [cpu_quota] [scale_factor]
    local mode=$1 logf=$2 quota=${3:-} scale=${4:-0}
    OBI_PID=""
    [[ "$mode" == none ]] && return

    local features=$STATS_BASE cfg="${RUN_DIR}/obi-maps.yml"
    [[ "$mode" == cong ]] && features=$STATS_CONG
    [[ "$mode" == closed ]] && features=$STATS_CLOSED
    printf 'ebpf:\n  maps_config:\n    global_scale_factor: %d\n' "$scale" >"$cfg"

    local -a cmd=(env OTEL_EBPF_METRICS_FEATURES="$features" OTEL_EBPF_PROMETHEUS_PORT="$PROM_PORT"
        OTEL_EBPF_PROMETHEUS_TTL=1h "${REPO_DIR}/bin/obi" -config "$cfg")
    if [[ -n "$quota" ]]; then
        cmd=(systemd-run --scope --quiet -p "CPUQuota=${quota}" "${cmd[@]}")
    fi
    "${cmd[@]}" >"$logf" 2>&1 &

    for _ in $(seq 1 60); do
        if grep -q "Stats agent successfully started" "$logf" 2>/dev/null &&
            curl -sf "localhost:${PROM_PORT}/metrics" >/dev/null; then
            OBI_PID="$(pgrep -n -x obi)"
            return
        fi
        sleep 1
    done
    echo "OBI did not start, see $logf" >&2
    tail -20 "$logf" >&2
    exit 1
}

stop_obi() {
    [[ -z "$OBI_PID" ]] && return
    kill -INT "$OBI_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
        kill -0 "$OBI_PID" 2>/dev/null || { OBI_PID=""; return; }
        sleep 1
    done
    kill -9 "$OBI_PID" 2>/dev/null || true
    OBI_PID=""
}

# ---------------------------------------------------------------- load

start_servers() {
    for p in "${HTTP_PORTS[@]}"; do
        "$FORTIO" server -http-port "$p" -grpc-port disabled -redirect-port disabled -loglevel Warning \
            >"${RUN_DIR}/fortio-server-${p}.log" 2>&1 &
    done
    iperf3 -s -p "$IPERF_PORT" -D
    sleep 2
}

# fortio_load <seconds> <conns> <qps|0=max> <port> <json|-> <response size> [extra args...]
# A non-zero exit (e.g. some failed requests) doesn't stop the run: errors are reported in the results.
fortio_load() {
    local secs=$1 conns=$2 qps=$3 port=$4 json=$5 size=$6
    shift 6
    local -a out=()
    [[ "$json" != - ]] && out=(-json "$json")
    "$FORTIO" load -quiet -t "${secs}s" -c "$conns" -qps "$qps" -p "50,99" -allow-initial-errors \
        "${out[@]}" "$@" "http://127.0.0.1:${port}/echo?size=${size}" >>"${RUN_DIR}/fortio-load.log" 2>&1 || true
}

# run_load <kind> <seconds> <base|->: results go to <base>.fortio.json or <base>.iperf.json, "-" discards them
run_load() {
    local kind=$1 secs=$2 base=$3 json="-" iperf_out=/dev/null
    if [[ "$base" != - ]]; then
        json="${base}.fortio.json"
        iperf_out="${base}.iperf.json"
    fi
    case "$kind" in
        http_fixed) fortio_load "$secs" "$CONNS" "$QPS" "${HTTP_PORTS[0]}" "$json" 1024 ;;
        http_max) fortio_load "$secs" "$CONNS" 0 "${HTTP_PORTS[0]}" "$json" 1024 ;;
        http_churn) fortio_load "$secs" "$CONNS" "$BAD_QPS" "${HTTP_PORTS[0]}" "$json" 1024 -keepalive=false ;;
        http_churn_max) fortio_load "$secs" "$CONNS" 0 "${HTTP_PORTS[0]}" "$json" 1024 -keepalive=false ;;
        http_bad) fortio_load "$secs" "$CONNS" "$BAD_QPS" "${HTTP_PORTS[0]}" "$json" "$BAD_SIZE" ;;
        http_bad_many) fortio_load "$secs" 10000 "$BAD_QPS" "${HTTP_PORTS[0]}" "$json" "$BAD_SIZE" ;;
        http_extreme)
            # two clients and two server ports: one destination port can't hold more than ~64k sockets
            local half=$((EXTREME_CONNS / 2)) qhalf=$((EXTREME_QPS / 2))
            fortio_load "$secs" "$half" "$qhalf" "${HTTP_PORTS[1]}" - "$BAD_SIZE" &
            local second=$!
            fortio_load "$secs" "$half" "$qhalf" "${HTTP_PORTS[0]}" "$json" "$BAD_SIZE"
            # wait for this client only: a bare `wait` would also wait for OBI, which runs in the background
            wait "$second" || true
            ;;
        iperf_ecn) iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -P 32 -t "$secs" --json >"$iperf_out" || true ;;
        iperf_bulk) iperf3 -c 127.0.0.1 -p "$IPERF_PORT" -P 1 -t "$secs" --json >"$iperf_out" || true ;;
    esac
}

# ---------------------------------------------------------------- scenarios

# id | description | obi mode | network | load | cpu quota | scale factor
scenario_def() {
    case "$1" in
        S1) echo "No OBI, healthy HTTP|none|healthy|http_fixed||0" ;;
        S2) echo "OBI stats without congestion, healthy HTTP|base|healthy|http_fixed||0" ;;
        S3) echo "OBI stats with congestion, healthy HTTP|cong|healthy|http_fixed||0" ;;
        S4) echo "Max HTTP rate, with congestion (compare S4b)|cong|healthy|http_max||0" ;;
        S4b) echo "Max HTTP rate, without congestion|base|healthy|http_max||0" ;;
        S5) echo "Connection churn (Connection: close)|cong|healthy|http_churn||0" ;;
        S6) echo "Bad network (reorder 25%), 1k conns|cong|reorder|http_bad||0" ;;
        S7) echo "Bad network (reorder 25%), 10k conns|cong|reorder|http_bad_many||0" ;;
        S8) echo "ECN: tbf 200mbit + fq_codel ecn, iperf3 -P 32|cong|ecn|iperf_ecn||0" ;;
        S9) echo "Bulk one-way iperf3, reorder|cong|reorder|iperf_bulk||0" ;;
        S10) echo "Extreme: ${EXTREME_CONNS} conns, reorder, OBI at 0.5 CPU|cong|reorder|http_extreme|50%|0" ;;
        S11) echo "Extreme + map scale factor +1|cong|reorder|http_extreme|50%|1" ;;
        C1) echo "Churn, without closed connections|base|healthy|http_churn||0" ;;
        C2) echo "Churn, with closed connections|closed|healthy|http_churn||0" ;;
        C3) echo "Max-rate churn, without closed connections|base|healthy|http_churn_max||0" ;;
        C4) echo "Max-rate churn, with closed connections|closed|healthy|http_churn_max||0" ;;
        *) return 1 ;;
    esac
}

run_one() { # <id> <repeat>
    local id=$1 rep=$2 def desc mode net load quota scale
    def="$(scenario_def "$id")" || { echo "unknown scenario $id" >&2; return; }
    IFS='|' read -r desc mode net load quota scale <<<"$def"
    local base="${RUN_DIR}/${id}-r${rep}"
    log "=== ${id} (repeat ${rep}): ${desc}"

    "net_${net}"
    start_obi "$mode" "${base}.obi.log" "$quota" "$scale"
    if [[ "$mode" == cong ]]; then
        "$PY" "$HELPER" check
    fi

    log "warm-up ${WARMUP}s"
    run_load "$load" "$WARMUP" -
    # let the warm-up connections close and their last events reach OBI before the window starts
    sleep 3

    "$PY" "$HELPER" snap "${base}.start.json" "$OBI_PID"
    log "measure ${MEASURE}s"
    run_load "$load" "$MEASURE" "$base"
    sleep 3 # close-time flushes and ring-buffer reads
    "$PY" "$HELPER" snap "${base}.end.json" "$OBI_PID"

    stop_obi
    net_healthy
    "$PY" "$HELPER" row "$id" "$rep" "$desc" "$base" "$MEASURE" >>"${RUN_DIR}/results.jsonl"
    "$PY" "$HELPER" table "${RUN_DIR}/results.jsonl" | tail -1
}

cmd_run() {
    need_root run
    [[ -x "${REPO_DIR}/bin/obi" ]] || { echo "bin/obi missing: run 'make compile' first" >&2; exit 1; }
    [[ -x "$FORTIO" ]] || { echo "fortio not found at $FORTIO (go install fortio.org/fortio@v1.69.4)" >&2; exit 1; }
    if curl -sf "localhost:${PROM_PORT}/metrics" >/dev/null || pgrep -x obi >/dev/null; then
        echo "another OBI is running (port ${PROM_PORT}): stop it first" >&2
        exit 1
    fi

    RUN_DIR="${RESULTS_ROOT}/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$RUN_DIR"
    write_helper
    save_state
    trap 'stop_obi; cmd_cleanup; chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$RESULTS_ROOT"' EXIT

    ulimit -n 1048576
    sysctl -qw kernel.bpf_stats_enabled=1 net.core.somaxconn=65535 \
        net.ipv4.ip_local_port_range="1024 65000"

    {
        echo "kernel=$(uname -r) cpus=$(nproc) warmup=${WARMUP}s measure=${MEASURE}s repeats=${REPEATS}"
        echo "qps=${QPS} conns=${CONNS} bad_qps=${BAD_QPS} bad_size=${BAD_SIZE} extreme_conns=${EXTREME_CONNS} extreme_qps=${EXTREME_QPS}"
        echo "scenarios=${SCENARIOS}"
    } | tee "${RUN_DIR}/settings.txt"

    start_servers
    local ids=()
    for id in $SCENARIOS; do
        ids+=("$id")
        if [[ "$id" == S4 ]]; then
            ids+=(S4b) # S4 is a pair: with and without congestion
        fi
    done
    for rep in $(seq 1 "$REPEATS"); do
        for id in "${ids[@]}"; do
            run_one "$id" "$rep"
        done
    done

    echo
    "$PY" "$HELPER" summary "${RUN_DIR}/results.jsonl" | tee "${RUN_DIR}/summary.md"
    log "results: ${RUN_DIR}"
}

cmd_summary() {
    RUN_DIR="$(find "$RESULTS_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
    write_helper
    "$PY" "$HELPER" summary "${RUN_DIR}/results.jsonl"
}

# ---------------------------------------------------------------- measurement helper

PY=python3
HELPER=""

write_helper() {
    HELPER="${RUN_DIR}/measure.py"
    cat >"$HELPER" <<'PY'
import json, os, statistics, subprocess, sys, time, urllib.request

CONG = ["obi_stat_tcp_ecn_ce_packets_total", "obi_stat_tcp_reordering_events_total",
        "obi_stat_tcp_out_of_order_packets_total"]
CLOSED = "obi_stat_tcp_closed_connections_total"
NSTAT = ["TcpExtTCPDeliveredCE", "TcpExtTCPSACKReorder", "TcpExtTCPTSReorder",
         "TcpExtTCPRenoReorder", "TcpExtTCPOFOQueue", "TcpExtTCPWinProbe", "TcpRetransSegs",
         "TcpActiveOpens", "TcpPassiveOpens"]


def sh_json(*args):
    try:
        return json.loads(subprocess.run(args, capture_output=True, text=True, check=True).stdout or "null")
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return None


def nstat():
    # -s: don't touch nstat's history file
    out = subprocess.run(["nstat", "-azs", "--json"], capture_output=True, text=True).stdout
    data = json.loads(out).get("kernel", {})
    return {k: data.get(k, 0) for k in NSTAT}


def cpu_stat():
    with open("/proc/stat") as f:
        vals = [int(v) for v in f.readline().split()[1:]]
    return {"user": vals[0] + vals[1], "system": vals[2], "idle": vals[3] + vals[4],
            "irq": vals[5], "softirq": vals[6], "total": sum(vals[:8])}


def proc(pid):
    if not pid:
        return None
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(")", 1)[1].split()
        status = {}
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                status[k] = v.strip()
        return {"cpu_ticks": int(parts[11]) + int(parts[12]),
                "rss_kb": int(status["VmRSS"].split()[0]), "hwm_kb": int(status["VmHWM"].split()[0])}
    except (OSError, KeyError, IndexError):
        return None


def prom():
    try:
        body = urllib.request.urlopen("http://localhost:9400/metrics", timeout=10).read().decode()
    except OSError:
        return None
    # loopback series are the test traffic; "other" are the host's own connections, which report
    # their whole history the first time OBI sees them (one-time bump after OBI starts)
    sums = {"lo": {}, "other": {}}
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        name = line.split("{", 1)[0].split(" ", 1)[0]
        if name in CONG or name == CLOSED:
            where = "lo" if 'dst_address="127.0.0.1"' in line else "other"
            sums[where][name] = sums[where].get(name, 0) + float(line.rsplit(" ", 1)[1])
    return sums


def progs():
    out = {}
    for p in sh_json("bpftool", "-j", "prog", "show") or []:
        name = p.get("name", "")
        if not name.startswith("obi_stats"):
            continue
        out[f'{name}#{p["id"]}'] = {"name": name, "run_cnt": p.get("run_cnt", 0),
                                    "run_time_ns": p.get("run_time_ns", 0), "map_ids": p.get("map_ids", [])}
    return out


def map_by_name(prog_list, wanted):
    ids = {m for p in prog_list.values() for m in p["map_ids"]}
    for mid in sorted(ids):
        m = sh_json("bpftool", "-j", "map", "show", "id", str(mid))
        if m and m.get("name") == wanted:
            return mid, m.get("max_entries")
    return None, None


def int_values(obj):
    if isinstance(obj, bool):
        return []
    if isinstance(obj, int):
        return [obj]
    if isinstance(obj, list) and obj and all(isinstance(x, str) and x.startswith("0x") for x in obj):
        return [int.from_bytes(bytes(int(x, 16) for x in obj), "little")]
    if isinstance(obj, list):
        return [v for x in obj for v in int_values(x)]
    if isinstance(obj, dict):
        return [v for k, x in obj.items() if k not in ("key", "cpu") for v in int_values(x)]
    return []


def maps(prog_list):
    out = {}
    mid, max_entries = map_by_name(prog_list, "tcp_cong_last")
    if mid:
        dump = sh_json("bpftool", "-j", "map", "dump", "id", str(mid)) or []
        out["cong_last_entries"], out["cong_last_max"] = len(dump), max_entries
    mid, _ = map_by_name(prog_list, "tcp_cong_drops")
    if mid:
        dump = sh_json("bpftool", "-j", "map", "dump", "id", str(mid)) or []
        total = 0
        for entry in dump:
            src = entry.get("formatted", entry)
            total += sum(int_values(src.get("values", src.get("value", []))))
        out["cong_drops"] = total
    return out


def snap(path, pid):
    p = progs()
    data = {"time": time.time(), "nstat": nstat(), "cpu": cpu_stat(), "obi": proc(pid),
            "prom": prom(), "progs": p, "maps": maps(p)}
    with open(path, "w") as f:
        json.dump(data, f)


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def pct(part, total):
    return round(100.0 * part / total, 2) if total else None


def row(sid, rep, desc, base, measure):
    a, b = load_json(base + ".start.json"), load_json(base + ".end.json")
    secs = b["time"] - a["time"]
    r = {"id": sid, "repeat": int(rep), "desc": desc, "seconds": round(secs, 1)}

    f = load_json(base + ".fortio.json")
    if f:
        perc = {p["Percentile"]: p["Value"] for p in f["DurationHistogram"].get("Percentiles", [])}
        r["req_s"] = round(f["ActualQPS"])
        r["p50_ms"] = round(perc.get(50, 0) * 1000, 3)
        r["p99_ms"] = round(perc.get(99, 0) * 1000, 3)
        r["errors"] = f.get("ErrorsDurationHistogram", {}).get("Count", 0)
    ip = load_json(base + ".iperf.json")
    if ip and "end" in ip:
        r["mbit_s"] = round(ip["end"]["sum_received"]["bits_per_second"] / 1e6, 1)

    dc = {k: b["cpu"][k] - a["cpu"][k] for k in a["cpu"]}
    r["host_cpu_pct"] = pct(dc["total"] - dc["idle"], dc["total"])
    r["softirq_pct"] = pct(dc["softirq"], dc["total"])

    if a["obi"] and b["obi"]:
        hz = os.sysconf("SC_CLK_TCK")
        r["obi_cpu_pct"] = round(100.0 * (b["obi"]["cpu_ticks"] - a["obi"]["cpu_ticks"]) / hz / secs, 1)
        r["obi_rss_mb"] = round(b["obi"]["rss_kb"] / 1024, 1)
        r["obi_peak_rss_mb"] = round(b["obi"]["hwm_kb"] / 1024, 1)

    per_prog = {}
    for key, pb in b["progs"].items():
        pa = a["progs"].get(key)
        if not pa:
            continue
        cnt, ns = pb["run_cnt"] - pa["run_cnt"], pb["run_time_ns"] - pa["run_time_ns"]
        if cnt > 0:
            per_prog[pb["name"]] = {"calls_s": round(cnt / secs), "ns_call": round(ns / cnt),
                                    "cpu_ms_s": round(ns / secs / 1e6, 2)}
    r["progs"] = per_prog
    cong = [v for n, v in per_prog.items() if "congestion" in n]
    if cong:
        calls = sum(v["calls_s"] for v in cong)
        r["cong_ns_call"] = round(sum(v["ns_call"] * v["calls_s"] for v in cong) / calls) if calls else None
        r["cong_cpu_ms_s"] = round(sum(v["cpu_ms_s"] for v in cong), 2)

    closed = [v for n, v in per_prog.items() if "tcp_closed_connection" in n]
    if closed:
        r["closed_ns_call"] = closed[0]["ns_call"]
        r["closed_cpu_ms_s"] = closed[0]["cpu_ms_s"]

    m = b["maps"]
    if "cong_last_entries" in m:
        r["map_fill_pct"] = pct(m["cong_last_entries"], m["cong_last_max"])
        r["map_entries"] = m["cong_last_entries"]
    if "cong_drops" in m:
        r["drops"] = m["cong_drops"] - a["maps"].get("cong_drops", 0)

    dn = {k: b["nstat"][k] - a["nstat"][k] for k in b["nstat"]}
    r["nstat"] = dn
    if a["prom"] is not None and b["prom"] is not None:
        do = {k: round(b["prom"]["lo"].get(k, 0) - a["prom"]["lo"].get(k, 0)) for k in CONG}
        r["obi"] = do
        r["obi_other"] = sum(round(b["prom"]["other"].get(k, 0) - a["prom"]["other"].get(k, 0)) for k in CONG)
        if CLOSED in b["prom"]["lo"]:
            # under steady churn every opened loopback connection closes within the window (both ends);
            # the difference is the connections still open at the window edges
            obi_closed = round(b["prom"]["lo"][CLOSED] - a["prom"]["lo"].get(CLOSED, 0))
            opens = dn["TcpActiveOpens"] + dn["TcpPassiveOpens"]
            r["closed"] = {"obi": obi_closed, "kernel_opens": opens, "diff_pct": pct(obi_closed - opens, opens)}
        kern = {"ce": dn["TcpExtTCPDeliveredCE"],
                "reord": dn["TcpExtTCPSACKReorder"] + dn["TcpExtTCPTSReorder"] + dn["TcpExtTCPRenoReorder"],
                "ooo": dn["TcpExtTCPOFOQueue"]}
        obi = {"ce": do[CONG[0]], "reord": do[CONG[1]], "ooo": do[CONG[2]]}
        r["accuracy"] = {k: {"obi": obi[k], "kernel": kern[k],
                             "diff_pct": pct(obi[k] - kern[k], kern[k])} for k in kern}
    print(json.dumps(r))


def fmt(v):
    return "–" if v is None else str(v)


def acc_str(r):
    acc = r.get("accuracy")
    if not acc:
        return "–"
    parts = []
    for k in ("ce", "reord", "ooo"):
        a = acc[k]
        if a["obi"] or a["kernel"]:
            d = "" if a["diff_pct"] is None else f' ({a["diff_pct"]:+}%)'
            parts.append(f'{k} {a["obi"]}/{a["kernel"]}{d}')
    out = ", ".join(parts) or "all 0"
    if r.get("obi_other"):
        out += f'; non-loopback {r["obi_other"]}'
    return out


COLS = ["id", "req_s", "mbit_s", "p50_ms", "p99_ms", "errors", "host_cpu_pct", "softirq_pct",
        "obi_cpu_pct", "obi_peak_rss_mb", "cong_ns_call", "cong_cpu_ms_s", "map_entries",
        "map_fill_pct", "drops"]


def read_rows(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def table(path):
    rows = read_rows(path)
    print("| " + " | ".join(COLS) + " | OBI/kernel (ce, reord, ooo) |")
    print("|" + "---|" * (len(COLS) + 1))
    for r in rows:
        print("| " + " | ".join(fmt(r.get(c)) for c in COLS) + f" | {acc_str(r)} |")


def median_rows(rows):
    by_id = {}
    for r in rows:
        by_id.setdefault(r["id"], []).append(r)
    out = {}
    for sid, rs in by_id.items():
        m = dict(rs[len(rs) // 2])
        for c in COLS[1:]:
            vals = [r[c] for r in rs if r.get(c) is not None]
            m[c] = round(statistics.median(vals), 3) if vals else None
        out[sid] = m
    return out


def change(new, old):
    return f"{100.0 * (new - old) / old:+.2f}%" if new is not None and old else "–"


def summary(path):
    rows = read_rows(path)
    med = median_rows(rows)
    print("## Results (median per scenario)\n")
    print("| " + " | ".join(COLS) + " | OBI/kernel (ce, reord, ooo) |")
    print("|" + "---|" * (len(COLS) + 1))
    for sid in sorted(med, key=lambda s: (int("".join(ch for ch in s if ch.isdigit())), s)):
        r = med[sid]
        print("| " + " | ".join(fmt(r.get(c)) for c in COLS) + f" | {acc_str(r)} |")

    print("\n## Checks\n")
    if "S2" in med and "S3" in med:
        s2, s3 = med["S2"], med["S3"]
        print(f'- Q1 S3 vs S2: throughput {change(s3.get("req_s"), s2.get("req_s"))}, '
              f'p99 {change(s3.get("p99_ms"), s2.get("p99_ms"))}, '
              f'host CPU {change(s3.get("host_cpu_pct"), s2.get("host_cpu_pct"))} (pass: < 2%)')
    if "S4" in med and "S4b" in med:
        s4, s4b = med["S4"], med["S4b"]
        print(f'- Q1 S4 (max rate) with vs without congestion: throughput {change(s4.get("req_s"), s4b.get("req_s"))}, '
              f'p99 {change(s4.get("p99_ms"), s4b.get("p99_ms"))}')
    ns = [(s, r["cong_ns_call"]) for s, r in med.items() if r.get("cong_ns_call") is not None]
    if ns:
        print("- Q1 ns per call of the congestion programs (pass: < 300): "
              + ", ".join(f"{s} {v}" for s, v in ns))
    for new, old in (("C2", "C1"), ("C4", "C3")):
        if new in med and old in med:
            n, o = med[new], med[old]
            print(f'- {new} vs {old} (closed connections on vs off): throughput {change(n.get("req_s"), o.get("req_s"))}, '
                  f'p99 {change(n.get("p99_ms"), o.get("p99_ms"))}, '
                  f'host CPU {change(n.get("host_cpu_pct"), o.get("host_cpu_pct"))} (pass: within 2%)')
    for s in ("C2", "C4"):
        r = med.get(s)
        if r and r.get("closed_ns_call") is not None:
            failed = next((v["ns_call"] for k, v in (r.get("progs") or {}).items() if "tcp_failed_connection" in k), None)
            print(f'- {s} closed program: {r["closed_ns_call"]} ns/call, {r.get("closed_cpu_ms_s")} CPU ms/s '
                  f'(failed program: {fmt(failed)} ns/call)')
        if r and r.get("closed"):
            c = r["closed"]
            print(f'- {s} OBI closed vs kernel opens (pass: within 1%): {c["obi"]}/{c["kernel_opens"]} ({fmt(c["diff_pct"])}%)')
    for s in ("S6", "S8", "S9"):
        if s in med:
            print(f"- Q2 {s} OBI vs nstat (pass: within 1%): {acc_str(med[s])}")
    drops = [(s, r.get("drops")) for s, r in med.items() if r.get("drops") is not None]
    if drops:
        print("- Q3/Q4 ring-buffer drops (pass: 0): " + ", ".join(f"{s} {v}" for s, v in drops))
    fill = [(s, r.get("map_fill_pct")) for s, r in med.items() if r.get("map_fill_pct") is not None]
    if fill:
        print("- Q3/Q4 tcp_cong_last fill % (act at > 80): " + ", ".join(f"{s} {v}" for s, v in fill))

    print("\n## Per-program cost (median run, calls/s, ns/call, CPU ms/s)\n")
    for sid in sorted(med, key=lambda s: (int("".join(ch for ch in s if ch.isdigit())), s)):
        progs = med[sid].get("progs") or {}
        if progs:
            items = ", ".join(f'{n.replace("obi_stats_", "")} {v["calls_s"]}/s {v["ns_call"]}ns {v["cpu_ms_s"]}ms'
                              for n, v in sorted(progs.items()))
            print(f"- {sid}: {items}")


def check():
    p = progs()
    names = sorted({v["name"] for v in p.values() if "congestion" in v["name"]})
    m = maps(p)
    print(f"  bpftool sees congestion programs: {names or 'NONE (per-program cost will be missing)'}")
    print(f"  maps: tcp_cong_last entries={m.get('cong_last_entries')} max={m.get('cong_last_max')}, "
          f"tcp_cong_drops={m.get('cong_drops')}")


cmd = sys.argv[1]
if cmd == "check":
    check()
elif cmd == "snap":
    snap(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
elif cmd == "row":
    row(*sys.argv[2:7])
elif cmd == "table":
    table(sys.argv[2])
elif cmd == "summary":
    summary(sys.argv[2])
PY
}

case "${1:-}" in
    run) cmd_run ;;
    summary) cmd_summary ;;
    cleanup) cmd_cleanup ;;
    *)
        awk 'NR == 1 || /Copyright|SPDX/ { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
        exit 1
        ;;
esac
