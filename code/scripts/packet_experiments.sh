#!/usr/bin/env bash
# Packet-size, RTT, latency-under-load, and UDP-loss experiments.
# Complements the bulk TCP benchmark; does not replace it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

TS="$(date +%Y%m%d-%H%M%S)"
OUT="${ROOT}/results/${TS}-packet"
UDP_DURATION="${PACKET_UDP_DURATION:-10}"
UDP_REPEATS="${PACKET_UDP_REPEATS:-2}"
PING_COUNT="${PACKET_PING_COUNT:-30}"
PING_INTERVAL="${PACKET_PING_INTERVAL:-0.2}"
LOAD_DURATION="${PACKET_LOAD_DURATION:-15}"
LOAD_REPEATS="${PACKET_LOAD_REPEATS:-2}"
FIXED_RATE="${PACKET_FIXED_RATE:-20M}"
SIZES=(64 128 256 512 1024 1372)
RATES=(5M 10M 20M 40M 80M)
MAX_SIZES=(64 1372)

mkdir -p "${OUT}/system"

record_system() {
  local host="$1"
  local tag="$2"
  local peer="$3"
  pi_ssh "${host}" "uname -a; echo; ip -br addr; echo; date -Is; ip route get ${peer}; command -v vcgencmd >/dev/null && vcgencmd measure_temp && vcgencmd get_throttled || true" \
    > "${OUT}/system/${tag}.txt"
}

stop_all() {
  pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/stop_tunnel.sh" >/dev/null 2>&1 || true
  pi_ssh "${VPN_B_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/stop_tunnel.sh" >/dev/null 2>&1 || true
}

start_mode() {
  local mode="$1"
  if [[ "${mode}" == "direct" ]]; then
    stop_all
    return
  fi
  pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/setup_tun.sh a"
  pi_ssh "${VPN_B_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/setup_tun.sh b"
  stop_all
  pi_ssh "${VPN_B_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/start_tunnel.sh b ${mode} background"
  pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/start_tunnel.sh a ${mode} background"
  if [[ "${mode}" == "encrypted" ]]; then
    pi_ssh "${VPN_A_HOST}" "for i in \$(seq 1 40); do grep -q 'session established' ${REMOTE_PROJECT_DIR}/run/svpn.log && exit 0; sleep 0.25; done; exit 1"
  fi
  sleep 0.6
}

endpoints() {
  # Sets client_host server_host dest client_bind server_bind from dir+mode.
  local dir="$1"
  local mode="$2"
  if [[ "${dir}" == "a_to_b" ]]; then
    client_host="${VPN_A_HOST}"
    server_host="${VPN_B_HOST}"
    if [[ "${mode}" == "direct" ]]; then
      dest="${VPN_B_OUTER_IP}"
      client_bind="${VPN_A_OUTER_IP}"
      server_bind="${VPN_B_OUTER_IP}"
    else
      dest="${VPN_B_TUN_IP}"
      client_bind="${VPN_A_TUN_IP}"
      server_bind="${VPN_B_TUN_IP}"
    fi
  else
    client_host="${VPN_B_HOST}"
    server_host="${VPN_A_HOST}"
    if [[ "${mode}" == "direct" ]]; then
      dest="${VPN_A_OUTER_IP}"
      client_bind="${VPN_B_OUTER_IP}"
      server_bind="${VPN_A_OUTER_IP}"
    else
      dest="${VPN_A_TUN_IP}"
      client_bind="${VPN_B_TUN_IP}"
      server_bind="${VPN_A_TUN_IP}"
    fi
  fi
}

stop_iperf_server() {
  local host="$1"
  pi_ssh "${host}" 'if [[ -f /tmp/svpn-iperf-server.pid ]]; then p=$(cat /tmp/svpn-iperf-server.pid); if [[ "$p" =~ ^[0-9]+$ ]] && [[ "$(ps -p "$p" -o comm= 2>/dev/null || true)" == "iperf3" ]]; then kill "$p" 2>/dev/null || true; fi; rm -f /tmp/svpn-iperf-server.pid; fi'
}

start_iperf_server() {
  local host="$1"
  local bind="$2"
  stop_iperf_server "${host}"
  pi_ssh "${host}" "nohup iperf3 -s -1 -B ${bind} -p 5201 >/tmp/svpn-iperf-s.log 2>&1 </dev/null & echo \$! > /tmp/svpn-iperf-server.pid"
  sleep 0.3
}

start_pidstat() {
  local mode="$1"
  if [[ "${mode}" == "direct" ]]; then
    return
  fi
  local svpn_a svpn_b
  svpn_a="$(pi_ssh "${VPN_A_HOST}" "cat ${REMOTE_PROJECT_DIR}/run/svpn.pid")"
  svpn_b="$(pi_ssh "${VPN_B_HOST}" "cat ${REMOTE_PROJECT_DIR}/run/svpn.pid")"
  pi_ssh "${VPN_A_HOST}" "nohup pidstat -u -p ${svpn_a} 1 > /tmp/svpn-pidstat.log 2>&1 </dev/null & echo \$! > /tmp/svpn-pidstat.pid"
  pi_ssh "${VPN_B_HOST}" "nohup pidstat -u -p ${svpn_b} 1 > /tmp/svpn-pidstat.log 2>&1 </dev/null & echo \$! > /tmp/svpn-pidstat.pid"
}

stop_pidstat() {
  local mode="$1"
  local dest_dir="$2"
  local run="$3"
  if [[ "${mode}" == "direct" ]]; then
    return
  fi
  pi_ssh "${VPN_A_HOST}" "kill \$(cat /tmp/svpn-pidstat.pid) 2>/dev/null || true"
  pi_ssh "${VPN_B_HOST}" "kill \$(cat /tmp/svpn-pidstat.pid) 2>/dev/null || true"
  scp_base "${PI_USER}@${VPN_A_HOST}:/tmp/svpn-pidstat.log" "${dest_dir}/run${run}_pidstat_a.txt" || true
  scp_base "${PI_USER}@${VPN_B_HOST}:/tmp/svpn-pidstat.log" "${dest_dir}/run${run}_pidstat_b.txt" || true
}

run_udp() {
  local mode="$1"
  local dir="$2"
  local rundir="$3"
  local run="$4"
  local extra="$5"
  endpoints "${dir}" "${mode}"
  mkdir -p "${rundir}"
  start_iperf_server "${server_host}" "${server_bind}"
  start_pidstat "${mode}"
  phase "UDP ${mode} ${dir} run ${run}: ${client_bind} -> ${dest} ${extra}"
  set +e
  pi_ssh "${client_host}" "iperf3 -c ${dest} -B ${client_bind} -p 5201 -u ${extra} --get-server-output -J" \
    > "${rundir}/run${run}_iperf.json"
  local rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    echo "[WARN] iperf3 exited ${rc} (${rundir} run ${run})"
  fi
  stop_pidstat "${mode}" "${rundir}" "${run}"
}

# --- Test 1: UDP size sweep at fixed offered load, plus max-effort ---
test1_udp_size() {
  local dir size mode run
  phase "TEST 1: UDP datagram size sweep at ${FIXED_RATE}"
  for dir in a_to_b b_to_a; do
    for size in "${SIZES[@]}"; do
      for run in $(seq 1 "${UDP_REPEATS}"); do
        for mode in direct plaintext encrypted; do
          start_mode "${mode}"
          run_udp "${mode}" "${dir}" "${OUT}/test1_udp_size/${dir}/${size}/${mode}" "${run}" \
            "-b ${FIXED_RATE} -l ${size} -t ${UDP_DURATION}"
          stop_all
          sleep 1
        done
      done
    done
  done

  phase "TEST 1b: UDP max-effort at 64 and 1372 (A→B)"
  for size in "${MAX_SIZES[@]}"; do
    for run in $(seq 1 "${UDP_REPEATS}"); do
      for mode in direct plaintext encrypted; do
        start_mode "${mode}"
        run_udp "${mode}" "a_to_b" "${OUT}/test1_udp_max/a_to_b/${size}/${mode}" "${run}" \
          "-b 100M -l ${size} -t ${UDP_DURATION}"
        stop_all
        sleep 1
      done
    done
  done
}

# --- Test 2: ping RTT vs ICMP payload size + DF oversize ---
run_ping() {
  local host="$1"
  local dest="$2"
  local outfile="$3"
  local extra="$4"
  set +e
  pi_ssh "${host}" "ping ${extra} ${dest}" > "${outfile}" 2>&1
  echo "exit=$?" >> "${outfile}"
  set -e
}

test2_ping() {
  local size mode
  phase "TEST 2: ping RTT vs size (A→B) and DF oversize"
  for size in 0 64 256 512 1024 1372; do
    for mode in direct plaintext encrypted; do
      start_mode "${mode}"
      endpoints a_to_b "${mode}"
      mkdir -p "${OUT}/test2_ping/a_to_b/${size}/${mode}"
      phase "ping ${mode} -s ${size} -> ${dest}"
      run_ping "${client_host}" "${dest}" \
        "${OUT}/test2_ping/a_to_b/${size}/${mode}/run1_ping.txt" \
        "-c ${PING_COUNT} -i ${PING_INTERVAL} -W 1 -s ${size}"
      stop_all
    done
  done

  for mode in direct plaintext encrypted; do
    start_mode "${mode}"
    endpoints a_to_b "${mode}"
    mkdir -p "${OUT}/test2_ping_df/${mode}"
    phase "ping DF oversize ${mode} -M do -s 1400 -> ${dest}"
    run_ping "${client_host}" "${dest}" \
      "${OUT}/test2_ping_df/${mode}/run1_ping.txt" \
      "-c 3 -W 1 -M do -s 1400"
    stop_all
  done
}

# --- Test 3: idle RTT vs RTT during TCP load ---
test3_load() {
  local dir mode run
  phase "TEST 3: ping RTT idle vs during TCP iperf (A→B)"
  dir="a_to_b"
  for run in $(seq 1 "${LOAD_REPEATS}"); do
    for mode in direct plaintext encrypted; do
      start_mode "${mode}"
      endpoints "${dir}" "${mode}"
      local rundir="${OUT}/test3_load/${dir}/${mode}"
      mkdir -p "${rundir}"
      phase "idle ping ${mode} run ${run}"
      run_ping "${client_host}" "${dest}" "${rundir}/run${run}_ping_idle.txt" \
        "-c ${PING_COUNT} -i ${PING_INTERVAL} -W 1"
      start_iperf_server "${server_host}" "${server_bind}"
      start_pidstat "${mode}"
      phase "loaded ping+iperf ${mode} run ${run}"
      pi_ssh "${client_host}" "nohup ping -c 30 -i 0.5 -W 1 ${dest} >/tmp/svpn-ping-load.txt 2>&1 </dev/null & echo \$! > /tmp/svpn-ping-load.pid"
      set +e
      pi_ssh "${client_host}" "iperf3 -c ${dest} -B ${client_bind} -p 5201 -t ${LOAD_DURATION} -J" \
        > "${rundir}/run${run}_iperf.json"
      set -e
      sleep 1
      pi_ssh "${client_host}" "if [[ -f /tmp/svpn-ping-load.pid ]]; then kill \$(cat /tmp/svpn-ping-load.pid) 2>/dev/null || true; fi" || true
      scp_base "${PI_USER}@${client_host}:/tmp/svpn-ping-load.txt" "${rundir}/run${run}_ping_load.txt" || true
      stop_pidstat "${mode}" "${rundir}" "${run}"
      stop_all
      sleep 1
    done
  done
}

# --- Test 4: UDP loss vs offered rate at 64 and 1372 ---
test4_rate() {
  local size rate mode run
  phase "TEST 4: UDP loss vs offered rate (A→B, sizes 64 and 1372)"
  for size in 64 1372; do
    for rate in "${RATES[@]}"; do
      for run in $(seq 1 "${UDP_REPEATS}"); do
        for mode in direct plaintext encrypted; do
          start_mode "${mode}"
          run_udp "${mode}" "a_to_b" "${OUT}/test4_udp_rate/a_to_b/${size}/${rate}/${mode}" "${run}" \
            "-b ${rate} -l ${size} -t ${UDP_DURATION}"
          stop_all
          sleep 1
        done
      done
    done
  done
}

{
  echo "timestamp ${TS}"
  echo "kind packet_experiments"
  echo "sizes ${SIZES[*]}"
  echo "fixed_rate ${FIXED_RATE}"
  echo "rates ${RATES[*]}"
  echo "udp_duration ${UDP_DURATION} udp_repeats ${UDP_REPEATS}"
  echo "ping_count ${PING_COUNT} ping_interval ${PING_INTERVAL}"
  echo "load_duration ${LOAD_DURATION} load_repeats ${LOAD_REPEATS}"
  echo "order interleaved: direct -> plaintext -> encrypted per trial"
} > "${OUT}/meta.txt"

trap stop_all EXIT

record_system "${VPN_A_HOST}" "pi_a" "${VPN_B_OUTER_IP}"
record_system "${VPN_B_HOST}" "pi_b" "${VPN_A_OUTER_IP}"

test1_udp_size
test2_ping
test3_load
test4_rate
stop_all

phase "summarize"
python3 "${ROOT}/scripts/summarize_packet_experiments.py" "${OUT}"
echo
echo "Packet experiments in ${OUT}"
echo "  ${OUT}/summary.md"
