#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

TS="$(date +%Y%m%d-%H%M%S)"
OUT="${ROOT}/results/${TS}"
mkdir -p "${OUT}/system" "${OUT}/cpu" \
  "${OUT}/direct/a_to_b" "${OUT}/direct/b_to_a" \
  "${OUT}/plaintext/a_to_b" "${OUT}/plaintext/b_to_a" \
  "${OUT}/encrypted/a_to_b" "${OUT}/encrypted/b_to_a"

record_system() {
  local host="$1"
  local tag="$2"
  pi_ssh "${host}" "uname -a; echo; ip -br addr; echo; ip route; echo; ip route get ${3}; echo; date -Is; command -v vcgencmd >/dev/null && vcgencmd measure_temp && vcgencmd get_throttled || echo 'thermal=unavailable'" \
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
    local i
    pi_ssh "${VPN_A_HOST}" "for i in \$(seq 1 40); do grep -q 'session established' ${REMOTE_PROJECT_DIR}/run/svpn.log && exit 0; sleep 0.25; done; exit 1"
  fi
  sleep 1
}

precheck_route() {
  local dest="$1"
  local host="$2"
  local r
  r="$(pi_ssh "${host}" "ip route get ${dest}")"
  echo "    ${host} route get ${dest}: ${r}"
  if [[ "${dest}" == "${VPN_A_OUTER_IP}" || "${dest}" == "${VPN_B_OUTER_IP}" ]]; then
    grep -qw wlan0 <<<"${r}" || die "outer route is not wlan0: ${r}"
  fi
}

run_iperf() {
  local mode="$1"     # direct|plaintext|encrypted
  local dir="$2"      # a_to_b|b_to_a
  local run="$3"
  local server_host server_bind client_host client_bind dest

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

  precheck_route "${dest}" "${client_host}"
  local rundir="${OUT}/${mode}/${dir}"
  mkdir -p "${rundir}"

  local therm_before_a therm_before_b
  therm_before_a="$(pi_ssh "${VPN_A_HOST}" "vcgencmd measure_temp 2>/dev/null; vcgencmd get_throttled 2>/dev/null" || echo unavailable)"
  therm_before_b="$(pi_ssh "${VPN_B_HOST}" "vcgencmd measure_temp 2>/dev/null; vcgencmd get_throttled 2>/dev/null" || echo unavailable)"
  printf '%s\n' "${therm_before_a}" > "${rundir}/run${run}_therm_before_a.txt"
  printf '%s\n' "${therm_before_b}" > "${rundir}/run${run}_therm_before_b.txt"

  # Do not disturb unrelated iperf3 processes on a shared endpoint.
  pi_ssh "${server_host}" 'if [[ -f /tmp/svpn-iperf-server.pid ]]; then p=$(cat /tmp/svpn-iperf-server.pid); if [[ "$p" =~ ^[0-9]+$ ]] && [[ "$(ps -p "$p" -o comm= 2>/dev/null || true)" == "iperf3" ]]; then kill "$p" 2>/dev/null || true; fi; rm -f /tmp/svpn-iperf-server.pid; fi'
  pi_ssh "${server_host}" "nohup iperf3 -s -1 -B ${server_bind} -p 5201 -J >/tmp/svpn-iperf-server.json 2>/tmp/svpn-iperf-server.err </dev/null & echo \$! > /tmp/svpn-iperf-server.pid"

  local cpu_a_pid cpu_b_pid
  cpu_a_pid=""
  cpu_b_pid=""
  if [[ "${mode}" != "direct" ]]; then
    local svpn_a svpn_b
    svpn_a="$(pi_ssh "${VPN_A_HOST}" "cat ${REMOTE_PROJECT_DIR}/run/svpn.pid")"
    svpn_b="$(pi_ssh "${VPN_B_HOST}" "cat ${REMOTE_PROJECT_DIR}/run/svpn.pid")"
    pi_ssh "${VPN_A_HOST}" "nohup pidstat -u -p ${svpn_a} 1 > /tmp/svpn-pidstat.log 2>&1 </dev/null & echo \$! > /tmp/svpn-pidstat.pid"
    pi_ssh "${VPN_B_HOST}" "nohup pidstat -u -p ${svpn_b} 1 > /tmp/svpn-pidstat.log 2>&1 </dev/null & echo \$! > /tmp/svpn-pidstat.pid"
  fi

  sleep 0.4
  phase "${mode} ${dir} run ${run}: iperf3 ${client_bind} -> ${dest} (${BENCH_DURATION}s omit ${BENCH_OMIT}s)"
  pi_ssh "${client_host}" "iperf3 -c ${dest} -B ${client_bind} -p 5201 -t ${BENCH_DURATION} -O ${BENCH_OMIT} -J" \
    > "${rundir}/run${run}_iperf.json"

  if [[ "${mode}" != "direct" ]]; then
    pi_ssh "${VPN_A_HOST}" "kill \$(cat /tmp/svpn-pidstat.pid) 2>/dev/null || true"
    pi_ssh "${VPN_B_HOST}" "kill \$(cat /tmp/svpn-pidstat.pid) 2>/dev/null || true"
    scp_base "${PI_USER}@${VPN_A_HOST}:/tmp/svpn-pidstat.log" "${rundir}/run${run}_pidstat_a.txt" || true
    scp_base "${PI_USER}@${VPN_B_HOST}:/tmp/svpn-pidstat.log" "${rundir}/run${run}_pidstat_b.txt" || true
  fi
  scp_base "${PI_USER}@${server_host}:/tmp/svpn-iperf-server.json" "${rundir}/run${run}_iperf_server.json" || true

  pi_ssh "${VPN_A_HOST}" "vcgencmd measure_temp 2>/dev/null; vcgencmd get_throttled 2>/dev/null" \
    > "${rundir}/run${run}_therm_after_a.txt" || echo unavailable > "${rundir}/run${run}_therm_after_a.txt"
  pi_ssh "${VPN_B_HOST}" "vcgencmd measure_temp 2>/dev/null; vcgencmd get_throttled 2>/dev/null" \
    > "${rundir}/run${run}_therm_after_b.txt" || echo unavailable > "${rundir}/run${run}_therm_after_b.txt"

    if grep -q 'throttled=0x' "${rundir}/run${run}_therm_after_a.txt" "${rundir}/run${run}_therm_after_b.txt" 2>/dev/null; then
      # Live flags are the low nibble. Sticky history is bits 16+.
      if grep -E 'throttled=0x[0-9a-f]*[1-9a-f]$' "${rundir}/run${run}_therm_after_a.txt" "${rundir}/run${run}_therm_after_b.txt" 2>/dev/null \
         | grep -qvE 'throttled=0x[0-9a-f]*0000$|throttled=0x0$|throttled=0x50000$|throttled=0x80000$|throttled=0xd0000$'; then
        echo "[WARN] live throttle flags after ${mode} ${dir} run ${run}"
      fi
    fi
  sleep 1
}

phase "recording system state"
record_system "${VPN_A_HOST}" "pi_a" "${VPN_B_OUTER_IP}"
record_system "${VPN_B_HOST}" "pi_b" "${VPN_A_OUTER_IP}"
{
  echo "timestamp ${TS}"
  echo "A_HOST ${VPN_A_HOST} A_OUTER ${VPN_A_OUTER_IP} A_TUN ${VPN_A_TUN_IP}"
  echo "B_HOST ${VPN_B_HOST} B_OUTER ${VPN_B_OUTER_IP} B_TUN ${VPN_B_TUN_IP}"
  echo "duration ${BENCH_DURATION} omit ${BENCH_OMIT} runs ${BENCH_RUNS}"
  echo "order interleaved: for each direction and run, direct -> plaintext -> encrypted"
} > "${OUT}/system/meta.txt"

# Interleave modes within each trial instead of completing all direct trials
# first. This makes changing Wi-Fi contention, RSSI, and AP scheduling much
# less likely to be mistaken for encryption overhead.
for dir in a_to_b b_to_a; do
  for run in $(seq 1 "${BENCH_RUNS}"); do
    phase "interleaved trial ${run}/${BENCH_RUNS}, direction ${dir}"
    for mode in direct plaintext encrypted; do
      start_mode "${mode}"
      run_iperf "${mode}" "${dir}" "${run}"
      stop_all
      sleep 2
    done
  done
done

phase "summarize"
python3 "${ROOT}/scripts/summarize_results.py" "${OUT}"
echo
echo "Results in ${OUT}"
echo "  ${OUT}/summary.md"
echo "  ${OUT}/summary.csv"
