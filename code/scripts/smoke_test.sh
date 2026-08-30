#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

MODE="${1:-all}"

remote_setup_tun() {
  local host="$1"
  local role="$2"
  phase "setup tun on ${host} (${role})"
  pi_ssh "${host}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/setup_tun.sh ${role}"
}

remote_start() {
  local host="$1"
  local role="$2"
  local mode="$3"
  phase "start ${mode} tunnel on ${host} (${role})"
  pi_ssh "${host}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/start_tunnel.sh ${role} ${mode} background"
}

remote_stop() {
  local host="$1"
  pi_ssh "${host}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/stop_tunnel.sh" || true
}

stop_iperf_server() {
  # Only stop the server started by this project; never kill another user's
  # iperf experiment on a shared Pi.
  pi_ssh "${VPN_B_HOST}" 'if [[ -f /tmp/svpn-iperf-server.pid ]]; then p=$(cat /tmp/svpn-iperf-server.pid); if [[ "$p" =~ ^[0-9]+$ ]] && [[ "$(ps -p "$p" -o comm= 2>/dev/null || true)" == "iperf3" ]]; then kill "$p" 2>/dev/null || true; fi; rm -f /tmp/svpn-iperf-server.pid; fi'
}

start_iperf_server() {
  pi_ssh "${VPN_B_HOST}" "nohup iperf3 -s -1 -B ${VPN_B_TUN_IP} -p 5201 >/tmp/svpn-iperf-s.log 2>&1 </dev/null & echo \$! > /tmp/svpn-iperf-server.pid"
}

wait_handshake() {
  local host="$1"
  local i
  for i in $(seq 1 40); do
    if pi_ssh "${host}" "grep -q 'session established' ${REMOTE_PROJECT_DIR}/run/svpn.log" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  echo "---- A log ----"
  pi_ssh "${VPN_A_HOST}" "tail -n 40 ${REMOTE_PROJECT_DIR}/run/svpn.log" || true
  echo "---- B log ----"
  pi_ssh "${VPN_B_HOST}" "tail -n 40 ${REMOTE_PROJECT_DIR}/run/svpn.log" || true
  die "handshake did not complete"
}

run_traffic() {
  local tag="$1"
  phase "${tag}: ICMP"
  pi_ssh "${VPN_A_HOST}" "ping -c 4 -W 2 ${VPN_B_TUN_IP}"
  phase "${tag}: TCP iperf3"
  stop_iperf_server
  start_iperf_server
  sleep 0.8
  pi_ssh "${VPN_A_HOST}" "iperf3 -c ${VPN_B_TUN_IP} -B ${VPN_A_TUN_IP} -p 5201 -t 3"
  phase "${tag}: UDP iperf3"
  stop_iperf_server
  start_iperf_server
  sleep 0.8
  pi_ssh "${VPN_A_HOST}" "iperf3 -c ${VPN_B_TUN_IP} -B ${VPN_A_TUN_IP} -p 5201 -u -b 10M -t 3"
}

plaintext() {
  remote_setup_tun "${VPN_A_HOST}" a
  remote_setup_tun "${VPN_B_HOST}" b
  remote_stop "${VPN_A_HOST}"
  remote_stop "${VPN_B_HOST}"
  remote_start "${VPN_B_HOST}" b plaintext
  remote_start "${VPN_A_HOST}" a plaintext
  sleep 1
  run_traffic "plaintext"
  remote_stop "${VPN_A_HOST}"
  remote_stop "${VPN_B_HOST}"
}

encrypted() {
  remote_setup_tun "${VPN_A_HOST}" a
  remote_setup_tun "${VPN_B_HOST}" b
  remote_stop "${VPN_A_HOST}"
  remote_stop "${VPN_B_HOST}"
  remote_start "${VPN_B_HOST}" b encrypted
  remote_start "${VPN_A_HOST}" a encrypted
  wait_handshake "${VPN_A_HOST}"
  run_traffic "encrypted"
  remote_stop "${VPN_A_HOST}"
  remote_stop "${VPN_B_HOST}"
}

negative() {
  phase "negative: wrong peer identity on A"
  remote_setup_tun "${VPN_A_HOST}" a
  remote_setup_tun "${VPN_B_HOST}" b
  remote_stop "${VPN_A_HOST}"
  remote_stop "${VPN_B_HOST}"
  pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && mkdir -p /tmp/svpn-neg && ./bin/svpn-keygen --force --secret /tmp/svpn-neg/x.key --public /tmp/svpn-neg/x.pub"
  remote_start "${VPN_B_HOST}" b encrypted
  # Start A with the wrong pin; expect handshake failure (non-zero).
  set +e
  pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./bin/svpn --role client --mode encrypted --tun ${VPN_TUN_NAME} --bind-ip ${VPN_A_OUTER_IP} --bind-port ${VPN_PORT} --peer-ip ${VPN_B_OUTER_IP} --peer-port ${VPN_PORT} --identity-secret keys/identity.key --peer-identity-public /tmp/svpn-neg/x.pub" > /tmp/svpn-neg-a.log 2>&1
  rc=$?
  set -e
  echo "---- client log ----"
  cat /tmp/svpn-neg-a.log || true
  grep -E "signature invalid|peer identity|handshake timed out|authentication" /tmp/svpn-neg-a.log || true
  if grep -q "session established" /tmp/svpn-neg-a.log; then
    remote_stop "${VPN_B_HOST}"
    die "handshake unexpectedly succeeded with wrong identity"
  fi
  if [[ "${rc}" -eq 0 ]]; then
    remote_stop "${VPN_B_HOST}"
    die "svpn exited 0 with wrong identity"
  fi
  echo "[OK] wrong identity rejected (exit ${rc})"
  remote_stop "${VPN_B_HOST}"
  # Confirm inner ping does not pass without a session.
  if pi_ssh "${VPN_A_HOST}" "ping -c 2 -W 1 ${VPN_B_TUN_IP}" >/dev/null 2>&1; then
    die "ping unexpectedly succeeded without authenticated session"
  fi
  echo "[OK] no tunnel data without handshake"
}

case "${MODE}" in
  plaintext) plaintext ;;
  encrypted) encrypted ;;
  negative) negative ;;
  all)
    plaintext
    encrypted
    negative
    ;;
  *)
    echo "Usage: $0 [all|plaintext|encrypted|negative]" >&2
    exit 1
    ;;
esac

echo
echo "Smoke tests passed (${MODE})."
