#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

MARKER="SVPN_DEMO_SECRET_6F91C2A7"
CAP="${ROOT}/captures"
mkdir -p "${CAP}"

remote_stop() {
  pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/stop_tunnel.sh" >/dev/null 2>&1 || true
  pi_ssh "${VPN_B_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/stop_tunnel.sh" >/dev/null 2>&1 || true
}

start_dumps() {
  local iface="$1"
  local filter="$2"
  local out="$3"
  pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && bash -s -- ${iface} ${out} ${filter}" <<EOS
set -euo pipefail
IFACE="\$1"; OUT="\$2"; shift 2; FILTER="\${*:-}"
printf '%s\n' '${PI_SUDO_PASSWORD}' | sudo -S -p '' rm -f "\$OUT"
nohup bash -c "printf '%s\n' '${PI_SUDO_PASSWORD}' | sudo -S -p '' tcpdump -U -ni \$IFACE \$FILTER -w \$OUT" >/tmp/svpn-tcpdump-\$IFACE.log 2>&1 </dev/null &
echo \$! > /tmp/svpn-tcpdump-\$IFACE.pid
disown || true
echo "[OK] tcpdump \$IFACE"
EOS
}

http_once() {
  pi_ssh "${VPN_B_HOST}" "mkdir -p /tmp/svpn-http && printf 'demo %s\n' '${MARKER}' > /tmp/svpn-http/index.html"
  pi_ssh "${VPN_B_HOST}" "if [[ -f /tmp/svpn-http.pid ]]; then kill \"\$(cat /tmp/svpn-http.pid)\" 2>/dev/null || true; rm -f /tmp/svpn-http.pid; fi"
  pi_ssh "${VPN_B_HOST}" "cd /tmp/svpn-http && nohup python3 -m http.server 8080 --bind ${VPN_B_TUN_IP} >/tmp/svpn-http.log 2>&1 </dev/null & echo \$! > /tmp/svpn-http.pid; disown || true; echo started"
  sleep 0.8
  pi_ssh "${VPN_A_HOST}" "timeout 8 curl -sS --max-time 5 http://${VPN_B_TUN_IP}:8080/" | grep -q "${MARKER}"
  pi_ssh "${VPN_B_HOST}" "if [[ -f /tmp/svpn-http.pid ]]; then kill \"\$(cat /tmp/svpn-http.pid)\" 2>/dev/null || true; fi"
}

stop_dumps() {
  local iface="$1"
  pi_ssh "${VPN_A_HOST}" 'if [[ -f /tmp/svpn-tcpdump-'"${iface}"'.pid ]]; then p=$(cat /tmp/svpn-tcpdump-'"${iface}"'.pid); if [[ "$p" =~ ^[0-9]+$ ]] && kill -0 "$p" 2>/dev/null; then args=$(ps -p "$p" -o args= 2>/dev/null || true); [[ "$args" == *tcpdump* ]] && kill "$p" || true; fi; rm -f /tmp/svpn-tcpdump-'"${iface}"'.pid; fi'
}

check_marker() {
  local file="$1"
  local expect="$2" # present|absent
  if grep -a -q "${MARKER}" "${file}"; then
    if [[ "${expect}" == "present" ]]; then
      echo "[PASS] marker found in ${file}"
    else
      echo "[FAIL] marker unexpectedly found in ${file}"
      return 1
    fi
  else
    if [[ "${expect}" == "absent" ]]; then
      echo "[PASS] marker absent from ${file}"
    else
      echo "[FAIL] marker missing from ${file}"
      return 1
    fi
  fi
}

if [[ -z "${PI_SUDO_PASSWORD:-}" ]]; then
  cat >&2 <<EOF
[ERROR] remote tcpdump needs sudo on the Pis, and passwordless sudo is not configured.
This script will not modify sudoers.

Either:
  export SSHPASS='...'   # and set PI_SUDO_PASSWORD in config.env
or run these on Pi A while repeating the HTTP demo by hand:

  sudo tcpdump -ni tun0 -w /tmp/encrypted_tun0.pcap
  sudo tcpdump -ni wlan0 udp port ${VPN_PORT} -w /tmp/encrypted_wlan0.pcap
  sudo tcpdump -ni wlan0 udp port ${VPN_PORT} -w /tmp/plaintext_wlan0.pcap
EOF
  exit 1
fi

phase "TUN setup"
pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/setup_tun.sh a"
pi_ssh "${VPN_B_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/setup_tun.sh b"

phase "encrypted captures (tun0 + wlan0 on A)"
remote_stop
pi_ssh "${VPN_B_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/start_tunnel.sh b encrypted background"
pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/start_tunnel.sh a encrypted background"
pi_ssh "${VPN_A_HOST}" "for i in \$(seq 1 40); do grep -q 'session established' ${REMOTE_PROJECT_DIR}/run/svpn.log && exit 0; sleep 0.25; done; exit 1"

start_dumps tun0 "" /tmp/encrypted_tun0.pcap
start_dumps wlan0 "udp port ${VPN_PORT}" /tmp/encrypted_wlan0.pcap
sleep 1
http_once
sleep 1
stop_dumps tun0
stop_dumps wlan0
remote_stop
sleep 0.5
scp_base "${PI_USER}@${VPN_A_HOST}:/tmp/encrypted_tun0.pcap" "${CAP}/encrypted_tun0.pcap"
scp_base "${PI_USER}@${VPN_A_HOST}:/tmp/encrypted_wlan0.pcap" "${CAP}/encrypted_wlan0.pcap"

phase "plaintext control capture (wlan0 on A)"
pi_ssh "${VPN_B_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/start_tunnel.sh b plaintext background"
pi_ssh "${VPN_A_HOST}" "cd ${REMOTE_PROJECT_DIR} && ./scripts/start_tunnel.sh a plaintext background"
sleep 1
start_dumps wlan0 "udp port ${VPN_PORT}" /tmp/plaintext_wlan0.pcap
sleep 1
http_once
sleep 1
stop_dumps wlan0
remote_stop
scp_base "${PI_USER}@${VPN_A_HOST}:/tmp/plaintext_wlan0.pcap" "${CAP}/plaintext_wlan0.pcap"

phase "automated marker check"
FAIL=0
check_marker "${CAP}/encrypted_tun0.pcap" present || FAIL=1
check_marker "${CAP}/encrypted_wlan0.pcap" absent || FAIL=1
check_marker "${CAP}/plaintext_wlan0.pcap" present || FAIL=1

echo
echo "An observer on Wi-Fi still sees outer IPs, UDP port ${VPN_PORT}, sizes, and timing."
echo "The encrypted tunnel hides the inner IP packet and application payload, not metadata."

if [[ "${FAIL}" -ne 0 ]]; then
  die "capture demonstration checks failed"
fi
echo "[OK] confidentiality demonstration captures are in ${CAP}"
