#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

FAILS=0
fail() {
  echo "[FAIL] $*" >&2
  FAILS=$((FAILS + 1))
}
ok() { echo "[OK] $*"; }

check_one() {
  local label="$1"
  local host="$2"
  local expect_hn="$3"
  local expect_ip="$4"
  local peer_ip="$5"

  phase "Pi ${label} (${host})"

  if ! pi_ssh "${host}" true; then
    fail "SSH to ${PI_USER}@${host}"
    return
  fi
  ok "SSH ${PI_USER}@${host}"

  local hn
  hn="$(pi_ssh "${host}" hostname)"
  if [[ "${hn}" != "${expect_hn}" ]]; then
    fail "hostname is '${hn}', expected '${expect_hn}'"
  else
    ok "hostname ${hn}"
  fi

  local wlan_ip
  wlan_ip="$(pi_ssh "${host}" "ip -4 -o addr show wlan0 | awk '{print \$4}' | cut -d/ -f1" || true)"
  if [[ -z "${wlan_ip}" ]]; then
    fail "no IPv4 on wlan0"
  elif [[ "${wlan_ip}" != "${expect_ip}" ]]; then
    echo "[STOP] ${label} wlan0 is ${wlan_ip}, config.env has ${expect_ip}"
    echo "       Update VPN_${label}_OUTER_IP / VPN_${label}_HOST in config.env"
    fail "configured outer IP does not match wlan0"
  else
    ok "wlan0 IPv4 ${wlan_ip}"
  fi

  local rget
  rget="$(pi_ssh "${host}" "ip route get ${peer_ip}" || true)"
  echo "    route get ${peer_ip}: ${rget}"
  if ! grep -qw wlan0 <<<"${rget}"; then
    fail "route to ${peer_ip} does not use wlan0"
  else
    ok "peer route uses wlan0"
  fi
  if grep -qw eth0 <<<"${rget}"; then
    fail "peer route unexpectedly uses eth0"
  fi

  if pi_ssh "${host}" "ping -c 2 -W 2 ${peer_ip}" >/dev/null; then
    ok "ping ${peer_ip}"
  else
    fail "cannot ping peer ${peer_ip} (possible client isolation)"
  fi

  pi_ssh "${host}" "test -e /dev/net/tun" && ok "/dev/net/tun" || fail "/dev/net/tun missing"
  pi_ssh "${host}" "command -v gcc >/dev/null" && ok "gcc" || fail "gcc missing"
  pi_ssh "${host}" "command -v make >/dev/null" && ok "make" || fail "make missing"
  if pi_ssh "${host}" "pkg-config --exists libsodium"; then
    ok "pkg-config libsodium"
  else
    fail "libsodium not found via pkg-config (run scripts/install_deps_pi.sh --remote)"
  fi
  pi_ssh "${host}" "command -v iperf3 >/dev/null" && ok "iperf3" || fail "iperf3 missing"
  pi_ssh "${host}" "command -v tcpdump >/dev/null" && ok "tcpdump" || fail "tcpdump missing"
  pi_ssh "${host}" "command -v pidstat >/dev/null" && ok "pidstat" || fail "pidstat missing (sysstat)"

  if pi_ssh "${host}" "ss -lun | grep -q ':${VPN_PORT} '"; then
    fail "UDP port ${VPN_PORT} already in use"
  else
    ok "UDP port ${VPN_PORT} free"
  fi

  if pi_ssh "${host}" "pgrep -x svpn >/dev/null"; then
    fail "stale svpn process running"
  else
    ok "no stale svpn"
  fi

  if pi_ssh "${host}" "command -v vcgencmd >/dev/null"; then
    local temp throttled
    temp="$(pi_ssh "${host}" "vcgencmd measure_temp")"
    throttled="$(pi_ssh "${host}" "vcgencmd get_throttled")"
    echo "    ${temp}  ${throttled}"
    if [[ "${throttled}" != "throttled=0x0" ]]; then
      echo "[WARN] ${label} throttle flags ${throttled} (sticky under-voltage/throttle bits are common)"
    fi
  else
    echo "[WARN] vcgencmd unavailable; thermal data will be marked N/A"
  fi
}

phase "Fedora preflight for svpn"
check_one "A" "${VPN_A_HOST}" "${VPN_A_HOSTNAME}" "${VPN_A_OUTER_IP}" "${VPN_B_OUTER_IP}"
check_one "B" "${VPN_B_HOST}" "${VPN_B_HOSTNAME}" "${VPN_B_OUTER_IP}" "${VPN_A_OUTER_IP}"

if [[ "${FAILS}" -ne 0 ]]; then
  echo
  die "${FAILS} preflight check(s) failed. Do not continue until they pass."
fi

echo
echo "Preflight passed."
