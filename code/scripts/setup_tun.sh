#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"

ROLE="${1:-}"
if [[ "${ROLE}" != "a" && "${ROLE}" != "b" ]]; then
  echo "Usage: $0 a|b" >&2
  exit 1
fi

# Local Pi path: source config if present.
if [[ -f "${ROOT}/config.env" ]]; then
  load_config
else
  die "config.env missing"
fi

if [[ "${ROLE}" == "a" ]]; then
  ADDR="${VPN_A_TUN_IP}"
else
  ADDR="${VPN_B_TUN_IP}"
fi
DEV="${VPN_TUN_NAME}"
MTU="${VPN_TUN_MTU}"
PFX="${VPN_TUN_PREFIX}"

phase "configure ${DEV} ${ADDR}/${PFX} mtu ${MTU} (no default-route changes)"

sudo_cmd() {
  if [[ -n "${PI_SUDO_PASSWORD:-}" ]]; then
    printf '%s\n' "${PI_SUDO_PASSWORD}" | sudo -S -p '' "$@"
  else
    sudo "$@"
  fi
}

if ip link show "${DEV}" >/dev/null 2>&1; then
  echo "${DEV} already exists"
else
  sudo_cmd ip tuntap add dev "${DEV}" mode tun user "${USER}"
fi
sudo_cmd ip addr replace "${ADDR}/${PFX}" dev "${DEV}"
sudo_cmd ip link set dev "${DEV}" mtu "${MTU}"
sudo_cmd ip link set dev "${DEV}" up
ip -br addr show "${DEV}"
echo "[OK] ${DEV} ready"
