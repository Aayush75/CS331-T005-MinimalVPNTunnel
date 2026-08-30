#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
if [[ -f "${ROOT}/config.env" ]]; then
  load_config
else
  VPN_TUN_NAME="${VPN_TUN_NAME:-tun0}"
fi

DEV="${VPN_TUN_NAME}"
phase "delete only ${DEV}"

sudo_cmd() {
  if [[ -n "${PI_SUDO_PASSWORD:-}" ]]; then
    printf '%s\n' "${PI_SUDO_PASSWORD}" | sudo -S -p '' "$@"
  else
    sudo "$@"
  fi
}

if ip link show "${DEV}" >/dev/null 2>&1; then
  sudo_cmd ip link set "${DEV}" down || true
  sudo_cmd ip tuntap del dev "${DEV}" mode tun
  echo "[OK] deleted ${DEV}"
else
  echo "${DEV} not present"
fi
