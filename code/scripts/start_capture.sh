#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
if [[ -f "${ROOT}/config.env" ]]; then
  load_config
fi

IFACE="${1:-}"
OUT="${2:-}"
shift 2 || true

[[ -n "${IFACE}" && -n "${OUT}" ]] || die "Usage: $0 IFACE OUTFILE [tcpdump filter...]"

sudo_cmd() {
  if [[ -n "${PI_SUDO_PASSWORD:-}" ]]; then
    printf '%s\n' "${PI_SUDO_PASSWORD}" | sudo -S -p '' "$@"
  else
    sudo "$@"
  fi
}

mkdir -p "${ROOT}/run"
PIDFILE="${ROOT}/run/tcpdump-${IFACE}.pid"
if [[ -f "${PIDFILE}" ]] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null; then
  die "tcpdump already running for ${IFACE} pid=$(cat "${PIDFILE}")"
fi

sudo_cmd rm -f "${OUT}"
# Packet-buffered so a short HTTP transfer is flushed to the pcap.
if [[ -n "${PI_SUDO_PASSWORD:-}" ]]; then
  # setsid runs an executable, not the shell-local sudo_cmd function.
  printf '%s\n' "${PI_SUDO_PASSWORD}" | setsid sudo -S -p '' tcpdump -U -ni "${IFACE}" "$@" -w "${OUT}" \
    </dev/null >/tmp/svpn-tcpdump-${IFACE}.log 2>&1 &
else
  setsid sudo tcpdump -U -ni "${IFACE}" "$@" -w "${OUT}" \
    </dev/null >/tmp/svpn-tcpdump-${IFACE}.log 2>&1 &
fi
echo $! >"${PIDFILE}"
sleep 0.3
echo "[OK] tcpdump ${IFACE} -> ${OUT} pid=$(cat "${PIDFILE}")"
