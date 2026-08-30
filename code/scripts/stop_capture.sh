#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE="${1:-}"
[[ -n "${IFACE}" ]] || { echo "Usage: $0 IFACE" >&2; exit 1; }

PIDFILE="${ROOT}/run/tcpdump-${IFACE}.pid"
if [[ -f "${ROOT}/config.env" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT}/scripts/common.sh"
  load_config
fi

sudo_cmd() {
  if [[ -n "${PI_SUDO_PASSWORD:-}" ]]; then
    printf '%s\n' "${PI_SUDO_PASSWORD}" | sudo -S -p '' "$@"
  else
    sudo "$@"
  fi
}

if [[ -f "${PIDFILE}" ]]; then
    PID="$(cat "${PIDFILE}")"
  if [[ "${PID}" =~ ^[0-9]+$ ]] && kill -0 "${PID}" 2>/dev/null; then
    # The recorded process can be sudo or tcpdump depending on authentication.
    # Refuse to signal a reused, unrelated PID.
    ARGS="$(ps -p "${PID}" -o args= 2>/dev/null || true)"
    if [[ "${ARGS}" == *tcpdump* || "${ARGS}" == *"sudo -S"* ]]; then
      sudo_cmd kill "${PID}" 2>/dev/null || true
    else
      echo "[WARN] refusing to stop unexpected pid ${PID}: ${ARGS}" >&2
    fi
  fi
  rm -f "${PIDFILE}"
fi
echo "[OK] stopped tcpdump ${IFACE}"
