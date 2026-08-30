#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDFILE="${ROOT}/run/svpn.pid"

if [[ ! -f "${PIDFILE}" ]]; then
  echo "no pid file ${PIDFILE}"
  exit 0
fi
PID="$(cat "${PIDFILE}")"
if ! [[ "${PID}" =~ ^[0-9]+$ ]]; then
  echo "invalid pid file" >&2
  rm -f "${PIDFILE}"
  exit 1
fi
if kill -0 "${PID}" 2>/dev/null; then
  EXE="$(readlink -f "/proc/${PID}/exe" 2>/dev/null || true)"
  if [[ "${EXE}" != "${ROOT}/bin/svpn" ]]; then
    echo "refusing to signal pid ${PID}: expected ${ROOT}/bin/svpn, got ${EXE:-unknown}" >&2
    exit 1
  fi
  echo "sending SIGTERM to ${PID}"
  kill -TERM "${PID}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "${PID}" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done
  if kill -0 "${PID}" 2>/dev/null; then
    echo "process still running after SIGTERM" >&2
    exit 1
  fi
fi
rm -f "${PIDFILE}"
echo "[OK] stopped"
