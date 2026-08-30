#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

ROLE="${1:-}"
MODE="${2:-}"
BG="${3:-}"

if [[ "${ROLE}" != "a" && "${ROLE}" != "b" ]]; then
  echo "Usage: $0 a|b plaintext|encrypted [background]" >&2
  exit 1
fi
if [[ "${MODE}" != "plaintext" && "${MODE}" != "encrypted" ]]; then
  echo "Usage: $0 a|b plaintext|encrypted [background]" >&2
  exit 1
fi

if [[ "${ROLE}" == "a" ]]; then
  SVPN_ROLE="client"
  BIND_IP="${VPN_A_OUTER_IP}"
  PEER_IP="${VPN_B_OUTER_IP}"
else
  SVPN_ROLE="server"
  BIND_IP="${VPN_B_OUTER_IP}"
  PEER_IP="${VPN_A_OUTER_IP}"
fi

BIN="${ROOT}/bin/svpn"
[[ -x "${BIN}" ]] || die "missing ${BIN} (build on this Pi first)"

ARGS=(
  --role "${SVPN_ROLE}"
  --mode "${MODE}"
  --tun "${VPN_TUN_NAME}"
  --bind-ip "${BIND_IP}"
  --bind-port "${VPN_PORT}"
  --peer-ip "${PEER_IP}"
  --peer-port "${VPN_PORT}"
)
if [[ "${MODE}" == "encrypted" ]]; then
  ARGS+=(--identity-secret "${ROOT}/keys/identity.key"
         --peer-identity-public "${ROOT}/keys/peer_identity.pub")
fi

phase "start svpn role=${SVPN_ROLE} mode=${MODE} bind=${BIND_IP}:${VPN_PORT} peer=${PEER_IP}:${VPN_PORT}"

if [[ "${BG}" == "background" ]]; then
  mkdir -p "${ROOT}/run"
  PIDFILE="${ROOT}/run/svpn.pid"
  if [[ -f "${PIDFILE}" ]] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null; then
    OLD_PID="$(cat "${PIDFILE}")"
    OLD_EXE="$(readlink -f "/proc/${OLD_PID}/exe" 2>/dev/null || true)"
    [[ "${OLD_EXE}" == "${BIN}" ]] || die "pid file points to unexpected process ${OLD_PID}: ${OLD_EXE:-unknown}"
    die "svpn already running pid=${OLD_PID}"
  fi
  nohup "${BIN}" "${ARGS[@]}" >"${ROOT}/run/svpn.log" 2>&1 </dev/null &
  echo $! >"${PIDFILE}"
  disown || true
  echo "[OK] background pid=$(cat "${PIDFILE}") log=${ROOT}/run/svpn.log"
else
  exec "${BIN}" "${ARGS[@]}"
fi
