#!/usr/bin/env bash
# Shared helpers. Sourced by other scripts. Not executed directly.

set -euo pipefail

svpn_root() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
  cd "${here}/.." && pwd
}

ROOT="$(svpn_root)"
cd "${ROOT}"

load_config() {
  if [[ ! -f "${ROOT}/config.env" ]]; then
    echo "[ERROR] missing ${ROOT}/config.env — copy config.env.example and edit" >&2
    exit 1
  fi
  # shellcheck disable=SC1091
  source "${ROOT}/config.env"
  : "${PI_USER:?}"
  : "${VPN_A_HOST:?}"
  : "${VPN_B_HOST:?}"
  : "${VPN_A_OUTER_IP:?}"
  : "${VPN_B_OUTER_IP:?}"
  : "${VPN_PORT:?}"
  : "${VPN_A_TUN_IP:?}"
  : "${VPN_B_TUN_IP:?}"
  : "${VPN_TUN_NAME:?}"
  : "${VPN_TUN_MTU:?}"
  : "${VPN_TUN_PREFIX:?}"
  : "${REMOTE_PROJECT_DIR:=~/code}"
  : "${VPN_A_HOSTNAME:=vpn-a}"
  : "${VPN_B_HOSTNAME:=vpn-b}"
  : "${BENCH_DURATION:=20}"
  : "${BENCH_OMIT:=3}"
  : "${BENCH_RUNS:=5}"

  if [[ -n "${PI_SSH_PASSWORD:-}" && -z "${SSHPASS:-}" ]]; then
    export SSHPASS="${PI_SSH_PASSWORD}"
  fi
  if [[ -z "${PI_SUDO_PASSWORD:-}" && -n "${SSHPASS:-}" ]]; then
    PI_SUDO_PASSWORD="${SSHPASS}"
  fi
}

phase() {
  echo
  echo "=== $* ==="
}

die() {
  echo "[ERROR] $*" >&2
  exit 1
}

ssh_base() {
  local args=()
  if [[ -n "${SVPN_SSH_CONFIG:-}" ]]; then
    args+=(-F "${SVPN_SSH_CONFIG}")
  fi
  args+=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10
              -o ServerAliveInterval=5)
  if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
    sshpass -e ssh "${args[@]}" "$@"
  else
    ssh "${args[@]}" "$@"
  fi
}

scp_base() {
  local args=()
  if [[ -n "${SVPN_SSH_CONFIG:-}" ]]; then
    args+=(-F "${SVPN_SSH_CONFIG}")
  fi
  args+=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
  if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
    sshpass -e scp "${args[@]}" "$@"
  else
    scp "${args[@]}" "$@"
  fi
}

rsync_base() {
  local args=(-e)
  local sshcmd="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
  if [[ -n "${SVPN_SSH_CONFIG:-}" ]]; then
    sshcmd="ssh -F ${SVPN_SSH_CONFIG} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
  fi
  if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
    sshcmd="sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
  fi
  rsync "${args[@]}" "${sshcmd}" "$@"
}

pi_ssh() {
  local host="$1"
  shift
  ssh_base "${PI_USER}@${host}" "$@"
}

pi_sudo() {
  local host="$1"
  shift
  local cmd="$*"
  if [[ -z "${PI_SUDO_PASSWORD:-}" ]]; then
    pi_ssh "${host}" "sudo -n ${cmd}"
  else
    pi_ssh "${host}" "printf '%s\n' '${PI_SUDO_PASSWORD}' | sudo -S -p '' ${cmd}"
  fi
}

remote_dir() {
  # Expand ~ on the remote side.
  echo "${REMOTE_PROJECT_DIR/#\~/\$HOME}"
}
