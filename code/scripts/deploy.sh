#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

RSYNC_EXCLUDES=(
  --exclude '.git/'
  --exclude 'bin/'
  --exclude 'build/'
  --exclude 'keys/'
  --exclude 'results/'
  --exclude 'captures/'
  --exclude 'run/'
  --exclude 'config.env'
  --exclude '*.o'
  --exclude '*.pcap'
  --exclude '*.pcapng'
)

deploy_one() {
  local host="$1"
  phase "rsync -> ${PI_USER}@${host}:${REMOTE_PROJECT_DIR}"
  rsync_base -az --delete "${RSYNC_EXCLUDES[@]}" \
    "${ROOT}/" "${PI_USER}@${host}:${REMOTE_PROJECT_DIR}/"
  # Keep a copy of config.env for start scripts (no private keys).
  scp_base "${ROOT}/config.env" "${PI_USER}@${host}:${REMOTE_PROJECT_DIR}/config.env"
  phase "make clean && make && make test on ${host}"
  pi_ssh "${host}" "cd ${REMOTE_PROJECT_DIR} && make clean && make && make test"
}

deploy_one "${VPN_A_HOST}"
deploy_one "${VPN_B_HOST}"
echo
echo "Deploy and native tests succeeded on both Pis."
