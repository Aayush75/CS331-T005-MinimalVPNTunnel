#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

phase() { echo "=== $* ==="; }

phase "checking Fedora development dependencies"

need_dnf=()

check_cmd() {
  local cmd="$1"
  local pkg="$2"
  if command -v "${cmd}" >/dev/null 2>&1; then
    echo "[OK] ${cmd}"
  else
    echo "[MISSING] ${cmd} (package: ${pkg})"
    need_dnf+=("${pkg}")
  fi
}

check_cmd git git
check_cmd rsync rsync
check_cmd ssh openssh-clients
check_cmd python3 python3
check_cmd jq jq
check_cmd iperf3 iperf3
check_cmd sshpass sshpass
check_cmd gcc gcc
check_cmd make make
check_cmd pkg-config pkgconf-pkg-config

if command -v tshark >/dev/null 2>&1; then
  echo "[OK] tshark"
else
  echo "[MISSING] tshark (package: wireshark-cli)"
  need_dnf+=(wireshark-cli)
fi

if pkg-config --exists libsodium 2>/dev/null; then
  echo "[OK] libsodium (pkg-config)"
else
  echo "[MISSING] libsodium-devel"
  need_dnf+=(libsodium-devel)
fi

if [[ ${#need_dnf[@]} -eq 0 ]]; then
  echo "All Fedora dependencies are present."
  echo "Open saved PCAPs in the Wireshark GUI if it is already installed:"
  echo "  wireshark captures/encrypted_wlan0.pcap"
  exit 0
fi

echo
echo "Would install with dnf: ${need_dnf[*]}"
if [[ "${1:-}" == "--yes" ]]; then
  sudo dnf install -y "${need_dnf[@]}"
else
  echo "Run: sudo dnf install -y ${need_dnf[*]}"
  echo "Or re-run: $0 --yes"
  exit 1
fi
