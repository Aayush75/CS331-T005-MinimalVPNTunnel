#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

PACKAGES=(
  build-essential
  pkg-config
  libsodium-dev
  iperf3
  tcpdump
  tshark
  sysstat
  jq
  netcat-openbsd
  python3
  rsync
)

install_local() {
  phase "installing Pi/Debian packages"
  if [[ ! -f /etc/os-release ]]; then
    die "cannot detect OS (/etc/os-release missing)"
  fi
  # shellcheck disable=SC1091
  source /etc/os-release
  case "${ID:-}" in
    debian|ubuntu|raspbian)
      ;;
    *)
      die "Pi OS is not apt-based (ID=${ID:-unknown}). Install dependencies manually."
      ;;
  esac
  if [[ -n "${PI_SUDO_PASSWORD:-}" ]]; then
    printf '%s\n' "${PI_SUDO_PASSWORD}" | sudo -S -p '' apt-get update
    printf '%s\n' "${PI_SUDO_PASSWORD}" | sudo -S -p '' apt-get install -y "${PACKAGES[@]}"
  else
    sudo apt-get update
    sudo apt-get install -y "${PACKAGES[@]}"
  fi
  echo "[OK] packages installed on $(hostname)"
}

install_remote() {
  local host="$1"
  phase "installing packages on ${host}"
  pi_ssh "${host}" "cat > /tmp/svpn-install-deps.sh && bash /tmp/svpn-install-deps.sh" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
source /etc/os-release
case "${ID:-}" in
  debian|ubuntu|raspbian) ;;
  *) echo "not apt-based: ${ID:-unknown}"; exit 2 ;;
esac
PACKAGES=(build-essential pkg-config libsodium-dev iperf3 tcpdump tshark sysstat jq netcat-openbsd python3 rsync)
if sudo -n true 2>/dev/null; then
  sudo apt-get update
  sudo apt-get install -y "${PACKAGES[@]}"
else
  echo "NEED_SUDO"
  exit 3
fi
EOS
}

if [[ "${1:-}" == "--remote" ]]; then
  for host in "${VPN_A_HOST}" "${VPN_B_HOST}"; do
    phase "apt install on ${host}"
    # Stream a local installer that uses sudo -S with the known lab password.
    pi_ssh "${host}" "PI_SUDO_PASSWORD=$(printf '%q' "${PI_SUDO_PASSWORD:-}") bash -s" <<'EOS'
set -euo pipefail
source /etc/os-release
case "${ID:-}" in
  debian|ubuntu|raspbian) ;;
  *) echo "not apt-based: ${ID:-unknown}"; exit 2 ;;
esac
PACKAGES=(build-essential pkg-config libsodium-dev iperf3 tcpdump tshark sysstat jq netcat-openbsd python3 rsync)
if [[ -n "${PI_SUDO_PASSWORD:-}" ]]; then
  printf '%s\n' "${PI_SUDO_PASSWORD}" | sudo -S -p '' apt-get update
  printf '%s\n' "${PI_SUDO_PASSWORD}" | sudo -S -p '' DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"
else
  sudo apt-get update
  sudo apt-get install -y "${PACKAGES[@]}"
fi
echo "[OK] $(hostname)"
EOS
  done
  exit 0
fi

install_local
