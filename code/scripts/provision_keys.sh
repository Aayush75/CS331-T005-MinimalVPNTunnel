#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"
load_config

gen_one() {
  local host="$1"
  phase "identity keys on ${host}"
  pi_ssh "${host}" "mkdir -p ${REMOTE_PROJECT_DIR}/keys && chmod 700 ${REMOTE_PROJECT_DIR}/keys"
  if pi_ssh "${host}" "test -f ${REMOTE_PROJECT_DIR}/keys/identity.key"; then
    echo "existing identity.key left in place on ${host} (will not overwrite)"
  else
    pi_ssh "${host}" "cd ${REMOTE_PROJECT_DIR} && ./bin/svpn-keygen --secret keys/identity.key --public keys/identity.pub"
  fi
}

fp_of() {
  local host="$1"
  local rel="$2"
  pi_ssh "${host}" "python3 -c \"from hashlib import blake2b; from pathlib import Path; import os; p=Path(os.path.expanduser('${REMOTE_PROJECT_DIR}'))/'${rel}'; print(blake2b(p.read_bytes(), digest_size=32).digest()[:8].hex())\""
}

phase "ensure keygen exists"
pi_ssh "${VPN_A_HOST}" "test -x ${REMOTE_PROJECT_DIR}/bin/svpn-keygen" || die "build missing on A; run ./scripts/deploy.sh"
pi_ssh "${VPN_B_HOST}" "test -x ${REMOTE_PROJECT_DIR}/bin/svpn-keygen" || die "build missing on B; run ./scripts/deploy.sh"

gen_one "${VPN_A_HOST}"
gen_one "${VPN_B_HOST}"

phase "exchange public keys only"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
scp_base "${PI_USER}@${VPN_A_HOST}:${REMOTE_PROJECT_DIR}/keys/identity.pub" "${tmp}/a.pub"
scp_base "${PI_USER}@${VPN_B_HOST}:${REMOTE_PROJECT_DIR}/keys/identity.pub" "${tmp}/b.pub"
scp_base "${tmp}/a.pub" "${PI_USER}@${VPN_B_HOST}:${REMOTE_PROJECT_DIR}/keys/peer_identity.pub"
scp_base "${tmp}/b.pub" "${PI_USER}@${VPN_A_HOST}:${REMOTE_PROJECT_DIR}/keys/peer_identity.pub"

pi_ssh "${VPN_A_HOST}" "chmod 0600 ${REMOTE_PROJECT_DIR}/keys/identity.key && chmod 0644 ${REMOTE_PROJECT_DIR}/keys/identity.pub ${REMOTE_PROJECT_DIR}/keys/peer_identity.pub"
pi_ssh "${VPN_B_HOST}" "chmod 0600 ${REMOTE_PROJECT_DIR}/keys/identity.key && chmod 0644 ${REMOTE_PROJECT_DIR}/keys/identity.pub ${REMOTE_PROJECT_DIR}/keys/peer_identity.pub"

phase "fingerprints"
echo "A identity : $(fp_of "${VPN_A_HOST}" keys/identity.pub)"
echo "B identity : $(fp_of "${VPN_B_HOST}" keys/identity.pub)"
echo "A peer pin : $(fp_of "${VPN_A_HOST}" keys/peer_identity.pub)"
echo "B peer pin : $(fp_of "${VPN_B_HOST}" keys/peer_identity.pub)"

a_id="$(fp_of "${VPN_A_HOST}" keys/identity.pub)"
b_id="$(fp_of "${VPN_B_HOST}" keys/identity.pub)"
a_peer="$(fp_of "${VPN_A_HOST}" keys/peer_identity.pub)"
b_peer="$(fp_of "${VPN_B_HOST}" keys/peer_identity.pub)"
[[ "${a_id}" == "${b_peer}" ]] || die "B's peer pin does not match A's identity"
[[ "${b_id}" == "${a_peer}" ]] || die "A's peer pin does not match B's identity"

echo
echo "Pinned public keys match. Private identity keys never left their Pi."
