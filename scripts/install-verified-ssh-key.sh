#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/install-verified-ssh-key.sh HOST USER PUBLIC_KEY EXPECTED_SHA256_FINGERPRINT

Verifies the host's Ed25519 SSH identity against a fingerprint obtained directly
from that machine, then uses ssh-copy-id. The SSH password is entered only at
the local terminal prompt. No private key is read or copied.
EOF
}

if [[ $# -ne 4 ]]; then
  usage >&2
  exit 2
fi

host=$1
username=$2
public_key=$3
expected_fingerprint=$4

if [[ ! $host =~ ^[A-Za-z0-9.-]+$ || ! $username =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]]; then
  echo "Host or username has an invalid format." >&2
  exit 2
fi
if [[ ! -r $public_key ]]; then
  echo "Readable OpenSSH .pub key file required." >&2
  exit 2
fi
IFS=' ' read -r key_type _ < "$public_key" || true
if [[ $key_type != ssh-ed25519 ]]; then
  echo "An Ed25519 OpenSSH public key is required; private-key files are not accepted." >&2
  exit 2
fi
if [[ ! $expected_fingerprint =~ ^SHA256:[A-Za-z0-9+/]+$ ]]; then
  echo "Expected fingerprint must use SHA256: format." >&2
  exit 2
fi
if ! command -v ssh-keyscan >/dev/null || ! command -v ssh-keygen >/dev/null || ! command -v ssh-copy-id >/dev/null; then
  echo "Install OpenSSH client tools (ssh-keyscan, ssh-keygen, ssh-copy-id) first." >&2
  exit 1
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
known_hosts="$tmpdir/known_hosts"

if ! ssh-keyscan -T 5 -t ed25519 "$host" >"$known_hosts" 2>/dev/null || [[ ! -s $known_hosts ]]; then
  echo "Could not retrieve an Ed25519 host key from $host." >&2
  exit 1
fi

mapfile -t fingerprints < <(ssh-keygen -lf "$known_hosts" -E sha256 | awk '{print $2}' | sort -u)
if [[ ${#fingerprints[@]} -ne 1 ]]; then
  echo "The endpoint returned multiple Ed25519 host identities; refusing to install the key." >&2
  exit 1
fi
if [[ ${fingerprints[0]} != "$expected_fingerprint" ]]; then
  echo "Host identity mismatch. Expected $expected_fingerprint; received ${fingerprints[0]}." >&2
  exit 1
fi

if ! ssh-keygen -lf "$public_key" -E sha256 >/dev/null 2>&1; then
  echo "The selected file is not a valid OpenSSH public key." >&2
  exit 2
fi

echo "Verified $host Ed25519 host identity: ${fingerprints[0]}"
echo "SSH will now prompt for the $username account password in this terminal."
ssh-copy-id -i "$public_key" \
  -o "UserKnownHostsFile=$known_hosts" \
  -o StrictHostKeyChecking=yes \
  -o HostKeyAlgorithms=ssh-ed25519 \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password,keyboard-interactive \
  "$username@$host"
