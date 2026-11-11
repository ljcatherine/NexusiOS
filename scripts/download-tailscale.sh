#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
payload_dir="$repo_root/payloads"
destination="$payload_dir/Tailscale.ipa"
bundled_ipatool="$repo_root/build/tools/ipatool-2.7.0/ipatool-2.7.0-linux-amd64"

if [[ "${1:-}" == "--help" ]]; then
  echo "Download the official Tailscale iPhone IPA into the ignored payloads/ folder."
  echo "Usage: $0 [--help]"
  exit 0
fi
if [[ $# -gt 0 ]]; then
  echo "Unknown argument: $1" >&2
  exit 2
fi

mkdir -p "$payload_dir"
chmod 700 "$payload_dir"

if ! git -C "$repo_root" check-ignore -q payloads/; then
  echo "Refusing to save the App Store package: payloads/ is not ignored by Git." >&2
  exit 1
fi

if [[ -e "$destination" ]]; then
  echo "Refusing to overwrite existing file: $destination" >&2
  exit 1
fi

staging_dir="$(mktemp -d "$payload_dir/.tailscale-download.XXXXXXXX")"
staging_ipa="$staging_dir/Tailscale.ipa"
cleanup_staging() {
  python3 - "$staging_dir" <<'PY'
import shutil
import sys
shutil.rmtree(sys.argv[1], ignore_errors=True)
PY
}
trap cleanup_staging EXIT

if command -v ipatool >/dev/null 2>&1; then
  ipatool_bin="$(command -v ipatool)"
elif [[ -x "$bundled_ipatool" ]]; then
  ipatool_bin="$bundled_ipatool"
else
  bash "$repo_root/scripts/setup-ipatool.sh"
  ipatool_bin="$bundled_ipatool"
fi

# ipatool keeps its local session and cookie state under ~/.ipatool (or the
# first absolute XDG state/data directory). Do not proceed through an existing
# directory that exposes this state to group or other users.
ipatool_state_dir="${HOME:?HOME must be set}/.ipatool"
if [[ ! -e "$ipatool_state_dir" ]]; then
  for xdg_base in "${XDG_STATE_HOME:-}" "${XDG_DATA_HOME:-}"; do
    if [[ "$xdg_base" == /* ]]; then
      ipatool_state_dir="$xdg_base/ipatool"
      break
    fi
  done
fi
if [[ -e "$ipatool_state_dir" ]]; then
  if [[ ! -d "$ipatool_state_dir" ]]; then
    echo "ipatool's local state path is not a directory; refusing to continue." >&2
    exit 1
  fi
  state_mode="$(stat -c '%a' "$ipatool_state_dir")"
  if [[ ! "$state_mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$state_mode & 077) != 0 )); then
    echo "ipatool's existing local state folder is accessible to other users. Set its permissions to 700 before continuing." >&2
    exit 1
  fi
fi

if ! "$ipatool_bin" auth info >/dev/null; then
  echo "Sign in to your Apple Account in this terminal. The password prompt is masked."
  # Keep stderr attached: ipatool reads Apple ID, 2FA, and local keychain
  # passphrase prompts there. Suppress stdout, which can contain account data.
  "$ipatool_bin" auth login >/dev/null
fi

echo "Requesting the official Tailscale iPhone app from the App Store."
"$ipatool_bin" download \
  --app-id 1470499037 \
  --platform iphone \
  --purchase \
  --output "$staging_ipa"

if [[ ! -s "$staging_ipa" ]]; then
  echo "ipatool reported success but did not produce a non-empty IPA." >&2
  exit 1
fi

chmod 600 "$staging_ipa"
python3 "$repo_root/scripts/validate_tailscale_ipa.py" "$staging_ipa"

mv -- "$staging_ipa" "$destination"
echo "Saved privately to: $destination"
sha256sum "$destination"
echo "This App Store package may be FairPlay-protected and may not be installable with an external signing tool."
