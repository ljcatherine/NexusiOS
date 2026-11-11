#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
config_file="$repo_root/local/nexus-gateway.env"
if [[ ! -f "$config_file" || -L "$config_file" ]]; then
  echo "Missing private gateway config. Copy gateway/.env.example to local/nexus-gateway.env and fill in your own OIDC/upstream settings." >&2
  exit 2
fi
owner="$(stat -c '%u' -- "$config_file")"
mode="$(stat -c '%a' -- "$config_file")"
if [[ "$owner" != "$EUID" ]] || (( (8#$mode & 077) != 0 )); then
  echo "Gateway config must be owned by your user and inaccessible to group/other users (chmod 600)." >&2
  exit 2
fi
command -v go >/dev/null || { echo "Go is required; run nix develop first." >&2; exit 127; }
cd "$repo_root/gateway"
set -a
# shellcheck disable=SC1090
source "$config_file"
set +a
exec go run .
