#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

archive="build/appetize/Nexus-simulator.zip"
if [[ -z "${APPETIZE_API_TOKEN:-}" ]]; then
  echo "Appetize upload skipped: APPETIZE_API_TOKEN is not configured."
  exit 0
fi
if [[ -z "${APPETIZE_PUBLIC_KEY:-}" ]]; then
  echo "Appetize upload skipped: set APPETIZE_PUBLIC_KEY to an existing demo app to avoid creating duplicate entries." >&2
  exit 0
fi
[[ -f "$archive" ]] || { echo "Simulator ZIP is missing; run scripts/xtool-simulator-build.sh first." >&2; exit 1; }
[[ "$APPETIZE_PUBLIC_KEY" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "Appetize public key contains unsupported characters." >&2; exit 1; }

umask 077
response_file="$(mktemp)"
header_file="$(mktemp)"
trap 'rm -f "$response_file" "$header_file"' EXIT
source_commit="${APP_SOURCE_COMMIT:-$(git rev-parse HEAD)}"
note="Nexus simulator demo ${APP_VERSION:-unknown} (${APP_BUILD:-unknown}) · ${source_commit}"
printf 'X-API-KEY: %s\n' "$APPETIZE_API_TOKEN" > "$header_file"
unset APPETIZE_API_TOKEN
if ! http_status="$(curl --silent --show-error --output "$response_file" --write-out '%{http_code}' \
  --request POST "https://api.appetize.io/v1/apps/$APPETIZE_PUBLIC_KEY" \
  --header "@$header_file" \
  --form "file=@$archive;type=application/zip" \
  --form 'platform=ios' \
  --form "note=$note")"; then
  echo "Appetize upload request failed (HTTP ${http_status:-no response}); response body was suppressed." >&2
  exit 1
fi
if [[ ! "$http_status" =~ ^2[0-9]{2}$ ]]; then
  echo "Appetize upload request returned HTTP $http_status; response body was suppressed." >&2
  exit 1
fi

preview_url="$(python3 - "$response_file" "$APPETIZE_PUBLIC_KEY" <<'PY'
import json
import sys
from urllib.parse import urlparse

with open(sys.argv[1], encoding="utf-8") as response_file:
    response = json.load(response_file)
if response.get("publicKey") != sys.argv[2]:
    raise SystemExit("Appetize response did not match the configured app key.")
url = response.get("appURL")
parsed = urlparse(url or "")
if parsed.scheme != "https" or parsed.netloc != "appetize.io" or not parsed.path.startswith("/app/"):
    raise SystemExit("Appetize returned an unexpected preview URL; response body was suppressed.")
print(url)
PY
)" || {
  echo "Appetize upload returned an invalid response (HTTP $http_status); response body was suppressed." >&2
  exit 1
}

mkdir -p build/appetize
printf '%s\n' "$preview_url" > build/appetize/appetize-preview-url.txt
echo "Appetize demo preview updated: $preview_url"
