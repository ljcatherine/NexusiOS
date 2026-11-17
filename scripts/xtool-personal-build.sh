#!/usr/bin/env bash
# Personal dev build: an IPA preconfigured for the owner's own Nexus network
# (Cloudflare gateway, Access sign-in, relay devices, default AI endpoint).
#
# The deployment values live OUTSIDE the repository, in an owner-only file
# (default: ~/.config/nexus/personal-deployment.plist), so they can never be
# committed, and so scripts/xtool-release.sh (which reads local/deployment.plist)
# can never pick them up. The IPA is written to the ignored build/personal/ folder.
# This script never uploads anything. Never attach its IPA to a GitHub release.
#
# Usage: ./scripts/xtool-personal-build.sh [--debug]
# Version/build default to project.yml; to install over a newer release, set e.g.
#   APP_MARKETING_VERSION=1.0.1 APP_BUILD_NUMBER=149 ./scripts/xtool-personal-build.sh
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

configuration=release
while (($#)); do
  case "$1" in
    --debug) configuration=debug ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

values="${NEXUS_PERSONAL_DEPLOYMENT_PLIST:-$HOME/.config/nexus/personal-deployment.plist}"
values="$(realpath -m -- "$values")"

case "$values" in
  "$repo_root"/*)
    echo "Keep personal deployment values outside the repository: $values" >&2
    exit 1 ;;
esac

if [[ ! -f "$values" ]]; then
  mkdir -p -- "$(dirname -- "$values")"
  install -m 600 Config/deployment.example.plist "$values"
  echo "Created $values from the example template." >&2
  echo "Replace every example value, then run this script again." >&2
  exit 1
fi
chmod 600 -- "$values"

# Refuse example placeholders and unknown keys; require the full gateway trio.
python3 -I - "$values" <<'PY'
import plistlib, sys
path = sys.argv[1]
with open(path, "rb") as f:
    v = plistlib.load(f)
allowed = {"NexusGatewayHost", "NexusAccessIssuer", "NexusAccessClientID",
           "NexusDefaultAIEndpoint", "NexusRelayDevices"}
unknown = sorted(set(v) - allowed)
if unknown:
    sys.exit(f"Unsupported keys in {path}: {', '.join(unknown)}")
missing = [k for k in ("NexusGatewayHost", "NexusAccessIssuer", "NexusAccessClientID") if not v.get(k)]
if missing:
    sys.exit(f"{path} is missing {', '.join(missing)}")
text = repr(v)
for marker in ("example.workers.dev", "your-team", "00000000-0000-0000-0000-000000000000", "192.0.2."):
    if marker in text:
        sys.exit(f"{path} still contains the example value {marker!r}")
print(f"Using personal deployment values for {v['NexusGatewayHost']} "
      f"({len(v.get('NexusRelayDevices', []))} relay devices).")
PY

args=(--"$configuration")
[[ "$configuration" == release ]] && args+=(--ipa)
NEXUS_DEPLOYMENT_PLIST="$values" ./scripts/xtool-build.sh "${args[@]}"

# Move the configured product out of xtool/ so a later public build or release
# never finds a personalised Nexus.app/Nexus.ipa lying around.
out_dir="build/personal"
mkdir -p "$out_dir"
chmod 700 "$out_dir"
commit="$(git rev-parse --short HEAD)"
stamp="$(date +%Y%m%d-%H%M%S)"
if [[ "$configuration" == release ]]; then
  product="$out_dir/Nexus-personal-$commit-$stamp.ipa"
  mv -- xtool/Nexus.ipa "$product"
  rm -rf -- xtool/Nexus.app
  info_cmd=(unzip -p "$product" 'Payload/Nexus.app/Info.plist')
else
  product="$out_dir/Nexus-personal-$commit-$stamp.app"
  mv -- xtool/Nexus.app "$product"
  info_cmd=(cat "$product/Info.plist")
fi
chmod -R go-rwx -- "$product"

# Confirm the product really carries the personal values and the fixed bundle ID.
"${info_cmd[@]}" | python3 -I -c '
import plistlib, sys
info = plistlib.loads(sys.stdin.buffer.read())
values = plistlib.load(open(sys.argv[1], "rb"))
assert info.get("CFBundleIdentifier") == "com.ljcatherine.Nexus", "bundle ID changed"
for key, value in values.items():
    assert info.get(key) == value, f"{key} missing from the built Info.plist"
print("Verified personal values in Info.plist:", ", ".join(sorted(values)))
' "$values"

git check-ignore -q -- "$product" || { echo "Refusing: $product is not ignored by Git." >&2; exit 1; }
echo "Personal build: $product"
echo "Private to you: do not upload or attach it to a GitHub release."
