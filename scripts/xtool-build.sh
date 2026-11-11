#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname -- "$script_dir")"

if [[ "${NEXUS_SWIFT_FHS_ACTIVE:-}" != 1 ]]; then
  command -v nix >/dev/null || { echo "Nix is required for the Swift FHS build environment." >&2; exit 1; }
  cd "$repo_root"
  exec nix run .#swift-fhs -- -lc '
    unset NIX_CFLAGS_COMPILE NIX_LDFLAGS NIX_CC NIX_CC_WRAPPER_TARGET_HOST
    unset CC CXX CFLAGS CXXFLAGS CPPFLAGS LDFLAGS CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH
    unset LIBRARY_PATH SDKROOT
    export PATH="$HOME/.local/share/swiftly/bin:$HOME/.local/bin:/usr/bin:/bin"
    export NEXUS_SWIFT_FHS_ACTIVE=1
    cd "$1"
    shift
    ./scripts/prepare-swift-fhs.sh
    exec ./scripts/xtool-build.sh "$@"
  ' nexus-swift-fhs "$repo_root" "$@"
fi

unset NEXUS_DEMO_MODE

configuration=debug
clean=false
ipa=false
while (($#)); do
  case "$1" in
    --debug) configuration=debug ;;
    --release) configuration=release ;;
    --clean) clean=true ;;
    --ipa) ipa=true ;;
    -h|--help)
      echo "Usage: $0 [--debug|--release] [--clean] [--ipa]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

command -v swift >/dev/null || { echo "Swift 6.4 is missing. Install Swift 6.4 with Swiftly; see docs/BUILDING.md." >&2; exit 1; }
command -v xtool >/dev/null || { echo "xtool is missing. Run scripts/setup-xtool.sh from nix develop." >&2; exit 1; }
swift --version | head -n 1 | rg -q 'Swift version 6\.4([. ]|$)' || {
  echo "xtool 1.24 requires Swift 6.4. Current toolchain:" >&2; swift --version >&2; exit 1;
}
swift sdk list | rg -q '(^|[[:space:]])darwin([[:space:]]|$)' || {
  echo "Apple's Darwin/iOS SDK is not installed. Follow the Apple SDK steps in docs/BUILDING.md." >&2; exit 1;
}
[[ "$(sed -n 's/^bundleID: *//p' xtool.yml)" == "com.ljcatherine.Nexus" ]] || {
  echo "xtool.yml bundle ID must remain com.ljcatherine.Nexus" >&2; exit 1;
}
app_version="${APP_MARKETING_VERSION:-$(sed -n 's/^    MARKETING_VERSION: *//p' project.yml | head -n 1)}"
app_build="${APP_BUILD_NUMBER:-$(sed -n 's/^    CURRENT_PROJECT_VERSION: *//p' project.yml | head -n 1)}"
[[ "$app_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$app_build" =~ ^[0-9]+$ ]] || {
  echo "project.yml must define a numeric MARKETING_VERSION and CURRENT_PROJECT_VERSION." >&2; exit 1;
}
if $clean; then
  echo "Cleaning the app's SwiftPM products and xtool outputs; preserving dependency checkouts and Linux test caches."
  swift package clean
  rm -rf xtool/Nexus.app xtool/Nexus.ipa
fi
swift package resolve
metadata_file="$repo_root/Config/xtool-Info.plist"
metadata_backup="$(mktemp "${TMPDIR:-/tmp}/nexus-xtool-info.XXXXXX")"
cp -p -- "$metadata_file" "$metadata_backup"
restore_xtool_metadata() {
  cp -- "$metadata_backup" "$metadata_file"
  rm -f -- "$metadata_backup"
}
trap restore_xtool_metadata EXIT
# Optional, ignored deployment values (Worker host, Access issuer, ...); see docs/CONFIGURATION.md.
deployment_plist="${NEXUS_DEPLOYMENT_PLIST:-$repo_root/local/deployment.plist}"
python3 - "$metadata_file" "$app_version" "$app_build" "$deployment_plist" <<'PY'
import plistlib
import sys
from pathlib import Path

DEPLOYMENT_KEYS = {"NexusGatewayHost", "NexusAccessIssuer", "NexusAccessClientID",
                   "NexusDefaultAIEndpoint", "NexusRelayDevices"}
path = Path(sys.argv[1])
with path.open("rb") as source:
    info = plistlib.load(source)
info["CFBundleShortVersionString"] = sys.argv[2]
info["CFBundleVersion"] = sys.argv[3]
deployment = Path(sys.argv[4])
if deployment.is_file():
    with deployment.open("rb") as source:
        values = plistlib.load(source)
    unknown = sorted(set(values) - DEPLOYMENT_KEYS)
    if unknown:
        sys.exit(f"Unsupported deployment keys in {deployment}: {', '.join(unknown)}")
    info.update(values)
    print(f"Applied deployment configuration from {deployment.name} ({len(values)} keys).")
with path.open("wb") as target:
    plistlib.dump(info, target, sort_keys=False)
PY
echo "Building Nexus for iOS ($configuration) through xtool; no attached phone is required."
if $ipa; then
  xtool dev build --configuration "$configuration" --ipa
  NEXUS_ALLOWED_PRIVATE_ADDRESSES="$(python3 scripts/deployment-allowed-addresses.py "${NEXUS_DEPLOYMENT_PLIST:-local/deployment.plist}")" \
  APP_MARKETING_VERSION="$app_version" APP_BUILD_NUMBER="$app_build" \
  NEXUS_SOURCE_COMMIT="$(git rev-parse HEAD)" \
  NEXUS_RELEASE_TAG="nexus-v${app_version}-build.${app_build}" \
    python3 scripts/validate_unsigned_ipa.py xtool/Nexus.ipa
  python3 scripts/validate_ssh_linkage.py xtool/Nexus.ipa
else
  xtool dev build --configuration "$configuration"
  python3 - "xtool/Nexus.app/Info.plist" "$app_version" "$app_build" <<'PY'
import plistlib
import sys
from pathlib import Path

with Path(sys.argv[1]).open("rb") as source:
    info = plistlib.load(source)
expected = {
    "CFBundleIdentifier": "com.ljcatherine.Nexus",
    "CFBundleShortVersionString": sys.argv[2],
    "CFBundleVersion": sys.argv[3],
}
for key, value in expected.items():
    if info.get(key) != value:
        raise SystemExit(f"Built app metadata mismatch for {key}: expected {value!r}, got {info.get(key)!r}.")
print(f"Verified xtool app metadata: {expected['CFBundleIdentifier']} {expected['CFBundleShortVersionString']} ({expected['CFBundleVersion']}).")
PY
  python3 scripts/validate_ssh_linkage.py xtool/Nexus.app
fi
echo "xtool build finished. Inspect the build output reported above; xtool output support depends on the installed SDK/toolchain."
