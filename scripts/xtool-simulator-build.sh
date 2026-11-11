#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname -- "$script_dir")"

if [[ "${NEXUS_SWIFT_FHS_ACTIVE:-}" != 1 ]]; then
  command -v nix >/dev/null || { echo "Nix is required for the xtool simulator build." >&2; exit 1; }
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
    exec ./scripts/xtool-simulator-build.sh "$@"
  ' nexus-swift-fhs "$repo_root" "$@"
fi

cd "$repo_root"
architecture=arm64
while (($#)); do
  case "$1" in
    --architecture)
      (($# >= 2)) || { echo "--architecture requires arm64 or x86_64." >&2; exit 2; }
      architecture="$2"
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--architecture arm64|x86_64]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$architecture" == arm64 || "$architecture" == x86_64 ]] || {
  echo "Unsupported simulator architecture '$architecture'; use arm64 or x86_64." >&2
  exit 2
}

command -v swift >/dev/null || { echo "Swift 6.4 is missing. Enter nix develop." >&2; exit 1; }
command -v xtool >/dev/null || { echo "xtool is missing. Run scripts/setup-xtool.sh." >&2; exit 1; }
command -v llvm-objdump >/dev/null || { echo "llvm-objdump is required to validate the simulator binary." >&2; exit 1; }
swift --version | head -n 1 | rg -q 'Swift version 6\.4([. ]|$)' || {
  echo "xtool 1.24 requires Swift 6.4; current toolchain:" >&2; swift --version >&2; exit 1;
}
swift sdk list | rg -q '(^|[[:space:]])darwin([[:space:]]|$)' || {
  echo "Apple's Darwin/iOS SDK is missing. Follow docs/BUILDING.md." >&2; exit 1;
}
[[ "$(sed -n 's/^bundleID: *//p' xtool.yml)" == "com.ljcatherine.Nexus" ]] || {
  echo "xtool.yml bundle ID must remain com.ljcatherine.Nexus." >&2; exit 1;
}

app_version="$(sed -n 's/^    MARKETING_VERSION: *//p' project.yml | head -n 1)"
app_build="${APP_BUILD_NUMBER:-$(sed -n 's/^    CURRENT_PROJECT_VERSION: *//p' project.yml | head -n 1)}"
[[ "$app_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$app_build" =~ ^[0-9]+$ ]] || {
  echo "project.yml must define numeric app version and build values." >&2; exit 1;
}

swift package resolve

metadata_file="$repo_root/Config/xtool-Info.plist"
metadata_backup="$(mktemp "${TMPDIR:-/tmp}/nexus-xtool-simulator-info.XXXXXX")"
cp -p -- "$metadata_file" "$metadata_backup"
restore_metadata() {
  cp -- "$metadata_backup" "$metadata_file"
  rm -f -- "$metadata_backup"
}
trap restore_metadata EXIT
python3 - "$metadata_file" "$app_version" "$app_build" <<'PY'
import plistlib
import sys
from pathlib import Path

path = Path(sys.argv[1])
with path.open("rb") as source:
    info = plistlib.load(source)
info["CFBundleShortVersionString"] = sys.argv[2]
info["CFBundleVersion"] = sys.argv[3]
with path.open("wb") as target:
    plistlib.dump(info, target, sort_keys=False)
PY

echo "Building Nexus demo for $architecture iOS Simulator with xtool; this does not require macOS or a connected phone."
NEXUS_DEMO_MODE=1 xtool dev build --configuration debug --triple "$architecture-apple-ios-simulator"

app="$repo_root/xtool/Nexus.app"
executable_name="$(python3 - "$app/Info.plist" "$app_version" "$app_build" <<'PY'
import plistlib
import sys
from pathlib import Path

with Path(sys.argv[1]).open("rb") as source:
    info = plistlib.load(source)
expected = {
    "CFBundleIdentifier": "com.ljcatherine.Nexus",
    "CFBundleShortVersionString": sys.argv[2],
    "CFBundleVersion": sys.argv[3],
    "CFBundleSupportedPlatforms": ["iPhoneSimulator"],
}
for key, value in expected.items():
    if info.get(key) != value:
        raise SystemExit(f"Simulator app metadata mismatch for {key}: expected {value!r}, got {info.get(key)!r}.")
print(info["CFBundleExecutable"])
PY
)"
executable="$app/$executable_name"
[[ -f "$executable" ]] || { echo "Simulator executable is missing." >&2; exit 1; }
[[ -f "$app/PrivacyInfo.xcprivacy" ]] || {
  echo "App privacy manifest is missing from the simulator app bundle root." >&2; exit 1;
}
python3 scripts/validate_privacy_manifest.py "$app/PrivacyInfo.xcprivacy"
macho_metadata="$(llvm-objdump --macho --private-headers "$executable")"
if [[ "$architecture" == arm64 ]]; then
  expected_arch='ARM64'
else
  expected_arch='X86_64|X86-64'
fi
rg -q "MH_MAGIC_64[[:space:]]+($expected_arch)[[:space:]].*EXECUTE" <<<"$macho_metadata" || {
  echo "Expected a $architecture Mach-O executable." >&2; exit 1;
}
rg -q 'platform iossimulator' <<<"$macho_metadata" || {
  echo "Mach-O build metadata does not identify the iOS Simulator platform." >&2; exit 1;
}
python3 scripts/validate_demo_binary.py "$executable"

output_dir="$repo_root/build/appetize"
mkdir -p "$output_dir"
if [[ "$architecture" == arm64 ]]; then
  artifact_name='Nexus-simulator'
  metadata_path="$output_dir/build-metadata.json"
else
  artifact_name="Nexus-simulator-$architecture"
  metadata_path="$output_dir/$artifact_name-build-metadata.json"
fi
rm -f "$output_dir/$artifact_name.zip" "$output_dir/$artifact_name.zip.sha256" "$metadata_path"
(
  cd "$repo_root/xtool"
  zip -qr "$output_dir/$artifact_name.zip" Nexus.app
)
unzip -tq "$output_dir/$artifact_name.zip"
(
  cd "$output_dir"
  sha256sum "$artifact_name.zip" > "$artifact_name.zip.sha256"
)
APP_VERSION="$app_version" APP_BUILD="$app_build" APP_SOURCE_COMMIT="$(git rev-parse HEAD)" \
APP_ARCHITECTURE="$architecture" python3 - "$metadata_path" <<'PY'
import json
import os
import sys

with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump({
        "version": os.environ["APP_VERSION"],
        "build": os.environ["APP_BUILD"],
        "bundle_id": "com.ljcatherine.Nexus",
        "source_commit": os.environ["APP_SOURCE_COMMIT"],
        "platform": "iOS Simulator",
        "architecture": os.environ["APP_ARCHITECTURE"],
        "simulator_demo": True,
        "signed": False,
    }, output, indent=2)
    output.write("\n")
PY

echo "Validated demo-only iOS Simulator ZIP: $output_dir/$artifact_name.zip"
