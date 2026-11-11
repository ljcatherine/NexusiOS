#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prototype_dir="$repo_root/prototypes/expo-nexus"
output_dir="$repo_root/build/snack"
archive="$output_dir/nexus-expo-snack.zip"

for required in "$prototype_dir/App.tsx" "$prototype_dir/designTokens.ts" "$prototype_dir/assets/icon.png"; do
  if [[ ! -f "$required" ]]; then
    printf 'Required Snack prototype file is missing: %s\n' "$required" >&2
    exit 1
  fi
done

mkdir -p "$output_dir"
python3 - "$prototype_dir" "$archive" <<'PY'
from pathlib import Path
import sys
import zipfile

source = Path(sys.argv[1])
archive = Path(sys.argv[2])
files = (
    (source / "App.tsx", "App.tsx"),
    (source / "designTokens.ts", "designTokens.ts"),
    (source / "assets/icon.png", "assets/icon.png"),
)
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
    for path, name in files:
        bundle.write(path, name)
    bundle.writestr(
        "SNACK-SETUP.txt",
        "Nexus UI demo only. In Expo Snack select SDK 54, copy App.tsx and "
        "designTokens.ts, upload assets/icon.png, and add expo-status-bar ~3.0.9. "
        "No real endpoints, credentials, network requests, or server actions are included.\n",
    )
print(f"Snack source archive: {archive}")
PY
