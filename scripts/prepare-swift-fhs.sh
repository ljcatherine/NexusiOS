#!/usr/bin/env bash
set -euo pipefail

if [[ "${NEXUS_SWIFT_FHS_ACTIVE:-}" != 1 ]]; then
  echo "Run this script through scripts/xtool-build.sh inside the project FHS environment." >&2
  exit 2
fi
command -v patchelf >/dev/null || { echo "patchelf is missing from the project FHS environment." >&2; exit 1; }

swift_version="$(swift --version | sed -n 's/^Swift version \([^ ]*\).*/\1/p')"
toolchain_root="$HOME/.local/share/swiftly/toolchains/$swift_version/usr"
if [[ ! -d "$toolchain_root/bin" || -z "${LD_LIBRARY_PATH:-}" ]]; then
  echo "Could not locate the Swiftly toolchain or its Nix runtime libraries." >&2
  exit 1
fi

python3 - "$toolchain_root" "$LD_LIBRARY_PATH" <<'PY'
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
library_dirs = [path for path in sys.argv[2].split(":") if path]
tools = [
    root / "bin" / "swiftc",
    root / "bin" / "swift-frontend",
    root / "bin" / "swift-package",
    root / "bin" / "swift-build",
]
changed = []
for tool in tools:
    if not tool.is_file() or tool.read_bytes()[:4] != b"\x7fELF":
        continue
    result = subprocess.run(["patchelf", "--print-rpath", str(tool)], text=True,
                            capture_output=True, check=True)
    current = result.stdout.strip().split(":") if result.stdout.strip() else []
    missing = [directory for directory in library_dirs if directory not in current]
    if missing:
        subprocess.run(["patchelf", "--set-rpath", ":".join(current + missing), str(tool)],
                       check=True)
        changed.append(tool.name)
if changed:
    print("Added project FHS runtime paths to Swift tools: " + ", ".join(changed))
PY
