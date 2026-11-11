#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux test preparation can only run on Linux." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export NEXUS_LINUX_PACKAGE_PATH="${NEXUS_LINUX_PACKAGE_PATH:-$ROOT_DIR/.build/linux-test-package}"
mkdir -p "$NEXUS_LINUX_PACKAGE_PATH"
ln -sfn "$ROOT_DIR/Sources" "$NEXUS_LINUX_PACKAGE_PATH/Sources"
ln -sfn "$ROOT_DIR/Tests" "$NEXUS_LINUX_PACKAGE_PATH/Tests"
cp "$ROOT_DIR/Package.linux-tests.swift" "$NEXUS_LINUX_PACKAGE_PATH/Package.swift"
cp "$ROOT_DIR/Package.resolved" "$NEXUS_LINUX_PACKAGE_PATH/Package.resolved"
swift package --package-path "$NEXUS_LINUX_PACKAGE_PATH" resolve
