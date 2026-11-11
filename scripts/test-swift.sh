#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v nixos-version >/dev/null && [[ "${NEXUS_SWIFT_TEST_CONTAINER:-0}" != 1 ]]; then
  command -v docker >/dev/null || {
    echo "Docker is required to run Swift 6.4 tests on NixOS; install/start Docker or run this script in swift:6.4.1-noble." >&2
    exit 1
  }
  docker run --rm --volume "$repo_root:/workspace" --workdir /workspace swift:6.4.1-noble \
    bash -lc 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3 git >/dev/null && git config --global --add safe.directory "*" && NEXUS_LINUX_PACKAGE_PATH=/workspace/build/linux-test-package NEXUS_SWIFT_TEST_CONTAINER=1 bash scripts/test-swift.sh'
  exit $?
fi
command -v swift >/dev/null || { echo "Swift is required; enter nix develop and install Swift 6.4 with Swiftly." >&2; exit 1; }
echo "Running Nexus package tests supported by the current platform."
if [[ "$(uname -s)" == "Linux" ]]; then
  # shellcheck source=scripts/prepare-linux-swift-tests.sh
  source "$(dirname "$0")/prepare-linux-swift-tests.sh"
  swift test --package-path "$NEXUS_LINUX_PACKAGE_PATH" --parallel --filter NexusCoreTests
  swift test --package-path "$NEXUS_LINUX_PACKAGE_PATH" --parallel --filter NexusSSHTests
else
  swift package resolve
  swift test --parallel
fi
