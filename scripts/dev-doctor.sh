#!/usr/bin/env bash
set -euo pipefail
failed=0
check() { if command -v "$1" >/dev/null 2>&1; then printf 'OK   %-16s %s\n' "$1" "$("$1" --version 2>/dev/null | head -n 1 || true)"; else printf 'MISS %-16s %s\n' "$1" "$2"; failed=1; fi; }
check nix "Install Nix with flakes enabled"
check swift "Install Swift 6.4 through Swiftly"
if command -v sourcekit-lsp >/dev/null 2>&1; then
  printf 'OK   %-16s %s\n' sourcekit-lsp "$(sourcekit-lsp --help 2>&1 | head -n 1)"
else
  echo "MISS sourcekit-lsp    Install it with the Swift toolchain or the project Nix shell"
  failed=1
fi
check xtool "Run scripts/setup-xtool.sh inside nix develop"
check git "Install Git"
check gh "Authenticate GitHub CLI if you need remote operations"
check node "Install Node.js LTS for the Expo prototype"
check appimage-run "Enter nix develop"
if command -v swift >/dev/null 2>&1; then
  swift_version="$(swift --version | head -n 1)"
  printf '%s\n' "$swift_version"
  if ! rg -q 'Swift version 6\.4([. ]|$)' <<<"$swift_version"; then
    echo "WAIT xtool compiler   xtool 1.24 requires Swift 6.4; Swift 6.3.3 is currently for Linux package work."
    failed=1
  fi
  sdk_list="$(swift sdk list 2>&1 || true)"
  printf '%s\n' "$sdk_list"
  if ! rg -q '(^|[[:space:]])darwin([[:space:]]|$)' <<<"$sdk_list"; then
    echo "WAIT Apple SDK        Install the matching Darwin SDK through xtool setup."
    failed=1
  fi
fi
if [[ -f xtool.yml ]] && rg -q '^bundleID: com\.ljcatherine\.Nexus$' xtool.yml; then
  echo "OK   bundle ID        com.ljcatherine.Nexus"
else
  echo "FAIL bundle ID        xtool.yml must use com.ljcatherine.Nexus"; failed=1
fi
if ((failed)); then
  echo "Some tools still need setup; see docs/BUILDING.md." >&2
  exit 1
fi
echo "Core command checks passed. Confirm that swift sdk list includes darwin before using xtool."
