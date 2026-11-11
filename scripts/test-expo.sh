#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_dir="$repo_root/prototypes/expo-nexus"

for required in node npm; do
  if ! command -v "$required" >/dev/null 2>&1; then
    printf 'Missing %s. Enter the project development shell with `nix develop` or install Node.js 24 and npm.\n' "$required" >&2
    exit 1
  fi
done

if ! node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit((major === 22 && minor >= 13) || (major === 24 && minor >= 3) || major >= 26 ? 0 : 1)'; then
  printf 'Expo prototype checks require Node.js 22.13+, 24.3+, or 26+; found %s.\n' "$(node --version)" >&2
  exit 1
fi

cd "$project_dir"
npm ci
npm run test:security
npx tsc --noEmit
npx expo export --platform web
npx expo-doctor
