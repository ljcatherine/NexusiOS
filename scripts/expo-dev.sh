#!/usr/bin/env bash
set -euo pipefail
project="$(cd "$(dirname "$0")/../prototypes/expo-nexus" && pwd)"
command -v node >/dev/null || { echo "Node.js is required. Enter nix develop." >&2; exit 1; }
mode="web"
if [[ "${1:-}" == "--native" ]]; then
  mode="native"
  shift
elif [[ "${1:-}" == "--web" ]]; then
  shift
fi
if [[ ! -d "$project/node_modules" ]]; then
  (cd "$project" && npm ci)
fi
cd "$project"
if [[ "$mode" == "native" ]]; then
  cat >&2 <<'EOF'
The local prototype uses Expo SDK 57. The iPhone App Store build of Expo Go supports SDK 54, so it cannot open this SDK 57 project. Use the SDK 54 Snack export for Expo Go, or use a matching custom development build for SDK 57. The browser preview remains available with `./scripts/expo-dev.sh --web`.
EOF
  exec npx expo start --lan "$@"
fi
exec npx expo start --web "$@"
