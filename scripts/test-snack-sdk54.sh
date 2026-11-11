#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prototype_dir="$repo_root/prototypes/expo-nexus"
manifest_dir="$prototype_dir/snack-sdk54"
work_dir="$repo_root/build/snack/sdk54-check"

command -v node >/dev/null || { echo "Node.js is required; enter nix develop." >&2; exit 1; }
command -v npm >/dev/null || { echo "npm is required; enter nix develop." >&2; exit 1; }
[[ -s "$manifest_dir/package-lock.json" ]] || {
  echo "SDK 54 lockfile is missing: $manifest_dir/package-lock.json" >&2
  exit 1
}

"$repo_root/scripts/export-snack.sh"
mkdir -p "$work_dir"
unzip -oq "$repo_root/build/snack/nexus-expo-snack.zip" -d "$work_dir"
cp "$manifest_dir/package.json" "$manifest_dir/package-lock.json" "$work_dir/"
mkdir -p "$work_dir/scripts"
cp "$prototype_dir/scripts/test-node-forge-security.cjs" "$work_dir/scripts/"
cat > "$work_dir/app.json" <<'EOF'
{"expo":{"name":"Nexus Snack SDK54 check","slug":"nexus-snack-sdk54-check","userInterfaceStyle":"automatic"}}
EOF
cat > "$work_dir/index.ts" <<'EOF'
import { registerRootComponent } from 'expo';
import App from './App';
registerRootComponent(App);
EOF
cat > "$work_dir/tsconfig.json" <<'EOF'
{"extends":"expo/tsconfig.base","compilerOptions":{"strict":true,"noEmit":true}}
EOF

cd "$work_dir"
npm ci --no-audit --no-fund
npm run test:security
npx expo install --check
npx tsc --noEmit
npx expo export --platform web
echo "SDK 54 source/dependency/web-export checks passed. This does not run Snack's hosted runtime or iOS Expo Go."
