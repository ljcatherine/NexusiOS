#!/usr/bin/env bash
set -euo pipefail

version="1.24.0"
expected="dbfd9d7216f077c84c171b688c4173c37c23ca76bf7fd185d1a9ae8a53dab59f"
tool_dir="${XDG_DATA_HOME:-$HOME/.local/share}/nexus/tools"
image="$tool_dir/xtool-${version}-x86_64.AppImage"
image_cache="${XDG_CACHE_HOME:-$HOME/.cache}/appimage-run/$expected"
wrapper="${XDG_BIN_HOME:-$HOME/.local/bin}/xtool"
mkdir -p "$tool_dir" "$(dirname "$wrapper")"

if [[ ! -f "$image" ]] || [[ "$(sha256sum "$image" | cut -d' ' -f1)" != "$expected" ]]; then
  temp="$image.tmp"
  trap 'rm -f "$temp"' EXIT
  curl --fail --location --silent --show-error \
    "https://github.com/xtool-org/xtool/releases/download/${version}/xtool-x86_64.AppImage" \
    --output "$temp"
  actual="$(sha256sum "$temp" | cut -d' ' -f1)"
  if [[ "$actual" != "$expected" ]]; then
    echo "xtool AppImage checksum mismatch; refusing to install." >&2
    exit 1
  fi
  chmod 755 "$temp"
  mv "$temp" "$image"
  trap - EXIT
fi

if ! command -v appimage-run >/dev/null 2>&1; then
  echo "appimage-run is required. Enter the project Nix shell with: nix develop" >&2
  exit 1
fi

cat >"$wrapper" <<EOF
#!/usr/bin/env bash
if [[ "\${NEXUS_SWIFT_FHS_ACTIVE:-}" == 1 ]]; then
  if [[ -x "$image_cache/AppRun" ]]; then
    export LD_LIBRARY_PATH="$image_cache/usr/lib:\${LD_LIBRARY_PATH:-}"
    exec "$image_cache/AppRun" "\$@"
  fi
  echo "xtool AppImage cache is missing; rerun scripts/setup-xtool.sh inside nix develop." >&2
  exit 1
fi
exec appimage-run "$image" "\$@"
EOF
chmod 755 "$wrapper"
echo "Installed verified xtool ${version} wrapper at $wrapper"
"$wrapper" --help
echo "Add $HOME/.local/bin to PATH if it is not already available."
