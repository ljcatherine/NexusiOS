#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly swiftly_version='1.1.2'
toolchain_version="$(tr -d '[:space:]' < .swift-version)"
readonly toolchain_version
readonly swiftly_root="${SWIFTLY_HOME_DIR:-$HOME/.local/share/swiftly}"
readonly swiftly_bin_dir="${SWIFTLY_BIN_DIR:-$swiftly_root/bin}"
swiftly_bin="$swiftly_bin_dir/swiftly"

if [[ ! "$toolchain_version" =~ ^6\.4\.[0-9]+$ ]]; then
  echo "Expected a pinned Swift 6.4.x version in .swift-version; found '$toolchain_version'." >&2
  exit 1
fi

if [[ ! -x "$swiftly_bin" ]]; then
  for tool in curl tar gpg; do
    command -v "$tool" >/dev/null || { echo "Missing $tool; run this script inside nix develop." >&2; exit 1; }
  done
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' EXIT
  archive="swiftly-${swiftly_version}-x86_64.tar.gz"
  base_url='https://download.swift.org/swiftly/linux'
  curl --compressed -fsSL "$base_url/$archive" -o "$temp_dir/$archive"
  curl --compressed -fsSL "$base_url/$archive.sig" -o "$temp_dir/$archive.sig"
  mkdir -m 700 "$temp_dir/gnupg"
  curl --compressed -fsSL https://www.swift.org/keys/all-keys.asc -o "$temp_dir/swift-keys.asc"
  gpg --homedir "$temp_dir/gnupg" --batch --import "$temp_dir/swift-keys.asc" >/dev/null
  gpg --homedir "$temp_dir/gnupg" --batch --verify "$temp_dir/$archive.sig" "$temp_dir/$archive"
  tar -xzf "$temp_dir/$archive" -C "$temp_dir"
  [[ -x "$temp_dir/swiftly" ]] || { echo 'Verified archive did not contain the swiftly executable.' >&2; exit 1; }
  mkdir -p "$swiftly_bin_dir"
  "$temp_dir/swiftly" init --platform ubuntu24.04 --no-modify-profile --skip-install --assume-yes --quiet-shell-followup
fi

"$swiftly_bin" install "$toolchain_version" --use
echo "Swift $toolchain_version installed in $swiftly_root. Re-enter nix develop, then verify with swift --version."
