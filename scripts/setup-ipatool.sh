#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tool_dir="$repo_root/build/tools/ipatool-2.7.0"
archive="$tool_dir/ipatool-2.7.0-linux-amd64.tar.gz"
binary="$tool_dir/ipatool-2.7.0-linux-amd64"
archive_url="https://github.com/majd/ipatool/releases/download/v2.7.0/ipatool-2.7.0-linux-amd64.tar.gz"
expected_sha256="68372de9743d468296f2dba5b413a3e7df56ad0c85b8d0f4f0f6c9b8b53a54e8"

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "This pinned setup supports Linux x86_64 only." >&2
  exit 1
fi

if [[ -x "$binary" ]]; then
  if [[ "$("$binary" --version)" == "ipatool version 2.7.0" ]]; then
    echo "ipatool 2.7.0 is already installed at $binary"
    exit 0
  fi
  echo "Refusing to replace an existing ipatool binary: $binary" >&2
  exit 1
fi

mkdir -p "$tool_dir"
if [[ -e "$archive" ]]; then
  actual_sha256="$(sha256sum "$archive" | cut -d ' ' -f 1)"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "Refusing to use an archive with an unexpected checksum: $archive" >&2
    exit 1
  fi
else
  command -v curl >/dev/null || { echo "curl is required to download ipatool." >&2; exit 1; }
  temporary_archive="$tool_dir/.ipatool-download-$$.tar.gz"
  curl --fail --location --silent --show-error "$archive_url" --output "$temporary_archive"
  actual_sha256="$(sha256sum "$temporary_archive" | cut -d ' ' -f 1)"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "Downloaded ipatool archive checksum did not match the pinned release." >&2
    python3 - "$temporary_archive" <<'PY'
import os, sys
os.unlink(sys.argv[1])
PY
    exit 1
  fi
  mv -- "$temporary_archive" "$archive"
fi

archive_entries="$(tar -tzf "$archive")"
if [[ "$archive_entries" != "bin/ipatool-2.7.0-linux-amd64" ]]; then
  echo "Unexpected paths in the ipatool release archive." >&2
  exit 1
fi

temporary_dir="$(mktemp -d "$tool_dir/.extract-XXXXXXXX")"
tar --no-same-owner -xzf "$archive" --strip-components=1 -C "$temporary_dir"
extracted_binary="$temporary_dir/ipatool-2.7.0-linux-amd64"
chmod 700 "$extracted_binary"
if [[ "$("$extracted_binary" --version)" != "ipatool version 2.7.0" ]]; then
  echo "The extracted executable did not report the pinned ipatool version." >&2
  exit 1
fi
if [[ -e "$binary" ]]; then
  echo "Refusing to overwrite an existing path: $binary" >&2
  exit 1
fi
mv -- "$extracted_binary" "$binary"
python3 - "$temporary_dir" <<'PY'
import shutil, sys
shutil.rmtree(sys.argv[1])
PY
chmod 700 "$tool_dir"
echo "Installed verified ipatool 2.7.0 at $binary"
