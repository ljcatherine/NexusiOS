#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

repo="${NEXUS_GITHUB_REPO:-ljcatherine/NexusiOS}"
project_version="$(sed -n 's/^    MARKETING_VERSION: *//p' project.yml | head -n 1)"
if [[ ! "$project_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid MARKETING_VERSION in project.yml: $project_version" >&2
  exit 1
fi

command -v gh >/dev/null || { echo "GitHub CLI is required to publish the release." >&2; exit 1; }
command -v nix >/dev/null || { echo "Nix is required for the xtool build environment." >&2; exit 1; }
gh auth status --hostname github.com >/dev/null || {
  echo "Sign in with GitHub CLI before creating a release; no credentials are read or saved by this script." >&2
  exit 1
}

branch="$(git branch --show-current)"
if [[ "$branch" != "main" ]]; then
  echo "Publish releases from the main branch; current branch is '$branch'." >&2
  exit 1
fi
head_commit="$(git rev-parse HEAD)"
if ! remote_main="$(git ls-remote --exit-code origin refs/heads/main | cut -f 1)" ||
   [[ "$remote_main" != "$head_commit" ]]; then
  echo "Push the current main commit to origin before building and publishing a release." >&2
  exit 1
fi

build_inputs=(App Sources Package.swift Package.resolved project.yml xtool.yml Config/xtool-Info.plist Vendor)
if [[ -n "$(git status --porcelain -- "${build_inputs[@]}")" ]]; then
  echo "Commit or discard changes to app/build inputs before publishing, so the release commit matches the IPA." >&2
  exit 1
fi

release_json="$(gh release list --repo "$repo" --limit 1000 --json tagName)"
# Build numbers keep increasing across the earlier private repository's releases;
# CURRENT_PROJECT_VERSION in project.yml is the floor.
minimum_build="$(sed -n 's/^    CURRENT_PROJECT_VERSION: *//p' project.yml | head -n 1)"
build_number="$(printf '%s' "$release_json" | python3 scripts/next_release_build_number.py --minimum-build "${minimum_build:-1}")"
version_args=(--project-version "$project_version")
if [[ "${NEXUS_ALLOW_VERSION_LINE_CHANGE:-0}" == "1" ]]; then
  version_args+=(--allow-version-line-change)
fi
version="$(printf '%s' "$release_json" | python3 scripts/next_release_version.py "${version_args[@]}")"
tag="nexus-v${version}-build.${build_number}"
output_dir="build/local-release"
ipa_name="Nexus-v${version}-build.${build_number}-unsigned.ipa"
ipa_path="$output_dir/$ipa_name"
metadata_name="Nexus-v${version}-build.${build_number}-metadata.json"
metadata_path="$output_dir/$metadata_name"

if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  echo "Release already exists: $tag" >&2
  exit 1
fi
if [[ -e "$ipa_path" ]]; then
  echo "Refusing to overwrite existing local artifact: $ipa_path" >&2
  exit 1
fi

commit="$(git rev-parse HEAD)"
echo "Building unsigned Nexus ${version} (${build_number}) locally with xtool."
APP_MARKETING_VERSION="$version" APP_BUILD_NUMBER="$build_number" \
  ./scripts/xtool-build.sh --release --ipa

mkdir -p "$output_dir"
cp -- xtool/Nexus.ipa "$ipa_path"
NEXUS_ALLOWED_PRIVATE_ADDRESSES="$(python3 scripts/deployment-allowed-addresses.py "${NEXUS_DEPLOYMENT_PLIST:-local/deployment.plist}")" \
APP_MARKETING_VERSION="$version" APP_BUILD_NUMBER="$build_number" \
  python3 scripts/validate_unsigned_ipa.py "$ipa_path"
python3 scripts/validate_ssh_linkage.py "$ipa_path"

(
  cd "$output_dir"
  sha256sum "$ipa_name" > "$ipa_name.sha256"
)
sha256="$(sha256sum "$ipa_path" | cut -d ' ' -f 1)"
python3 - "$metadata_path" "$commit" "$version" "$build_number" "$tag" "$sha256" <<'PY'
import json
import sys
from pathlib import Path

metadata = {
    "commit": sys.argv[2],
    "bundle": "com.ljcatherine.Nexus",
    "version": sys.argv[3],
    "build": sys.argv[4],
    "release_tag": sys.argv[5],
    "signed": False,
    "build_tool": "xtool",
    "sha256": sys.argv[6],
}
Path(sys.argv[1]).write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
PY

cat > "$output_dir/release-notes.md" <<EOF
Unsigned iPhoneOS build for external signing.

Version: ${version}
Build: ${build_number}
Bundle ID: com.ljcatherine.Nexus
Source commit: ${commit}
Builder: local xtool
SHA-256: ${sha256}

This IPA is unsigned and cannot be installed until signed externally with a matching provisioning profile.
EOF

gh release create "$tag" \
  "$ipa_path" \
  "$ipa_path.sha256" \
  --repo "$repo" \
  --title "Nexus ${version} (${build_number}) — unsigned" \
  --notes-file "$output_dir/release-notes.md" \
  --target "$commit"

# Upload uniquely named release provenance once. Reusing a shared asset name
# with --clobber can leave GitHub's public download URL serving cached bytes.
gh release upload "$tag" "$metadata_path" --repo "$repo"
asset_id="$(gh api "repos/$repo/releases/tags/$tag" --jq ".assets[] | select(.name == \"$metadata_name\") | .id")"
if [[ ! "$asset_id" =~ ^[0-9]+$ ]] || \
   ! cmp -s "$metadata_path" <(gh api -H 'Accept: application/octet-stream' "repos/$repo/releases/assets/$asset_id"); then
  echo "Published metadata did not match the locally generated release provenance." >&2
  exit 1
fi

echo "Published https://github.com/${repo}/releases/tag/${tag}"
echo "Local artifact: ${ipa_path}"
