#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
revision="$(cat "$repo_root/integrations/hermes/revision")"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid Hermes revision' >&2; exit 1; }
mkdir -p "$repo_root/build"
context="$(mktemp -d "$repo_root/build/hermes-image.XXXXXX")"
trap 'rm -rf -- "$context"' EXIT
source_repo="${1:-$context/source}"
if [[ $# == 0 ]]; then
  git init -q "$source_repo"
  git -C "$source_repo" fetch --depth=1 https://github.com/NousResearch/hermes-agent.git "$revision"
fi
mkdir "$context/upstream"
git -C "$source_repo" archive "$revision" | tar -x -C "$context/upstream"
cp "$repo_root/integrations/hermes/worker.py" "$context/worker.py"
cp "$repo_root/integrations/hermes/Dockerfile" "$context/Dockerfile"
docker build --build-arg "HERMES_REVISION=$revision" --tag nexus-hermes:local "$context"
docker image inspect --format '{{.Id}}' nexus-hermes:local
