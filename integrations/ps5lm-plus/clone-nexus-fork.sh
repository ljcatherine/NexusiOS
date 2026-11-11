#!/usr/bin/env bash
# Clone pinned upstream and apply the Nexus model-control extension reproducibly.
# Does not contact, update, or reboot a PlayStation 5.
set -euo pipefail
root="$(cd -- "$(dirname -- "$0")" && pwd)"
repository="$(cd -- "$root/../.." && pwd)"
destination="${1:-$repository/build/ps5lm-nexus-fork}"
upstream='https://github.com/abhi245y/PS5LM-Plus.git'
revision='6729b4acbaf65e23b2e8bc8708b2acba524a7aa8'
if [[ -e "$destination" ]]; then
    echo "Refusing to overwrite existing folder: $destination" >&2
    exit 2
fi
mkdir -p -- "$(dirname "$destination")"
git clone --filter=blob:none --no-checkout "$upstream" "$destination"
git -C "$destination" checkout --detach "$revision"
git -C "$destination" apply --unidiff-zero --check "$root/patches/0001-nexus-control.patch"
git -C "$destination" apply --unidiff-zero "$root/patches/0001-nexus-control.patch"
git -C "$destination" apply --check "$root/patches/0003-nexusai-branding.patch"
git -C "$destination" apply "$root/patches/0003-nexusai-branding.patch"
git -C "$destination" apply --check "$root/patches/0004-nexus-model-metadata.patch"
git -C "$destination" apply "$root/patches/0004-nexus-model-metadata.patch"
git -C "$destination" apply --check "$root/patches/0005-nexus-executable-modes.patch"
git -C "$destination" apply "$root/patches/0005-nexus-executable-modes.patch"
git -C "$destination" apply --check "$root/patches/0006-nexus-provisioning-pin.patch"
git -C "$destination" apply "$root/patches/0006-nexus-provisioning-pin.patch"
cp -- "$root/native/nexus_control.cpp" "$root/native/nexus_control.hpp" "$root/native/nexus_control_test.cpp" "$destination/ps5/app/"
# The upstream build scripts apply patches in the native clone's patches/
# directory to the pinned llama.cpp submodule before compiling. Keep the
# PS5-only numeric JSON compatibility guard reproducible for new clones.
cp -- "$root/patches/0002-ps5-empty-locale-decimal.patch" "$destination/patches/nexus-ps5-empty-locale-decimal.patch"
echo "Nexus PS5LM Plus fork prepared at: $destination"
echo "Upstream revision: $revision"
echo "Run: $root/test-nexus-control.sh '$destination'"
echo "To compile for PS5, first initialize upstream submodules and install its documented PS5_Vulkan/SDK toolchain."
