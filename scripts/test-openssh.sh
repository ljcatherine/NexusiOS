#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" == Linux ]] && command -v nixos-version >/dev/null && [[ "${NEXUS_SWIFT_FIXTURE_CONTAINER:-0}" != 1 ]]; then
  command -v docker >/dev/null || {
    echo "Docker is required to run the Linux Swift/OpenSSH fixture on NixOS; install/start Docker or run this script in swift:6.4.1-noble." >&2
    exit 1
  }
  [[ -S /var/run/docker.sock ]] || {
    echo "The Docker daemon socket is unavailable. Start Docker, then retry the OpenSSH fixture." >&2
    exit 1
  }
  docker run --rm --network host \
    --volume "$repo_root:/workspace" --volume /tmp:/tmp \
    --volume /var/run/docker.sock:/var/run/docker.sock --workdir /workspace \
    swift:6.4.1-noble bash -lc \
    'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends docker.io python3 ripgrep >/dev/null && git config --global --add safe.directory "*" && NEXUS_LINUX_PACKAGE_PATH=/workspace/build/linux-test-package NEXUS_SWIFT_FIXTURE_CONTAINER=1 bash scripts/test-openssh.sh'
  exit $?
fi
if [[ "$(uname -s)" == "Linux" ]]; then
  # shellcheck source=scripts/prepare-linux-swift-tests.sh
  source "$(dirname "$0")/prepare-linux-swift-tests.sh"
else
  swift package resolve
fi
FIXTURE_DIR=$(mktemp -d /tmp/nexus-openssh.XXXXXX)
export FIXTURE_DIR
sshd_bin="$(command -v sshd || true)"
fixture_container=""
cleanup() {
  if [[ -n "$fixture_container" ]]; then docker rm -f "$fixture_container" >/dev/null 2>&1 || true
  elif [[ -f "$FIXTURE_DIR/sshd.pid" ]]; then kill "$(cat "$FIXTURE_DIR/sshd.pid")" 2>/dev/null || true; fi
  # The optional retained fixture is generated only for diagnosis; it contains disposable keys.
  if [[ "${NEXUS_KEEP_FIXTURE:-0}" == 1 ]]; then
    printf 'Retained disposable SSH fixture: %s\n' "$FIXTURE_DIR"
  else
    rm -rf "$FIXTURE_DIR"
  fi
}
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N '' -f "$FIXTURE_DIR/host"
ssh-keygen -q -t ed25519 -N '' -f "$FIXTURE_DIR/client"
ssh-keygen -q -t ed25519 -N '' -f "$FIXTURE_DIR/rejected-client"
export NEXUS_TEST_PRIVATE_KEY="$FIXTURE_DIR/client"
export NEXUS_TEST_REJECTED_PRIVATE_KEY="$FIXTURE_DIR/rejected-client"
export NEXUS_TEST_USER
if [[ "$(uname -s)" == Linux ]]; then NEXUS_TEST_USER=root; else NEXUS_TEST_USER=$(id -un); fi
export NEXUS_TEST_HOST_FINGERPRINT
NEXUS_TEST_HOST_FINGERPRINT=$(ssh-keygen -lf "$FIXTURE_DIR/host.pub" -E sha256 | awk '{print $2}')
# Runtime fixture configuration, generated without changing the system SSH service or authorized_keys.
python3 scripts/prepare_ssh_fixture.py
if [[ "$(uname -s)" == "Linux" ]]; then
  command -v docker >/dev/null || { echo "Docker is required to run an isolated root-capable OpenSSH PTY fixture on Linux." >&2; exit 1; }
  fixture_container="nexus-openssh-$$"
  docker run --detach --name "$fixture_container" --network host \
    --volume "$FIXTURE_DIR:$FIXTURE_DIR" alpine:3.20 sh -c \
    "apk add --no-cache openssh >/dev/null && mkdir -p /run/sshd && exec /usr/sbin/sshd -D -e -f '$FIXTURE_DIR/sshd_config'" >/dev/null
  for _ in {1..30}; do
    if docker logs "$fixture_container" 2>&1 | rg -q 'Server listening'; then break; fi
    sleep 1
  done
  if ! docker logs "$fixture_container" 2>&1 | rg -q 'Server listening'; then
    docker logs "$fixture_container" >&2
    exit 1
  fi
  swift test --package-path "$NEXUS_LINUX_PACKAGE_PATH" --filter OpenSSHIntegrationTests
else
  [[ -n "$sshd_bin" ]] || { echo "OpenSSH server is required for the disposable SSH integration fixture." >&2; exit 1; }
  "$sshd_bin" -t -f "$FIXTURE_DIR/sshd_config"
  "$sshd_bin" -f "$FIXTURE_DIR/sshd_config" -E "$FIXTURE_DIR/sshd.log"
  swift test --filter OpenSSHIntegrationTests
  # Exercise OpenSSH's usual bcrypt work factor and a higher one. Citadel previously
  # rejected rounds below 32, which made ordinary ssh-keygen keys look like bad passphrases.
  for rounds in 16 100; do
    old_passphrase=''
    if [[ "$rounds" == 100 ]]; then old_passphrase='nexus-disposable-test-passphrase'; fi
    ssh-keygen -q -p -a "$rounds" -P "$old_passphrase" -N 'nexus-disposable-test-passphrase' -f "$FIXTURE_DIR/client" >/dev/null
    export NEXUS_TEST_KEY_PASSPHRASE='nexus-disposable-test-passphrase'
    echo "Running encrypted OpenSSH key integration with bcrypt rounds=$rounds"
    swift test --filter OpenSSHIntegrationTests
  done
  exit
fi
# Exercise OpenSSH's usual bcrypt work factor and a higher one. Citadel previously
# rejected rounds below 32, which made ordinary ssh-keygen keys look like bad passphrases.
for rounds in 16 100; do
  old_passphrase=''
  if [[ "$rounds" == 100 ]]; then old_passphrase='nexus-disposable-test-passphrase'; fi
  ssh-keygen -q -p -a "$rounds" -P "$old_passphrase" -N 'nexus-disposable-test-passphrase' -f "$FIXTURE_DIR/client" >/dev/null
  export NEXUS_TEST_KEY_PASSPHRASE='nexus-disposable-test-passphrase'
  echo "Running encrypted OpenSSH key integration with bcrypt rounds=$rounds"
  swift test --package-path "$NEXUS_LINUX_PACKAGE_PATH" --filter OpenSSHIntegrationTests
done
