#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "$0")" && pwd)"
repo="$(cd -- "$root/../.." && pwd)"
fork="${1:-$repo/build/upstream/PS5LM-Plus}"
[[ -r "$fork/ps5/app/stats.hpp" ]] || { echo 'PS5LM Plus clone not found' >&2; exit 1; }
output="$(mktemp -d)"
trap 'rm -rf -- "$output"' EXIT
cc -std=c11 -O2 -Wall -Wextra -Werror -I "$fork/third_party/llama.cpp/vendor" \
  -I "$fork/third_party/llama.cpp/vendor/hash" \
  -c "$fork/third_party/llama.cpp/vendor/hash/sha256/sha256.c" -o "$output/sha256.o"
compile_controller() {
c++ -std=c++20 -O2 -pthread -Wall -Wextra -Werror "$@" \
  -I "$fork/ps5/app" -I "$fork/third_party/llama.cpp/vendor" \
  "$root/native/nexus_control.cpp" "$root/native/nexus_control_test.cpp" \
  "$fork/ps5/app/model_plan.cpp" \
  "$output/sha256.o" -Wl,--wrap=geteuid -Wl,--wrap=fstat -Wl,--wrap=read -o "$output/nexus-control-tests"
}
compile_controller
"$output/nexus-control-tests"
python3 - "$output/pin.h" <<'PY'
import hashlib, pathlib, sys
token = b'ABCDEF0123456789ABCDEF0123456789'  # public test fixture only
pathlib.Path(sys.argv[1]).write_text('#define NEXUS_CONTROL_PROVISIONING_DIGEST "sha256:' + hashlib.sha256(token).hexdigest() + '"\n')
PY
compile_controller -DNEXUS_CONTROL_TEST_PLATFORM=1 -DNEXUS_CONTROL_REQUIRE_PROVISIONING_PIN=1 -include "$output/pin.h"
"$output/nexus-control-tests"
reject_configuration() {
    if c++ -std=c++20 -fsyntax-only -I "$fork/ps5/app" -I "$fork/third_party/llama.cpp/vendor" \
        -DNEXUS_CONTROL_REQUIRE_PROVISIONING_PIN=1 "$@" "$root/native/nexus_control.cpp" \
        > "$output/rejected-build.log" 2>&1; then
        echo 'Invalid provisioning configuration unexpectedly compiled' >&2
        exit 1
    fi
}
reject_configuration -DNEXUS_CONTROL_TEST_PLATFORM=1  # missing header
printf '#define NEXUS_CONTROL_PROVISIONING_DIGEST "invalid"\n' > "$output/invalid-pin.h"
reject_configuration -DNEXUS_CONTROL_TEST_PLATFORM=1 -include "$output/invalid-pin.h"
reject_configuration -include "$output/pin.h"  # non-PS5 build without test seam
echo 'Provisioning policy negative compilation checks passed'
