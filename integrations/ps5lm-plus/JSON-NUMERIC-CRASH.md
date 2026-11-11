# Experimental title :8081 crash: numeric JSON / PS5 locale (offline analysis)

**Scope and status:** This is an offline-only source-level correction and host
regression. No PS5 upload, restart, title replacement, credential access, or
console-side verification was performed. Original `PPSA99581` is untouched.

## Observed evidence and cause

The PS5's trailing `app.log` reported:

```
third_party/llama.cpp/vendor/nlohmann/json.hpp:8323:
GGML_ASSERT(endptr == token_buffer.data() + token_buffer.size()) failed
```

The pinned nlohmann JSON lexer initializes its `decimal_point_char` from
`*localeconv()->decimal_point` at `json.hpp:7158,7175–7180`. If this pointer
is non-null but points at the empty C string (`""`), a valid JSON fraction
such as `0.5` is assembled as a token containing an embedded NUL. The
subsequent `strtod`/`strtof` conversion stops before the end of the token,
and the `json.hpp:8323` assertion aborts the process.

The PS5 Vulkan link recipe already documents the platform's problematic empty
`localeconv()` decimal separator and has an **optional**
`--defsym=localeconv=ps5_localeconv` compatibility binding. Inspection of the
exact SDK archive present under `/tmp/ps5lm-nexus-test.dGnBVr/PS5_Vulkan`
found `ps5_localeconv_l` but **not** `ps5_localeconv`, so that conditional
binding cannot activate. The previously built test title's `llvm-pie.elf`
retained `U localeconv` (platform import), unlike its locally resolved
`localeconv_l`. The app's process therefore depends on the uncorrected system
locale behavior for this lexer.

**Proof of mechanism:** A host C++ reproducer overriding `localeconv()` to
return a non-null empty `decimal_point` makes the unmodified vendored header
abort with exit 134 at the **same line 8323**. The patched header parses five
fraction/exponent cases with the simulated PS5 locale and also passes the
normal host C locale. This supports the failure mechanism without depending on
network access or a model workload. The **specific PS5 JSON request** that
triggered the crash was not captured, and repaired behaviour **on hardware**
remains to be verified.

## Minimal correction

`patches/0002-ps5-empty-locale-decimal.patch` changes only
`lexer::get_decimal_point()` in the bundled pinned vendor file:

```cpp
return (loc->decimal_point == nullptr || *loc->decimal_point == '\0')
    ? '.' : *loc->decimal_point;
```

JSON itself requires `.` as the fractional separator. This leaves valid
non-empty decimal separators unchanged; it does not disable parsing checks,
alter numerical conversion algorithms, or override global libc symbols.

The integration's `clone-nexus-fork.sh` copies this patch into its new clone's
`patches/nexus-ps5-empty-locale-decimal.patch`; the upstream pinned
`scripts/build-app.sh` already loops over that folder and applies all patches
to the llama.cpp submodule **before** compiling. For the existing throwaway
clone under `/tmp/ps5lm-nexus-test.dGnBVr/PS5LM-Nexus`, this patch was also
applied directly to its vendor header and copied into its `patches/` folder.
No full PS5-native rebuild was executed in this worker.

## Reproduction and validation (offline host)

```bash
python3 -B integrations/ps5lm-plus/tests/test_json_numeric_locale.py \
  /tmp/ps5lm-nexus-test.dGnBVr/PS5LM-Nexus
```

The script uses the pinned submodule's pristine `HEAD:vendor/nlohmann/json.hpp`
as its control. It applies the integration patch to a separate temporary copy,
compiles with host `c++ -std=c++17 -O1 -g0 -Wall -Wextra -Werror` (compatible with NixOS fortify), then checks:

1. Pristine header + simulated PS5 empty decimal separator: abort at 8323.
2. Patched header + simulated PS5 empty separator: numeric cases pass.
3. Patched header + normal system C locale: numeric cases pass.

The test disables core dumps and uses only disposable host binaries.

Before another deployment, prime should **rebuild the experimental title**
from the patched source, inspect the new title's compiled/vendor provenance,
preserve the original PPSA99581, and perform a controlled long-running
fraction/exponent JSON acceptance test in the isolated experimental title.
Do not assume an offline passing host test proves the model-server crash is
fully fixed, or that :8081 will remain stable under other workloads.

## Subsequent native rebuild and package (2026-11-02)

The pinned native PS5 fork was rebuilt with the corrected vendored JSON header. An initial attempt hit a NixOS wrapped-compiler/glibc header conflict; the subsequent build used the pinned unwrapped Clang 20 (`PS5_CLANG_CXX`, `PS5_CLANG_C`, `PS5_CLANG`) and two-job cap, and **completed successfully**. The `common/json.cpp.o` object was freshly compiled, and the PS5 title verifier passed with the same distinct experimental title ID, `PPSA99742`.

New, CRC-valid **84-file** test artifact (local and ignored, not released):

```
build/PS5LM-Nexus-JSON-Decimal-Fix-PPSA99742.zip
ZIP SHA-256 b9c9be2b8a98aae0fd7270c1f14549102054a059fa900716821f281ec1b43715
eboot.bin SHA-256 3a1446a0c1c2213bec8af6020f3f816143ea649e1fa7a7826c9d63d8191367bf
```

The old crashing test archive and sidecar still pass SHA-256, and the original PS5LM `PPSA99581` binary and GGUFs remain untouched. The new ZIP is **not yet hardware tested**.

**Later read-only investigation:** The prior FTP :2121 hash discrepancy was attributed to its on-the-fly SELF-to-ELF conversion; disabling that conversion for the session recovered the expected raw fSELF hash. ShadowMount logs identified `/data/homebrew/PPSA99742` as the mounted source. This does not establish that the corrected package works on the console; it remains uninstalled and untested on hardware.
