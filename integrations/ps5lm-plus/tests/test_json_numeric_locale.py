#!/usr/bin/env python3
"""Offline PS5 JSON decimal-point regression against the pinned vendor header.

Compiles and executes three host variants: unmodified vendor + simulated
empty PS5 locale (must assert), patched vendor + empty locale (must succeed),
patched vendor + normal system locale (must succeed). No PS5 access/build.
"""
import argparse
import pathlib
import resource
import subprocess
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
INTEGRATION = HERE.parent
PATCH = INTEGRATION / "patches" / "0002-ps5-empty-locale-decimal.patch"


def call(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, timeout=90, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("clone", type=pathlib.Path, help="Existing offline PS5LM-Nexus source clone")
    args = parser.parse_args()
    submodule = args.clone.resolve() / "third_party" / "llama.cpp"
    if not (submodule / "vendor" / "nlohmann" / "json.hpp").is_file():
        parser.error("clone has no initialized pinned llama.cpp vendor source")
    original = call(["git", "-C", str(submodule), "show", "HEAD:vendor/nlohmann/json.hpp"])
    if original.returncode:
        raise SystemExit("could not read pristine vendored JSON header from clone commit")

    with tempfile.TemporaryDirectory(prefix="ps5lm-json-locale-regression-") as tmp:
        tmp = pathlib.Path(tmp)
        for variant in ("pristine", "patched"):
            header = tmp / variant / "vendor" / "nlohmann" / "json.hpp"
            header.parent.mkdir(parents=True)
            header.write_text(original.stdout)
        applied = call(["git", "apply", str(PATCH)], cwd=tmp / "patched")
        if applied.returncode:
            raise SystemExit(f"PS5 integration compatibility patch does not apply cleanly: {applied.stderr}")

        def compile_run(name, variant, normal_locale=False):
            exe = tmp / name
            # NixOS commonly enables _FORTIFY_SOURCE, which requires an
            # optimized build and otherwise fails under -Werror.
            cmd = ["c++", "-std=c++17", "-O1", "-g0", "-Wall", "-Wextra", "-Werror"]
            if normal_locale:
                cmd.append("-DPS5LM_TEST_NORMAL_LOCALE")
            cmd += ["-I", str(tmp / variant / "vendor"), str(HERE / "json_numeric_locale.cpp"), "-o", str(exe)]
            compiled = call(cmd)
            if compiled.returncode:
                raise SystemExit(f"{name} compile failed:\n{compiled.stderr}")
            return call([str(exe)])

        # Never generate crash cores in an unattended offline regression.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        baseline = compile_run("baseline", "pristine")
        if baseline.returncode == 0 or "json.hpp:8323" not in baseline.stderr:
            raise SystemExit("expected original JSON parser to assert at 8323 with empty PS5 decimal point; "
                             f"got exit={baseline.returncode}: {baseline.stderr[:250]}")
        patched = compile_run("fixed-empty-locale", "patched")
        if patched.returncode:
            raise SystemExit(f"patched parser still fails with empty locale: {patched.stderr[:400]}")
        normal = compile_run("fixed-normal-locale", "patched", normal_locale=True)
        if normal.returncode:
            raise SystemExit(f"patched parser regresses normal C locale: {normal.stderr[:400]}")
    print("PASS pristine parser reproduces line 8323 assertion with empty PS5 localeconv")
    print("PASS integration patch parses fractions/exponents with empty PS5 localeconv")
    print("PASS integration patch preserves normal libc numeric parsing")


if __name__ == "__main__":
    main()
