#!/usr/bin/env python3
"""Offline PS5LM Nexus title integrity/provenance check before first PS5 test.

Does not install, modify, execute, sign or contact a console. Optional SHA256
manifest is emitted only after checking a separate test title identity.
"""
import argparse
import hashlib
import json
import pathlib
import sys

ORIGINAL_ID = "PPSA99581"
REQUIRED = (
    "eboot.bin", "sce_module/libc.prx", "sce_sys/param.json",
    "sce_sys/icon0.png", "sce_sys/pic0.dds", "sce_sys/pic1.dds",
    "assets/fonts/inter-regular.huifont",
    "assets/fonts/inter-semibold.huifont",
    "assets/audio/sfx",
)
EXECUTABLE_FILES = ("eboot.bin", "sce_module/libc.prx")


def verify(root: pathlib.Path) -> dict:
    if not root.is_dir():
        raise ValueError("PS5 test title folder does not exist")
    root = root.resolve(strict=True)
    for name in REQUIRED:
        path = root / name
        if path.is_symlink() or not path.exists() or path.resolve() != root / name:
            raise ValueError(f"missing or unsafe title asset: {name}")
        if name != "assets/audio/sfx" and (not path.is_file() or path.stat().st_size == 0):
            raise ValueError(f"invalid or empty title asset: {name}")
        if name == "assets/audio/sfx" and not path.is_dir():
            raise ValueError("audio/sfx directory is missing")
    raw = (root / "sce_sys/param.json").read_bytes()
    if len(raw) > 16384:
        raise ValueError("oversized param.json")
    params = json.loads(raw)
    title_id = params.get("titleId")
    cid = params.get("contentId", "")
    if not isinstance(title_id, str) or len(title_id) != 9 or not title_id.startswith("PPSA") or not title_id[4:].isdigit():
        raise ValueError("invalid PS5 title identity")
    if title_id == ORIGINAL_ID:
        raise ValueError("refusing original PS5LM Plus title ID; use an isolated TEST title")
    if not isinstance(cid, str) or not cid.startswith(f"UP9000-{title_id}_00-") or len(cid) != 36:
        raise ValueError("test title contentId is inconsistent with titleId")
    name = params.get("localizedParameters", {}).get("en-US", {}).get("titleName", "")
    if "Nexus" not in name or "Test" not in name:
        raise ValueError("titleName must clearly identify an experimental Nexus test build")
    if root.name != title_id:
        raise ValueError("title directory and param.json titleId differ")
    executable = root / "eboot.bin"
    if executable.stat().st_size < 4096:
        raise ValueError("eboot.bin is too small to trust as a linked PS5 title")
    for name in EXECUTABLE_FILES:
        if (root / name).stat().st_mode & 0o111 != 0o111:
            raise ValueError(f"PS5 executable lacks execute permissions: {name}")
    assets = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"title contains symlink: {path.relative_to(root)}")
        if path.is_file():
            assets[str(path.relative_to(root))] = {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
                "mode": format(path.stat().st_mode & 0o777, "04o"),
            }
    return {"titleId": title_id, "contentId": cid, "titleName": name,
            "verified_files": assets,
            "warning": "Offline checks only: not PS5 hardware/firmware execution verification; preserve original data/settings and avoid parallel launch on port 8081."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("title", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path, help="Write checksum manifest JSON (never overwrites)")
    args = parser.parse_args()
    result = verify(args.title)
    print(json.dumps(result, indent=2))
    if args.manifest:
        with args.manifest.open("x") as out:
            json.dump(result, out, indent=2)
            out.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"PS5 Nexus title verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
