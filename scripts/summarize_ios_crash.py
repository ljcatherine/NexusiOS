#!/usr/bin/env python3
"""Print a privacy-minimized summary of an Apple .ips crash report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def load_report(path: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    raw = path.read_bytes()
    lines = raw.splitlines()
    if not lines:
        raise ValueError("The crash report is empty.")
    try:
        header = json.loads(lines[0])
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("The first line is not a valid Apple crash-report header.") from error
    if not isinstance(header, dict):
        raise ValueError("The crash-report header must be a JSON object.")
    if len(lines) > 1:
        try:
            report = json.loads(b"\n".join(lines[1:]))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("The crash-report body is not valid JSON.") from error
    else:
        report = header
    if not isinstance(report, dict):
        raise ValueError("The crash-report body must be a JSON object.")
    return header, report, hashlib.sha256(raw).hexdigest()


def crash_thread(report: dict[str, Any]) -> dict[str, Any] | None:
    threads = report.get("threads")
    if not isinstance(threads, list):
        return None
    faulting_index = report.get("faultingThread")
    if isinstance(faulting_index, int) and 0 <= faulting_index < len(threads):
        selected = threads[faulting_index]
        if isinstance(selected, dict):
            return selected
    return next((thread for thread in threads
                 if isinstance(thread, dict) and thread.get("triggered") is True), None)


def summarize(header: dict[str, Any], report: dict[str, Any], digest: str) -> str:
    info = report.get("bundleInfo")
    if not isinstance(info, dict):
        info = {}
    exception = report.get("exception")
    if not isinstance(exception, dict):
        exception = {}
    os_info = report.get("osVersion")
    if not isinstance(os_info, dict):
        os_info = {}
    thread = crash_thread(report)

    lines = [
        f"Report SHA-256: {digest}",
        "App: {} {} build {} ({})".format(
            header.get("app_name", "unknown"),
            info.get("CFBundleShortVersionString", header.get("app_version", "unknown")),
            info.get("CFBundleVersion", header.get("build_version", "unknown")),
            info.get("CFBundleIdentifier", header.get("bundleID", "unknown")),
        ),
        "Captured: {}".format(report.get("captureTime", header.get("timestamp", "unknown"))),
        "Device / OS: {} / {} {}".format(
            report.get("modelCode", "unknown"),
            os_info.get("train", "unknown"),
            os_info.get("build", ""),
        ),
        "Crash: {} {} — {}".format(
            exception.get("type", "unknown"),
            exception.get("signal", ""),
            exception.get("subtype", "unknown"),
        ),
    ]
    if thread:
        lines.append("Fault thread: {} · {} · {}".format(
            thread.get("name", "unnamed"),
            thread.get("queue", "no queue name"),
            thread.get("id", "unknown id"),
        ))
        used_images = report.get("usedImages", [])
        for frame in thread.get("frames", [])[:12]:
            if not isinstance(frame, dict):
                continue
            symbol = frame.get("symbol") or frame.get("symbolLocation")
            image_name = frame.get("imageName")
            image_index = frame.get("imageIndex")
            if image_name is None and isinstance(image_index, int) and isinstance(used_images, list):
                if 0 <= image_index < len(used_images) and isinstance(used_images[image_index], dict):
                    image_name = used_images[image_index].get("name")
            if symbol or image_name:
                lines.append("  {}{}".format(symbol or "frame", f" — {image_name}" if image_name else ""))
    else:
        lines.append("Fault thread: not identified in report")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Path to the .ips file")
    args = parser.parse_args()
    try:
        header, report, digest = load_report(args.report)
        print(summarize(header, report, digest))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
