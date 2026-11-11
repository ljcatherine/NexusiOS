"""Advance Nexus patch versions without silently changing major/minor versions."""

import argparse
import json
import re
import sys

RELEASE_TAG = re.compile(r"^nexus-v(\d+)\.(\d+)\.(\d+)-build\.(\d+)$")
VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def next_release_version(release_tags: list[str], project_version: str,
                         allow_version_line_change: bool = False) -> str:
    match = VERSION.fullmatch(project_version)
    if match is None:
        raise ValueError("project version must use major.minor.patch")
    major, minor, minimum_patch = map(int, match.groups())
    releases = [tuple(map(int, found.groups())) for tag in release_tags
                if (found := RELEASE_TAG.fullmatch(tag))]
    if releases:
        latest = max(releases, key=lambda value: value[3])
        if (major, minor) != latest[:2] and not allow_version_line_change:
            raise ValueError(
                f"major/minor {major}.{minor} differs from latest release "
                f"{latest[0]}.{latest[1]}; explicit approval and "
                "NEXUS_ALLOW_VERSION_LINE_CHANGE=1 are required"
            )
    released_patches = [patch for released_major, released_minor, patch, _ in releases
                        if (released_major, released_minor) == (major, minor)]
    next_patch = max(minimum_patch, max(released_patches, default=-1) + 1)
    return f"{major}.{minor}.{next_patch}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-version", required=True)
    parser.add_argument("--allow-version-line-change", action="store_true")
    args = parser.parse_args()
    tags = [release["tagName"] for release in json.load(sys.stdin)]
    try:
        print(next_release_version(tags, args.project_version, args.allow_version_line_change))
    except ValueError as error:
        parser.error(str(error))
