"""Choose a local Nexus build number above all published Nexus release builds."""
import re

RELEASE_TAG = re.compile(r"^nexus-v\d+\.\d+\.\d+-build\.(\d+)$")


def next_build_number(release_tags: list[str], minimum_build: int = 1) -> int:
    if minimum_build < 1:
        raise ValueError("minimum build number must be a positive integer")
    released = [int(match.group(1)) for tag in release_tags if (match := RELEASE_TAG.fullmatch(tag))]
    return max(minimum_build, max(released, default=0) + 1)


if __name__ == "__main__":
    import json
    import sys

    releases = json.load(sys.stdin)
    names = [item["tagName"] for item in releases]
    print(next_build_number(names))
