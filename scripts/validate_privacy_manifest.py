"""Validate Nexus's app privacy manifest against its documented practices."""
import plistlib
import sys
from pathlib import Path


def validate_manifest(data: bytes) -> None:
    try:
        manifest = plistlib.loads(data)
    except (ValueError, plistlib.InvalidFileException) as error:
        raise ValueError("App privacy manifest is not a valid property list.") from error

    if not isinstance(manifest, dict):
        raise ValueError("App privacy manifest root must be a dictionary.")
    if manifest.get("NSPrivacyTracking") is not False:
        raise ValueError("App privacy manifest must explicitly declare tracking disabled.")
    if manifest.get("NSPrivacyCollectedDataTypes") != []:
        raise ValueError("App privacy manifest must match Nexus's no-data-collection disclosure.")

    accessed_api_types = manifest.get("NSPrivacyAccessedAPITypes")
    if not isinstance(accessed_api_types, list) or not any(
        isinstance(entry, dict)
        and entry.get("NSPrivacyAccessedAPIType") == "NSPrivacyAccessedAPICategoryUserDefaults"
        and "CA92.1" in entry.get("NSPrivacyAccessedAPITypeReasons", [])
        for entry in accessed_api_types
    ):
        raise ValueError("App privacy manifest is missing the declared UserDefaults required reason.")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {Path(sys.argv[0]).name} APP/PrivacyInfo.xcprivacy")
    manifest_path = Path(sys.argv[1])
    validate_manifest(manifest_path.read_bytes())
    print(f"Verified app privacy manifest: {manifest_path}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"Privacy manifest validation failed: {error}")
