"""Fail-closed validation for an App Store Tailscale iOS IPA."""
from pathlib import Path
import plistlib
import sys
import zipfile

EXPECTED_BUNDLE = "io.tailscale.ipn.ios"


def validate(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if not names or len(names) != len(set(names)):
            raise ValueError("IPA is empty or contains duplicate ZIP paths.")
        for name in names:
            if name.startswith("/") or ".." in name.split("/") or "\\" in name:
                raise ValueError("IPA contains an unsafe ZIP path.")

        app_names = {
            name.split("/", 2)[1]
            for name in names
            if name.startswith("Payload/") and len(name.split("/", 2)) == 3
            and name.split("/", 2)[1].endswith(".app")
        }
        if len(app_names) != 1:
            raise ValueError("IPA must contain exactly one top-level iOS app bundle.")

        app_root = f"Payload/{next(iter(app_names))}/"
        try:
            info = plistlib.loads(archive.read(app_root + "Info.plist"))
        except (KeyError, plistlib.InvalidFileException) as error:
            raise ValueError("IPA app bundle has no valid Info.plist.") from error

        bundle = info.get("CFBundleIdentifier")
        if bundle != EXPECTED_BUNDLE:
            raise ValueError(
                f"Unexpected app bundle identifier: expected {EXPECTED_BUNDLE}, got {bundle!r}."
            )
        executable = info.get("CFBundleExecutable")
        if not isinstance(executable, str) or not executable or "/" in executable or "\\" in executable:
            raise ValueError("IPA app bundle has an invalid executable name.")
        if app_root + executable not in names:
            raise ValueError("IPA app bundle executable is missing.")
        version = info.get("CFBundleShortVersionString")
        if not isinstance(version, str) or not version:
            raise ValueError("IPA app bundle has no version string.")
        return {"bundle": bundle, "version": version, "app": next(iter(app_names))}


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else None
    if path is None:
        raise SystemExit("Usage: validate_tailscale_ipa.py PATH.ipa")
    result = validate(path)
    print(f"Verified Tailscale iOS IPA: {result['bundle']} {result['version']} ({result['app']})")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise SystemExit(f"Tailscale IPA validation failed: {error}")
