"""Verify an unsigned physical-iOS IPA before release or external signing."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import sys
import zipfile

from validate_privacy_manifest import validate_manifest

EXPECTED_BUNDLE = "com.ljcatherine.Nexus"
MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
PRIVATE_IPV4 = re.compile(
    rb"(?<![0-9])(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|"
    rb"192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}|"
    rb"172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3})(?![0-9])"
)
TAILSCALE_DNS = re.compile(rb"(?i)(?:[a-z0-9-]+\.)+ts\.net")


def allowed_private_addresses() -> set[bytes]:
    """Private IPv4 literals a deployment deliberately embeds (for example its default AI endpoint).

    Set NEXUS_ALLOWED_PRIVATE_ADDRESSES to a comma-separated list; empty allows none.
    """
    raw = os.environ.get("NEXUS_ALLOWED_PRIVATE_ADDRESSES", "")
    return {item.strip().encode() for item in raw.split(",") if item.strip()}


def validate(ipa: Path) -> dict:
    allowed = allowed_private_addresses()
    with zipfile.ZipFile(ipa) as archive:
        names = archive.namelist()
        root = "Payload/Nexus.app/"
        if not names or any(
            name.startswith("/") or ".." in Path(name).parts or
            not name.startswith(root) and name not in ("Payload/", "Payload/Nexus.app/")
            for name in names
        ):
            raise ValueError("IPA contains unexpected paths outside Payload/Nexus.app.")
        for name in names:
            if not name.startswith(root) or name.endswith("/"):
                continue
            contents = archive.read(name)
            if any(match.group() not in allowed for match in PRIVATE_IPV4.finditer(contents)):
                raise ValueError("IPA contains a private IPv4 address; remove private network configuration before distribution.")
            if TAILSCALE_DNS.search(contents):
                raise ValueError("IPA contains a Tailscale DNS name; configure private endpoints on-device before distribution.")
        plist = plistlib.loads(archive.read(root + "Info.plist"))
        privacy_manifest_path = root + "PrivacyInfo.xcprivacy"
        if privacy_manifest_path not in names:
            raise ValueError("App privacy manifest must be at the root of Payload/Nexus.app.")
        validate_manifest(archive.read(privacy_manifest_path))
        bundle = plist.get("CFBundleIdentifier")
        if bundle != EXPECTED_BUNDLE:
            raise ValueError(f"Incorrect bundle ID: expected {EXPECTED_BUNDLE}, got {bundle!r}.")
        transport_security = plist.get("NSAppTransportSecurity", {})
        if not isinstance(transport_security, dict) or transport_security.get("NSAllowsLocalNetworking") is not True:
            raise ValueError("App Info.plist must allow ATS local networking for configured private AI endpoints.")
        version = plist.get("CFBundleShortVersionString")
        build = plist.get("CFBundleVersion")
        if not isinstance(version, str) or not version or not isinstance(build, str) or not build:
            raise ValueError("App Info.plist must include a marketing version and build number.")
        expected_version = os.environ.get("APP_MARKETING_VERSION")
        expected_build = os.environ.get("APP_BUILD_NUMBER")
        if expected_version and version != expected_version:
            raise ValueError(f"Incorrect app version: expected {expected_version}, got {version}.")
        if expected_build and build != expected_build:
            raise ValueError(f"Incorrect app build number: expected {expected_build}, got {build}.")
        binary = plist.get("CFBundleExecutable")
        if not isinstance(binary, str) or "/" in binary or binary in ("", ".", ".."):
            raise ValueError("Missing or invalid CFBundleExecutable.")
        with archive.open(root + binary) as executable:
            if executable.read(4) not in MACHO_MAGICS:
                raise ValueError("IPA executable is not a Mach-O binary.")
        if root + "embedded.mobileprovision" in names or any("/_CodeSignature/" in name for name in names):
            raise ValueError("Unsigned artifact unexpectedly contains a signing profile or signature.")
    return {"bundle": bundle, "executable": binary, "version": version, "build": build}


def main() -> None:
    ipa = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("build/export/Nexus-unsigned.ipa")
    result = validate(ipa)
    digest = hashlib.sha256(ipa.read_bytes()).hexdigest()
    ipa.with_suffix(".ipa.sha256").write_text(f"{digest}  {ipa.name}\n")
    (ipa.parent / "build-metadata.json").write_text(json.dumps({
        "commit": os.environ.get("NEXUS_SOURCE_COMMIT"),
        "bundle": result["bundle"], "executable": result["executable"],
        "version": result["version"], "build": result["build"],
        "release_tag": os.environ.get("NEXUS_RELEASE_TAG") or f"nexus-v{result['version']}-build.{result['build']}",
        "signed": False, "sha256": digest,
    }, indent=2))
    print(f"Verified unsigned iPhone IPA: {result['bundle']} {result['version']} ({result['build']}); sha256={digest}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"::error::Unsigned IPA validation failed: {exc}")
