import os
import plistlib
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path

from validate_unsigned_ipa import validate


class UnsignedIPAValidationTests(unittest.TestCase):
    def make_ipa(self, bundle="com.ljcatherine.Nexus", extra=None, binary=b"\xcf\xfa\xed\xfeapp",
                 privacy_manifest=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "Nexus-unsigned.ipa"
        with zipfile.ZipFile(path, "w") as archive:
            root = "Payload/Nexus.app/"
            archive.writestr(root + "Info.plist", plistlib.dumps({
                "CFBundleIdentifier": bundle, "CFBundleExecutable": "Nexus",
                "CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "42",
                "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},
            }))
            archive.writestr(root + "PrivacyInfo.xcprivacy",
                             privacy_manifest if privacy_manifest is not None else self.valid_privacy_manifest())
            archive.writestr(root + "Nexus", binary)
            if extra:
                archive.writestr(root + extra, b"content")
        return path

    def test_valid_ios_app(self):
        result = validate(self.make_ipa())
        self.assertEqual(result["bundle"], "com.ljcatherine.Nexus")
        self.assertEqual(result["version"], "0.1.0")
        self.assertEqual(result["build"], "42")

    def test_rejects_missing_version_or_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing-version.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                root = "Payload/Nexus.app/"
                archive.writestr(root + "Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "com.ljcatherine.Nexus",
                    "CFBundleExecutable": "Nexus",
                    "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},
                }))
                archive.writestr(root + "PrivacyInfo.xcprivacy", self.valid_privacy_manifest())
                archive.writestr(root + "Nexus", b"\xcf\xfa\xed\xfeapp")
            with self.assertRaisesRegex(ValueError, "marketing version and build number"):
                validate(path)

    def test_rejects_missing_local_network_transport_permission(self):
        path = self.make_ipa()
        with zipfile.ZipFile(path, "r") as source:
            contents = {name: source.read(name) for name in source.namelist()}
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in contents.items():
                if name.endswith("Info.plist"):
                    plist = plistlib.loads(value)
                    del plist["NSAppTransportSecurity"]
                    value = plistlib.dumps(plist)
                archive.writestr(name, value)
        with self.assertRaisesRegex(ValueError, "allow ATS local networking"):
            validate(path)

    def test_rejects_missing_root_privacy_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing-privacy.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                root = "Payload/Nexus.app/"
                archive.writestr(root + "Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "com.ljcatherine.Nexus",
                    "CFBundleExecutable": "Nexus",
                    "CFBundleShortVersionString": "0.1.0",
                    "CFBundleVersion": "42",
                    "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},
                }))
                archive.writestr(root + "Nexus", b"\xcf\xfa\xed\xfeapp")
            with self.assertRaisesRegex(ValueError, "privacy manifest must be at the root"):
                validate(path)

    def test_rejects_unreported_userdefaults_usage(self):
        path = self.make_ipa(privacy_manifest=plistlib.dumps({
                "NSPrivacyTracking": False, "NSPrivacyCollectedDataTypes": [],
                "NSPrivacyAccessedAPITypes": [],
            }))
        with self.assertRaisesRegex(ValueError, "UserDefaults required reason"):
            validate(path)

    @staticmethod
    def valid_privacy_manifest():
        return plistlib.dumps({
            "NSPrivacyTracking": False,
            "NSPrivacyCollectedDataTypes": [],
            "NSPrivacyAccessedAPITypes": [{
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
                "NSPrivacyAccessedAPITypeReasons": ["CA92.1"],
            }],
        })

    def test_rejects_wrong_bundle_and_unsigned_policy_violations(self):
        with self.assertRaisesRegex(ValueError, "Incorrect bundle ID"):
            validate(self.make_ipa(bundle="app.cassava5895.plum3908"))
        with self.assertRaisesRegex(ValueError, "signing profile or signature"):
            validate(self.make_ipa(extra="embedded.mobileprovision"))
        with self.assertRaisesRegex(ValueError, "not a Mach-O"):
            validate(self.make_ipa(binary=b"not a binary"))

    def test_rejects_private_ipv4_in_app_bundle(self):
        binary = b"\xcf\xfa\xed\xfeNexus config 192.168.77.21"
        with self.assertRaisesRegex(ValueError, "private IPv4 address"):
            validate(self.make_ipa(binary=binary))

    def test_only_configured_private_address_is_allowed(self):
        binary = b"\xcf\xfa\xed\xfehttp://192.168.1.50:8081/v1"
        with self.assertRaisesRegex(ValueError, "private IPv4 address"):
            validate(self.make_ipa(binary=binary))
        with mock.patch.dict(os.environ, {"NEXUS_ALLOWED_PRIVATE_ADDRESSES": "192.168.1.50"}):
            validate(self.make_ipa(binary=binary))
            with self.assertRaisesRegex(ValueError, "private IPv4 address"):
                validate(self.make_ipa(binary=b"\xcf\xfa\xed\xfe192.168.1.50 192.168.1.70"))

    def test_rejects_tailscale_dns_name_in_app_bundle(self):
        binary = b"\xcf\xfa\xed\xfeNexus config node.example.ts.net"
        with self.assertRaisesRegex(ValueError, "Tailscale DNS name"):
            validate(self.make_ipa(binary=binary))
