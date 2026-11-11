import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from validate_tailscale_ipa import validate


class TailscaleIPAValidationTests(unittest.TestCase):
    def make_ipa(self, *, bundle="io.tailscale.ipn.ios", extra_apps=(), include_executable=True):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "download.ipa"
        with zipfile.ZipFile(path, "w") as archive:
            self.add_app(archive, "Tailscale.app", bundle, include_executable)
            for app_name, app_bundle in extra_apps:
                self.add_app(archive, app_name, app_bundle)
        return path

    @staticmethod
    def add_app(archive, app_name, bundle, include_executable=True):
        root = f"Payload/{app_name}/"
        archive.writestr(root + "Info.plist", plistlib.dumps({
            "CFBundleIdentifier": bundle,
            "CFBundleExecutable": "Tailscale",
            "CFBundleShortVersionString": "1.2.3",
        }))
        if include_executable:
            archive.writestr(root + "Tailscale", b"Mach-O fixture")

    def test_accepts_official_tailscale_ios_bundle(self):
        result = validate(self.make_ipa())
        self.assertEqual(result, {
            "bundle": "io.tailscale.ipn.ios", "version": "1.2.3", "app": "Tailscale.app",
        })

    def test_rejects_unrelated_or_lookalike_app(self):
        with self.assertRaisesRegex(ValueError, "Unexpected app bundle identifier"):
            validate(self.make_ipa(bundle="com.example.tailscale"))

    def test_rejects_multiple_top_level_apps(self):
        with self.assertRaisesRegex(ValueError, "exactly one top-level"):
            validate(self.make_ipa(extra_apps=[("Impostor.app", "io.tailscale.ipn.ios")]))

    def test_rejects_missing_executable(self):
        path = self.make_ipa(include_executable=False)
        with self.assertRaisesRegex(ValueError, "executable is missing"):
            validate(path)

    def test_rejects_unsafe_zip_paths(self):
        path = self.make_ipa()
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("Payload/Tailscale.app/../outside", b"bad")
        with self.assertRaisesRegex(ValueError, "unsafe ZIP path"):
            validate(path)


if __name__ == "__main__":
    unittest.main()
