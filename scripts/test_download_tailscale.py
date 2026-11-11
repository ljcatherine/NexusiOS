import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent


class TailscaleDownloadFlowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "bin").mkdir()
        shutil.copy(REPO / "scripts/download-tailscale.sh", self.root / "scripts")
        shutil.copy(REPO / "scripts/validate_tailscale_ipa.py", self.root / "scripts")
        (self.root / ".gitignore").write_text("/payloads/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)

        self.ipa_source = self.root / "source.ipa"
        with zipfile.ZipFile(self.ipa_source, "w") as archive:
            app_root = "Payload/Tailscale.app/"
            archive.writestr(app_root + "Info.plist", plistlib.dumps({
                "CFBundleIdentifier": "io.tailscale.ipn.ios",
                "CFBundleExecutable": "Tailscale",
                "CFBundleShortVersionString": "1.2.3",
            }))
            archive.writestr(app_root + "Tailscale", b"binary fixture")

        fake_tool = self.root / "bin/ipatool"
        fake_tool.write_text("""#!/usr/bin/env bash
set -euo pipefail
case "${1:-} ${2:-}" in
  "auth info")
    printf '%s\\n' 'private-account@example.invalid'
    printf '%s\\n' 'KEYCHAIN_PASSPHRASE_PROMPT' >&2
    exit "${FAKE_AUTH_EXIT:-0}"
    ;;
  "auth login")
    printf '%s\\n' 'private-account@example.invalid'
    printf '%s\\n' 'APPLE_PASSWORD_PROMPT' >&2
    exit 0
    ;;
  "download --app-id")
    while (($#)); do
      if [[ "$1" == --output ]]; then
        cp -- "$FAKE_IPA_SOURCE" "$2"
        exit 0
      fi
      shift
    done
    exit 9
    ;;
  *) exit 8 ;;
esac
""", encoding="utf-8")
        fake_tool.chmod(0o700)

    def run_downloader(self, auth_exit="0"):
        environment = os.environ.copy()
        environment["PATH"] = f"{self.root / 'bin'}:{environment['PATH']}"
        environment["FAKE_AUTH_EXIT"] = auth_exit
        environment["FAKE_IPA_SOURCE"] = str(self.ipa_source)
        environment["HOME"] = str(self.root / "home")
        Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
        return subprocess.run(
            ["bash", str(self.root / "scripts/download-tailscale.sh")],
            cwd=self.root, env=environment, text=True, capture_output=True, check=False,
        )

    def test_authenticated_preflight_keeps_keychain_prompt_visible_and_hides_account(self):
        result = self.run_downloader()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("KEYCHAIN_PASSPHRASE_PROMPT", result.stderr)
        self.assertNotIn("private-account@example.invalid", result.stdout + result.stderr)
        self.assertTrue((self.root / "payloads/Tailscale.ipa").is_file())

    def test_first_login_keeps_password_prompt_visible_and_hides_account(self):
        result = self.run_downloader(auth_exit="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("APPLE_PASSWORD_PROMPT", result.stderr)
        self.assertNotIn("private-account@example.invalid", result.stdout + result.stderr)
        self.assertTrue((self.root / "payloads/Tailscale.ipa").is_file())

    def test_refuses_existing_state_directory_open_to_other_users(self):
        state_dir = self.root / "home/.ipatool"
        state_dir.mkdir(parents=True)
        state_dir.chmod(0o755)
        result = self.run_downloader()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("accessible to other users", result.stderr)
        self.assertFalse((self.root / "payloads/Tailscale.ipa").exists())


if __name__ == "__main__":
    unittest.main()
