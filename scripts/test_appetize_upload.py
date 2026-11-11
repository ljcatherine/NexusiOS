import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "upload-appetize-preview.sh"
TOKEN = "mock-secret-token-must-not-be-logged"
PUBLIC_KEY = "existing_demo_key-42"
PREVIEW_URL = f"https://appetize.io/app/{PUBLIC_KEY}"


class AppetizeUploadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts" / SCRIPT.name)
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.capture_path = self.root / "request.json"
        self.mock_curl = self.fake_bin / "curl"
        self.mock_curl.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "def value_after(option): return args[args.index(option) + 1]\n"
            "output = pathlib.Path(value_after('--output'))\n"
            "header_arg = value_after('--header')\n"
            "header_file = pathlib.Path(header_arg[1:])\n"
            "forms = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == '--form']\n"
            "request = {'method': value_after('--request'), 'url': next(a for a in args if a.startswith('https://')),\n"
            " 'header': header_file.read_text(), 'forms': forms}\n"
            "pathlib.Path(os.environ['MOCK_CAPTURE']).write_text(json.dumps(request))\n"
            "output.write_text(os.environ['MOCK_RESPONSE'])\n"
            "print(os.environ['MOCK_STATUS'], end='')\n"
            "sys.exit(int(os.environ.get('MOCK_CURL_EXIT', '0')))\n",
            encoding="utf-8",
        )
        self.mock_curl.chmod(0o700)

    def run_upload(self, *, token=None, public_key=None, status="200", response=None,
                   curl_exit="0"):
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        env.pop("APPETIZE_API_TOKEN", None)
        env.pop("APPETIZE_PUBLIC_KEY", None)
        if token is not None:
            env["APPETIZE_API_TOKEN"] = token
        if public_key is not None:
            env["APPETIZE_PUBLIC_KEY"] = public_key
        env.update({
            "MOCK_CAPTURE": str(self.capture_path),
            "MOCK_STATUS": status,
            "MOCK_RESPONSE": response if response is not None else json.dumps({
                "publicKey": PUBLIC_KEY, "appURL": PREVIEW_URL,
            }),
            "MOCK_CURL_EXIT": curl_exit,
            "APP_VERSION": "0.3.0",
            "APP_BUILD": "50",
            "APP_SOURCE_COMMIT": "0123456789abcdef",
        })
        return subprocess.run(
            ["bash", str(self.root / "scripts" / SCRIPT.name)],
            cwd=self.root, env=env, text=True, capture_output=True, check=False,
        )

    def make_archive(self):
        archive = self.root / "build" / "appetize" / "Nexus-simulator.zip"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"mock simulator archive")
        return archive

    def test_skips_without_credentials_or_existing_app_key(self):
        no_token = self.run_upload()
        self.assertEqual(no_token.returncode, 0, no_token.stderr)
        self.assertIn("APPETIZE_API_TOKEN is not configured", no_token.stdout)
        self.assertFalse(self.capture_path.exists())

        no_app_key = self.run_upload(token=TOKEN)
        self.assertEqual(no_app_key.returncode, 0, no_app_key.stderr)
        self.assertIn("APPETIZE_PUBLIC_KEY", no_app_key.stderr)
        self.assertFalse(self.capture_path.exists())

    def test_posts_only_to_existing_app_and_masks_token(self):
        self.make_archive()
        result = self.run_upload(token=TOKEN, public_key=PUBLIC_KEY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        request = json.loads(self.capture_path.read_text(encoding="utf-8"))
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], f"https://api.appetize.io/v1/apps/{PUBLIC_KEY}")
        self.assertEqual(request["header"], f"X-API-KEY: {TOKEN}\n")
        self.assertIn("file=@build/appetize/Nexus-simulator.zip;type=application/zip", request["forms"])
        self.assertIn("platform=ios", request["forms"])
        self.assertEqual((self.root / "build/appetize/appetize-preview-url.txt").read_text().strip(), PREVIEW_URL)
        self.assertFalse(TOKEN in (self.root / "build/appetize/appetize-preview-url.txt").read_text())

    def test_rejects_http_errors_even_with_valid_response_body(self):
        self.make_archive()
        result = self.run_upload(token=TOKEN, public_key=PUBLIC_KEY, status="503")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 503", result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertFalse((self.root / "build/appetize/appetize-preview-url.txt").exists())

    def test_rejects_wrong_key_or_untrusted_preview_url(self):
        self.make_archive()
        cases = [
            {"publicKey": "different_key", "appURL": PREVIEW_URL},
            {"publicKey": PUBLIC_KEY, "appURL": "https://attacker.example/app/key"},
        ]
        for body in cases:
            with self.subTest(body=body):
                result = self.run_upload(
                    token=TOKEN, public_key=PUBLIC_KEY, response=json.dumps(body),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid response", result.stderr)
                self.assertNotIn(TOKEN, result.stdout + result.stderr)
                self.assertFalse((self.root / "build/appetize/appetize-preview-url.txt").exists())

    def test_rejects_invalid_configured_key_before_curl(self):
        self.make_archive()
        result = self.run_upload(token=TOKEN, public_key="../untrusted")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported characters", result.stderr)
        self.assertFalse(self.capture_path.exists())


if __name__ == "__main__":
    unittest.main()
