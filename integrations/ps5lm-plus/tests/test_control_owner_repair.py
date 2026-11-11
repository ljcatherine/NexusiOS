"""Filesystem acceptance for the one-shot ownership helper, without a console."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "native/repair_control_owner.c"
DIGEST = "sha256:" + "a" * 64


class OwnerRepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        root = Path(cls.build.name)
        harness = root / "harness.c"
        harness.write_text(
            '#define NEXUS_OWNER_REPAIR_HOST_TEST\n'
            f'#include "{SOURCE}"\n'
            'int main(int argc, char **argv) {\n'
            'if (argc != 3) return 2;\n'
            'return repair_control_owner(argv[1], argv[2], geteuid()); }\n'
        )
        cls.binary = root / "repair-test"
        subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
                        str(harness), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "app.log").write_text("fixture")
        self.token = self.root / "nexus-control.token"
        self.token.write_text(DIGEST + "\n")
        self.token.chmod(0o600)

    def run_helper(self, digest=DIGEST):
        return subprocess.run([str(self.binary), str(self.root), digest], check=False).returncode

    def test_owner_correct_file_is_idempotent_with_exact_bytes_mode_and_inode(self):
        before = self.token.stat()
        self.assertEqual(self.run_helper(), 0)
        self.assertEqual(self.run_helper(), 0)
        after = self.token.stat()
        self.assertEqual((before.st_ino, before.st_mode, before.st_uid, before.st_gid),
                         (after.st_ino, after.st_mode, after.st_uid, after.st_gid))
        self.assertEqual(self.token.read_text(), DIGEST + "\n")

    def test_digest_drift_is_refused_without_changing_file(self):
        self.assertEqual(self.run_helper("sha256:" + "b" * 64), 1)
        self.assertEqual(self.token.read_text(), DIGEST + "\n")

    def test_wide_permissions_and_extra_content_are_refused(self):
        self.token.chmod(0o644)
        self.assertEqual(self.run_helper(), 1)
        self.assertEqual(self.token.stat().st_mode & 0o777, 0o644)
        self.token.chmod(0o600)
        self.token.write_text(DIGEST + "\nextra")
        self.assertEqual(self.run_helper(), 1)

    def test_symlink_and_hardlink_are_refused(self):
        real = self.root / "real"
        self.token.rename(real)
        self.token.symlink_to(real)
        self.assertEqual(self.run_helper(), 1)
        self.token.unlink()
        os.link(real, self.token)
        self.assertEqual(self.run_helper(), 1)

    def test_missing_or_symlinked_app_log_is_refused(self):
        log = self.root / "app.log"
        log.unlink()
        self.assertEqual(self.run_helper(), 1)
        log.symlink_to(self.token)
        self.assertEqual(self.run_helper(), 1)


if __name__ == "__main__":
    unittest.main()
