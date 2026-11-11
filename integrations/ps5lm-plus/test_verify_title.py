import importlib.util
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('titlecheck', pathlib.Path(__file__).with_name('verify-test-title.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

class VerifyTitleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.id = 'PPSA99742'
        self.root = pathlib.Path(self.temp.name) / self.id
        for item in check.REQUIRED:
            target = self.root / item
            target.parent.mkdir(parents=True, exist_ok=True)
            if item == 'assets/audio/sfx':
                target.mkdir()
            else:
                target.write_bytes(b'X' * (8192 if item == 'eboot.bin' else 16))
        self.params = {'titleId': self.id, 'contentId': 'UP9000-PPSA99742_00-NEXUSPS5LM000001',
                       'localizedParameters': {'en-US': {'titleName': 'PS5LM Nexus Test'}}}
        self.write_params()
        for name in check.EXECUTABLE_FILES:
            (self.root / name).chmod(0o755)

    def write_params(self):
        (self.root / 'sce_sys/param.json').write_text(json.dumps(self.params))

    def test_accepts_isolated_title_with_manifest(self):
        result = check.verify(self.root)
        self.assertEqual(result['titleId'], self.id)
        self.assertEqual(result['verified_files']['eboot.bin']['size'], 8192)
        self.assertEqual(result['verified_files']['eboot.bin']['mode'], '0755')

    def test_rejects_non_executable_boot_or_runtime_module(self):
        for name in check.EXECUTABLE_FILES:
            target = self.root / name
            target.chmod(0o644)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'execute permissions'):
                check.verify(self.root)
            target.chmod(0o755)

    def test_rejects_original_title_and_inconsistent_contentid(self):
        self.params['titleId'] = check.ORIGINAL_ID
        self.write_params()
        with self.assertRaisesRegex(ValueError, 'original'):
            check.verify(self.root)
        self.params['titleId'] = self.id
        self.params['contentId'] = 'UP9000-PPSA99581_00-PS5LMPLUS0000001'
        self.write_params()
        with self.assertRaisesRegex(ValueError, 'inconsistent'):
            check.verify(self.root)

    def test_rejects_missing_or_symlinked_assets(self):
        target = self.root / 'sce_module/libc.prx'
        target.unlink()
        with self.assertRaises(ValueError):
            check.verify(self.root)
        target.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            check.verify(self.root)

if __name__ == '__main__':
    unittest.main()
