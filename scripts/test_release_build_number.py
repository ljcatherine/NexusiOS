import unittest
from pathlib import Path
from next_release_build_number import next_build_number
from next_release_version import next_release_version


class ReleaseBuildNumberTests(unittest.TestCase):
    def test_advances_past_releases_across_app_versions(self):
        self.assertEqual(next_build_number([
            "nexus-v0.1.0-build.13", "nexus-v0.2.0-build.16", "v0.3.0",
        ], minimum_build=1), 17)

    def test_uses_requested_minimum_when_it_is_ahead(self):
        self.assertEqual(next_build_number(["nexus-v0.2.0-build.16"], minimum_build=22), 22)

    def test_starts_from_project_counter_without_prior_releases(self):
        self.assertEqual(next_build_number(["unrelated-release"], minimum_build=3), 3)

    def test_rejects_invalid_minimum_build(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            next_build_number([], minimum_build=0)

    def test_local_release_script_builds_with_xtool_and_publishes_unsigned_assets(self):
        script = (Path(__file__).resolve().parent / "xtool-release.sh").read_text()
        self.assertIn("./scripts/xtool-build.sh --release --ipa", script)
        self.assertIn('"signed": False', script)
        self.assertIn("gh release create", script)
        self.assertIn('branch="$(git branch --show-current)"', script)
        self.assertIn('git ls-remote --exit-code origin refs/heads/main', script)
        self.assertIn("Push the current main commit to origin before building and publishing a release.", script)
        self.assertIn('metadata_name="Nexus-v${version}-build.${build_number}-metadata.json"', script)
        self.assertIn('gh release upload "$tag" "$metadata_path" --repo "$repo"', script)
        self.assertIn('cmp -s "$metadata_path"', script)
        self.assertNotIn('gh release upload "$tag" "$metadata_path" --repo "$repo" --clobber', script)
        self.assertNotIn("codemagic", script.lower())

    def test_patch_increments_for_every_release_with_major_minor_preserved(self):
        self.assertEqual(next_release_version(["nexus-v0.4.0-build.129"], "0.4.1"), "0.4.1")
        self.assertEqual(next_release_version(["nexus-v0.4.1-build.130"], "0.4.1"), "0.4.2")
        self.assertEqual(next_release_version(["nexus-v0.4.1-build.130", "nexus-v0.4.2-build.131"], "0.4.1"), "0.4.3")

    def test_latest_released_line_cannot_change_without_explicit_override(self):
        tags = ["nexus-v0.3.8-build.128", "nexus-v0.4.0-build.129"]
        with self.assertRaisesRegex(ValueError, "explicit approval"):
            next_release_version(tags, "0.5.0")
        self.assertEqual(next_release_version(tags, "0.5.0", allow_version_line_change=True), "0.5.0")

    def test_release_script_uses_patch_allocator_and_requires_version_line_override(self):
        script = (Path(__file__).resolve().parent / "xtool-release.sh").read_text()
        self.assertIn("scripts/next_release_version.py", script)
        self.assertIn("NEXUS_ALLOW_VERSION_LINE_CHANGE", script)


if __name__ == "__main__":
    unittest.main()
