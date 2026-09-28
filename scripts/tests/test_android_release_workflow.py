# SPDX-License-Identifier: AGPL-3.0-only
"""The unsigned Android candidate workflow must stay secret-free and main/tag gated."""

from pathlib import Path
import re
import unittest

WORKFLOW = (Path(__file__).resolve().parents[2]
            / ".github" / "workflows" / "android-release-candidate.yml")


def top_level_block(text: str, key: str) -> str:
    """Return the indented lines under a top-level `key:` of the workflow."""
    match = re.search(rf"^{key}:[^\n]*\n((?:[ \t]+[^\n]*\n|\n)*)", text, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing top-level {key}")
    return match.group(1)


class AndroidReleaseWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_triggers_are_manual_dispatch_and_published_releases_only(self):
        triggers = [line.strip() for line in top_level_block(self.text, "on").splitlines()
                    if line.strip() and not line.strip().startswith("#")]
        self.assertEqual(triggers, ["workflow_dispatch:", "release:", "types: [published]"])
        self.assertNotIn("pull_request", self.text)
        self.assertNotIn("push:", self.text)

    def test_permissions_are_exactly_read_plus_attestation(self):
        permissions = sorted(line.strip() for line in
                             top_level_block(self.text, "permissions").splitlines()
                             if line.strip())
        self.assertEqual(permissions, ["attestations: write", "contents: read",
                                       "id-token: write"])
        # No job widens them.
        self.assertEqual(self.text.count("permissions:"), 1)

    def test_no_secrets_or_signing_step(self):
        self.assertNotIn("secrets.", self.text)
        self.assertNotRegex(self.text, r"release_candidate\.py (sign|verify)\b(?!-unsigned)")
        self.assertNotIn("keystore", self.text.lower())
        self.assertNotIn("gh release upload", self.text)

    def test_job_runs_only_on_main_dispatch_or_this_repository_releases(self):
        guard = re.search(r"^    if: >-\n((?:      [^\n]*\n)+)", self.text, re.MULTILINE)
        self.assertIsNotNone(guard)
        condition = " ".join(guard.group(1).split())
        self.assertIn("github.event_name == 'workflow_dispatch' && "
                      "github.ref == 'refs/heads/main'", condition)
        self.assertIn("github.event_name == 'release' && "
                      "github.repository == 'pboachie/zrotext'", condition)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", condition)

    def test_release_tag_is_validated_before_anything_is_built(self):
        validate = self.text.index("python3 scripts/check_release_tag.py")
        self.assertIn("git fetch origin main", self.text[:validate])
        for later in ["release_candidate.py build", "actions/attest@",
                      "actions/upload-artifact@"]:
            self.assertLess(validate, self.text.index(later), later)
        step = self.text[self.text.rindex("- name:", 0, validate):validate]
        self.assertIn("if: github.event_name == 'release'", step)

    def test_release_artifacts_are_named_after_the_tag(self):
        self.assertIn('echo "name=android-unsigned-candidate-${GITHUB_REF_NAME}"', self.text)
        self.assertIn("name: ${{ steps.artifact.outputs.name }}", self.text)
        self.assertIn('if [[ "$RELEASE_TAG" != "$GITHUB_REF_NAME" ]]', self.text)


if __name__ == "__main__":
    unittest.main()
