"""Exercise release-source identity checks with an isolated Git repository."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).resolve().parents[1] / "check_release_tag.py"
TAG = "v0.1.0-rc.1"


def git(directory: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=directory, text=True).strip()


class ReleaseCheckoutTest(unittest.TestCase):
    def test_tag_checkout_and_event_commit_must_match(self):
        with tempfile.TemporaryDirectory(prefix="zrotext-release-tag-") as raw:
            repo = Path(raw)
            git(repo, "init", "-q", "-b", "main")
            (repo / "README.md").write_text("release candidate\n", encoding="utf-8")
            git(repo, "add", "README.md")
            git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "-q", "-m", "candidate")
            tagged = git(repo, "rev-parse", "HEAD")
            git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "tag", "-a", TAG, "-m", "candidate")
            git(repo, "update-ref", "refs/remotes/origin/main", tagged)
            env = {**os.environ, "GITHUB_ACTIONS": "true", "GITHUB_REF_NAME": TAG,
                   "GITHUB_SHA": tagged}

            def check() -> subprocess.CompletedProcess[str]:
                return subprocess.run([sys.executable, str(CHECK)], cwd=repo,
                                      env=env, capture_output=True, text=True, check=False)

            self.assertEqual(check().returncode, 0)
            env["GITHUB_SHA"] = "0" * 40
            self.assertIn("Release event commit differs", check().stderr)

            env["GITHUB_SHA"] = tagged
            (repo / "README.md").write_text("different checkout\n", encoding="utf-8")
            git(repo, "add", "README.md")
            git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "-q", "-m", "different")
            self.assertIn("Checked-out source differs", check().stderr)


if __name__ == "__main__":
    unittest.main()
