"""Regression checks for the pull request DCO sign-off policy."""

import contextlib
import io
import os
import subprocess
import tempfile
import unittest

import check_dco

BOT_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"
GITHUB_EMAIL = "noreply@github.com"
# After POLICY_START so every fixture commit is subject to the policy.
PR_CREATED_AT = "2026-09-24T00:00:00Z"


class CheckDcoTests(unittest.TestCase):
    def setUp(self):
        self.previous_cwd = os.getcwd()
        self.repo = tempfile.TemporaryDirectory()
        os.chdir(self.repo.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test Author")
        self.git("config", "user.email", "author@example.com")
        self.git("commit", "--allow-empty", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self):
        os.chdir(self.previous_cwd)
        self.repo.cleanup()

    def git(self, *args, author_email=None, committer_email=None):
        env = dict(os.environ)
        if author_email is not None:
            env["GIT_AUTHOR_NAME"] = "Test Author"
            env["GIT_AUTHOR_EMAIL"] = author_email
        if committer_email is not None:
            env["GIT_COMMITTER_NAME"] = "Test Committer"
            env["GIT_COMMITTER_EMAIL"] = committer_email
        return subprocess.check_output(["git", *args], text=True, env=env, stderr=subprocess.DEVNULL).strip()

    def run_check(self):
        os.environ.update(
            PR_BASE_SHA=self.base,
            PR_HEAD_SHA=self.git("rev-parse", "HEAD"),
            PR_CREATED_AT=PR_CREATED_AT,
        )
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return check_dco.main()
        finally:
            for key in ("PR_BASE_SHA", "PR_HEAD_SHA", "PR_CREATED_AT"):
                os.environ.pop(key, None)

    def diverge(self):
        self.git("checkout", "-q", "-b", "feature")
        self.git("commit", "--allow-empty", "-m", "side", "-s")
        side = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "main")
        self.git("commit", "--allow-empty", "-m", "trunk", "-s")
        return side

    def test_unsigned_commit_fails(self):
        self.git("commit", "--allow-empty", "-m", "unsigned")
        self.assertEqual(self.run_check(), 1)

    def test_signed_commit_passes(self):
        self.git("commit", "--allow-empty", "-m", "signed", "-s")
        self.assertEqual(self.run_check(), 0)

    def test_bot_commit_is_exempt(self):
        self.git("commit", "--allow-empty", "-m", "bump deps", author_email=BOT_EMAIL)
        self.assertEqual(self.run_check(), 0)

    def test_github_committed_merge_is_exempt(self):
        side = self.diverge()
        self.git("merge", "--no-ff", "--no-edit", side, committer_email=GITHUB_EMAIL)
        self.assertEqual(self.run_check(), 0)

    def test_local_unsigned_merge_fails(self):
        side = self.diverge()
        self.git("merge", "--no-ff", "--no-edit", side, committer_email="committer@example.com")
        self.assertEqual(self.run_check(), 1)

    def test_local_signed_merge_passes(self):
        side = self.diverge()
        self.git("merge", "--no-ff", "--no-commit", side)
        self.git("commit", "-s", "-m", "Merge branch 'feature'")
        self.assertEqual(self.run_check(), 0)


if __name__ == "__main__":
    unittest.main()
