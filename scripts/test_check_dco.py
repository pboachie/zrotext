"""Regression checks for the pull request DCO sign-off policy."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

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

    def run_check(self, *, pr_author="contributor", head_repo="pboachie/zrotext"):
        environment = {
            "PR_BASE_SHA": self.base,
            "PR_HEAD_SHA": self.git("rev-parse", "HEAD"),
            "PR_CREATED_AT": PR_CREATED_AT,
            "PR_AUTHOR_LOGIN": pr_author,
            "PR_HEAD_REPO": head_repo,
            "PR_BASE_REPO": "pboachie/zrotext",
        }
        with patch.dict(os.environ, environment):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return check_dco.main()

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
        self.assertEqual(self.run_check(pr_author="dependabot[bot]"), 0)

    def test_spoofed_bot_email_on_human_pr_fails(self):
        self.git("commit", "--allow-empty", "-m", "unsigned", author_email=BOT_EMAIL)
        self.assertEqual(self.run_check(), 1)

    def test_bot_pr_from_fork_does_not_get_exemption(self):
        self.git("commit", "--allow-empty", "-m", "unsigned", author_email=BOT_EMAIL)
        self.assertEqual(self.run_check(pr_author="dependabot[bot]",
                                        head_repo="contributor/zrotext"), 1)

    def test_human_commit_in_bot_pr_requires_signoff(self):
        self.git("commit", "--allow-empty", "-m", "unsigned")
        self.assertEqual(self.run_check(pr_author="dependabot[bot]"), 1)

    def test_missing_pr_identity_fails_closed(self):
        with patch.dict(os.environ, {
            "PR_BASE_SHA": self.base,
            "PR_HEAD_SHA": self.git("rev-parse", "HEAD"),
            "PR_CREATED_AT": PR_CREATED_AT,
        }, clear=True):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(check_dco.main(), 2)

    def test_github_committed_merge_is_exempt(self):
        side = self.diverge()
        self.git("merge", "--no-ff", "--no-edit", side, committer_email=GITHUB_EMAIL)
        with patch.object(check_dco, "github_web_merge_verified", return_value=True) as verified:
            self.assertEqual(self.run_check(), 0)
        verified.assert_called_once()

    def test_spoofed_github_committer_merge_without_signature_fails(self):
        side = self.diverge()
        self.git("merge", "--no-ff", "--no-edit", side, committer_email=GITHUB_EMAIL)
        with patch.object(check_dco, "github_web_merge_verified", return_value=False):
            self.assertEqual(self.run_check(), 1)

    def test_verified_web_signature_api_response(self):
        sha = "b" * 40
        payload = {
            "sha": sha,
            "committer": {"email": GITHUB_EMAIL},
            "verification": {"verified": True, "reason": "valid"},
        }
        with patch.dict(os.environ, {"GITHUB_TOKEN": BOT_EMAIL}):
            with patch.object(check_dco.urllib.request, "urlopen",
                              return_value=io.BytesIO(json.dumps(payload).encode())) as urlopen:
                self.assertTrue(check_dco.github_web_merge_verified(sha, "pboachie/zrotext"))
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url,
                         f"https://api.github.com/repos/pboachie/zrotext/git/commits/{sha}")
        self.assertEqual(request.get_header("Authorization"), f"Bearer {BOT_EMAIL}")

    def test_repository_slug_validation_is_bounded(self):
        self.assertTrue(check_dco.valid_github_repo_slug("pboachie/zrotext"))
        for invalid in ("", "owner/", "/repo", "owner/repo/extra",
                        "owner/repo?query", "-" * 10000 + "/repo"):
            with self.subTest(invalid=invalid[:32]):
                self.assertFalse(check_dco.valid_github_repo_slug(invalid))

    def test_web_merge_verification_fails_closed(self):
        sha = "b" * 40
        with patch.dict(os.environ, {"GITHUB_TOKEN": ""}):
            self.assertFalse(check_dco.github_web_merge_verified(sha, "pboachie/zrotext"))
        valid = {
            "sha": sha,
            "committer": {"email": GITHUB_EMAIL},
            "verification": {"verified": True, "reason": "valid"},
        }
        with patch.dict(os.environ, {"GITHUB_TOKEN": BOT_EMAIL}):
            for invalid in (
                {**valid, "sha": "c" * 40},
                {**valid, "verification": {"verified": False, "reason": "unsigned"}},
                {**valid, "committer": {"email": "attacker@example.test"}},
                {**valid, "verification": "malformed"},
            ):
                with self.subTest(invalid=invalid):
                    with patch.object(check_dco.urllib.request, "urlopen",
                                      return_value=io.BytesIO(json.dumps(invalid).encode())):
                        self.assertFalse(check_dco.github_web_merge_verified(sha, "pboachie/zrotext"))
            with patch.object(check_dco.urllib.request, "urlopen",
                              side_effect=urllib.error.URLError("offline")):
                self.assertFalse(check_dco.github_web_merge_verified(sha, "pboachie/zrotext"))

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
