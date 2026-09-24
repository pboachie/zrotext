#!/usr/bin/env python3
"""Check that each human-authored pull request commit has a DCO sign-off."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

SIGNOFF = re.compile(r"^Signed-off-by:\s+.+\s+<([^<>\s]+@[^<>\s]+)>\s*$", re.I | re.M)
DEPENDABOT_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"
DEPENDABOT_LOGIN = "dependabot[bot]"
GITHUB_COMMITTER_EMAILS = {"noreply@github.com"}
POLICY_START = datetime(2026, 9, 23, 14, 32, tzinfo=timezone.utc)
GITHUB_OWNER_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")
GITHUB_REPO_CHARS = GITHUB_OWNER_CHARS | frozenset("_.")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def valid_github_repo_slug(value: str) -> bool:
    """Check a GitHub owner/repo path without regex backtracking."""
    if len(value) > 200:
        return False
    owner, separator, repo = value.partition("/")
    return (bool(separator and owner and repo)
            and all(char in GITHUB_OWNER_CHARS for char in owner)
            and all(char in GITHUB_REPO_CHARS for char in repo))


def github_web_merge_verified(sha: str, head_repo: str) -> bool:
    """Require GitHub's verified web signature before exempting a merge."""
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token or not valid_github_repo_slug(head_repo):
        return False
    request = urllib.request.Request(
        f"https://api.github.com/repos/{head_repo}/git/commits/{sha}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            commit = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return False
    if not isinstance(commit, dict):
        return False
    verification = commit.get("verification") or {}
    committer = commit.get("committer") or {}
    if not isinstance(verification, dict) or not isinstance(committer, dict):
        return False
    return (commit.get("sha") == sha
            and committer.get("email", "").lower() in GITHUB_COMMITTER_EMAILS
            and verification.get("verified") is True
            and verification.get("reason") == "valid")


def main() -> int:
    base = os.environ.get("PR_BASE_SHA", "")
    head = os.environ.get("PR_HEAD_SHA", "")
    created_at = os.environ.get("PR_CREATED_AT", "")
    pr_author = os.environ.get("PR_AUTHOR_LOGIN", "")
    head_repo = os.environ.get("PR_HEAD_REPO", "")
    base_repo = os.environ.get("PR_BASE_REPO", "")
    if not re.fullmatch(r"[0-9a-f]{40}", base) or not re.fullmatch(r"[0-9a-f]{40}", head):
        print("PR_BASE_SHA and PR_HEAD_SHA must be commit hashes.", file=sys.stderr)
        return 2
    try:
        pr_created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        print("PR_CREATED_AT must be an ISO-8601 timestamp.", file=sys.stderr)
        return 2
    if not pr_author or not head_repo or not base_repo:
        print("PR_AUTHOR_LOGIN, PR_HEAD_REPO and PR_BASE_REPO are required.", file=sys.stderr)
        return 2
    trusted_dependabot_pr = pr_author == DEPENDABOT_LOGIN and head_repo == base_repo
    commits = git("rev-list", "--reverse", f"{base}..{head}").splitlines()
    if not commits:
        print("No pull request commits to check.")
        return 0
    failures = []
    for sha in commits:
        author = git("show", "-s", "--format=%ae", sha)
        if trusted_dependabot_pr and author.lower() == DEPENDABOT_EMAIL:
            continue
        # GitHub's web UI cannot add a sign-off trailer to merge commits.
        # Exempt only a merge with GitHub's verified web signature; local
        # commits can spoof the committer email but not that signature.
        if (len(git("show", "-s", "--format=%P", sha).split()) > 1
                and git("show", "-s", "--format=%ce", sha).lower() in GITHUB_COMMITTER_EMAILS
                and github_web_merge_verified(sha, head_repo)):
            continue
        # Existing open PRs retain their historical commits; new commits on them
        # and every commit on newly opened PRs follow the current policy.
        committed = datetime.fromisoformat(git("show", "-s", "--format=%cI", sha))
        if pr_created < POLICY_START and committed < POLICY_START:
            continue
        message = git("show", "-s", "--format=%B", sha)
        signed = {email.lower() for email in SIGNOFF.findall(message)}
        if author.lower() not in signed:
            failures.append(sha[:12])
    if failures:
        print("Missing author-matched Signed-off-by trailer in commits: " + ", ".join(failures), file=sys.stderr)
        print("Use git commit --amend -s, or add -s when creating a new commit.", file=sys.stderr)
        return 1
    print(f"DCO sign-off passed for {len(commits)} commit(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
