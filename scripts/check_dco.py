#!/usr/bin/env python3
"""Check that each human-authored pull request commit has a DCO sign-off."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime, timezone

SIGNOFF = re.compile(r"^Signed-off-by:\s+.+\s+<([^<>\s]+@[^<>\s]+)>\s*$", re.I | re.M)
BOT_EMAILS = {"49699333+dependabot[bot]@users.noreply.github.com"}
GITHUB_COMMITTER_EMAILS = {"noreply@github.com"}
POLICY_START = datetime(2026, 9, 23, 14, 32, tzinfo=timezone.utc)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def main() -> int:
    base = os.environ.get("PR_BASE_SHA", "")
    head = os.environ.get("PR_HEAD_SHA", "")
    created_at = os.environ.get("PR_CREATED_AT", "")
    if not re.fullmatch(r"[0-9a-f]{40}", base) or not re.fullmatch(r"[0-9a-f]{40}", head):
        print("PR_BASE_SHA and PR_HEAD_SHA must be commit hashes.", file=sys.stderr)
        return 2
    try:
        pr_created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        print("PR_CREATED_AT must be an ISO-8601 timestamp.", file=sys.stderr)
        return 2
    commits = git("rev-list", "--reverse", f"{base}..{head}").splitlines()
    if not commits:
        print("No pull request commits to check.")
        return 0
    failures = []
    for sha in commits:
        author = git("show", "-s", "--format=%ae", sha)
        if author.lower() in BOT_EMAILS:
            continue
        # GitHub's web UI ("Update branch", the merge button) cannot add a
        # sign-off trailer, so its merge commits are exempt; the commits they
        # combine are checked individually. Locally created merges can carry
        # a trailer and stay subject to the policy.
        if len(git("show", "-s", "--format=%P", sha).split()) > 1 and git("show", "-s", "--format=%ce", sha).lower() in GITHUB_COMMITTER_EMAILS:
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
