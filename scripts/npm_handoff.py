#!/usr/bin/env python3
"""Request one public-safe npm preview review; never approve or publish."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from npm_release import OWNER, REPO, ReleaseError, context, read_json
from release_handoff import HandoffError, gh, marker


def handoff(receipt: dict, api=gh, env=None) -> dict:
    tag, commit, run_id, attempt = context() if env is None else context(env)
    if (receipt.get("name"), receipt.get("tag"), receipt.get("version"), receipt.get("source_commit"),
        receipt.get("run_id"), receipt.get("run_attempt")) != (
        "zrotext", tag, tag[1:], commit, run_id, attempt
    ):
        raise ReleaseError("Notification receipt identity differs.")
    if not re.fullmatch(r"[0-9a-f]{64}", receipt.get("sha256", "")):
        raise ReleaseError("Invalid notification digest.")
    notification = f"<!-- npm-preview:{tag}:{commit}:{receipt['sha256']}:{run_id}:{attempt} -->"
    pages = api("api", "--paginate", "--slurp", f"repos/{REPO}/issues?state=all&per_page=100")
    matches = [i for page in pages for i in page if "pull_request" not in i
               and i.get("user", {}).get("login") in (OWNER, "github-actions[bot]")
               and marker(tag) in (i.get("body") or "")]
    if len(matches) > 1:
        raise HandoffError("Multiple release checklists require reconciliation.")
    issue = matches[0] if matches else None
    if issue:
        if issue.get("state") != "open" or OWNER not in [a.get("login") for a in issue.get("assignees", [])]:
            raise HandoffError("The release checklist requires maintainer reconciliation.")
        comments = api("api", "--paginate", "--slurp", f"repos/{REPO}/issues/{issue['number']}/comments?per_page=100")
        if notification in (issue.get("body") or "") or any(notification in (c.get("body") or "")
            and c.get("user", {}).get("login") in (OWNER, "github-actions[bot]") for page in comments for c in page):
            return {"issue": issue["number"], "notified": False}
    run_url = f"https://github.com/{REPO}/actions/runs/{run_id}"
    body = (f"@{OWNER}: review the public zrotext {tag[1:]} npm preview for the next channel.\n\n"
            f"Source commit: {commit}.\nTarball SHA256: {receipt['sha256']}.\n"
            f"Review the exact package, content manifest and test/audit results in [the workflow run]({run_url}). "
            "Then approve or reject its npm-publication environment job. "
            "An issue comment or checkbox does not authorize publication. "
            "Approval permits publishing only the reviewed preview tarball; it does not enable messaging.\n\n"
            f"{notification}")
    if issue:
        api("api", "--method", "POST", f"repos/{REPO}/issues/{issue['number']}/comments", "-f", f"body={body}")
        return {"issue": issue["number"], "notified": True}
    created = api("api", "--method", "POST", f"repos/{REPO}/issues", "-f", f"title=Maintainer verification: {tag}",
                  "-f", f"body={marker(tag)}\n\n{body}", "-f", f"assignees[]={OWNER}")
    return {"issue": created["number"], "notified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(handoff(read_json(args.receipt))))
    except (ReleaseError, HandoffError, OSError) as exc:
        parser.exit(1, f"Npm handoff stopped: {exc}\n")


if __name__ == "__main__":
    main()
