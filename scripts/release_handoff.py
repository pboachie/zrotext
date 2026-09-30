#!/usr/bin/env python3
"""Explicit, public-safe maintainer handoff; never performs release checks."""
import argparse
import json
import re
import subprocess

REPO = "pboachie/zrotext"
OWNER = "pboachie"
GATES = {
    "release-candidate": "Verify the release candidate",
    "line-binding": "Verify line activation and binding readiness",
    "opt-out": "Verify opt-out readiness",
    "sealed-runtime": "Verify sealed runtime, SDK and recovery readiness",
    "device-cycle": "Verify the controlled device cycle",
}


class HandoffError(Exception):
    pass


def gh(*args):
    try:
        result = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HandoffError("GitHub CLI unavailable or timed out; check delivery and retry.") from exc
    if result.returncode:
        # Do not reflect environment, API payloads or credentials into logs.
        raise HandoffError("GitHub request failed; check authentication/access and retry.")
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise HandoffError("GitHub returned an invalid response.") from exc


def marker(release):
    return f"<!-- release-handoff:{release} -->"


def delivery_marker(gate):
    return f"<!-- release-handoff-notified:{gate} -->"


def validate(release, gate, prs, ready):
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.\d+)?", release):
        raise HandoffError("Use a version tag such as v1.2.3-rc.1.")
    if gate not in GATES or not ready:
        raise HandoffError("A known gate and explicit --ready confirmation are required.")
    if not prs or len(prs) > 20 or any(type(n) is not int or n <= 0 for n in prs):
        raise HandoffError("Supply 1 to 20 positive public PR numbers.")


def handoff(release, gate, prs, ready, api=gh):
    validate(release, gate, prs, ready)
    issue_marker = marker(release)
    title = f"Maintainer verification: {release}"
    issues = api("api", "--paginate", "--slurp", f"repos/{REPO}/issues?state=all&per_page=100")
    matches = [issue for page in issues for issue in page
               if "pull_request" not in issue and issue_marker in (issue.get("body") or "")]
    if len(matches) > 1:
        raise HandoffError("Multiple release checklists exist; reconcile them before retrying.")
    issue = matches[0] if matches else None
    if issue:
        if issue["user"]["login"] not in (OWNER, "github-actions[bot]"):
            raise HandoffError("The checklist author is not the trusted maintainer or workflow.")
        # A closed issue is a maintainer decision, never reopen it automatically.
        if issue["state"] != "open":
            raise HandoffError("The release checklist is closed; maintainer review is required.")
        if OWNER not in [a["login"] for a in issue.get("assignees", [])]:
            raise HandoffError("The checklist no longer has the maintainer assigned.")
        comments = api("api", "--paginate", "--slurp", f"repos/{REPO}/issues/{issue['number']}/comments?per_page=100")
        delivered = delivery_marker(gate) in (issue.get("body") or "") or any(
            delivery_marker(gate) in (comment.get("body") or "")
            and comment["user"]["login"] in (OWNER, "github-actions[bot]")
            for page in comments for comment in page)
        if delivered:
            return {"issue": issue["number"], "notified": False}
    for number in sorted(set(prs)):
        pr = api("api", f"repos/{REPO}/pulls/{number}")
        if not pr.get("merged_at"):
            raise HandoffError("Every supporting PR must be merged before requesting verification.")
    references = ", ".join(f"#{number}" for number in sorted(set(prs)))
    request = (f"@{OWNER}: {GATES[gate]} for {release}.\n\n"
               f"The coordinator explicitly confirms this prerequisite is ready for your verification. "
               f"Supporting public changes: {references}.\n\n"
               "Record only a generic outcome here. Keep operational evidence private. "
               "This request does not perform checks or authorize activation, messaging or deployment.\n\n"
               f"- [ ] {GATES[gate]}\n\n{delivery_marker(gate)}")
    if issue:
        # One comment is both the notification and durable retry marker. No
        # separate issue edit can fail after delivery and cause a second mention.
        api("api", "--method", "POST", f"repos/{REPO}/issues/{issue['number']}/comments",
            "-f", f"body={request}")
        return {"issue": issue["number"], "notified": True}
    created = api("api", "--method", "POST", f"repos/{REPO}/issues",
                  "-f", f"title={title}", "-f", f"body={issue_marker}\n\n{request}",
                  "-f", f"assignees[]={OWNER}")
    return {"issue": created["number"], "notified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True)
    parser.add_argument("--gate", choices=GATES, required=True)
    parser.add_argument("--pr", type=int, action="append", required=True)
    parser.add_argument("--ready", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(handoff(args.release, args.gate, args.pr, args.ready)))
    except HandoffError as exc:
        parser.exit(1, f"Handoff failed: {exc}\n")


if __name__ == "__main__":
    main()
