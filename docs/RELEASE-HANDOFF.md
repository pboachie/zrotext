# Maintainer verification handoff

When a prerequisite is actually ready for maintainer verification, the coordinator
runs **Request maintainer release verification** on `main`. Select the release tag,
one ready gate, a supporting merged public PR number, and the readiness confirmation.
This is an explicit coordinator handoff, not automatic inference from roadmap
stages, CI success, task leases or PR merges. Do not request checks prematurely.

The workflow creates one release checklist assigned to `pboachie`, with an explicit
mention. Each additional ready gate gets one checklist comment with a mention.
Repeated handoffs for the same release and gate do not notify again. Routine
updates do not run this workflow. A closed checklist or changed assignment requires
maintainer review; the workflow never reopens it. Workflow concurrency serializes
handoffs for the same release. Use the workflow rather than concurrent local calls.
Only maintainer- or workflow-authored checklists participate in deduplication;
markers in other contributors' issues are ignored.

The coordinator can invoke it with the GitHub CLI:

```sh
gh workflow run release-handoff.yml --ref main -f release=v1.2.3-rc.1 -f gate=release-candidate -f pr=123 -f ready=true
```

Check the workflow result: an unsuccessful run means delivery is unconfirmed.
Retry the same request after resolving access or API failures. A persisted issue
or comment marker makes a retry silent even if the original response was lost.
Deleting or editing delivery markers removes that guarantee. The script rejects
unmerged supporting PRs and does not accept free-form text or external links.

Public output contains only a version, generic action, and public PR references.
Keep device, SIM, credentials, infrastructure, customer details, operational
procedures, private evidence and security findings outside public issues. The
maintainer owns verification and records only a generic result here; the handoff
does not execute checks, enable sending, activate devices or deploy anything.

Assignment and mentions request GitHub delivery; email, push and inbox behavior
still depend on the maintainer's GitHub notification preferences. CODEOWNERS
review routing is separate and cannot detect that a launch prerequisite is ready.
