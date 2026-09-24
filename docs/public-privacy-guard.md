# Public repository privacy checks

Public source must not contain operator credentials, personal machine folders, or
private infrastructure inventories. Keep local operations outside the repository;
the ignored `.local/` directory is also forbidden in tracked Git trees. `.gitignore`
is not a security boundary: forced additions are checked too.

## Install and run

Python 3.10 or newer and Git are required. From any worktree of this public repo:

```sh
python scripts/install_privacy_hooks.py --dry-run
python scripts/install_privacy_hooks.py
python scripts/check_public_tree.py --index
python scripts/check_public_tree.py --range origin/main HEAD
python scripts/check_public_tree.py --tree HEAD
```

The installer refuses to replace active hooks or an existing `core.hooksPath`.
It copies the scanner and pre-commit, commit-msg, and pre-push hooks into Git's
common directory, then sets repository-local `core.hooksPath`. This protects linked
worktrees and older branches without relying on scripts in their checkout. It uses
the Python interpreter that performed installation; if Python moves, review and
reinstall the hooks. A per-worktree override of `core.hooksPath` can supersede the
shared setting and must be removed or integrated by the operator. Existing custom
hooks must be integrated manually; the installer never silently discards them.

Installed code is a snapshot. After scanner changes, review the installed copy and
update it deliberately; updating a branch alone does not update shared hooks.
Keep private operational tooling out of this public repository.

## What is checked

- Pre-commit reads the index's Git blobs, including unchanged tracked entries.
  Cleaning an unstaged file cannot hide a staged value.
- Commit-msg checks the proposed commit message for the same content patterns.
- Pre-push examines every introduced commit tree and message, including a leak
  added in one commit and removed in a later commit. Existing refs use their remote
  commit as the exclusion boundary. New refs exclude ancestry already reachable
  from fetched remote-tracking refs for that remote. Fetch before pushing; missing
  baselines cause a conservative full-history scan or a closed failure. Ref deletions
  introduce no content. Initial/orphan histories are scanned in full.
- Required CI `quality` checks scan both the current tree and every commit between
  the PR base/head or push before/after SHAs. Full history is fetched. Missing
  boundaries or objects fail the check rather than silently checking only the tip.

Filters cover credential-shaped tokens, private keys, literal environment-style
credential assignments, credential-bearing URLs, concrete Windows machine folders
and Unix home folders, UNC/WSL share paths, age recovery keys, non-synthetic phone
numbers, and forbidden tracked paths
such as `.local`, `.env` variants, credential stores, and key containers. `.env.example`
is allowed but its contents are checked. Standard service paths and explicit
placeholders remain valid. Private IPv4 endpoints in operational docs/config are
rejected; source IP-validation tests and address fixtures may use those ranges.
Other secret filters still run on fixtures. Use reserved documentation addresses
and phone numbers in examples.

Diagnostics contain only commit identifiers, entry ordinals, line numbers, and
rule names. Neither matched values nor filenames are printed because filenames
can themselves contain sensitive material. To locate an entry, inspect the same
ordered Git listing locally: `git ls-files --stage` for the index or
`git ls-tree -r --full-tree <commit>` for a commit. Count entries from one, and avoid
pasting that listing into public logs. Do not paste a matched value into an issue.

## Limits and required enforcement

Hooks prevent accidents on configured clones; they are bypassable (`--no-verify`,
configuration changes, or other clients). CI runs after a push, so CI alone cannot
prevent an initial disclosure to a remote. Pattern scanning cannot prove that all
private data is absent, and encrypted/binary containers or arbitrary encodings are
not fully inspected. Commit author identity is intentionally public Git metadata;
this guard does not redact it. Annotated-tag messages are not currently inspected.

Keep GitHub secret scanning and push protection enabled, require `quality` on the
protected branch, prevent bypasses, and review changes to the scanner/workflows.
Protection settings are server-side and must be verified by a repository owner;
this source change cannot enforce them by itself. For a guarantee that custom
privacy patterns are rejected before any Git object reaches public hosting, use a
controlled private intake remote with a server-side pre-receive check and publish
only approved history. No local hook can make an unconditional “never” guarantee.

If a secret was published, remove/rewrite affected history as appropriate **and
rotate the credential**. A later cleanup commit does not remove an earlier leak.
