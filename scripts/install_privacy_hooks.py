#!/usr/bin/env python3
"""Opt-in shared-worktree hooks; refuse to replace existing active hooks."""
import argparse
import shutil
import shlex
import subprocess
import sys
from pathlib import Path


def run(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    created = None
    installed = False
    try:
        common = Path(run("rev-parse", "--git-common-dir")).resolve()
        configured = subprocess.run(["git", "config", "--get", "core.hooksPath"], capture_output=True)
        if configured.returncode == 0:
            raise RuntimeError("Existing core.hooksPath must be reviewed manually; no changes made.")
        if configured.returncode != 1:
            raise RuntimeError("Cannot inspect hook configuration.")
        defaults = common / "hooks"
        if defaults.exists() and any(p.is_file() and not p.name.endswith(".sample") for p in defaults.iterdir()):
            raise RuntimeError("Active default hooks exist; integrate manually without replacing them.")
        destination = common / "privacy-hooks"
        if destination.exists():
            raise RuntimeError("Managed hook directory already exists; review updates manually.")
        if args.dry_run:
            print("Installation checks passed; shared hooks would protect every worktree of this repository.")
            return 0
        destination.mkdir()
        created = destination
        scanner = Path(__file__).with_name("privacy_guard.py")
        shutil.copyfile(scanner, destination / "privacy_guard.py")
        for name, mode in (("pre-commit", '--index'), ("pre-push", '--pre-push --remote "$1"'), ("commit-msg", '--message-file "$1"')):
            hook = destination / name
            hook.write_text('#!/bin/sh\nset -eu\n'
                            'hook_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
                            'exec ' + shlex.quote(Path(sys.executable).as_posix()) +
                            ' "$hook_dir/privacy_guard.py" --repo "$(git rev-parse --show-toplevel)" ' + mode + '\n', encoding="utf-8", newline="\n")
            hook.chmod(0o755)
        # A common-directory absolute path also works on branches lacking these
        # scripts. Installation affects only this public repository's worktrees.
        subprocess.run(["git", "config", "--local", "core.hooksPath", destination.as_posix()], check=True, capture_output=True)
        installed = True
        print("Privacy hooks installed for all worktrees; scanner copied outside branch files.")
        return 0
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        if isinstance(error, RuntimeError):
            print(str(error), file=sys.stderr)
        else:
            print("Hook installation failed; inspect Git configuration locally (details hidden).", file=sys.stderr)
        return 1
    finally:
        if created is not None and not installed:
            # Only remove files this installation owns, never existing hooks.
            try:
                for name in ("privacy_guard.py", "pre-commit", "pre-push", "commit-msg"):
                    (created / name).unlink(missing_ok=True)
                created.rmdir()
            except OSError:
                print("Incomplete installation cleanup; inspect the common Git directory locally.", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
