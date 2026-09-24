#!/usr/bin/env python3
"""Scan Git objects, never unstaged files; hide matched values and filenames."""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

TEXT_SUFFIXES = {".bat", ".css", ".html", ".js", ".json", ".kt", ".kts", ".md", ".pem", ".properties", ".ps1", ".py", ".rs", ".sh", ".sql", ".svg", ".toml", ".txt", ".xml", ".yaml", ".yml"}
TEXT_NAMES = {".dockerignore", ".editorconfig", ".env.example", ".gitignore", "CODEOWNERS", "DCO", "Dockerfile", "LICENSE"}
SECRET_PATTERNS = {
    "credential-shaped token": re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b|\bcfat_[A-Za-z0-9]{20,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b|\bAKIA[A-Z0-9]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "age recovery key": re.compile(r"\bAGE-SECRET-KEY-1[A-Z0-9]{40,}\b"),
    "personal Windows path": re.compile(r"(?i)\b[A-Z]:[/\\]+Users[/\\]+(?!<|\$\{|%)[^/\\\s]+"),
    "absolute machine folder": re.compile(r"(?i)\b[A-Z]:[/\\]+(?!Users[/\\]+(?:<|\$\{|%))(?!<|\$\{|%)[A-Za-z0-9_.-]+(?:[/\\]|\b)"),
    "personal Unix path": re.compile(r"(?<![A-Za-z0-9])/(?:home|Users|root|mnt|media)/(?!<|\$\{)[A-Za-z0-9_.-]+(?:/|\b)"),
    "machine network folder": re.compile(r"(?<!\\)\\{2,}[A-Za-z0-9][A-Za-z0-9_.-]*\\+[^\\\s]+"),
}
PHONE = re.compile(r"(?<![A-Za-z0-9])(?:\+1[-. ]?)?([2-9]\d{2})[-. ]?([2-9]\d{2})[-. ]?(\d{4})(?![A-Za-z0-9])")
ASSIGNMENT_VALUE = r'''"[^"\n]*"|'[^'\n]*'|(?:\$\{\{[^\r\n]*?\}\}|\$\{[^}\r\n]*\}|<[^>\r\n]*>)[^\s,;}]*|[^\s,;}]*'''
ASSIGNMENT = re.compile(r'''(?:^|[\s{,;])(?:export\s+|\$env:)?["']?([A-Z][A-Z0-9_]*)["']?\s*[:=]\s*(''' + ASSIGNMENT_VALUE + ")")
CONFIG_ASSIGNMENT = re.compile(ASSIGNMENT.pattern, re.IGNORECASE)
SENSITIVE_NAME = re.compile(r"(?:^|_)(?:PASSWORD|PASS|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY|PEPPER)(?:_|$)")
URI_PASSWORD = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:]+:([^\s@]+)@", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(prefix) for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
ZERO = "0" * 40

DIAGNOSTIC_MESSAGES = {
    "credential-shaped token": "credential-shaped token",
    "private key": "private key",
    "age recovery key": "age recovery key",
    "personal Windows path": "personal Windows path",
    "absolute machine folder": "absolute machine folder",
    "personal Unix path": "personal Unix path",
    "machine network folder": "machine network folder",
    "embedded credential assignment": "embedded credential assignment",
    "credential-bearing URL": "credential-bearing URL",
    "non-synthetic US phone number": "non-synthetic US phone number",
    "private infrastructure address": "private infrastructure address",
    "trailing whitespace": "trailing whitespace",
    "invalid text encoding": "invalid text encoding",
    "invalid UTF-8": "invalid UTF-8",
    "missing final newline": "missing final newline",
}


def diagnostic_text(code: str) -> str:
    # Only closed literal labels can cross into a log; never echo an unknown
    # string, even if a future detector accidentally returns matched content.
    return DIAGNOSTIC_MESSAGES.get(code, "unclassified privacy violation")


def placeholder(value: str, *, source: bool = False) -> bool:
    if value in {"", "example", "placeholder", "changeme", "your-password", "your-token", "your-api-key",
                 "replace-with-a-secret", "replace-with-a-long-random-local-secret"}:
        return True
    patterns = (
        r"<[^<>\r\n]+>",
        r"%[A-Z_][A-Z0-9_]*%",
        r"\$\{[A-Z_][A-Z0-9_]*(?::-|:\?[^{}\r\n]*)?\}",
        r"\$\{\{\s*(?:(?:secrets|vars|env)\.[A-Z_][A-Z0-9_]*|github\.token)\s*\}\}",
    )
    return any(re.fullmatch(pattern, value) for pattern in patterns) or bool(source and re.fullmatch(r"\$[A-Z_][A-Z0-9_]*", value))


def literal_value(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith(("#", "//")):
        return ""
    if raw[0] in "\"'":
        return raw[1:].split(raw[0], 1)[0]
    if raw.startswith(("${", "<")):
        return raw
    value = raw.split()[0].rstrip(",;")
    return value


def looks_synthetic(number: re.Match[str]) -> bool:
    area, exchange, subscriber = number.groups()
    return area == "555" or (exchange == "555" and 100 <= int(subscriber) <= 199)


def source_url_reference(password: str, line: str) -> bool:
    if password.startswith("{"):
        return True  # Source interpolation, not a literal password.
    return password in {"pass", "private"} and bool(re.search(r"@(?:[\w-]+\.)*example\.(?:org|com|net)(?:/|:)", line))


def scan_line(line: str, *, infrastructure: bool = False, hygiene: bool = True, source: bool = False, fixture: bool = False) -> list[str]:
    problems = [label for label, pattern in SECRET_PATTERNS.items() if pattern.search(line)]
    assignments = ASSIGNMENT if source else CONFIG_ASSIGNMENT
    for assignment in assignments.finditer(line):
        if not SENSITIVE_NAME.search(assignment[1].upper()):
            continue
        value = literal_value(assignment[2])
        env_name = bool(re.fullmatch(r"(?:[A-Z][A-Z0-9]*_){2,}(?:PASSWORD|SECRET|TOKEN|API_KEY|KEY)", value or ""))
        extra_name = assignment[1].startswith("EXTRA_") and value == assignment[1][6:].lower()
        reference = source and (not assignment[2].lstrip().startswith(('"', "'")) or env_name or extra_name)
        synthetic = fixture and value in {"store-password", "key-password", "future-secret"}
        if value is not None and not placeholder(value, source=source) and not reference and not synthetic:
            problems.append("embedded credential assignment")
    if any(not placeholder(match[1], source=source) and not (source and source_url_reference(match[1], line))
           for match in URI_PASSWORD.finditer(line)):
        problems.append("credential-bearing URL")
    if any(not looks_synthetic(match) for match in PHONE.finditer(line)):
        problems.append("non-synthetic US phone number")
    if infrastructure:
        for candidate in IPV4.finditer(line):
            try:
                address = ipaddress.ip_address(candidate[0])
            except ValueError:
                continue
            if any(address in network for network in PRIVATE_NETWORKS):
                problems.append("private infrastructure address")
                break
    if hygiene and line.rstrip(" \t") != line:
        problems.append("trailing whitespace")
    return problems


def forbidden_path(relative: str) -> bool:
    parts = PurePosixPath(relative.lower()).parts
    name = parts[-1]
    return (".local" in parts or any(part in {"credentials", "secret-vault"} for part in parts)
            or name == ".env" or (name.startswith(".env.") and name != ".env.example")
            or bool(re.search(r"(?:^|[._-])credentials?(?:[._-]|$)", name))
            or bool(re.search(r"(?:^|[._-])(?:recovery|age)[._-](?:key|codes?)(?:[._-]|$)", name))
            or name.endswith((".dpapi", ".pfx", ".p12", ".jks", ".keystore", ".agekey", ".key")))


def infrastructure_file(relative: str) -> bool:
    path = PurePosixPath(relative)
    # Source IP-validation tests legitimately contain RFC1918 addresses. Private
    # operational endpoints in docs/config should use RFC5737 examples instead.
    fixture = any(part in {"tests", "fixtures", "testdata"} for part in path.parts) or path.name.startswith("test_")
    return not fixture and (path.suffix.lower() in {".md", ".yaml", ".yml", ".toml", ".ini", ".conf", ".env"} or path.name.startswith(".env"))


class GitError(Exception):
    pass


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise GitError("Git lookup failed")
    return result.stdout


def resolve(root: Path, ref: str) -> str:
    return git(root, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()


def entries(root: Path, tree: str | None) -> list[tuple[str, str, str]]:
    records = git(root, "ls-tree", "-rz", "--full-tree", tree) if tree else git(root, "ls-files", "--stage", "-z")
    result = []
    for record in records.split(b"\0"):
        if not record:
            continue
        info, path = record.split(b"\t", 1)
        mode, kind_or_oid, oid_or_stage = info.decode().split()
        if tree:
            oid = oid_or_stage
        else:
            if oid_or_stage != "0":
                raise GitError("Unmerged index")
            oid = kind_or_oid
        result.append((path.decode("utf-8", "surrogateescape"), oid, mode))
    return result


def scan_blob(relative: str, data: bytes) -> list[tuple[int, str]]:
    path = PurePosixPath(relative)
    hygiene = path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            content = data.decode("utf-16")
        except UnicodeDecodeError:
            return [(0, "invalid text encoding")]
    elif b"\0" in data:
        # Binary containers are not fully inspectable; plaintext markers still are.
        text = data.decode("utf-8", "replace")
        return [(0, label) for label, pattern in SECRET_PATTERNS.items()
                if label in {"credential-shaped token", "private key", "age recovery key"} and pattern.search(text)]
    else:
        try:
            content = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return [(0, "invalid UTF-8")] if hygiene else []
    source = path.suffix.lower() in {".py", ".rs", ".kt", ".kts", ".js", ".ts"}
    fixture = path.name.startswith("test_") or any(part in {"tests", "fixtures", "testdata"} for part in path.parts)
    errors = [(number, issue) for number, line in enumerate(content.splitlines(), 1)
              for issue in scan_line(line, infrastructure=infrastructure_file(relative), hygiene=hygiene, source=source, fixture=fixture)]
    if hygiene and content and not content.endswith("\n"):
        errors.append((0, "missing final newline"))
    return errors


def scan_snapshot(root: Path, tree: str | None, cache: dict) -> list[str]:
    errors = []
    label = tree[:12] if tree else "index"
    if tree:
        message = git(root, "show", "-s", "--format=%B", tree)
        errors.extend(f"{label}:commit-message:line-{line}: {diagnostic_text(issue)}"
                      for line, issue in scan_blob("message.md", message))
    files = entries(root, tree)
    pending = list(dict.fromkeys(oid for relative, oid, mode in files if mode != "160000" and blob_key(relative, oid) not in cache))
    blobs = read_blobs(root, pending)
    for number, (relative, oid, mode) in enumerate(files, 1):
        # Names may themselves be private. Ordinals identify entries without
        # exposing paths in public CI output (see the local lookup in the docs).
        location = f"{label}:entry-{number}"
        if forbidden_path(relative):
            errors.append(f"{location}: forbidden tracked filename")
        if scan_line(relative, hygiene=False):
            errors.append(f"{location}: private data in filename")
        if mode == "160000":
            errors.append(f"{location}: uninspected submodule")
            continue
        key = blob_key(relative, oid)
        if key not in cache:
            cache[key] = scan_blob(relative, blobs[oid])
        errors.extend(f"{location}:line-{line}: {diagnostic_text(issue)}" for line, issue in cache[key])
    return errors


def blob_key(relative: str, oid: str) -> tuple:
    path = PurePosixPath(relative)
    return oid, relative


def read_blobs(root: Path, oids: list[str]) -> dict[str, bytes]:
    if not oids:
        return {}
    result = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"],
                            input=("\n".join(oids) + "\n").encode(), capture_output=True)
    if result.returncode:
        raise GitError("Cannot read blobs")
    offset, blobs = 0, {}
    for oid in oids:
        end = result.stdout.index(b"\n", offset)
        header = result.stdout[offset:end].split()
        if len(header) != 3 or header[1] != b"blob":
            raise GitError("Missing blob")
        size = int(header[2])
        blobs[oid] = result.stdout[end + 1:end + 1 + size]
        offset = end + size + 2
    return blobs


def commits(root: Path, base: str, head: str) -> list[str]:
    head = resolve(root, head)
    if base and set(base) != {"0"}:
        base = resolve(root, base)
        return git(root, "rev-list", "--reverse", head, "^" + base).decode().splitlines()
    return git(root, "rev-list", "--reverse", head).decode().splitlines()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--remote", help="Remote name for pre-push new-ref ancestry")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--index", action="store_true", help="Scan index blobs (default)")
    modes.add_argument("--tree", metavar="REF")
    modes.add_argument("--range", nargs=2, metavar=("BASE", "HEAD"), help="Every introduced commit tree")
    modes.add_argument("--history", metavar="HEAD")
    modes.add_argument("--pre-push", action="store_true", help="Read Git ref updates from stdin")
    modes.add_argument("--ci", action="store_true", help="Use PRIVACY_BASE_SHA / PRIVACY_HEAD_SHA")
    modes.add_argument("--message-file", type=Path, help="Check pending commit message")
    args = parser.parse_args(argv)
    try:
        root = Path(git(args.repo, "rev-parse", "--show-toplevel").decode().strip())
        if args.message_file:
            issues = scan_blob("message.md", args.message_file.read_bytes())
            if issues:
                print("Commit message rejected (values hidden): " + ", ".join(sorted({diagnostic_text(issue) for _, issue in issues})), file=sys.stderr)
                return 1
            return 0
        if args.pre_push:
            snapshots = []
            for update in sys.stdin:
                fields = update.split()
                if len(fields) != 4:
                    raise GitError("Malformed ref update")
                _, local_sha, _, remote_sha = fields
                if set(local_sha) != {"0"}:
                    if set(remote_sha) == {"0"} and args.remote and re.fullmatch(r"[A-Za-z0-9_.-]+", args.remote):
                        published = git(root, "for-each-ref", "--format=%(objectname)", "refs/remotes/" + args.remote + "/").decode().splitlines()
                        head = resolve(root, local_sha)
                        snapshots.extend(git(root, "rev-list", "--reverse", head, *("^" + sha for sha in published)).decode().splitlines())
                    else:
                        snapshots.extend(commits(root, remote_sha, local_sha))
        elif args.ci:
            base, head = os.environ.get("PRIVACY_BASE_SHA"), os.environ.get("PRIVACY_HEAD_SHA")
            if not base or not head:
                raise GitError("Missing CI commit boundaries")
            snapshots = commits(root, base, head)
        elif args.range:
            snapshots = commits(root, *args.range)
        elif args.history:
            snapshots = commits(root, ZERO, args.history)
        elif args.tree:
            snapshots = [resolve(root, args.tree)]
        else:
            snapshots = [None]
        errors = []
        cache: dict = {}
        for snapshot in dict.fromkeys(snapshots):
            errors.extend(scan_snapshot(root, snapshot, cache))
        if errors:
            print("Public-tree hygiene failed (values and filenames hidden):", file=sys.stderr)
            print("\n".join(errors), file=sys.stderr)
            return 1
        print(f"Public-tree hygiene passed ({len(set(snapshots))} snapshots).")
        return 0
    except (GitError, OSError, ValueError, UnicodeError):
        print("Public-tree scan failed closed: Git history/index unavailable or invalid; private details hidden.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
