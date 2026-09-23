#!/usr/bin/env python3
"""Fail on high-confidence private data and text hygiene errors in tracked files."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

TEXT_SUFFIXES = {".bat", ".css", ".html", ".js", ".json", ".kt", ".kts", ".md", ".pem", ".properties", ".py", ".rs", ".sh", ".sql", ".svg", ".toml", ".xml", ".yaml", ".yml"}
TEXT_NAMES = {".dockerignore", ".editorconfig", ".env.example", ".gitignore", "CODEOWNERS", "DCO", "Dockerfile", "LICENSE"}
SECRET_PATTERNS = {
    "credential-shaped token": re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b|\bcfat_[A-Za-z0-9]{20,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAKIA[A-Z0-9]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "SMTP password value": re.compile(r"(?i)\bSMTP_PASS\s*[:=]\s*['\"]?(?!\$\{|\$|<|example|changeme|your-|placeholder|\s*$)[^\s'\"]{8,}"),
    "personal Windows path": re.compile(r"(?i)\b[A-Z]:[/\\]Users[/\\](?!<|\$\{|%|example|user[/\\])[^/\\\s]+"),
}
PHONE = re.compile(r"(?<![A-Za-z0-9])(?:\+1[-. ]?)?([2-9]\d{2})[-. ]?([2-9]\d{2})[-. ]?(\d{4})(?![A-Za-z0-9])")


def looks_synthetic(number: re.Match[str]) -> bool:
    area, exchange, subscriber = number.groups()
    return area == "555" or (exchange == "555" and 100 <= int(subscriber) <= 199)


def scan_line(line: str) -> list[str]:
    problems = [label for label, pattern in SECRET_PATTERNS.items() if pattern.search(line)]
    if any(not looks_synthetic(match) for match in PHONE.finditer(line)):
        problems.append("non-synthetic US phone number")
    if line.rstrip(" \t") != line:
        problems.append("trailing whitespace")
    return problems


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    errors: list[str] = []
    for raw_path in paths:
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8", "surrogateescape")
        path = root / relative
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in TEXT_NAMES:
            continue
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            content = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            errors.append(f"{relative}: invalid UTF-8")
            continue
        for number, line in enumerate(content.splitlines(), 1):
            for issue in scan_line(line):
                errors.append(f"{relative}:{number}: {issue}")
        if content and not content.endswith("\n"):
            errors.append(f"{relative}: missing final newline")
    if errors:
        print("Public-tree hygiene failed (matched values are intentionally hidden):", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Public-tree hygiene passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
