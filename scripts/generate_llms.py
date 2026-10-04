#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the public documentation index from a reviewed file allowlist."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
RAW_BASE = "https://raw.githubusercontent.com/pboachie/zrotext/main/"
DOCUMENTS = (
    ("Project overview", "README.md"),
    ("Agent texting quickstart (simulator)", "docs/AGENT-QUICKSTART.md"),
    ("Local agent setup", "docs/agent-local-setup.md"),
    ("Local MCP tools", "docs/mcp-local-tools.md"),
    ("Agent recipes", "docs/agent-recipes.md"),
    ("Architecture and delivery outcomes", "docs/ARCHITECTURE.md"),
    ("Self-hosting", "docs/SELF-HOSTING.md"),
    ("SMS consent and compliance", "docs/SMS-COMPLIANCE.md"),
    ("Sealed API contract", "protocol/v1/sealed-api-v1.md"),
    ("Contributing", "CONTRIBUTING.md"),
)


def read_document(root: Path, relative: str) -> str:
    """Read only a declared public Markdown source, inside this checkout."""
    if relative not in {path for _, path in DOCUMENTS}:
        raise ValueError("document is not in the public allowlist")
    root = root.resolve()
    source = (root / relative).resolve()
    if not source.is_relative_to(root):
        raise ValueError("document resolves outside the repository")
    text = source.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"empty public document: {relative}")
    return text


def project_status(readme: str) -> str:
    """Keep the README's first project-status paragraph as the source of truth."""
    heading = "## Project status\n"
    if readme.count(heading) != 1:
        raise ValueError("README must have one Project status section")
    section = readme.split(heading, 1)[1].lstrip("\n")
    paragraph = section.split("\n\n", 1)[0]
    if not paragraph or paragraph.startswith("#"):
        raise ValueError("README Project status must start with a paragraph")
    return " ".join(paragraph.splitlines())


def render(root: Path = ROOT) -> str:
    documents = {path: read_document(root, path) for _, path in DOCUMENTS}
    lines = [
        "# ZROtext",
        "",
        "> Public documentation for the Android SMS gateway, in canonical Markdown.",
        "",
        "This index is generated from a fixed public-document allowlist. Follow each",
        "document's availability, authorization and verification limits. Simulator",
        "examples send no real SMS. An index or published artifact does not establish",
        "physical-device, carrier or provider acceptance.",
        "",
        "## Current status",
        "",
        project_status(documents["README.md"]),
        "",
        "## Documentation",
        "",
    ]
    lines.extend(f"- [{title}]({RAW_BASE}{path})" for title, path in DOCUMENTS)
    lines.extend(
        [
            "",
            "## Maintaining this index",
            "",
            "Run `python scripts/generate_llms.py` to regenerate, or add `--check`",
            "to verify the checked-in index. The linked Markdown files remain the",
            "canonical documentation; this index adds no API or execution authority.",
            "",
        ]
    )
    return "\n".join(lines)


def synchronize(root: Path = ROOT, *, check: bool = False) -> None:
    expected = render(root)
    output = root / "llms.txt"
    if output.is_symlink():
        raise ValueError("llms.txt must be a regular repository file")
    if check:
        if not output.is_file() or output.read_text(encoding="utf-8") != expected:
            raise ValueError("llms.txt is stale; run python scripts/generate_llms.py")
    else:
        output.write_bytes(expected.encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="refuse a stale index")
    args = parser.parse_args()
    try:
        synchronize(check=args.check)
    except (OSError, UnicodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Public documentation index is current" if args.check else "Generated llms.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
