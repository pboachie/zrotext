#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the public documentation index from a reviewed file allowlist."""

import argparse
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import privacy_guard  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RAW_BASE = "https://raw.githubusercontent.com/pboachie/zrotext/main/"
DOCUMENTS = (
    ("Project overview", "README.md", "What ZROtext is, its development status and how to run the local stack."),
    ("Agent texting quickstart (simulator)", "docs/AGENT-QUICKSTART.md", "Local walkthrough of the agent send flow against the simulator; sends no real SMS."),
    ("Send-first-message examples (restricted)", "docs/SEND-FIRST-MESSAGE.md", "Synthetic-alpha submit/status and webhook examples tested with local stubs and vectors; no general send route."),
    ("Public HTTP API reference", "docs/API-REFERENCE.md", "Generated current-route and planned-operation reference; outbound examples use the restricted synthetic-alpha plane."),
    ("Guarded agent send tools (simulator)", "docs/agent-send-guardrails.md", "Experimental local MCP guardrails with owner approval, idempotency and limits; simulator only, sends no real SMS."),
    ("Local agent setup", "docs/agent-local-setup.md", "Setting up a local development stack for agent testing."),
    ("Local MCP tools", "docs/mcp-local-tools.md", "Local Model Context Protocol tools for the development stack."),
    ("Agent recipes", "docs/agent-recipes.md", "Worked examples for agents using the local tools."),
    ("Architecture and delivery outcomes", "docs/ARCHITECTURE.md", "How the server, PostgreSQL store, WebSocket device stream and Android app fit together."),
    ("Delivery state model", "docs/DELIVERY-STATES.md", "Message delivery states and which evidence moves a message between them."),
    ("Self-hosting", "docs/SELF-HOSTING.md", "Running the Compose stack on your own infrastructure; development use, no hosted service."),
    ("SMS consent and compliance", "docs/SMS-COMPLIANCE.md", "Consent, opt-out and carrier-rule responsibilities for senders."),
    ("Roadmap", "docs/ROADMAP.md", "Stage of each capability; stages show progress, not availability or release dates."),
    ("Public HTTP API contract (OpenAPI)", "protocol/v1/openapi/public-v1.json", "Machine-readable contract for the public routes as the server implements them; planned routes are labeled."),
    ("Protocol v1 overview", "protocol/v1/README.md", "Index of protocol v1 schemas, vectors and contract documents."),
    ("Sealed API contract", "protocol/v1/sealed-api-v1.md", "Sealed-content API contract."),
    ("Security policy", "SECURITY.md", "How to report a vulnerability privately."),
    ("Contributing", "CONTRIBUTING.md", "Contribution rules, DCO sign-off and the checks CI runs."),
)


def read_document(root: Path, relative: str) -> str:
    """Read only a declared public Markdown source, inside this checkout."""
    if relative not in {path for _, path, _ in DOCUMENTS}:
        raise ValueError("document is not in the public allowlist")
    root = root.resolve()
    source = (root / relative).resolve()
    if not source.is_relative_to(root):
        raise ValueError("document resolves outside the repository")
    text = source.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"empty public document: {relative}")
    for number, line in enumerate(text.splitlines(), 1):
        if privacy_guard.scan_line(line, hygiene=False):
            # Never echo the line or the matched value.
            raise ValueError(f"privacy guard rejected {relative} line {number}")
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
    paragraph = " ".join(paragraph.splitlines())
    # Relative links would not resolve from a raw-text consumer.
    return re.sub(r"\]\((?![a-z][a-z0-9+.-]*:|#|/)([^)\s]+)\)", lambda m: f"]({RAW_BASE}{m[1]})", paragraph)


def render(root: Path = ROOT) -> str:
    documents = {path: read_document(root, path) for _, path, _ in DOCUMENTS}
    lines = [
        "# ZROtext",
        "",
        "> Public documentation and API contract for the Android SMS gateway, in canonical source form.",
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
    lines.extend(f"- [{title}]({RAW_BASE}{path}): {note}" for title, path, note in DOCUMENTS)
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
