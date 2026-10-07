# SPDX-License-Identifier: AGPL-3.0-only
"""Keeps the hosted billing portal scenario ledger tied to real tests (#676)."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "STRIPE-TEST-PORTAL-SCENARIOS.md"
STATUSES = {"source", "gap", "live-unverified"}
REQUIRED = (
    "card update", "invoice access", "cancellation", "spoofed", "cross-tenant",
    "stale ui", "offline", "retry budget", "self-hosted", "restricted",
)


def rows():
    found = []
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if line.startswith("|") and len(cells) == 3 and cells[1] in STATUSES:
            found.append(cells)
    return found


def declared(source, name):
    return re.search(
        r"(?:fn\s+%s\s*\(|test\(\s*[\"']%s[\"'])" % (re.escape(name), re.escape(name)),
        source,
    ) is not None


class BillingPortalScenarioLedger(unittest.TestCase):
    def test_every_issue_scenario_has_a_row(self):
        text = " ".join(row[0].lower() for row in rows())
        for needle in REQUIRED:
            self.assertIn(needle, text)

    def test_source_rows_name_existing_tests(self):
        checked = 0
        for scenario, status, evidence in rows():
            if status != "source":
                self.assertEqual(evidence, "none" if status == "live-unverified" else "none identified", scenario)
                continue
            path, _, name = evidence.partition("::")
            file = ROOT / path
            self.assertTrue(file.is_file(), f"{scenario}: missing {path}")
            self.assertTrue(declared(file.read_text(encoding="utf-8"), name), f"{scenario}: no test {name!r} in {path}")
            checked += 1
        self.assertGreater(checked, 0)

    def test_ledger_makes_no_live_claim(self):
        self.assertIn("No row below was exercised against Stripe TEST", LEDGER.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
