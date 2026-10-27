# SPDX-License-Identifier: AGPL-3.0-only
"""Keep browser provisioning and complete acceptance separately bounded."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def owner_browser(source):
    match = re.search(r"^  owner-browser:\n(.*?)(?=^  [\w-]+:|\Z)", source, re.M | re.S)
    if not match:
        raise AssertionError("missing owner browser job")
    return match.group(1)


def validate(source):
    job = owner_browser(source)
    if re.search(r"^\s+(?:if|continue-on-error|shell):", job, re.M):
        raise AssertionError("acceptance must run and fail normally")
    outer = re.findall(r"^    timeout-minutes: (\d+)$", job, re.M)
    steps = re.split(r"^      - ", job, flags=re.M)[1:]
    limits = []
    for step in steps:
        bound = re.findall(r"^        timeout-minutes: (\d+)$", step, re.M)
        if len(bound) != 1 or not 1 <= int(bound[0]) <= 10:
            raise AssertionError("every stage needs a finite bound")
        limits.append(int(bound[0]))
    if len(outer) != 1 or not 1 <= int(outer[0]) <= 30 or sum(limits) >= int(outer[0]):
        raise AssertionError("outer limit must cover all independent stage budgets")
    if len(steps) != 5:
        raise AssertionError("unexpected stage coverage")
    prepare, provision, acceptance = steps[2:]
    if re.findall(r"^          (.+)$", prepare, re.M) != [
        "(cd sdk/typescript && npm ci --ignore-scripts && npm run build)",
        "(cd web/owner && npm ci --ignore-scripts)",
    ]:
        raise AssertionError("missing dependency preparation")
    if "working-directory: web/owner" not in provision or re.findall(r"^        run: (.+)$", provision, re.M) != ["npx playwright install --with-deps chromium"]:
        raise AssertionError("missing complete browser provisioning")
    if re.findall(r"^          (.+)$", acceptance, re.M) != [
        "node --test web/owner/*.test.js",
        "(cd web/owner && npm run test:rendered)",
        "(cd sdk/typescript && npm ci --ignore-scripts && npm test)",
    ]:
        raise AssertionError("missing acceptance coverage")
    if limits[3:] != [10, 10]:
        raise AssertionError("provisioning and acceptance need separate full windows")
    if "persist-credentials: false" not in steps[0]:
        raise AssertionError("checkout credentials must not persist")


class OwnerBrowserCiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    def test_provisioning_and_all_acceptance_fit_independent_bounded_windows(self):
        validate(self.source)

    def test_shared_old_window_or_unbounded_stage_is_rejected(self):
        job = owner_browser(self.source)
        for broken in (
            job.replace("timeout-minutes: 30", "timeout-minutes: 10", 1),
            job.replace("        timeout-minutes: 10\n", "", 1),
        ):
            with self.subTest(broken=broken[:30]), self.assertRaises(AssertionError):
                validate("  owner-browser:\n" + broken)

    def test_missing_suite_or_conditional_failure_bypass_is_rejected(self):
        job = owner_browser(self.source)
        for broken in (
            job.replace("npm run test:rendered", "echo omitted"),
            job.replace("npm ci --ignore-scripts && npm test", "echo omitted"),
            job.replace("npm run test:rendered)", "npm run test:rendered || true)"),
            job.replace("        timeout-minutes: 10\n", "        if: false\n        timeout-minutes: 10\n", 1),
            job.replace("        timeout-minutes: 10\n", "        continue-on-error: true\n        timeout-minutes: 10\n", 1),
        ):
            with self.subTest(broken=broken[:30]), self.assertRaises(AssertionError):
                validate("  owner-browser:\n" + broken)


if __name__ == "__main__":
    unittest.main()
