# SPDX-License-Identifier: AGPL-3.0-only
"""Keep restore graph-fence fixtures quiescent without changing shared services."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("ci.yml", "conversation-simulator.yml")
VERIFY = "test \"$(docker exec \"$restore_container_id\" psql -U zrotext -d postgres -Atc 'SHOW autovacuum')\" = 'off'"


def require_quiescent_fixture(text):
    blocks = list(re.finditer(r'restore_container_id="\$\((docker run[\s\S]*?)\)"', text))
    assert len(blocks) == 1, "expected one dedicated restore container"
    block = blocks[0]
    invocation = block.group(1)
    for flag in ("--memory=1g", "--cpus=2", "--pids-limit=128",
                 "-c max_prepared_transactions=5", "-c max_locks_per_transaction=256",
                 "-c autovacuum=off", "-e POSTGRES_USER=zrotext",
                 "docker.io/library/postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"):
        assert len(re.findall(r"(?<!\S)" + re.escape(flag) + r"(?=\s|$)", invocation)) == 1, \
            "missing or changed fixture option: " + flag
    assert text.count("-c autovacuum=off") == 1, "shared services must retain their defaults"
    assert text.count(VERIFY) == 1, "effective autovacuum setting must be checked"
    runner = text.index("python3 scripts/ci_rust_postgresql.py run", block.end())
    assert block.end() < text.index(VERIFY) < runner, "check must precede the test runner"


class RestoreFixtureQuiescenceTests(unittest.TestCase):
    def test_both_workflows_validate_only_the_dedicated_fixture_before_tests(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow):
                require_quiescent_fixture((ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8"))

    def test_missing_or_enabled_autovacuum_setting_is_rejected(self):
        for workflow in WORKFLOWS:
            text = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
            for replacement in ("", "-c autovacuum=on"):
                with self.subTest(workflow=workflow, replacement=replacement):
                    with self.assertRaises(AssertionError):
                        require_quiescent_fixture(text.replace("-c autovacuum=off", replacement))

    def test_missing_or_late_effective_setting_check_is_rejected(self):
        for workflow in WORKFLOWS:
            text = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
            missing = text.replace(VERIFY, "")
            for changed in (missing, missing + "\n" + VERIFY):
                with self.subTest(workflow=workflow):
                    with self.assertRaises(AssertionError):
                        require_quiescent_fixture(changed)

    def test_resource_increase_or_shared_service_override_is_rejected(self):
        for workflow in WORKFLOWS:
            text = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
            for changed in (text.replace("--memory=1g", "--memory=2g"),
                            text + "\n-c autovacuum=off\n"):
                with self.subTest(workflow=workflow):
                    with self.assertRaises(AssertionError):
                        require_quiescent_fixture(changed)


if __name__ == "__main__":
    unittest.main()
