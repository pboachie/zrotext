# SPDX-License-Identifier: AGPL-3.0-only
"""Full ignored-library CI callers must provision the isolated control inputs."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
VARIABLES = ("ZT_REGISTERED_OWNER_EMPTY_DATABASE_URL", "ZT_REGISTERED_OWNER_MFA_DATABASE_URL")


class RegisteredControlProvisioningTest(unittest.TestCase):
    def test_every_full_ignored_library_caller_provisions_both_explicit_urls(self):
        callers = []
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            source = path.read_text(encoding="utf-8")
            jobs = re.split(r"(?m)^  ([a-z][a-z0-9-]*):\s*$", source.split("\njobs:\n", 1)[-1])
            for name, block in zip(jobs[1::2], jobs[2::2]):
                for command in re.findall(r"(?m)^.*(?:cargo test --locked --workspace.*--ignored|python3 scripts/ci_rust_postgresql\.py run).*$", block):
                    if "--bins" in command or "--doc" in command:
                        continue  # Those disjoint target sets cannot run library controls.
                    callers.append((path.name, name))
                    for variable in VARIABLES:
                        self.assertIn(variable + ": postgresql://zt_registered_control@", block)
                    self.assertIn("psql -U postgres -d postgres -v ON_ERROR_STOP=1 < scripts/registered_control_databases.sql", block)
                    self.assertLess(block.index("< scripts/registered_control_databases.sql"), block.index(command.strip().removeprefix("run: ")))
                    if "ci_rust_postgresql.py run" in command:
                        helper = (ROOT / "scripts/ci_rust_postgresql.py").read_text(encoding="utf-8")
                        self.assertIn('return args + ["--test-threads=4"]', helper)
                        self.assertIn("--lane", command)
                        if name == "rust-postgresql":
                            self.assertIn("lane: [delivery-store, server-0, server-1]", block)
                            self.assertIn("max-parallel: 3", block)
                        elif name == "conversation-postgresql-lanes":
                            self.assertIn("lane: [delivery-store, server-0, server-1, remaining]", block)
                            self.assertIn("max-parallel: 3", block)
                            self.assertIn("needs: [conversation-workspace]", block)
                    else:
                        self.assertIn("--test-threads=4", command)
                    self.assertIn("SHOW max_locks_per_transaction", block)
                    self.assertIn("max_locks_per_transaction = '256'", block)
                    self.assertIn("npm ci --ignore-scripts && npm run build", block)
        self.assertEqual(set(callers), {("ci.yml", "rust-workspace"), ("ci.yml", "rust-postgresql"),
                                       ("conversation-simulator.yml", "conversation-postgresql-lanes")})

    def test_fresh_fixture_provisioning_does_not_grant_runtime_elevation_or_force_cleanup(self):
        source = (ROOT / "scripts/registered_control_databases.sql").read_text(encoding="utf-8")
        sql = re.sub(r"--[^\n]*", "", source).upper()
        for restriction in ["NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION", "NOBYPASSRLS"]:
            self.assertIn(restriction, sql)
        self.assertEqual(sql.count("CREATE DATABASE"), 2)
        self.assertNotRegex(sql, r"\b(?:GRANT|DROP|ALTER|FORCE|PG_TERMINATE_BACKEND|PG_CANCEL_BACKEND)\b")
        self.assertEqual(sql.count("OWNER ZT_REGISTERED_CONTROL"), 2)


if __name__ == "__main__":
    unittest.main()
