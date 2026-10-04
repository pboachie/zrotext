# SPDX-License-Identifier: AGPL-3.0-only
"""Mocked Docker lifecycle checks; never starts a container."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "role_fixture", Path(__file__).parent / "tests" / "test_runtime_db_role.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
IDENTITY = "a" * 64


class CleanupTests(unittest.TestCase):
    def setup_failure(self, failure, listed=IDENTITY, owned=True, cleanup_failure=None):
        commands = []
        owner = None

        def run(command, **kwargs):
            nonlocal owner
            commands.append(command)
            if command[1] == "run":
                owner = command[command.index("--label") + 1].split("=", 1)[1]
                raise failure
            if command[2] == "ls":
                return subprocess.CompletedProcess(command, 0, listed, "")
            if command[2] == "inspect":
                return subprocess.CompletedProcess(command, 0,
                    fixture.json.dumps({fixture.OWNER_LABEL: owner if owned else "other"}), "")
            if cleanup_failure:
                raise cleanup_failure
            return subprocess.CompletedProcess(command, 0, "", "")

        class FailedFixture(fixture.RuntimeRoleTest):
            def test_body(self):
                raise AssertionError("setup failure must prevent test execution")

        result = unittest.TestResult()
        with patch.object(fixture, "ensure_local_docker"), patch.object(fixture.subprocess, "run", run):
            unittest.TestSuite([FailedFixture("test_body")]).run(result)
        return result, commands

    def test_timeout_after_creation_keeps_original_error_and_removes_owned_id(self):
        result, commands = self.setup_failure(subprocess.TimeoutExpired("synthetic-run", 60))
        self.assertEqual(len(result.errors), 1)
        self.assertIn("TimeoutExpired", result.errors[0][1])
        self.assertEqual(commands[-1], ["docker", "rm", "-f", "-v", IDENTITY])
        self.assertEqual(sum(command[1] == "rm" for command in commands), 1)
        self.assertEqual(commands[1][commands[1].index("--filter") + 1],
                         "name=^/" + commands[0][commands[0].index("--name") + 1] + "$")

    def test_failed_launch_with_proven_absence_preserves_failure_without_remove(self):
        result, commands = self.setup_failure(subprocess.CalledProcessError(1, "synthetic-run"), listed="")
        self.assertEqual(len(result.errors), 1)
        self.assertIn("CalledProcessError", result.errors[0][1])
        self.assertFalse(any(command[1] == "rm" for command in commands))

    def test_ownership_mismatch_reports_cleanup_error_without_removing_foreign_id(self):
        result, commands = self.setup_failure(subprocess.TimeoutExpired("synthetic-run", 60), owned=False)
        self.assertEqual(len(result.errors), 2)
        self.assertIn("TimeoutExpired", result.errors[0][1])
        self.assertIn("ownership mismatch", result.errors[1][1])
        self.assertFalse(any(command[1] == "rm" for command in commands))

    def test_remove_failure_does_not_hide_original_setup_failure(self):
        result, _ = self.setup_failure(subprocess.TimeoutExpired("synthetic-run", 60),
            cleanup_failure=subprocess.CalledProcessError(1, "synthetic-remove"))
        self.assertEqual(len(result.errors), 2)
        self.assertIn("TimeoutExpired", result.errors[0][1])
        self.assertIn("CalledProcessError", result.errors[1][1])

    def test_listing_failure_is_not_mistaken_for_absence(self):
        with patch.object(fixture.subprocess, "run", side_effect=subprocess.TimeoutExpired("synthetic-list", 60)):
            with self.assertRaises(subprocess.TimeoutExpired):
                fixture.remove_owned_container("synthetic", "owner")

    def test_successful_setup_removes_owned_container_once(self):
        class SuccessfulFixture(fixture.RuntimeRoleTest):
            @classmethod
            def sql(cls, *args, **kwargs):
                pass

            def test_body(self):
                pass

        commands = []
        owner = None

        def run(command, **kwargs):
            nonlocal owner
            commands.append(command)
            if command[1] == "run":
                owner = command[command.index("--label") + 1].split("=", 1)[1]
            output = IDENTITY if command[1:3] == ["container", "ls"] else ""
            if command[1:3] == ["container", "inspect"]:
                output = fixture.json.dumps({fixture.OWNER_LABEL: owner})
            return subprocess.CompletedProcess(command, 0, output, "")

        result = unittest.TestResult()
        with patch.object(fixture, "ensure_local_docker"), patch.object(fixture.subprocess, "run", run):
            unittest.TestSuite([SuccessfulFixture("test_body")]).run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(sum(command[1] == "rm" for command in commands), 1)
        self.assertEqual(commands[-1][-1], IDENTITY)

    def test_inspection_failure_is_preserved_without_removal(self):
        listed = subprocess.CompletedProcess([], 0, IDENTITY, "")
        with patch.object(fixture.subprocess, "run", side_effect=[listed,
                subprocess.CalledProcessError(1, "synthetic-inspect")]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                fixture.remove_owned_container("synthetic", "owner")
            self.assertEqual(run.call_count, 2)

    def test_multiple_or_malformed_ids_are_refused_before_inspection(self):
        for value in (IDENTITY + "\n" + "b" * 64, "not-an-id"):
            with self.subTest(value=value), patch.object(fixture.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], 0, value, "")) as run:
                with self.assertRaises(RuntimeError):
                    fixture.remove_owned_container("synthetic", "owner")
                self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
