# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sealed_setup_ci as driver


class SetupCiTest(unittest.TestCase):
    def test_database_is_explicit_credential_free_loopback(self):
        self.assertEqual(driver.database_url("postgresql://fixture@localhost:4444/postgres"),
                         "postgresql://fixture@localhost:4444/postgres")
        for value in ("postgresql://fixture:<PASSWORD>@localhost:4444/postgres",
                      "postgresql://fixture@example.test:4444/postgres",
                      "postgresql://fixture@localhost:4444/postgres?options=anything",
                      "postgresql://fixture@localhost:4444/other", "not-a-uri"):
            with self.assertRaises(ValueError):
                driver.database_url(value)

    def test_confined_owned_child_refuses_sibling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "owned"
            child.mkdir()
            self.assertEqual(driver.confined(child, root), child.resolve())
            with self.assertRaises(ValueError):
                driver.confined(root, root)

    def test_cluster_targets_only_new_data_and_stops_on_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owned = root / "owned"
            owned.mkdir()
            tools = root / "bin"
            tools.mkdir()
            for name in ("pg_ctl", "initdb"):
                (tools / (name + (".exe" if os.name == "nt" else ""))).write_bytes(b"fixture")
            calls = []
            with patch.object(driver, "quiet", side_effect=lambda command: calls.append(command)), \
                    patch.object(driver, "reserve_port", return_value=4444), \
                    patch.object(driver.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                cluster = driver.OwnedCluster(owned, tools)
                self.assertEqual(cluster.start(), "postgresql://fixture@localhost:4444/postgres")
                cluster.close()
            self.assertEqual([command[command.index("-D") + 1] for command in calls], [owned / "data"] * 3)
            self.assertIn("stop", calls[-1])
            self.assertNotIn("register", [str(part) for command in calls for part in command])

    def test_failed_start_still_checks_and_stops_owned_cluster(self):
        cluster = object.__new__(driver.OwnedCluster)
        cluster.initialize, cluster.control, cluster.data = Path("initdb"), Path("pg_ctl"), Path("owned-data")
        cluster.attempted = False
        with patch.object(driver, "quiet", side_effect=[None, RuntimeError("fixture start failure"), None]) as quiet, \
                patch.object(driver, "reserve_port", return_value=4444), \
                patch.object(driver.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaises(RuntimeError):
                cluster.start()
            cluster.close()
            self.assertEqual(quiet.call_count, 3)

    def test_unknown_cleanup_state_fails(self):
        cluster = object.__new__(driver.OwnedCluster)
        cluster.control, cluster.data, cluster.attempted = Path("pg_ctl"), Path("owned-data"), True
        with patch.object(driver.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaises(ValueError):
                cluster.close()

    def test_failed_status_or_stop_preserves_owned_data(self):
        for status in (1, 0):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                owned = Path(temporary) / "sealed-setup-ci-fixture"
                owned.mkdir()
                data = owned / "data"
                data.mkdir()
                marker = data / "fixture-only"
                marker.write_bytes(b"preserve")
                cluster = object.__new__(driver.OwnedCluster)
                cluster.control, cluster.data, cluster.attempted = Path("pg_ctl"), data, True
                with patch.object(driver.subprocess, "run", return_value=subprocess.CompletedProcess([], status)), \
                        patch.object(driver, "quiet", side_effect=subprocess.CalledProcessError(1, "pg_ctl")):
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        driver.cleanup_owned_directory(owned, cluster)
                self.assertEqual(marker.read_bytes(), b"preserve")

    def test_proven_stopped_owned_data_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned = Path(temporary) / "sealed-setup-ci-fixture"
            owned.mkdir()
            cluster = object.__new__(driver.OwnedCluster)
            cluster.control, cluster.data, cluster.attempted = Path("pg_ctl"), owned / "data", True
            with patch.object(driver.subprocess, "run", return_value=subprocess.CompletedProcess([], 3)):
                driver.cleanup_owned_directory(owned, cluster)
            self.assertFalse(owned.exists())

    def test_outer_timeout_waits_for_pid_scoped_tree_termination(self):
        child = unittest.mock.Mock(pid=123, returncode=-1)
        child.communicate.side_effect = subprocess.TimeoutExpired("node", 1)
        with patch.object(driver.subprocess, "Popen", return_value=child), \
                patch.object(driver.subprocess, "run") as terminate, \
                patch.dict(driver.os.environ, {"SystemRoot": str(Path("fixture-system").resolve())}):
            with self.assertRaises(subprocess.TimeoutExpired):
                driver.launch_consumer(["node"], {}, "{}", timeout=1)
            self.assertEqual(terminate.call_args.args[0][1:], ["/PID", "123", "/T", "/F"])
            child.wait.assert_called_once_with(timeout=10)

    def test_outer_termination_failure_requires_staging_preservation(self):
        child = unittest.mock.Mock(pid=123)
        child.communicate.side_effect = subprocess.TimeoutExpired("node", 1)
        with patch.object(driver.subprocess, "Popen", return_value=child), \
                patch.object(driver.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "taskkill")), \
                patch.dict(driver.os.environ, {"SystemRoot": str(Path("fixture-system").resolve())}):
            with self.assertRaises(driver.ProcessCleanupFailure):
                driver.launch_consumer(["node"], {}, "{}", timeout=1)
            child.wait.assert_not_called()

    def test_consumer_unknown_cleanup_receipt_refuses_pg_cleanup(self):
        child = unittest.mock.Mock(returncode=2)
        with patch.object(driver.subprocess, "Popen", return_value=child):
            with self.assertRaises(driver.ProcessCleanupFailure):
                driver.launch_consumer(["node"], {}, "{}")

    def test_main_preserves_pg_and_staging_on_consumer_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned = Path(temporary) / "sealed-setup-ci-retained"
            owned.mkdir()
            marker = owned / "fixture-only"
            marker.write_bytes(b"preserve")
            cluster = unittest.mock.Mock()
            cluster.start.return_value = "postgresql://fixture@localhost:4444/postgres"
            with patch.dict(driver.os.environ, {"RUNNER_TEMP": temporary}), \
                    patch.object(driver.tempfile, "mkdtemp", return_value=str(owned)), \
                    patch.object(driver, "OwnedCluster", return_value=cluster), \
                    patch.object(driver, "native_host_supported", return_value=True), \
                    patch.object(driver, "tls_fixture", return_value={}), \
                    patch.object(driver, "launch_consumer", side_effect=driver.ProcessCleanupFailure("fixture")):
                self.assertEqual(driver.main(["--tools", temporary, "--pg-bin", temporary]), 1)
            cluster.start.assert_called_once()
            cluster.close.assert_not_called()
            self.assertEqual(marker.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
