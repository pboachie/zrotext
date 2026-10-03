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


if __name__ == "__main__":
    unittest.main()
