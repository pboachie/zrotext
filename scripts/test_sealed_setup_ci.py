# SPDX-License-Identifier: AGPL-3.0-only
import os
import io
import base64
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import sealed_setup_ci as driver


class SetupCiTest(unittest.TestCase):
    def test_owned_directory_permission_change_is_confined_and_precedes_initialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with patch.object(driver, "ROOT", root), \
                    patch.object(driver, "native_host_supported", return_value=True), \
                    patch.object(driver, "grant_fixture_user_access") as grant:
                parent = driver.owned_fixture_parent()
                owned = parent / "sealed-setup-ci-fixture"
                owned.mkdir()
                self.assertEqual(driver.prepare_owned_directory(owned), owned)
                grant.assert_called_once_with(owned)
                grant.reset_mock()
                (owned / "existing").write_bytes(b"preserve")
                sibling = parent / "unrelated"
                sibling.mkdir()
                for selected in (parent, sibling, owned):
                    with self.assertRaises(ValueError):
                        driver.prepare_owned_directory(selected)
                grant.assert_not_called()
                self.assertEqual((owned / "existing").read_bytes(), b"preserve")

    def test_native_permission_tool_uses_fixed_code_and_literal_owned_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"fixture")
            def system_directory(buffer, _capacity):
                buffer.value = str(root)
                return len(str(root))
            api = SimpleNamespace(kernel32=SimpleNamespace(GetSystemDirectoryW=system_directory))
            selected = root / "sealed-setup-ci-literal-'$fixture"
            with patch.object(driver.ctypes, "windll", api, create=True), \
                    patch.object(driver.subprocess, "run") as run:
                driver.grant_fixture_user_access(selected)
            command = run.call_args.args[0]
            self.assertEqual(command[:4], [str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand"])
            script = base64.b64decode(command[4]).decode("utf-16-le")
            self.assertNotIn(str(selected), script)
            self.assertIn("$item.SetAccessControl($acl)", script)
            self.assertIn("$acl.SetOwner($user)", script)
            self.assertIn("$acl.SetAccessRuleProtection($true, $false)", script)
            self.assertEqual(run.call_args.kwargs["env"]["ZT_SEALED_SETUP_OWNED_DIRECTORY"], str(selected))
            self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
            self.assertTrue(run.call_args.kwargs["check"])

    @unittest.skipUnless(os.name == "nt", "requires native Windows PostgreSQL tools")
    def test_real_postgres_initializes_starts_queries_and_stops_private_user_fixture(self):
        try:
            tools = driver.installed_postgres_directory()
        except FileNotFoundError:
            self.skipTest("requires installed PostgreSQL 17")
        # Use the same fixed ancestor as the actual consumer. Windows runner
        # user-temp ancestors can refuse PostgreSQL's restricted token.
        owned = Path(tempfile.mkdtemp(prefix="sealed-setup-ci-", dir=driver.owned_fixture_parent()))
        cluster = None
        try:
            driver.prepare_owned_directory(owned)
            cluster = driver.OwnedCluster(owned, tools)
            # Run actual restricted-token tools, never a runner service.
            with patch.dict(os.environ):
                os.environ.pop("PG_RESTRICT_EXEC", None)
                try:
                    uri = cluster.start()
                except driver.FixtureToolFailure as error:
                    self.fail(error.category)  # Closed diagnostic, never raw tool output.
                result = subprocess.run([str(driver.tool(tools, "psql")), uri, "-X", "-A", "-t",
                                         "-c", "SELECT 1"], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        timeout=10, check=True)
            self.assertEqual(result.stdout.strip(), b"1")
            self.assertTrue((cluster.data / "PG_VERSION").is_file())
        finally:
            driver.cleanup_owned_directory(owned, cluster)
        self.assertFalse(owned.exists())

    def test_permission_failure_preserves_closed_diagnostics_and_cleans_owned_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with patch.object(driver, "ROOT", Path(temporary).resolve()), \
                    patch.dict(driver.os.environ, {"RUNNER_TEMP": temporary}), \
                    patch.object(driver, "native_host_supported", return_value=True), \
                    patch.object(driver, "grant_fixture_user_access", side_effect=ValueError("private-fixture-diagnostic")), \
                    patch.object(driver, "OwnedCluster") as cluster, redirect_stdout(output):
                self.assertEqual(driver.main(["--tools", temporary, "--pg-bin", temporary]), 1)
                self.assertEqual(list(driver.owned_fixture_parent().iterdir()), [])
            cluster.assert_not_called()
            self.assertEqual(output.getvalue(), "Explicit sealed setup fixture failed at owned-directory (fixture-error); private inputs withheld.\n")

    def test_failure_stage_withholds_exception_and_caller_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            cluster = unittest.mock.Mock(stage="cluster-initialization")
            cluster.start.side_effect = ValueError("private-fixture-diagnostic")
            output = io.StringIO()
            with patch.dict(driver.os.environ, {"RUNNER_TEMP": temporary}), \
                    patch.object(driver, "owned_fixture_parent", return_value=Path(temporary)), \
                    patch.object(driver, "native_host_supported", return_value=True), \
                    patch.object(driver, "installed_postgres_directory", return_value=Path(temporary)), \
                    patch.object(driver, "OwnedCluster", return_value=cluster), \
                    patch.object(driver, "prepare_owned_directory") as prepare, \
                    patch.object(driver, "cleanup_owned_directory") as cleanup, redirect_stdout(output):
                self.assertEqual(driver.main(["--tools", temporary, "--pg-bin", temporary]), 1)
            self.assertEqual(output.getvalue(), "Explicit sealed setup fixture failed at cluster-initialization (fixture-error); private inputs withheld.\n")
            cleanup.assert_called_once()
            prepare.assert_called_once_with(cleanup.call_args.args[0])
            # The mocked cleanup did not remove the newly owned empty fixture.
            owned = cleanup.call_args.args[0]
            self.assertEqual(owned.parent.resolve(), Path(temporary).resolve())
            owned.rmdir()

    def test_owned_namespace_is_fixed_and_rejects_linked_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with patch.object(driver, "ROOT", root):
                self.assertEqual(driver.owned_fixture_parent(), root / "target" / "sealed-setup-postgres-fixtures")
                with patch.object(Path, "is_symlink", return_value=True):
                    with self.assertRaises(ValueError):
                        driver.owned_fixture_parent()

    def test_tool_failure_reports_only_allowlisted_category(self):
        for material, expected in ((b"private-fixture restricted token secret", "restricted-token"),
                                   (b"private-fixture permission denied secret", "permission-denied"),
                                   (b"private-fixture unknown secret", "tool-exit")):
            result = subprocess.CompletedProcess([], 1, stdout=material)
            with patch.object(driver.subprocess, "run", return_value=result):
                with self.assertRaises(driver.FixtureToolFailure) as caught:
                    driver.quiet(["fixture-tool"], classify_failure=True)
            self.assertEqual(caught.exception.category, expected)
            self.assertEqual(str(caught.exception), "Owned fixture tool failed")

    def test_background_tool_keeps_output_handles_discarded(self):
        with patch.object(driver.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            driver.quiet(["fixture-tool"])
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_permission_context_returns_only_static_categories(self):
        self.assertEqual(driver.tool_failure_category(b'could not create directory "private-fixture": Permission denied'), "directory-creation-denied")
        self.assertEqual(driver.tool_failure_category(b'could not execute "private-fixture": Permission denied'), "child-execution-denied")
        self.assertEqual(driver.tool_failure_category(b'running bootstrap script ... private-fixture Permission denied'), "bootstrap-permission-denied")

    def test_database_is_explicit_credential_free_loopback(self):
        self.assertEqual(driver.database_url("postgresql://fixture@localhost:4444/postgres"),
                         "postgresql://fixture@localhost:4444/postgres")
        for value in ("postgresql://fixture:<PASSWORD>@localhost:4444/postgres",
                      "postgresql://fixture@example.test:4444/postgres",
                      "postgresql://fixture@localhost:4444/postgres?options=anything",
                      "postgresql://fixture@localhost:4444/other", "not-a-uri"):
            with self.assertRaises(ValueError):
                driver.database_url(value)

    def test_installed_tools_refuse_a_caller_selected_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            trusted = root / "PostgreSQL" / "17" / "bin"
            trusted.mkdir(parents=True)
            other = root / "other"
            other.mkdir()
            def known_folder(_owner, _id, _token, _flags, buffer):
                buffer.value = str(root)
                return 0
            api = SimpleNamespace(shell32=SimpleNamespace(SHGetFolderPathW=known_folder))
            with patch.object(driver.ctypes, "windll", api, create=True):
                self.assertEqual(driver.installed_postgres_directory(trusted), trusted)
                with self.assertRaises(ValueError):
                    driver.installed_postgres_directory(other)

    def test_system_cleanup_ignores_inherited_root_and_requires_kernel_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / ("taskkill.exe" if os.name == "nt" else "taskkill")
            executable.write_bytes(b"fixture")
            def system_directory(buffer, _capacity):
                buffer.value = str(root)
                return len(str(root))
            api = SimpleNamespace(kernel32=SimpleNamespace(GetSystemDirectoryW=system_directory))
            with patch.object(driver.ctypes, "windll", api, create=True), \
                    patch.dict(driver.os.environ, {"SystemRoot": "untrusted-fixture-path"}):
                self.assertEqual(driver.system_tree_killer(), executable)
            api.kernel32.GetSystemDirectoryW = lambda _buffer, _capacity: 0
            with patch.object(driver.ctypes, "windll", api, create=True):
                with self.assertRaises(ValueError):
                    driver.system_tree_killer()

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
            with patch.object(driver, "quiet", side_effect=lambda command, **_options: calls.append(command)), \
                    patch.object(driver, "reserve_port", return_value=4444), \
                    patch.object(driver.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                cluster = driver.OwnedCluster(owned, tools)
                self.assertEqual(cluster.start(), "postgresql://fixture@localhost:4444/postgres")
                cluster.close()
            self.assertEqual([command[command.index("-D") + 1] for command in calls], [owned.resolve() / "data"] * 3)
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
                patch.object(driver, "system_tree_killer", return_value=Path("fixture-system") / "taskkill.exe"):
            with self.assertRaises(subprocess.TimeoutExpired):
                driver.launch_consumer(["node"], {}, "{}", timeout=1)
            self.assertEqual(terminate.call_args.args[0][1:], ["/PID", "123", "/T", "/F"])
            child.wait.assert_called_once_with(timeout=10)

    def test_outer_termination_failure_requires_staging_preservation(self):
        child = unittest.mock.Mock(pid=123)
        child.communicate.side_effect = subprocess.TimeoutExpired("node", 1)
        with patch.object(driver.subprocess, "Popen", return_value=child), \
                patch.object(driver.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "taskkill")), \
                patch.object(driver, "system_tree_killer", return_value=Path("fixture-system") / "taskkill.exe"):
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
                    patch.object(driver, "installed_postgres_directory", return_value=Path(temporary)), \
                    patch.object(driver, "native_host_supported", return_value=True), \
                    patch.object(driver, "prepare_owned_directory"), \
                    patch.object(driver, "tls_fixture", return_value={}), \
                    patch.object(driver, "launch_consumer", side_effect=driver.ProcessCleanupFailure("fixture")):
                self.assertEqual(driver.main(["--tools", temporary, "--pg-bin", temporary]), 1)
            cluster.start.assert_called_once()
            cluster.close.assert_not_called()
            self.assertEqual(marker.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
