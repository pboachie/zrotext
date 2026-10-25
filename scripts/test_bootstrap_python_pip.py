# SPDX-License-Identifier: AGPL-3.0-only
"""Offline regression tests for the packaging bootstrap and its call ordering."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import bootstrap_python_pip as bootstrap

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    "ci", "conversation-simulator", "guided-connector-verification",
    "owner-opening-capacity-contract", "sdk-consolidated",
)


def load_script(relative):
    spec = importlib.util.spec_from_file_location("package_check", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.data = b"synthetic wheel bytes; never executed"
        self.digest = hashlib.sha256(self.data).hexdigest()

    def test_pinned_vendor_identity(self):
        self.assertEqual(bootstrap.PIP_VERSION, "26.2.2")
        self.assertEqual(bootstrap.CERTIFI_VERSION, "2026.10.19")
        self.assertEqual(bootstrap.WHEEL_SHA256,
                         "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70")
        self.assertTrue(bootstrap.WHEEL_URL.startswith("https://files.pythonhosted.org/"))
        self.assertTrue(bootstrap.WHEEL_URL.endswith(bootstrap.WHEEL_NAME))

    def test_qualified_requires_both_stable_version_floors(self):
        for pip, certifi, expected in (
            ("26.2.1", "2026.10.19", False),
            ("26.2.2", "2026.10.18", False),
            ("26.2.2rc1", "2026.10.19", False),
            ("26.2.2", "2026.10.19", True),
            ("26.3", "2026.10.20", True),
        ):
            with self.subTest(pip=pip, certifi=certifi), patch.object(
                bootstrap.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 0, json.dumps([pip, certifi])),
            ) as run:
                self.assertEqual(bootstrap.qualified(), expected)
                self.assertEqual(run.call_args.args[0][1:3], ["-I", "-c"])

    def test_missing_pip_and_malformed_qualification_refuse(self):
        for code, output in ((1, ""), (0, "not json"), (0, "[]"), (0, "[null,null]")):
            with self.subTest(output=output), patch.object(
                bootstrap.subprocess, "run",
                return_value=subprocess.CompletedProcess([], code, output),
            ):
                self.assertFalse(bootstrap.qualified())

    def test_qualified_interpreter_is_idempotent_without_network(self):
        with patch.object(bootstrap, "qualified", return_value=True), patch.object(
            bootstrap, "obtain_wheel", side_effect=AssertionError("unexpected network"),
        ):
            self.assertFalse(bootstrap.bootstrap())

    def test_bad_hash_prevents_wheel_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / bootstrap.WHEEL_NAME
            wheel.write_bytes(self.data)
            with patch.object(bootstrap, "qualified", return_value=False), patch.object(
                bootstrap.subprocess, "run",
            ) as run, self.assertRaisesRegex(ValueError, "checksum"):
                bootstrap.bootstrap(wheel=wheel)
            run.assert_not_called()

    def test_explicit_wheel_is_checked_even_if_already_qualified(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / bootstrap.WHEEL_NAME
            wheel.write_bytes(self.data)
            with patch.object(bootstrap, "qualified", return_value=True), self.assertRaisesRegex(
                ValueError, "checksum",
            ):
                bootstrap.bootstrap(wheel=wheel)

    def test_local_wheel_is_offline_and_installs_before_postcheck(self):
        with tempfile.TemporaryDirectory(prefix="pip fixture space ") as directory:
            wheel = Path(directory) / bootstrap.WHEEL_NAME
            wheel.write_bytes(self.data)
            events = []

            def qualified():
                events.append("check")
                return len(events) > 1

            def install(args, **kwargs):
                events.append("install")
                self.assertEqual(args[:2], [bootstrap.sys.executable, "-I"])
                self.assertEqual(args[3:-1], ["--isolated", "--disable-pip-version-check",
                                 "install", "--no-index", "--no-deps", "--no-cache-dir",
                                 "--force-reinstall"])
                staged = Path(args[-1])
                self.assertNotEqual(staged, wheel)
                self.assertEqual(staged.read_bytes(), self.data)
                self.assertEqual(Path(args[2]), staged / "pip")
                self.assertEqual(kwargs["env"]["PIP_CONFIG_FILE"], os.devnull)
                self.assertEqual(kwargs["env"]["PIP_DISABLE_PIP_VERSION_CHECK"], "1")
                self.assertNotIn("PIP_INDEX_URL", kwargs["env"])
                self.assertTrue(kwargs["check"])

            with patch.object(bootstrap, "WHEEL_SHA256", self.digest), patch.object(
                bootstrap, "qualified", side_effect=qualified,
            ), patch.object(bootstrap, "download_wheel", side_effect=AssertionError("network")), patch.object(
                bootstrap.subprocess, "run", side_effect=install,
            ), patch.dict(os.environ, {"PIP_INDEX_URL": "https://packages.example.invalid/simple"}):
                self.assertTrue(bootstrap.bootstrap(wheel=wheel))
            self.assertEqual(events, ["check", "install", "check"])

    def test_install_failure_and_failed_postcheck_stop_bootstrap(self):
        with patch.object(bootstrap, "qualified", return_value=False), patch.object(
            bootstrap, "obtain_wheel", return_value=self.data,
        ), patch.object(bootstrap, "WHEEL_SHA256", self.digest):
            with patch.object(bootstrap.subprocess, "run", side_effect=subprocess.CalledProcessError(1, [])):
                with self.assertRaises(subprocess.CalledProcessError):
                    bootstrap.bootstrap()
            with patch.object(bootstrap.subprocess, "run"):
                with self.assertRaisesRegex(ValueError, "did not qualify"):
                    bootstrap.bootstrap()

    def test_cache_populates_before_offline_use_and_is_reverified(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            bootstrap, "WHEEL_SHA256", self.digest,
        ), patch.object(bootstrap, "download_wheel", return_value=self.data) as download:
            cache = Path(directory) / "wheels"
            self.assertEqual(bootstrap.obtain_wheel(wheel_dir=cache), self.data)
            download.assert_called_once()
            download.side_effect = AssertionError("offline cache must not download")
            self.assertEqual(bootstrap.obtain_wheel(wheel_dir=cache), self.data)
            wheel = cache / bootstrap.WHEEL_NAME
            wheel.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum"):
                bootstrap.obtain_wheel(wheel_dir=cache)

    def test_missing_explicit_wheel_never_falls_back_to_network(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            bootstrap, "download_wheel", side_effect=AssertionError("network"),
        ), self.assertRaises(FileNotFoundError):
            bootstrap.obtain_wheel(wheel=Path(directory) / bootstrap.WHEEL_NAME)

    def test_download_has_default_tls_verification_size_bound_and_hash(self):
        class Response(io.BytesIO):
            def read(self, size):
                self.requested_size = size
                return super().read(size)

        response = Response(self.data)
        with patch.object(bootstrap, "WHEEL_SHA256", self.digest), patch.object(
            bootstrap.urllib.request, "build_opener",
        ) as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(bootstrap.download_wheel(), self.data)
            opener.return_value.open.assert_called_once_with(bootstrap.WHEEL_URL, timeout=60)
            context = opener.call_args.args[1]._context
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, bootstrap.ssl.CERT_REQUIRED)
            self.assertEqual(response.requested_size, bootstrap.MAX_WHEEL_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "checksum"):
            bootstrap.verify_wheel(b"x" * (bootstrap.MAX_WHEEL_BYTES + 1))

    def test_redirect_cannot_downgrade_tls(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            bootstrap.HttpsOnlyRedirect().redirect_request(None, None, 302, "", {},
                                                          "http://packages.example.invalid/wheel")

    def test_config_environment_is_clean_without_changing_parent(self):
        with patch.dict(os.environ, {"PIP_TRUSTED_HOST": "packages.example.invalid", "PIP_CONFIG_FILE": "fixture.ini"}):
            env = bootstrap.pip_environment()
            self.assertNotIn("PIP_TRUSTED_HOST", env)
            self.assertEqual(env["PIP_CONFIG_FILE"], os.devnull)
            self.assertEqual(os.environ["PIP_CONFIG_FILE"], "fixture.ini")

    def test_fetch_only_prepares_installer_without_running_any_pip(self):
        with patch.object(bootstrap.sys, "argv", ["bootstrap", "--fetch-only", "--wheel-dir", "fixture-wheels"]), patch.object(
            bootstrap, "obtain_wheel", return_value=self.data,
        ) as obtain, patch.object(bootstrap, "bootstrap") as install, patch("sys.stdout", new=io.StringIO()):
            bootstrap.main()
        obtain.assert_called_once_with(wheel_dir=Path("fixture-wheels"))
        install.assert_not_called()

    def test_fetch_only_requires_explicit_output_directory(self):
        with patch.object(bootstrap.sys, "argv", ["bootstrap", "--fetch-only"]), patch(
            "sys.stderr", new=io.StringIO(),
        ), self.assertRaises(SystemExit) as error:
            bootstrap.main()
        self.assertEqual(error.exception.code, 2)


class IntegrationOrderingTests(unittest.TestCase):
    def test_setup_action_pip_upgrade_is_offline_after_verified_prefetch(self):
        selections = 0
        for name in WORKFLOWS:
            source = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
            steps = re.split(r"(?=^      - )", source, flags=re.M)
            for index, step in enumerate(steps):
                if "uses: actions/setup-python@" not in step:
                    continue
                selections += 1
                self.assertIn('--fetch-only --wheel-dir "${{ runner.temp }}/python-pip-bootstrap"', steps[index - 1])
                self.assertIn("PIP_NO_INDEX: '1'", step)
                self.assertIn("PIP_FIND_LINKS: ${{ runner.temp }}/python-pip-bootstrap/pip-26.2.2-py3-none-any.whl", step)
                self.assertIn("PIP_CONFIG_FILE: ${{ runner.os == 'Windows' && 'nul' || '/dev/null' }}", step)
                self.assertIn("PIP_DISABLE_PIP_VERSION_CHECK: '1'", step)
                gates = re.findall(r"^        if: (.+)$", step, flags=re.M)
                self.assertEqual(gates, re.findall(r"^        if: (.+)$", steps[index - 1], flags=re.M))
                self.assertIn("run: python -I scripts/bootstrap_python_pip.py", steps[index + 1])
        self.assertEqual(selections, 17)

    def test_all_workflow_network_installs_follow_interpreter_bootstrap(self):
        installs = 0
        for name in WORKFLOWS:
            source = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
            for job in re.split(r"(?=^  [\w-]+:\n)", source, flags=re.M):
                qualified = False
                lines = job.splitlines()
                for index, line in enumerate(lines):
                    if "uses: actions/setup-python@" in line:
                        qualified = False
                    if "run: python -I scripts/bootstrap_python_pip.py" in line:
                        qualified = True
                    if "pip install" not in line:
                        continue
                    installs += 1
                    self.assertTrue(qualified, (name, line))
                    self.assertIn("--disable-pip-version-check", line)
                    if "/bin/" in line or "/Scripts/" in line:
                        self.assertTrue(any("-I scripts/bootstrap_python_pip.py" in previous
                                            for previous in lines[index - 2:index]), (name, line))
        self.assertEqual(installs, 66)

    def test_current_platform_pins_and_check_latest(self):
        allowed = {
            "'3.11.17'", "'3.12.15'", "'3.13.17'",
            "${{ runner.os == 'Windows' && '3.13.17' || '3.12.15' }}",
        }
        for name in WORKFLOWS:
            source = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
            lines = source.splitlines()
            for index, line in enumerate(lines):
                if "python-version:" not in line:
                    continue
                self.assertIn(line.split("python-version: ", 1)[1], allowed)
                self.assertEqual(lines[index + 1].strip(), "check-latest: true")
        sdk = (ROOT / ".github/workflows/sdk-consolidated.yml").read_text()
        linux = sdk.split("  py-packages:\n", 1)[1].split("  tungsten:\n", 1)[0]
        versions = re.findall(r"python-version: '([^']+)'", linux)
        self.assertEqual(versions, ["3.12.15", "3.11.17", "3.12.15"])

    def test_package_environments_bootstrap_before_returning_interpreter(self):
        for relative in ("sdk/python/workflow/check_package.py",
                         "sdk/native/sealed-candidate/python/check_package.py"):
            module = load_script(relative)
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "consumer"
                with patch.object(module.venv, "EnvBuilder") as builder, patch.object(module, "run") as run:
                    python = module.environment(path)
                builder.return_value.create.assert_called_once_with(path)
                args = run.call_args.args[0]
                self.assertEqual(args[:3], [python, "-I", ROOT / "scripts/bootstrap_python_pip.py"])
                self.assertEqual(args[3:], ["--wheel-dir", path.parent / "pip-bootstrap"])

    def test_tungsten_offline_consumer_uses_retained_bootstrap_not_network(self):
        source = (ROOT / "sdk/tungsten/package-artifacts.py").read_text()
        function = source.split("def python_package(", 1)[1].split("def ruby_package(", 1)[0]
        download = function.index('"download"')
        self.assertLess(function.index('"--wheel-dir", bootstrap_wheels'), download)
        consumer = function.split('consumer = stage / "consumer"', 1)[1]
        self.assertLess(consumer.index('"--wheel", bootstrap_wheels / PIP_WHEEL'),
                        consumer.index('"install", "--no-index"'))
        self.assertNotIn('"--wheel-dir"', consumer)
        self.assertNotIn('"download"', consumer)
        self.assertIn('"--constraint", requirements', consumer)
        check = (ROOT / "sdk/tungsten/check-python.py").read_text()
        self.assertLess(check.index('"scripts/bootstrap_python_pip.py"'), check.index('"wheel", "--wheel-dir"'))
        self.assertIn('"install", "--no-index"', check)


if __name__ == "__main__":
    unittest.main()
