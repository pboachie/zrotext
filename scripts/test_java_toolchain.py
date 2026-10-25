# SPDX-License-Identifier: AGPL-3.0-only
"""Fail closed on stale JDKs or impacted trust roots, without store writes."""
import base64
import contextlib
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_java_toolchain as java


ROOT = Path(__file__).resolve().parents[1]
SAFE_CERTIFICATE = b"synthetic certificate bytes"
SAFE_PEM = ("-----BEGIN CERTIFICATE-----\n"
            + base64.b64encode(SAFE_CERTIFICATE).decode() + "\n-----END CERTIFICATE-----")


def properties(version="21.0.13+9-LTS", **changes):
    return {"java.runtime.version": version, "java.vendor": "Eclipse Adoptium", **changes}


class JavaToolchainTests(unittest.TestCase):
    def test_same_major_patch_floor_accepts_qualified_and_later_patches(self):
        for major, version in ((17, "17.0.21+9"), (21, "21.0.13+9-LTS"),
                               (21, "21.0.14+1-LTS"), (17, "17.0.21.1+1")):
            with self.subTest(version=version):
                self.assertEqual(java.verify_runtime(properties(version), major), version)

    def test_old_wrong_major_early_access_or_unknown_vendor_refuses(self):
        for version in ("21.0.12+9", "21.0.13+8-LTS", "17.0.21+9", "21.0.13-ea+9", "21"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                java.verify_runtime(properties(version), 21)
        with self.assertRaisesRegex(ValueError, "vendor"):
            java.verify_runtime(properties(**{"java.vendor": "other vendor"}), 21)

    def test_custom_trust_overrides_are_unverified_not_a_compromise_claim(self):
        for name in ("javax.net.ssl.trustStore", "javax.net.ssl.trustStoreType",
                     "javax.net.ssl.trustStorePassword", "javax.net.ssl.trustStoreProvider",
                     "java.security.properties"):
            with self.subTest(property=name), self.assertRaisesRegex(ValueError, "unverified"):
                java.verify_runtime(properties(**{name: "custom"}), 21)

    def test_parse_only_properties_and_reject_duplicate_version_fields(self):
        self.assertEqual(java.java_properties("    java.vendor = Eclipse Adoptium\nopenjdk version\n"),
                         {"java.vendor": "Eclipse Adoptium"})
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            java.java_properties("    java.runtime.version = a\n    java.runtime.version = b\n")

    def test_each_impacted_root_is_rejected_independently(self):
        self.assertEqual({value[0] for value in java.IMPACTED_ROOTS.values()},
                         {"emSign ECC Root CA - G3", "AAA Certificate Services",
                          "emSign Root CA - G1", "emSign Root CA - G2"})
        for fingerprint in java.IMPACTED_ROOTS:
            with self.subTest(root=java.IMPACTED_ROOTS[fingerprint]), \
                    self.assertRaisesRegex(ValueError, "impacted root"):
                java.verify_roots({fingerprint})

    def test_g1_and_g2_require_the_additional_advisory_not_the_older_parent_claim(self):
        for fingerprint in ("40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367",
                            "1aa0c2709e831bd6e3b5129a00ba41f7eeef020872f1e6504bf0f6c3f24f3af3"):
            with self.subTest(root=java.IMPACTED_ROOTS[fingerprint]), \
                    self.assertRaisesRegex(ValueError, "CVE-2026-114820") as failure:
                java.verify_roots({fingerprint})
            self.assertNotIn("CVE-2026-91403", str(failure.exception))

    def test_root_hashes_use_certificate_bytes_instead_of_aliases(self):
        fingerprint = hashlib.sha256(SAFE_CERTIFICATE).hexdigest()
        self.assertEqual(java.root_fingerprints("arbitrary alias\n" + SAFE_PEM), {fingerprint})
        java.verify_roots({fingerprint})

    def test_empty_malformed_or_incomplete_policy_cannot_pass(self):
        for listing in ("", "no certificates", "-----BEGIN CERTIFICATE-----\n?\n-----END CERTIFICATE-----",
                        SAFE_PEM + "\n-----BEGIN CERTIFICATE-----"):
            with self.subTest(listing=listing), self.assertRaisesRegex(ValueError, "unverified"):
                java.root_fingerprints(listing)
        with self.assertRaisesRegex(ValueError, "unverified"):
            java.verify_roots(set())
        with patch.object(java, "IMPACTED_ROOTS", {}), \
                self.assertRaisesRegex(ValueError, "incomplete"):
            java.verify_roots({"synthetic"})

    def test_selected_jdk_inspection_is_read_only_and_bound_to_java_home(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            suffix = ".exe" if os.name == "nt" else ""
            java_path = home / "bin" / ("java" + suffix)
            output = "\n".join(f"    {k} = {v}" for k, v in
                               properties(**{"java.home": str(home)}).items())
            with patch.dict(os.environ, {"JAVA_HOME": str(home)}, clear=True), \
                    patch.object(java.shutil, "which", return_value=str(java_path)), \
                    patch.object(java, "read_tool", side_effect=[output, SAFE_PEM]) as read, \
                    contextlib.redirect_stdout(io.StringIO()):
                java.check(21)
            self.assertEqual(read.call_args_list[0].args,
                             (str(java_path), "-XshowSettings:properties", "-version"))
            self.assertEqual(read.call_args_list[1].args,
                             (str(home / "bin" / ("keytool" + suffix)), "-list", "-rfc",
                              "-keystore", str(home / "lib/security/cacerts"), "-storepass", "changeit"))

    def test_missing_or_mismatched_java_home_refuses_before_inspection(self):
        for environment in ({}, {"JAVA_HOME": "synthetic-jdk"}):
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(java.shutil, "which", return_value="other-java"), \
                    patch.object(java, "read_tool") as read, self.assertRaises(ValueError):
                java.check(21)
            read.assert_not_called()

    def test_reported_home_mismatch_or_custom_jsse_store_refuses_before_keytool(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            suffix = ".exe" if os.name == "nt" else ""
            for reported_home, custom_store, expected in ((str(home / "other"), False, "Reported"),
                                                         (str(home), True, "jssecacerts")):
                output = "\n".join(f"    {k} = {v}" for k, v in
                                   properties(**{"java.home": reported_home}).items())
                with self.subTest(custom_store=custom_store), \
                        patch.dict(os.environ, {"JAVA_HOME": str(home)}, clear=True), \
                        patch.object(java.shutil, "which", return_value=str(home / "bin" / ("java" + suffix))), \
                        patch.object(java.Path, "exists", return_value=custom_store), \
                        patch.object(java, "read_tool", return_value=output) as read, \
                        self.assertRaisesRegex(ValueError, expected):
                    java.check(21)
                self.assertEqual(read.call_count, 1)

    def test_cli_returns_failure_without_turning_an_unknown_result_into_success(self):
        stderr = io.StringIO()
        with patch.object(java, "check", side_effect=ValueError("trust is unverified")) as check, \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(java.main(["--major", "21"]), 1)
        check.assert_called_once_with(21, "temurin")
        self.assertEqual(stderr.getvalue(), "trust is unverified\n")

    def test_failed_inspection_does_not_print_tool_output(self):
        with patch.object(java.subprocess, "run", side_effect=subprocess.CalledProcessError(
                1, "keytool", output="synthetic-private-output")), \
                self.assertRaisesRegex(ValueError, "unverified") as failure:
            java.read_tool("keytool")
        self.assertNotIn("synthetic-private-output", str(failure.exception))

    def test_every_java_setup_prepares_and_verifies_job_local_trust(self):
        count = 0
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            steps = re.split(r"(?m)^      - ", workflow.read_text())
            for index, step in enumerate(steps):
                if "uses: actions/setup-java@" not in step:
                    continue
                with self.subTest(workflow=workflow.name, step=index):
                    version = re.search(r"(?:17\.0\.21|21\.0\.13)\+(?:9|10)", step)
                    self.assertIsNotNone(version)
                    if "jdkfile" in step:
                        self.assertIn("force-download:", step)
                        self.assertIn("jdk-file: ${{ runner.temp }}/corretto-", step)
                        download = steps[index - 1]
                        self.assertIn("Download checksum-pinned Corretto JDK", download)
                        self.assertIn("Get-FileHash -Algorithm SHA256", download)
                        self.assertIn("throw 'Corretto archive checksum mismatch'", download)
                        expected = ("8681393133cde8d2fd0d52ccae48e8096b6eed11fc119eaf9cf1c84721311322"
                                    if version[0].startswith("17") else
                                    "abd264a79e07c64e19aaa705e5b8ea8db01d5213877b8ac0b855a94541a4b0fd")
                        self.assertIn(expected, download)
                    if "temurin" in step:
                        self.assertIn("check-latest: true", step)
                    preparation = steps[index + 1]
                    self.assertIn("Prepare job-local Java TLS trust", preparation)
                    self.assertIn("python scripts/prepare_java_ci_trust.py --major "
                                  + version[0].split(".")[0], preparation)
                    gate = steps[index + 2]
                    self.assertIn("Verify patched Java runtime and trust roots", gate)
                    self.assertIn("python scripts/check_java_toolchain.py --major "
                                  + version[0].split(".")[0], gate)
                    conditions = re.findall(r"(?m)^        if: (.+)$", step)
                    self.assertEqual(re.findall(r"(?m)^        if: (.+)$", gate), conditions)
                    self.assertEqual(re.findall(r"(?m)^        if: (.+)$", preparation), conditions)
                    self.assertNotIn("continue-on-error", preparation)
                    self.assertNotIn("continue-on-error", gate)
                    if "jdkfile" in step:
                        self.assertIn("--distribution", preparation)
                        self.assertIn("corretto", preparation)
                        self.assertIn("--distribution", gate)
                        self.assertIn("corretto", gate)
                    if "runner.os" in step:
                        self.assertIn("runner.os == 'Windows'", download)
                        self.assertIn("'corretto' || 'temurin'", preparation)
                        self.assertIn("'corretto' || 'temurin'", gate)
                count += 1
        self.assertEqual(count, 16)


if __name__ == "__main__":
    unittest.main()
