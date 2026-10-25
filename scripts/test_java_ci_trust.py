# SPDX-License-Identifier: AGPL-3.0-only
"""Job-local TLS mitigation must not change installed stores or other anchors."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

import check_java_toolchain as java
import prepare_java_ci_trust as prepare


SAFE = "a" * 64
def certificate(digest):
    return {"sha256": digest, "entry_type": "trusted-certificate", "attributes": {"synthetic.trust-usage": "TLS"}}


ORIGINAL = {"safe": certificate(SAFE), **{f"target-{i}": certificate(value)
            for i, value in enumerate(java.IMPACTED_ROOTS)}}
ORIGINAL["duplicate-target"] = certificate(next(iter(java.IMPACTED_ROOTS)))
COPIED = {"safe": certificate(SAFE)}


def encoded(value):
    return base64.b64encode(str(value).encode()).decode()


def listing(certificates):
    result = "TYPE\tJKS\n"
    for alias, entry in certificates.items():
        result += f"CERT\t{encoded(alias)}\t{entry['sha256']}\n"
        for name, value in entry["attributes"].items():
            result += f"ATTRIBUTE\t{encoded(alias)}\t{encoded(name)}\t{encoded(value)}\n"
    return result


def effective(store, certificates=COPIED):
    return f"SELECTED\t{encoded(store)}\n" + "".join(f"ROOT\t{digest}\n"
                                                      for digest in java.fingerprints(certificates))


class JavaTrustCopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "selected-jdk"
        self.source = self.home / "lib/security/cacerts"
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"synthetic original store")
        (self.home / "conf/security").mkdir(parents=True)
        (self.home / "conf/security/java.security").write_bytes(b"synthetic vendor policy")
        (self.home / "lib/security/blocked.certs").write_bytes(b"synthetic vendor blocklist")
        self.environment_file = self.root / "job-environment"
        self.environment_file.touch()
        self.environment = patch.dict(os.environ, {"RUNNER_TEMP": str(self.root),
                                                  "GITHUB_ENV": str(self.environment_file)}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def probe(self, executable, operation, *args, env=None):
        if operation == "inventory":
            return listing(ORIGINAL if Path(args[0]) == self.source else COPIED)
        if operation == "filter":
            self.assertEqual(set(args[2].split(",")), set(java.IMPACTED_ROOTS))
            self.store = Path(args[1])
            self.assertEqual(self.store.parent.parent, self.root)
            self.store.write_bytes(b"synthetic filtered copy")
            return listing(COPIED)
        self.assertEqual(operation, "effective")
        self.assertIn(str(self.store), env["JAVA_TOOL_OPTIONS"])
        return effective(self.store)

    def prepare(self, probe=None):
        with patch.object(java, "selected_runtime", return_value=(self.home, "java", "keytool", "21.0.13+9")), \
                patch.object(java, "probe", side_effect=probe or self.probe), \
                contextlib.redirect_stdout(io.StringIO()):
            prepare.prepare(21)

    def export(self):
        for line in self.environment_file.read_text().splitlines():
            key, value = line.split("=", 1)
            os.environ[key] = value

    def test_copy_removes_every_target_alias_and_exports_only_after_effective_qualification(self):
        source = self.source.read_bytes()
        policy = java.vendor_security(self.home)
        self.prepare()
        self.assertEqual(self.source.read_bytes(), source)
        self.assertEqual(java.vendor_security(self.home), policy)
        self.export()
        manifest, store = java.load_manifest()
        self.assertEqual(store, self.store)
        self.assertEqual(manifest["source_inventory"], ORIGINAL)
        self.assertEqual(manifest["copy_inventory"], COPIED)
        self.assertEqual(manifest["vendor_security"], policy)

    def test_effective_trust_mismatch_cannot_export_configuration(self):
        def probe(executable, operation, *args, env=None):
            if operation == "effective":
                return effective(self.store, ORIGINAL)
            return self.probe(executable, operation, *args, env=env)
        with self.assertRaisesRegex(ValueError, "TrustManager"):
            self.prepare(probe)
        self.assertEqual(self.environment_file.read_bytes(), b"")

    def test_installed_store_or_vendor_security_mutation_prevents_export(self):
        for target in (self.source, self.home / "lib/security/blocked.certs",
                       self.home / "conf/security/java.security"):
            original = target.read_bytes()
            def probe(executable, operation, *args, env=None):
                result = self.probe(executable, operation, *args, env=env)
                if operation == "effective":
                    target.write_bytes(b"unexpected change")
                return result
            with self.subTest(target=target.name), self.assertRaisesRegex(ValueError, "changed"):
                self.prepare(probe)
            self.assertEqual(self.environment_file.read_bytes(), b"")
            target.write_bytes(original)

    def test_non_target_alias_change_prevents_export(self):
        def probe(executable, operation, *args, env=None):
            result = self.probe(executable, operation, *args, env=env)
            return listing({"renamed-safe": certificate(SAFE)}) if operation == "filter" else result
        with self.assertRaisesRegex(ValueError, "non-target"):
            self.prepare(probe)
        self.assertEqual(self.environment_file.read_bytes(), b"")

    def test_non_target_trust_attribute_change_prevents_export(self):
        def probe(executable, operation, *args, env=None):
            result = self.probe(executable, operation, *args, env=env)
            altered = certificate(SAFE)
            altered["attributes"]["synthetic.trust-usage"] = "unrestricted"
            return listing({"safe": altered}) if operation == "filter" else result
        with self.assertRaisesRegex(ValueError, "non-target"):
            self.prepare(probe)
        self.assertEqual(self.environment_file.read_bytes(), b"")

    def test_preexisting_custom_trust_is_rejected_before_copy_creation(self):
        with patch.object(java, "selected_runtime", side_effect=ValueError("custom trust is unverified")), \
                patch.object(prepare.tempfile, "mkdtemp") as create, self.assertRaises(ValueError):
            prepare.prepare(21)
        create.assert_not_called()
        with patch.dict(os.environ, {java.TRUST_MANIFEST_ENV: "unqualified"}), \
                patch.object(java, "selected_runtime") as runtime, self.assertRaises(ValueError):
            prepare.prepare(21)
        runtime.assert_not_called()

    def test_options_preserve_existing_arguments_and_reject_line_or_quote_injection(self):
        self.assertTrue(prepare.tool_options("-Xmx256m", self.root / "space here", "JKS").startswith("-Xmx256m "))
        for existing, store in (("\nINJECT=value", self.root), ("", self.root / 'bad"path')):
            with self.subTest(existing=existing), self.assertRaises(ValueError):
                prepare.tool_options(existing, store, "JKS")

    def test_manifest_must_be_ordinary_job_local_artifact_and_copy_hash_must_match(self):
        self.prepare()
        self.export()
        manifest, store = java.load_manifest()
        store.write_bytes(b"changed after preparation")
        with self.assertRaisesRegex(ValueError, "changed"):
            java.verify_copy("java", self.home, store, manifest)
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.root / "other-job")}), \
                self.assertRaisesRegex(ValueError, "per-job"):
            java.load_manifest()
        manifest_path = Path(os.environ[java.TRUST_MANIFEST_ENV])
        manifest_path.unlink()
        manifest_path.mkdir()
        with self.assertRaisesRegex(ValueError, "ordinary"):
            java.load_manifest()

    def test_copy_mutation_during_effective_probe_is_detected(self):
        self.prepare()
        self.export()
        manifest, store = java.load_manifest()
        def probe(executable, operation, *args):
            if operation == "effective":
                store.write_bytes(b"changed during probe")
                return effective(store)
            return listing(ORIGINAL if Path(args[0]) == self.source else COPIED)
        with patch.object(java, "probe", side_effect=probe), self.assertRaisesRegex(ValueError, "changed"):
            java.verify_copy("java", self.home, store, manifest)

    def test_inventory_and_effective_protocols_reject_duplicates_and_malformed_values(self):
        for output in (listing(COPIED) + listing(COPIED), "TYPE\tJKS\n", "TYPE\tother\n",
                       "TYPE\tJKS\nCERT\t?\t" + SAFE,
                       listing(COPIED) + "ATTRIBUTE\t" + encoded("safe") + "\t"
                       + encoded("synthetic.trust-usage") + "\t" + encoded("TLS")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                java.inventory(output)
        for output in (effective(self.root) + "ROOT\t" + SAFE, "", effective(self.root / "other")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                java.verify_effective(output, self.root, COPIED)

    def test_corretto_is_explicit_vendor_specific_cpu_floor_not_generic_temurin_acceptance(self):
        for major, version in ((17, "17.0.21+10-LTS"), (21, "21.0.13+10-LTS")):
            properties = {"java.vendor": "Amazon.com Inc.", "java.runtime.version": version}
            self.assertEqual(java.verify_runtime(properties, major, distribution="corretto"), version)
            with self.assertRaisesRegex(ValueError, "vendor"):
                java.verify_runtime(properties, major)
            properties["java.runtime.version"] = version.replace("+10", "+9")
            with self.assertRaisesRegex(ValueError, "patch floor"):
                java.verify_runtime(properties, major, distribution="corretto")

    def test_probe_passes_explicit_vendor_integrity_default_and_does_not_swallow_failures(self):
        completed = subprocess.CompletedProcess([], 0, stdout="TYPE\tJKS\n", stderr="")
        with patch.object(java.subprocess, "run", return_value=completed) as run:
            java.probe("java", "inventory", self.source)
        self.assertEqual(run.call_args.args[0][-3:],
                         ["inventory", java.vendor_store_password(), str(self.source)])
        with patch.object(java.subprocess, "run", side_effect=subprocess.CalledProcessError(
                1, "java", stderr="store integrity verification failed")), \
                self.assertRaisesRegex(ValueError, "unverified"):
            java.probe("java", "inventory", self.source)


if __name__ == "__main__":
    unittest.main()
