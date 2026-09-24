import json
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import release_candidate


class ReleaseCandidateTest(unittest.TestCase):
    BOM = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"component": {"type": "application"}},
        "components": [{"type": "library", "name": "okhttp",
                        "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"}],
    }
    IDENTITY = {
        "package": "org.zrotext.gateway",
        "version_code": 6,
        "version_name": "0.1.5-m1-inbound-local",
        "min_sdk": 28,
        "target_sdk": 36,
    }
    COMMIT = "a" * 40
    CERTIFICATE = "b" * 64

    def verify_test_candidate(self, commit, certificate):
        return release_candidate.verify_candidate(
            commit, certificate, self.IDENTITY["version_code"],
            self.IDENTITY["version_name"],
        )

    @staticmethod
    def make_tagged_repository(directory):
        repository = Path(directory)

        def git(*args):
            return subprocess.check_output(
                ["git", *args], cwd=repository, text=True, stderr=subprocess.DEVNULL,
            ).strip()

        git("init", "-b", "main")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "--allow-empty", "-m", "synthetic source")
        main = git("rev-parse", "HEAD")
        git("update-ref", "refs/remotes/origin/main", main)
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "tag", "-a", "v0.1.0-rc.1", "-m", "synthetic annotated tag")
        git("init", "--bare", str(repository / "origin.git"))
        git("remote", "add", "origin", str(repository / "origin.git"))
        git("push", "origin", "main", "v0.1.0-rc.1")
        return git, main

    def test_reviewed_tag_requires_annotated_main_commit(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release_candidate, "ROOT", Path(directory)):
            git, main = self.make_tagged_repository(directory)
            self.assertEqual(release_candidate.reviewed_tag_commit("v0.1.0-rc.1"), main)
            git("tag", "v0.1.0-rc.2")
            with self.assertRaisesRegex(ValueError, "annotated"):
                release_candidate.reviewed_tag_commit("v0.1.0-rc.2")
            with self.assertRaisesRegex(ValueError, "valid independently selected"):
                release_candidate.reviewed_tag_commit("main")
            original_tag = git("rev-parse", "refs/tags/v0.1.0-rc.1")
            git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "tag", "-f", "-a", "v0.1.0-rc.1", "-m", "changed local tag")
            with self.assertRaisesRegex(ValueError, "differs from the published"):
                release_candidate.reviewed_tag_commit("v0.1.0-rc.1")
            git("update-ref", "refs/tags/v0.1.0-rc.1", original_tag)
            git("switch", "-c", "feature")
            git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "--allow-empty", "-m", "off-main source")
            git("update-ref", "refs/remotes/origin/main", git("rev-parse", "HEAD"))
            with self.assertRaisesRegex(ValueError, "Fetched origin/main differs"):
                release_candidate.reviewed_tag_commit("v0.1.0-rc.1")
            git("update-ref", "refs/remotes/origin/main", main)
            git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "tag", "-a", "v0.1.0-rc.3", "-m", "off-main annotated tag")
            git("push", "origin", "v0.1.0-rc.3")
            with self.assertRaisesRegex(ValueError, "not on fetched main"):
                release_candidate.reviewed_tag_commit("v0.1.0-rc.3")

    def test_reviewed_tag_commit_must_match_apk_receipts(self):
        with tempfile.TemporaryDirectory() as repository, \
             tempfile.TemporaryDirectory() as artifacts, \
             patch.object(release_candidate, "ROOT", Path(repository)), \
             patch.object(release_candidate, "ARTIFACT_ROOT", Path(artifacts)):
            self.make_tagged_repository(repository)
            self.make_candidate(artifacts)  # Receipt names a different source SHA.
            with self.assertRaisesRegex(ValueError, "Unsigned APK receipt"):
                release_candidate.verify_reviewed_candidate(
                    "v0.1.0-rc.1", self.CERTIFICATE,
                    self.IDENTITY["version_code"], self.IDENTITY["version_name"],
                )

    def test_version_must_match_independently_reviewed_metadata(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release_candidate, "ARTIFACT_ROOT", Path(directory)), \
             patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
            self.make_candidate(directory)
            with self.assertRaisesRegex(ValueError, "version differs"):
                release_candidate.verify_candidate(
                    self.COMMIT, self.CERTIFICATE,
                    self.IDENTITY["version_code"] + 1,
                    self.IDENTITY["version_name"],
                )
            with self.assertRaisesRegex(ValueError, "version differs"):
                release_candidate.verify_candidate(
                    self.COMMIT, self.CERTIFICATE,
                    self.IDENTITY["version_code"], "different-version",
                )

    def test_verify_cli_reads_prior_approval_from_stdin(self):
        with tempfile.TemporaryDirectory() as approvals, \
             patch.object(release_candidate, "verify_reviewed_candidate") as verify:
            manifest = Path(approvals) / "release-approval.json"
            manifest.write_text(json.dumps({
                "source_tag": "v0.1.0-rc.1",
                "certificate_sha256": self.CERTIFICATE,
                "version_code": self.IDENTITY["version_code"],
                "version_name": self.IDENTITY["version_name"],
            }), encoding="utf-8")
            arguments = ["release_candidate.py", "verify", "--source-tag",
                         "v0.1.0-rc.1", "--certificate-sha256", self.CERTIFICATE,
                         "--approval-stdin"]
            with patch.object(sys, "argv", arguments), \
                 patch.object(sys, "stdin", io.TextIOWrapper(
                     io.BytesIO(manifest.read_bytes()), encoding="utf-8")):
                release_candidate.main()
            verify.assert_called_once_with("v0.1.0-rc.1", self.CERTIFICATE,
                                           self.IDENTITY["version_code"],
                                           self.IDENTITY["version_name"])
            verify.reset_mock()
            with patch.object(sys, "argv", [*arguments[:5], "c" * 64, *arguments[6:]]), \
                 patch.object(sys, "stdin", io.TextIOWrapper(
                     io.BytesIO(manifest.read_bytes()), encoding="utf-8")):
                with self.assertRaisesRegex(ValueError, "approval differs"):
                    release_candidate.main()
            verify.assert_not_called()
            manifest.write_text('{"source_tag":"v0.1.0-rc.1","source_tag":"v0.1.0-rc.1"}',
                                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate fields"):
                release_candidate.release_approval(manifest.read_bytes())
            manifest.write_bytes(b" " * (release_candidate.MAX_RECEIPT_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "review size limit"):
                release_candidate.release_approval(manifest.read_bytes())

    def test_hosted_unsigned_cli_requires_matching_attestation(self):
        unsigned = Path("/tmp/zrotext-android-release/unsigned/unsigned.apk")
        digest = "a" * 64
        with patch.object(sys, "argv", ["release_candidate.py", "verify-unsigned"]), \
             patch.object(release_candidate, "source_commit", return_value=self.COMMIT), \
             patch.object(release_candidate, "checked_unsigned",
                          return_value=(unsigned, digest, self.IDENTITY, "b" * 64, self.BOM)), \
             patch.object(release_candidate, "verify_unsigned_sbom_attestation") as attestation, \
             redirect_stdout(io.StringIO()):
            release_candidate.main()
            attestation.assert_called_once_with(unsigned, digest, self.COMMIT, self.BOM)
            attestation.side_effect = ValueError("Unsigned APK SBOM attestation verification failed")
            with self.assertRaisesRegex(ValueError, "attestation verification failed"):
                release_candidate.main()

    def test_reviewed_tag_ignores_hostile_git_environment(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release_candidate, "ROOT", Path(directory)):
            _, main = self.make_tagged_repository(directory)
            hostile = {
                "GIT_DIR": str(Path(directory) / "origin.git"),
                "GIT_WORK_TREE": str(Path(directory) / "other"),
                "GIT_OBJECT_DIRECTORY": str(Path(directory) / "other-objects"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "remote.origin.url",
                "GIT_CONFIG_VALUE_0": str(Path(directory) / "attacker.git"),
            }
            with patch.dict(os.environ, hostile):
                self.assertEqual(release_candidate.reviewed_tag_commit(
                    "v0.1.0-rc.1"), main)

    def test_artifact_files_must_be_regular_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "candidate.json").mkdir()
            with self.assertRaisesRegex(ValueError, "regular file"):
                release_candidate.checked_artifact_file(root / "candidate.json", 100)
            (root / "candidate.json").rmdir()
            (root / "candidate.json").write_text("oversized", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "size limit"):
                release_candidate.checked_artifact_file(root / "candidate.json", 1)
            (root / "candidate.json").unlink()
            try:
                os.symlink(root / "target.json", root / "candidate.json")
            except OSError:
                pass  # Windows may deny symlink creation without Developer Mode.
            else:
                (root / "target.json").write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "symlink"):
                    release_candidate.checked_artifact_file(root / "candidate.json", 100)

    def test_compressed_apk_cannot_expand_beyond_review_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "compressed.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(release_candidate.ASSET, self.COMMIT + "\n")
                archive.writestr("classes.dex", b"X" * 4096)
            with patch.object(release_candidate, "MAX_UNCOMPRESSED_APK_BYTES", 1024):
                with self.assertRaisesRegex(ValueError, "review size limit"):
                    release_candidate.verify_source_asset(apk, self.COMMIT)
                with self.assertRaisesRegex(ValueError, "review size limit"):
                    release_candidate.apk_entry_digests(apk)

    def test_apk_directory_is_bounded_before_zipfile_opens(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "many-entries.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr(release_candidate.ASSET, self.COMMIT + "\n")
                archive.writestr("classes.dex", "synthetic")
            with patch.object(release_candidate, "MAX_APK_ENTRIES", 1), \
                 patch.object(release_candidate.zipfile, "ZipFile",
                              side_effect=AssertionError("ZipFile opened")):
                with self.assertRaisesRegex(ValueError, "central directory"):
                    release_candidate.verify_source_asset(apk, self.COMMIT)
            with patch.object(release_candidate, "MAX_CENTRAL_DIRECTORY_BYTES", 1), \
                 patch.object(release_candidate.zipfile, "ZipFile",
                              side_effect=AssertionError("ZipFile opened")):
                with self.assertRaisesRegex(ValueError, "central directory"):
                    release_candidate.apk_entry_digests(apk)

    def test_api28_signature_accepts_v3_without_v2(self):
        output = ("Verified using v2 scheme (APK Signature Scheme v2): false\n"
                  "Verified using v3 scheme (APK Signature Scheme v3): true\n")
        release_candidate.require_api28_signature(output)
        with self.assertRaisesRegex(ValueError, "did not verify with v3"):
            release_candidate.require_api28_signature(
                output.replace("Scheme v3): true", "Scheme v3): false"))

    def make_candidate(self, directory):
        build_dir = Path(directory) / "unsigned"
        candidate_dir = Path(directory) / "candidate"
        build_dir.mkdir()
        candidate_dir.mkdir()
        unsigned = build_dir / "unsigned.apk"
        signed = candidate_dir / f"zrotext-android-{self.COMMIT[:12]}-candidate.apk"
        for path in (unsigned, signed):
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(release_candidate.ASSET, self.COMMIT + "\n")
                archive.writestr("classes.dex", "disposable fake bytecode")
                if path == signed:
                    archive.comment = b"disposable fake signing block"
        unsigned_hash = release_candidate.sha256(unsigned)
        signed_hash = release_candidate.sha256(signed)
        sbom = build_dir / release_candidate.SBOM_NAME
        sbom.write_text(json.dumps(self.BOM), encoding="utf-8")
        sbom_hash = release_candidate.sha256(sbom)
        (build_dir / "unsigned.json").write_text(json.dumps({
            "source_commit": self.COMMIT,
            "unsigned_apk": unsigned.name,
            "unsigned_apk_sha256": unsigned_hash,
            "embedded_asset": release_candidate.ASSET,
            "apk_identity": self.IDENTITY,
            "sbom": sbom.name,
            "sbom_sha256": sbom_hash,
            "sbom_configuration": release_candidate.SBOM_CONFIGURATION,
        }), encoding="utf-8")
        receipt = {
            "source_commit": self.COMMIT,
            "embedded_asset": release_candidate.ASSET,
            "unsigned_apk_sha256": unsigned_hash,
            "sbom_sha256": sbom_hash,
            "apk": signed.name,
            "apk_sha256": signed_hash,
            "signing_certificate_sha256": self.CERTIFICATE,
            "apk_identity": self.IDENTITY,
            "min_sdk_verified": 28,
        }
        (candidate_dir / "candidate.json").write_text(json.dumps(receipt), encoding="utf-8")
        (candidate_dir / "SHA256SUMS").write_text(
            f"{signed_hash}  {signed.name}\n", encoding="ascii")
        return build_dir, candidate_dir, signed

    def test_independent_verification_checks_both_artifacts_and_certificate(self):
        output = ("Verified using v2 scheme (APK Signature Scheme v2): true\n"
                  "Verified using v3 scheme (APK Signature Scheme v3): true\n"
                  f"Signer #1 certificate SHA-256 digest: {self.CERTIFICATE}\n")
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release_candidate, "ARTIFACT_ROOT", Path(directory)):
            build_dir, candidate_dir, signed = self.make_candidate(directory)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY), \
                 patch.object(release_candidate, "sdk_tool", side_effect=lambda name: Path(name)), \
                 patch.object(release_candidate, "verify_unsigned_sbom_attestation") as sbom_attestation, \
                 patch.object(release_candidate, "run", side_effect=[output, ""]) as command:
                with redirect_stdout(io.StringIO()):
                    self.verify_test_candidate(self.COMMIT,
                                               self.CERTIFICATE.upper())
            sbom_attestation.assert_called_once()
            self.assertEqual(command.call_count, 2)
            self.assertEqual(command.call_args_list[0].args[1:3], ("verify", "--verbose"))
            extra = candidate_dir / "zrotext-android-cccccccccccc-candidate.apk"
            shutil.copyfile(signed, extra)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "exactly one signed APK"):
                    self.verify_test_candidate(self.COMMIT, self.CERTIFICATE)
            extra.unlink()
            signed.rename(extra)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "exactly one signed APK"):
                    self.verify_test_candidate(self.COMMIT, self.CERTIFICATE)
            extra.rename(signed)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY), \
                 patch.object(release_candidate, "sdk_tool", side_effect=lambda name: Path(name)), \
                 patch.object(release_candidate, "run", return_value=output.replace(
                     "APK Signature Scheme v3): true", "APK Signature Scheme v3): false")):
                with self.assertRaisesRegex(ValueError, "did not verify with v3"):
                    self.verify_test_candidate(self.COMMIT, self.CERTIFICATE)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY), \
                 patch.object(release_candidate, "sdk_tool", side_effect=lambda name: Path(name)), \
                 patch.object(release_candidate, "run", return_value=output.replace(
                     self.CERTIFICATE, "c" * 64)):
                with self.assertRaisesRegex(ValueError, "approved fingerprint"):
                    self.verify_test_candidate(self.COMMIT, self.CERTIFICATE)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "receipt differs"):
                    self.verify_test_candidate(self.COMMIT, "c" * 64)
            with signed.open("ab") as changed:
                changed.write(b"tampered")
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "receipt differs"):
                    self.verify_test_candidate(self.COMMIT, self.CERTIFICATE)
            with zipfile.ZipFile(signed, "w") as archive:
                archive.writestr(release_candidate.ASSET, self.COMMIT + "\n")
                archive.writestr("classes.dex", "changed fake bytecode")
            changed_hash = release_candidate.sha256(signed)
            receipt_path = candidate_dir / "candidate.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["apk_sha256"] = changed_hash
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            (candidate_dir / "SHA256SUMS").write_text(
                f"{changed_hash}  {signed.name}\n", encoding="ascii")
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "entries differ"):
                    self.verify_test_candidate(self.COMMIT, self.CERTIFICATE)

    def test_apk_identity_requires_gateway_package_and_complete_sdk_metadata(self):
        badging = (
            "package: name='org.zrotext.gateway' versionCode='6' "
            "versionName='0.1.5-m1-inbound-local' platformBuildVersionCode='37'\n"
            "sdkVersion:'28'\ntargetSdkVersion:'36'\n"
        )
        self.assertEqual(release_candidate.parse_apk_identity(badging), self.IDENTITY)
        with self.assertRaisesRegex(ValueError, "package name"):
            release_candidate.parse_apk_identity(
                badging.replace("org.zrotext.gateway", "org.example.impostor"))
        with self.assertRaisesRegex(ValueError, "metadata is missing"):
            release_candidate.parse_apk_identity(
                badging.replace("targetSdkVersion:'36'\n", ""))
        with self.assertRaisesRegex(ValueError, "minimum SDK"):
            release_candidate.parse_apk_identity(
                badging.replace("sdkVersion:'28'", "sdkVersion:'27'"))

    def test_unsigned_build_environment_excludes_every_android_signing_variable(self):
        source = {
            "ANDROID_HOME": "/external/sdk",
            "ZROTEXT_ANDROID_KEYSTORE_B64": "private-key",
            "ZROTEXT_ANDROID_KEYSTORE_PASSWORD": "store-password",
            "ZROTEXT_ANDROID_KEY_PASSWORD": "key-password",
            "ZROTEXT_ANDROID_KEY_ALIAS": "release",
            "ZROTEXT_ANDROID_FUTURE_SECRET": "future-secret",
        }
        self.assertEqual(release_candidate.unsigned_build_env(source),
                         {"ANDROID_HOME": "/external/sdk"})
        self.assertEqual(release_candidate.signing_env(source), {
            "ANDROID_HOME": "/external/sdk",
            "ZROTEXT_ANDROID_KEYSTORE_PASSWORD": "store-password",
            "ZROTEXT_ANDROID_KEY_PASSWORD": "key-password",
        })
        with self.assertRaisesRegex(ValueError, "required for signing"):
            release_candidate.signing_env({"ZROTEXT_ANDROID_KEYSTORE_PASSWORD": "store-password"})

    def test_signing_rejects_changed_unsigned_apk(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release_candidate, "ARTIFACT_ROOT", Path(directory)):
            build_dir = Path(directory) / "unsigned"
            build_dir.mkdir()
            apk = build_dir / "unsigned.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr(release_candidate.ASSET, commit + "\n")
            receipt = {
                "source_commit": commit,
                "unsigned_apk": apk.name,
                "unsigned_apk_sha256": release_candidate.sha256(apk),
                "embedded_asset": release_candidate.ASSET,
                "apk_identity": self.IDENTITY,
                "sbom": release_candidate.SBOM_NAME,
                "sbom_sha256": "",
                "sbom_configuration": release_candidate.SBOM_CONFIGURATION,
            }
            sbom = build_dir / release_candidate.SBOM_NAME
            sbom.write_text(json.dumps(self.BOM), encoding="utf-8")
            receipt["sbom_sha256"] = release_candidate.sha256(sbom)
            (build_dir / "unsigned.json").write_text(json.dumps(receipt), encoding="utf-8")
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                self.assertEqual(release_candidate.checked_unsigned(commit)[1],
                                 receipt["unsigned_apk_sha256"])
                with apk.open("ab") as output:
                    output.write(b"changed after build")
                with self.assertRaisesRegex(ValueError, "Unsigned APK receipt"):
                    release_candidate.checked_unsigned(commit)

    def test_release_sbom_hash_and_scope_reject_stale_inventory(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release_candidate, "ARTIFACT_ROOT", Path(directory)), \
             patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
            build_dir, candidate_dir, _ = self.make_candidate(directory)
            release_candidate.checked_unsigned(self.COMMIT)
            sbom = build_dir / release_candidate.SBOM_NAME
            sbom.write_text(json.dumps({**self.BOM, "components": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no usable dependency inventory"):
                release_candidate.checked_unsigned(self.COMMIT)
            sbom.write_text(json.dumps({**self.BOM, "components": [
                {"type": "library", "name": "different",
                 "purl": "pkg:maven/example/different@1.0"}]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unsigned APK receipt"):
                release_candidate.checked_unsigned(self.COMMIT)
            sbom.write_text(json.dumps(self.BOM), encoding="utf-8")
            receipt_path = build_dir / "unsigned.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["sbom_configuration"] = "debugRuntimeClasspath"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unsigned APK receipt"):
                release_candidate.checked_unsigned(self.COMMIT)
            receipt["sbom_configuration"] = release_candidate.SBOM_CONFIGURATION
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            signed_receipt = candidate_dir / "candidate.json"
            candidate = json.loads(signed_receipt.read_text(encoding="utf-8"))
            candidate["sbom_sha256"] = "0" * 64
            signed_receipt.write_text(json.dumps(candidate), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Signed APK receipt differs"):
                self.verify_test_candidate(self.COMMIT, self.CERTIFICATE)

    def test_unsigned_sbom_attestation_binds_exact_apk_digest_and_inventory(self):
        digest = "a" * 64
        statement = [{"verificationResult": {"statement": {
            "predicateType": release_candidate.SBOM_PREDICATE,
            "subject": [{"name": "unsigned.apk", "digest": {"sha256": digest}}],
            "predicate": self.BOM,
        }}}]
        result = type("Result", (), {"returncode": 0,
                                     "stdout": json.dumps(statement)})()
        with patch.object(release_candidate.subprocess, "run", return_value=result) as command:
            release_candidate.verify_unsigned_sbom_attestation(
                Path("unsigned.apk"), digest, self.COMMIT, self.BOM)
        arguments = command.call_args.args[0]
        self.assertIn("--predicate-type", arguments)
        self.assertIn(release_candidate.SBOM_PREDICATE, arguments)
        self.assertIn("--source-digest", arguments)
        self.assertIn(self.COMMIT, arguments)
        statement[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "b" * 64
        result.stdout = json.dumps(statement)
        with patch.object(release_candidate.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "differs from the candidate"):
                release_candidate.verify_unsigned_sbom_attestation(
                    Path("unsigned.apk"), digest, self.COMMIT, self.BOM)
        statement[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = digest
        statement[0]["verificationResult"]["statement"]["predicate"] = {**self.BOM, "components": []}
        result.stdout = json.dumps(statement)
        with patch.object(release_candidate.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "differs from the candidate"):
                release_candidate.verify_unsigned_sbom_attestation(
                    Path("unsigned.apk"), digest, self.COMMIT, self.BOM)

    def test_attested_non_ascii_sbom_survives_windows_default_encoding(self):
        bom = {**self.BOM, "components": [{**self.BOM["components"][0],
                                         "description": "Square’s HTTP client"}]}
        statement = [{"verificationResult": {"statement": {
            "predicateType": release_candidate.SBOM_PREDICATE,
            "subject": [{"digest": {"sha256": "a" * 64}}],
            "predicate": bom,
        }}}]
        raw = json.dumps(statement, ensure_ascii=False).encode("utf-8")

        def windows_like_run(*_args, **kwargs):
            return type("Result", (), {"returncode": 0,
                                        "stdout": raw.decode(kwargs.get("encoding") or "cp1252")})()

        with patch.object(release_candidate.subprocess, "run",
                          side_effect=windows_like_run) as command:
            release_candidate.verify_unsigned_sbom_attestation(
                Path("unsigned.apk"), "a" * 64, self.COMMIT, bom)
        self.assertEqual(command.call_args.kwargs["encoding"], "utf-8")

    def test_artifacts_must_remain_outside_checkout(self):
        with self.assertRaisesRegex(ValueError, "outside the source checkout"):
            release_candidate.external_artifact_path(
                release_candidate.ROOT / "android" / "app" / "build" / "candidate",
                "Output directory",
            )
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / "candidate"
            self.assertEqual(
                release_candidate.external_artifact_path(external, "Output directory"),
                external.resolve(),
            )


if __name__ == "__main__":
    unittest.main()
