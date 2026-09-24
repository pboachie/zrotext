import json
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import release_candidate


class ReleaseCandidateTest(unittest.TestCase):
    IDENTITY = {
        "package": "org.zrotext.gateway",
        "version_code": 6,
        "version_name": "0.1.5-m1-inbound-local",
        "min_sdk": 28,
        "target_sdk": 36,
    }
    COMMIT = "a" * 40
    CERTIFICATE = "b" * 64

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
                )

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
        (build_dir / "unsigned.json").write_text(json.dumps({
            "source_commit": self.COMMIT,
            "unsigned_apk": unsigned.name,
            "unsigned_apk_sha256": unsigned_hash,
            "embedded_asset": release_candidate.ASSET,
            "apk_identity": self.IDENTITY,
        }), encoding="utf-8")
        receipt = {
            "source_commit": self.COMMIT,
            "embedded_asset": release_candidate.ASSET,
            "unsigned_apk_sha256": unsigned_hash,
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
                 patch.object(release_candidate, "run", side_effect=[output, ""]) as command:
                with redirect_stdout(io.StringIO()):
                    release_candidate.verify_candidate(self.COMMIT,
                                                       self.CERTIFICATE.upper())
            self.assertEqual(command.call_count, 2)
            self.assertEqual(command.call_args_list[0].args[1:3], ("verify", "--verbose"))
            extra = candidate_dir / "zrotext-android-cccccccccccc-candidate.apk"
            shutil.copyfile(signed, extra)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "exactly one signed APK"):
                    release_candidate.verify_candidate(self.COMMIT, self.CERTIFICATE)
            extra.unlink()
            signed.rename(extra)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "exactly one signed APK"):
                    release_candidate.verify_candidate(self.COMMIT, self.CERTIFICATE)
            extra.rename(signed)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY), \
                 patch.object(release_candidate, "sdk_tool", side_effect=lambda name: Path(name)), \
                 patch.object(release_candidate, "run", return_value=output.replace(
                     "APK Signature Scheme v3): true", "APK Signature Scheme v3): false")):
                with self.assertRaisesRegex(ValueError, "did not verify with v3"):
                    release_candidate.verify_candidate(self.COMMIT, self.CERTIFICATE)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY), \
                 patch.object(release_candidate, "sdk_tool", side_effect=lambda name: Path(name)), \
                 patch.object(release_candidate, "run", return_value=output.replace(
                     self.CERTIFICATE, "c" * 64)):
                with self.assertRaisesRegex(ValueError, "approved fingerprint"):
                    release_candidate.verify_candidate(self.COMMIT, self.CERTIFICATE)
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "receipt differs"):
                    release_candidate.verify_candidate(self.COMMIT, "c" * 64)
            with signed.open("ab") as changed:
                changed.write(b"tampered")
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                with self.assertRaisesRegex(ValueError, "receipt differs"):
                    release_candidate.verify_candidate(self.COMMIT, self.CERTIFICATE)
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
                    release_candidate.verify_candidate(self.COMMIT, self.CERTIFICATE)

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
            }
            (build_dir / "unsigned.json").write_text(json.dumps(receipt), encoding="utf-8")
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                self.assertEqual(release_candidate.checked_unsigned(commit)[1],
                                 receipt["unsigned_apk_sha256"])
                with apk.open("ab") as output:
                    output.write(b"changed after build")
                with self.assertRaisesRegex(ValueError, "Unsigned APK receipt"):
                    release_candidate.checked_unsigned(commit)

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
