import json
from pathlib import Path
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
        with tempfile.TemporaryDirectory() as directory:
            build_dir = Path(directory)
            apk = build_dir / "unsigned.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr(release_candidate.ASSET, commit + "\n")
            receipt = {
                "source_commit": commit,
                "unsigned_apk": apk.name,
                "unsigned_apk_sha256": release_candidate.sha256(apk),
                "apk_identity": self.IDENTITY,
            }
            (build_dir / "unsigned.json").write_text(json.dumps(receipt), encoding="utf-8")
            with patch.object(release_candidate, "apk_identity", return_value=self.IDENTITY):
                self.assertEqual(release_candidate.checked_unsigned(build_dir, commit)[1],
                                 receipt["unsigned_apk_sha256"])
                with apk.open("ab") as output:
                    output.write(b"changed after build")
                with self.assertRaisesRegex(ValueError, "Unsigned APK receipt"):
                    release_candidate.checked_unsigned(build_dir, commit)

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
