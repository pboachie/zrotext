"""Release-image identity checks must fail closed before promotion."""

import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deploy" / "compose"))
import fresh_install_smoke as smoke  # noqa: E402


COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
IMAGE = "ghcr.io/pboachie/zrotext@" + DIGEST
IMAGE_ID = "sha256:" + "c" * 64
TAG = "v0.1.0-rc.1"
WEB_SHA = "d" * 64
SCHEMA_SHA = "e" * 64
MIGRATION_LAST = 21


class ReleaseImageSmokeTest(unittest.TestCase):
    def test_refuses_mutable_and_wrong_source_identity(self):
        for image in ("ghcr.io/pboachie/zrotext:v0.1.0-rc.1",
                      "ghcr.io/another/image@" + DIGEST,
                      "ghcr.io/pboachie/zrotext@sha256:bad"):
            with self.subTest(image=image), self.assertRaises(smoke.DrillError):
                smoke.validate_image_args(image, COMMIT, TAG,
                                          WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)
        with self.assertRaises(smoke.DrillError):
            smoke.validate_image_args(IMAGE, "bad", TAG,
                                      WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)
        with self.assertRaises(smoke.DrillError):
            smoke.validate_image_args(IMAGE, COMMIT, "main",
                                      WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)
        with self.assertRaisesRegex(smoke.DrillError, "source metadata"):
            smoke.validate_image_args(IMAGE, COMMIT, TAG)
        smoke.validate_image_args(IMAGE, COMMIT, TAG,
                                  WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)

    def test_rejects_image_with_wrong_revision_label(self):
        labels = {
            "org.opencontainers.image.source": smoke.SOURCE,
            "org.opencontainers.image.revision": "d" * 40,
            "org.opencontainers.image.version": TAG,
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
        }
        with patch.object(smoke, "run", side_effect=[json.dumps([IMAGE]),
                                                    json.dumps(labels)]):
            with self.assertRaisesRegex(smoke.DrillError, "source labels"):
                smoke.inspect_release_image(IMAGE, COMMIT, TAG,
                                            WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)

    def test_rejects_staged_image_without_selected_digest(self):
        with patch.object(smoke, "run", return_value=json.dumps([
                "ghcr.io/pboachie/zrotext@sha256:" + "e" * 64])):
            with self.assertRaisesRegex(smoke.DrillError, "selected digest"):
                smoke.inspect_release_image(IMAGE, COMMIT, TAG,
                                            WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)

    def test_rejects_image_with_wrong_embedded_web_digest(self):
        labels = {
            "org.opencontainers.image.source": smoke.SOURCE,
            "org.opencontainers.image.revision": COMMIT,
            "org.opencontainers.image.version": TAG,
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
            "org.zrotext.web.static-sha256": "f" * 64,
            "org.zrotext.device-stream.schema-sha256": SCHEMA_SHA,
            "org.zrotext.migration.last": str(MIGRATION_LAST),
        }
        with patch.object(smoke, "run", side_effect=[json.dumps([IMAGE]),
                                                    json.dumps(labels)]):
            with self.assertRaisesRegex(smoke.DrillError, "source labels"):
                smoke.inspect_release_image(IMAGE, COMMIT, TAG,
                                            WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)

    def test_running_version_must_match_tag_commit_and_web(self):
        class Response(io.BytesIO):
            status = 200

        fields = {
            "bundle_version": TAG, "source_commit": COMMIT,
            "web_static_sha256": WEB_SHA, "device_stream_protocol": "v1",
            "device_stream_schema_sha256": SCHEMA_SHA,
            "migration_last": str(MIGRATION_LAST),
        }
        with patch.object(smoke, "urlopen", return_value=Response(json.dumps(fields).encode())):
            smoke.verify_version_endpoint(8080, COMMIT, TAG,
                                          WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)
        fields["web_static_sha256"] = "f" * 64
        with patch.object(smoke, "urlopen", return_value=Response(json.dumps(fields).encode())):
            with self.assertRaisesRegex(smoke.DrillError, "version endpoint differs"):
                smoke.verify_version_endpoint(8080, COMMIT, TAG,
                                              WEB_SHA, SCHEMA_SHA, MIGRATION_LAST)

    def test_rejects_truncated_container_id(self):
        compose = ["docker", "compose", "--project-name", "synthetic"]
        with patch.object(smoke, "run", return_value="d" * 12) as command:
            with self.assertRaisesRegex(smoke.DrillError, "migrate container is missing"):
                smoke.verify_running_image(compose, IMAGE_ID)
        command.assert_called_once_with(
            [*compose, "ps", "--no-trunc", "-aq", "migrate"],
            "migrate container lookup",
        )

    def test_rejects_migrate_image_mismatch_before_app_lookup(self):
        compose = ["docker", "compose", "--project-name", "synthetic"]
        container = "d" * 64
        with patch.object(smoke, "run", side_effect=[container, "sha256:" + "e" * 64]) as command:
            with self.assertRaisesRegex(smoke.DrillError, "migrate did not run"):
                smoke.verify_running_image(compose, IMAGE_ID)
        self.assertEqual(command.call_count, 2)
        command.assert_any_call(
            [*compose, "ps", "--no-trunc", "-aq", "migrate"],
            "migrate container lookup",
        )
        command.assert_any_call(
            ["docker", "inspect", "--format", "{{.Image}}", container],
            "migrate image lookup",
        )

    def test_rejects_app_image_mismatch_after_migrate_matches(self):
        compose = ["docker", "compose", "--project-name", "synthetic"]
        container = "d" * 64
        with patch.object(smoke, "run", side_effect=[container, IMAGE_ID,
                                                      container, "sha256:" + "e" * 64]) as command:
            with self.assertRaisesRegex(smoke.DrillError, "app did not run"):
                smoke.verify_running_image(compose, IMAGE_ID)
        self.assertEqual(command.call_count, 4)
        command.assert_any_call(
            [*compose, "ps", "--no-trunc", "-aq", "app"],
            "app container lookup",
        )

    def test_release_image_must_bundle_source_license_and_dependency_notices(self):
        license_text = (Path(__file__).resolve().parents[2] / "LICENSE").read_text(
            encoding="utf-8")
        notices = "License: MIT\naxum 0.8.6\ntokio-postgres 0.7.13\n" + "text\n" * 250
        with patch.object(smoke, "run", side_effect=[license_text, notices]) as command:
            smoke.verify_release_licenses()
        self.assertEqual(command.call_count, 2)
        self.assertEqual(command.call_args_list[0].args[0], [
            "docker", "run", "--rm", "--entrypoint", "cat", smoke.STAGED_IMAGE,
            "/usr/share/doc/zrotext/LICENSE",
        ])
        self.assertEqual(command.call_args_list[1].args[0][-1],
                         "/usr/share/doc/zrotext/THIRD_PARTY_NOTICES")

        with patch.object(smoke, "run", side_effect=["wrong license", notices]):
            with self.assertRaisesRegex(smoke.DrillError, "license differs"):
                smoke.verify_release_licenses()
        with patch.object(smoke, "run", side_effect=[license_text, "short"]):
            with self.assertRaisesRegex(smoke.DrillError, "notices are incomplete"):
                smoke.verify_release_licenses()


if __name__ == "__main__":
    unittest.main()
