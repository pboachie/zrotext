"""Release-image identity checks must fail closed before promotion."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "compose"))
import fresh_install_smoke as smoke  # noqa: E402


COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
IMAGE = "ghcr.io/pboachie/zrotext@" + DIGEST
IMAGE_ID = "sha256:" + "c" * 64
TAG = "v0.1.0-rc.1"


class ReleaseImageSmokeTest(unittest.TestCase):
    def test_refuses_mutable_and_wrong_source_identity(self):
        for image in ("ghcr.io/pboachie/zrotext:v0.1.0-rc.1",
                      "ghcr.io/another/image@" + DIGEST,
                      "ghcr.io/pboachie/zrotext@sha256:bad"):
            with self.subTest(image=image), self.assertRaises(smoke.DrillError):
                smoke.validate_image_args(image, COMMIT, TAG)
        with self.assertRaises(smoke.DrillError):
            smoke.validate_image_args(IMAGE, "bad", TAG)
        with self.assertRaises(smoke.DrillError):
            smoke.validate_image_args(IMAGE, COMMIT, "main")
        smoke.validate_image_args(IMAGE, COMMIT, TAG)

    def test_rejects_image_with_wrong_revision_label(self):
        labels = {
            "org.opencontainers.image.source": smoke.SOURCE,
            "org.opencontainers.image.revision": "d" * 40,
            "org.opencontainers.image.version": TAG,
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
        }
        with patch.object(smoke, "run", side_effect=["", json.dumps(labels)]):
            with self.assertRaisesRegex(smoke.DrillError, "source labels"):
                smoke.inspect_release_image(IMAGE, COMMIT, TAG)

    def test_requires_both_containers_to_run_selected_image(self):
        compose = ["docker", "compose", "--project-name", "synthetic"]
        container = "d" * 64
        with patch.object(smoke, "run", side_effect=[container, IMAGE_ID,
                                                      container, "sha256:" + "e" * 64]):
            with self.assertRaisesRegex(smoke.DrillError, "migrate did not|app did not"):
                smoke.verify_running_image(compose, IMAGE_ID)


if __name__ == "__main__":
    unittest.main()
