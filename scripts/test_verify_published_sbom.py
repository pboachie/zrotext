import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from verify_published_sbom import (SbomError, checked_spdx, main, published_sbom,
                                   spdx_predicate)


DIGEST = "sha256:" + "b" * 64
IMAGE_REF = "ghcr.io/pboachie/zrotext@" + DIGEST
SPDX = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "packages": [{"SPDXID": "SPDXRef-Package-debian", "name": "debian-base"}],
}


class VerifyPublishedSbomTest(unittest.TestCase):
    def test_synthetic_oci_image_uses_exact_digest_and_valid_spdx(self):
        result = type("Result", (), {"returncode": 0, "stdout": json.dumps(SPDX)})()
        with patch("verify_published_sbom.subprocess.run", return_value=result) as command:
            self.assertEqual(published_sbom(IMAGE_REF), SPDX)
        self.assertEqual(command.call_args.args[0][:5],
                         ["docker", "buildx", "imagetools", "inspect", IMAGE_REF])
        self.assertIs(command.call_args.kwargs["shell"], False)
        with self.assertRaisesRegex(SbomError, "immutable image digest"):
            published_sbom("ghcr.io/pboachie/zrotext:latest")

    def test_missing_or_empty_oci_sbom_fails_closed(self):
        result = type("Result", (), {"returncode": 0, "stdout": "null"})()
        with patch("verify_published_sbom.subprocess.run", return_value=result):
            with self.assertRaisesRegex(SbomError, "no usable SPDX"):
                published_sbom(IMAGE_REF)
        with self.assertRaisesRegex(SbomError, "no usable SPDX"):
            checked_spdx(json.dumps({**SPDX, "packages": []}))

    def test_spdx_version_selects_the_exact_signed_predicate(self):
        self.assertEqual(spdx_predicate(checked_spdx(json.dumps(SPDX))),
                         "https://spdx.dev/Document/v2.3")
        legacy = checked_spdx(json.dumps({**SPDX, "spdxVersion": "SPDX-2.2"}))
        self.assertEqual(spdx_predicate(legacy), "https://spdx.dev/Document/v2.2")
        with self.assertRaisesRegex(SbomError, "no usable SPDX"):
            checked_spdx(json.dumps({**SPDX, "spdxVersion": "SPDX-2.1"}))

    def test_workflow_export_is_the_checked_published_sbom(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "server-sbom.spdx.json"
            with patch.object(sys, "argv", ["verify_published_sbom.py", "--image-ref",
                                            IMAGE_REF, "--output", str(output)]), \
                 patch("verify_published_sbom.published_sbom", return_value=SPDX) as lookup:
                main()
            lookup.assert_called_once_with(IMAGE_REF)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), SPDX)


if __name__ == "__main__":
    unittest.main()
