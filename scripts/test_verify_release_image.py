import json
import unittest
from unittest.mock import patch

from verify_release_image import (VerificationError, checked_receipt, ensure_local_docker,
                                  git_output,
                                  verify_attestation, verify_image,
                                  verify_sbom_attestation, verify_tag)
from verify_published_sbom import SbomError, spdx_predicate
from write_image_receipt import image_receipt


TAG = "v0.1.0-rc.1"
COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
RECEIPT = image_receipt(TAG, COMMIT, DIGEST, 123, 1)
SPDX = {
    "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
    "packages": [{"name": "debian-base"}],
}


class VerifyReleaseImageTest(unittest.TestCase):
    def test_git_runner_uses_fixed_executable_without_shell(self):
        with patch("verify_release_image.subprocess.run", return_value=type("Result", (), {
            "returncode": 0, "stdout": "ok\n",
        })()) as command:
            self.assertEqual(git_output(["rev-parse", "HEAD"], "git test"), "ok")
        self.assertEqual(command.call_args.args[0], ["git", "rev-parse", "HEAD"])
        self.assertIs(command.call_args.kwargs["shell"], False)

    def test_receipt_requires_independent_tag_and_all_derived_fields(self):
        raw = json.dumps(RECEIPT).encode("utf-8")
        self.assertEqual(checked_receipt(raw, TAG), RECEIPT)
        with self.assertRaisesRegex(VerificationError, "selected release"):
            checked_receipt(raw, "v0.1.0-rc.2")
        tampered = {**RECEIPT, "image_ref": "ghcr.io/pboachie/zrotext:latest"}
        with self.assertRaisesRegex(VerificationError, "fields do not match"):
            checked_receipt(json.dumps(tampered).encode("utf-8"), TAG)
        with self.assertRaisesRegex(VerificationError, "size limit"):
            checked_receipt(b"x" * (16 * 1024 + 1), TAG)

    def test_tag_must_be_annotated_and_match_receipt_commit(self):
        with patch("verify_release_image.git_output", side_effect=["tag", COMMIT, ""]) as command:
            verify_tag(TAG, COMMIT)
        self.assertEqual(command.call_count, 3)
        with patch("verify_release_image.git_output", side_effect=["commit"]):
            with self.assertRaisesRegex(VerificationError, "not annotated"):
                verify_tag(TAG, COMMIT)
        with patch("verify_release_image.git_output", side_effect=["tag", "c" * 40]):
            with self.assertRaisesRegex(VerificationError, "differs"):
                verify_tag(TAG, COMMIT)

    def test_attestation_must_name_exact_digest_and_bind_source_flags(self):
        statement = [{"verificationResult": {"statement": {"subject": [{
            "name": RECEIPT["image"], "digest": {"sha256": DIGEST[7:]},
        }]}}}]
        with patch("verify_release_image.gh_output", return_value=json.dumps(statement)) as command:
            verify_attestation(RECEIPT)
        arguments = command.call_args.args[0]
        self.assertIn("--source-ref", arguments)
        self.assertIn("refs/tags/" + TAG, arguments)
        self.assertIn("--source-digest", arguments)
        self.assertIn(COMMIT, arguments)
        statement[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "c" * 64
        with patch("verify_release_image.gh_output", return_value=json.dumps(statement)):
            with self.assertRaisesRegex(VerificationError, "selected image digest"):
                verify_attestation(RECEIPT)

    def test_pulled_image_requires_digest_and_source_labels(self):
        labels = {
            "org.opencontainers.image.source": "https://github.com/pboachie/zrotext",
            "org.opencontainers.image.revision": COMMIT,
            "org.opencontainers.image.version": TAG,
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
        }
        with patch("verify_release_image.ensure_local_docker"), \
             patch("verify_release_image.docker_output", side_effect=["", json.dumps([RECEIPT["image_ref"]]),
                                                           json.dumps(labels)]):
            verify_image(RECEIPT)
        with patch("verify_release_image.ensure_local_docker"), \
             patch("verify_release_image.docker_output", side_effect=["", json.dumps([]),
                                                           json.dumps(labels)]):
            with self.assertRaisesRegex(VerificationError, "receipt digest"):
                verify_image(RECEIPT)
        labels["org.opencontainers.image.revision"] = "c" * 40
        with patch("verify_release_image.ensure_local_docker"), \
             patch("verify_release_image.docker_output", side_effect=["", json.dumps([RECEIPT["image_ref"]]),
                                                           json.dumps(labels)]):
            with self.assertRaisesRegex(VerificationError, "labels differ"):
                verify_image(RECEIPT)

    def test_verified_sbom_must_match_published_digest_and_contents(self):
        statement = [{"verificationResult": {"statement": {
            "predicateType": spdx_predicate(SPDX),
            "subject": [{"name": RECEIPT["image"],
                         "digest": {"sha256": DIGEST[7:]}}],
            "predicate": SPDX,
        }}}]
        with patch("verify_release_image.published_sbom", return_value=SPDX) as lookup, \
             patch("verify_release_image.gh_output", return_value=json.dumps(statement)) as command:
            verify_sbom_attestation(RECEIPT)
        lookup.assert_called_once_with(RECEIPT["image_ref"])
        arguments = command.call_args.args[0]
        self.assertIn("--predicate-type", arguments)
        self.assertIn("https://spdx.dev/Document/v2.3", arguments)
        self.assertIn("--source-digest", arguments)
        self.assertIn(COMMIT, arguments)
        statement[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "c" * 64
        with patch("verify_release_image.published_sbom", return_value=SPDX), \
             patch("verify_release_image.gh_output", return_value=json.dumps(statement)):
            with self.assertRaisesRegex(VerificationError, "published image digest"):
                verify_sbom_attestation(RECEIPT)
        statement[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = DIGEST[7:]
        statement[0]["verificationResult"]["statement"]["predicate"] = {**SPDX, "packages": []}
        with patch("verify_release_image.published_sbom", return_value=SPDX), \
             patch("verify_release_image.gh_output", return_value=json.dumps(statement)):
            with self.assertRaisesRegex(VerificationError, "published image digest"):
                verify_sbom_attestation(RECEIPT)
        statement[0]["verificationResult"]["statement"]["predicate"] = SPDX
        statement[0]["verificationResult"]["statement"]["predicateType"] = \
            "https://spdx.dev/Document/v2.2"
        with patch("verify_release_image.published_sbom", return_value=SPDX), \
             patch("verify_release_image.gh_output", return_value=json.dumps(statement)):
            with self.assertRaisesRegex(VerificationError, "published image digest"):
                verify_sbom_attestation(RECEIPT)
        legacy = {**SPDX, "spdxVersion": "SPDX-2.2"}
        statement[0]["verificationResult"]["statement"]["predicate"] = legacy
        with patch("verify_release_image.published_sbom", return_value=legacy), \
             patch("verify_release_image.gh_output", return_value=json.dumps(statement)) as command:
            verify_sbom_attestation(RECEIPT)
        self.assertIn("https://spdx.dev/Document/v2.2", command.call_args.args[0])
        with patch("verify_release_image.published_sbom", side_effect=SbomError("missing")):
            with self.assertRaisesRegex(VerificationError, "no verified SPDX SBOM"):
                verify_sbom_attestation(RECEIPT)

    def test_attested_non_ascii_spdx_survives_windows_default_encoding(self):
        spdx = {**SPDX, "packages": [{"name": "Debian’s base"}]}
        statement = [{"verificationResult": {"statement": {
            "predicateType": spdx_predicate(spdx),
            "subject": [{"name": RECEIPT["image"],
                         "digest": {"sha256": DIGEST[7:]}}],
            "predicate": spdx,
        }}}]
        raw = json.dumps(statement, ensure_ascii=False).encode("utf-8")

        def windows_like_run(*_args, **kwargs):
            return type("Result", (), {"returncode": 0,
                                        "stdout": raw.decode(kwargs.get("encoding") or "cp1252")})()

        with patch("verify_release_image.published_sbom", return_value=spdx), \
             patch("verify_release_image.subprocess.run",
                   side_effect=windows_like_run) as command:
            verify_sbom_attestation(RECEIPT)
        self.assertEqual(command.call_args.kwargs["encoding"], "utf-8")

    def test_remote_docker_context_is_rejected_before_pull(self):
        with patch.dict("os.environ", {"DOCKER_HOST": "ssh://production.example"}):
            with self.assertRaisesRegex(VerificationError, "local Docker daemon"):
                ensure_local_docker()
        with patch.dict("os.environ", {"DOCKER_HOST": ""}), \
             patch("verify_release_image.docker_output", return_value=json.dumps(
                 "ssh://production.example")):
            with self.assertRaisesRegex(VerificationError, "local Docker context"):
                ensure_local_docker()


if __name__ == "__main__":
    unittest.main()
