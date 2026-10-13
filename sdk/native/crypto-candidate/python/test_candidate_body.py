"""Shared synthetic corpus; fixture slicing is not a production envelope parser."""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from candidate_body import CandidateBodyError, decode, open_body

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = json.loads((ROOT / "protocol/v1/vectors/ztse-body-text-01.json").read_text(encoding="utf-8"))


def fixture_parts(case):
    envelope = bytes.fromhex(case["envelopeHex"])
    assert envelope[:4] == b"ZTSE" and envelope[4] in (1, 2)
    end = 10 + int.from_bytes(envelope[8:10], "big")
    length = int.from_bytes(envelope[end + 12:end + 16], "big")
    return [bytes.fromhex(case["cekHex"]), envelope[end:end + 12],
            f"ZTSE/body/v{envelope[4]}\0".encode() + envelope[:end],
            envelope[end + 16:end + 16 + length]]


class CandidateBodyTests(unittest.TestCase):
    def test_shared_text_and_authenticated_vectors(self):
        checks = 0
        for case in FIXTURE["textCases"]:
            with self.subTest(case=case["name"]):
                raw = bytes.fromhex(case["hex"])
                if case["verdict"] == "accept":
                    self.assertEqual(decode(raw), raw.decode("utf-8"))
                else:
                    with self.assertRaises(CandidateBodyError) as error:
                        decode(raw)
                    self.assertEqual(error.exception.code, case["reason"])
                checks += 1
        for case in FIXTURE["authenticatedCases"]:
            with self.subTest(case=case["name"]):
                parts = fixture_parts(case)
                if case["verdict"] == "accept":
                    self.assertEqual(open_body(*parts), case["text"])
                else:
                    with self.assertRaises(CandidateBodyError) as error:
                        open_body(*parts)
                    self.assertEqual(error.exception.code, case["reason"])
                checks += 1
                if case["verdict"] != "accept":
                    continue
                for field in range(4):
                    damaged = list(parts)
                    changed = bytearray(damaged[field])
                    changed[-1] ^= 1
                    damaged[field] = changed
                    with self.assertRaisesRegex(CandidateBodyError, "authentication"):
                        open_body(*damaged)
                    checks += 1
                damaged = list(parts)
                damaged[3] = bytes([parts[3][0] ^ 1]) + parts[3][1:]
                with self.assertRaisesRegex(CandidateBodyError, "authentication"):
                    open_body(*damaged)
                checks += 1
                for field in range(4):
                    damaged = list(parts)
                    damaged[field] = b""
                    with self.assertRaisesRegex(CandidateBodyError, "shape"):
                        open_body(*damaged)
                    checks += 1
        self.assertEqual(checks, 47)

    def test_tampering_never_reaches_text_decoder(self):
        case = next(item for item in FIXTURE["authenticatedCases"] if item["verdict"] == "accept")
        parts = fixture_parts(case)
        parts[3] = parts[3][:-1] + bytes([parts[3][-1] ^ 1])
        with patch("candidate_body._decode") as decoder:
            with self.assertRaisesRegex(CandidateBodyError, "authentication"):
                open_body(*parts)
            decoder.assert_not_called()

    def test_mutable_owned_key_and_plaintext_clear_on_every_exit(self):
        for case in FIXTURE["authenticatedCases"]:
            keys, buffers = [], []
            class ObservedAESGCM:
                def __init__(self, key):
                    keys.append(key)
                    self.actual = AESGCM(key)
                def decrypt_into(self, nonce, data, aad, output):
                    buffers.append(output)
                    return self.actual.decrypt_into(nonce, data, aad, output)
            parts = fixture_parts(case)
            originals = list(parts)
            with patch("candidate_body.AESGCM", ObservedAESGCM):
                try:
                    open_body(*parts)
                except CandidateBodyError:
                    pass
            self.assertTrue(keys and buffers)
            self.assertTrue(all(not any(value) for value in keys + buffers))
            self.assertEqual(parts, originals)

    def test_closed_input_types_and_bounds(self):
        case = next(item for item in FIXTURE["authenticatedCases"] if item["verdict"] == "accept")
        parts = fixture_parts(case)
        for field, invalid in [(0, b"x" * 31), (0, b"x" * 33), (1, b"x" * 11),
                               (1, b"x" * 13), (2, b"x" * 36865), (3, b"x" * 32785),
                               (3, b"x" * 16), (0, memoryview(parts[0])), (0, None)]:
            malformed = list(parts)
            malformed[field] = invalid
            with self.assertRaisesRegex(CandidateBodyError, "shape"):
                open_body(*malformed)

    def test_utf8_error_does_not_retain_plaintext_decoder_exception(self):
        with self.assertRaises(CandidateBodyError) as error:
            decode(b"\xffprivate-synthetic")
        self.assertEqual(str(error.exception), "utf8")
        self.assertIsNone(error.exception.__context__)


if __name__ == "__main__":
    unittest.main()
