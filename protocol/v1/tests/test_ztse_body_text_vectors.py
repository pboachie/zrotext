"""Independent Python checks for the shared ZT-009 Q9 body-text corpus.

Recomputes every verdict from raw bytes with the standard library only, so the
fixture in protocol/v1/vectors/ztse-body-text-01.json stays honest for the
Rust, TypeScript and Android consumers.
"""

import json
import unittest
from pathlib import Path

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[1] / "vectors" / "ztse-body-text-01.json").read_text(encoding="utf-8")
)


def independent_verdict(raw: bytes) -> str:
    if not 1 <= len(raw) <= 32768:
        return "length"
    if b"\x00" in raw:
        return "nul"
    if raw.startswith(b"\xef\xbb\xbf"):
        return "bom"
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "utf8"
    return "accept"


class BodyTextVectorTests(unittest.TestCase):
    def test_every_text_case_verdict_matches_independent_byte_inspection(self):
        self.assertEqual(FIXTURE["status"], "UNAPPROVED_TEST_ONLY")
        self.assertEqual(FIXTURE["maxBodyTextBytes"], 32768)
        cases = FIXTURE["textCases"]
        self.assertGreaterEqual(len(cases), 10, "corpus must stay representative")
        for case in cases:
            raw = bytes.fromhex(case["hex"])
            verdict = independent_verdict(raw)
            self.assertEqual(
                verdict if verdict == "accept" else "reject",
                case["verdict"],
                case["name"],
            )
            if case["verdict"] == "reject":
                self.assertEqual(verdict, case["reason"], case["name"])
            else:
                text = raw.decode("utf-8")
                if "text" in case:
                    self.assertEqual(text, case["text"], case["name"])
                if "textLength" in case:
                    self.assertEqual(len(text), case["textLength"], case["name"])

    def test_authenticated_cases_are_well_formed_sealed_envelopes(self):
        # The Python suite does not decrypt; it pins the structural invariants
        # the Rust receiver relies on before opening a body.
        for case in FIXTURE["authenticatedCases"]:
            envelope = bytes.fromhex(case["envelopeHex"])
            self.assertEqual(envelope[:4], b"ZTSE", case["name"])
            self.assertEqual(envelope[4], case["profile"], case["name"])
            self.assertEqual(envelope[5], case["kind"], case["name"])
            self.assertTrue(426 <= len(envelope) <= 36864, case["name"])
            self.assertEqual(len(bytes.fromhex(case["cekHex"])), 32, case["name"])
            self.assertEqual(
                case["context"]["recipients"][0]["role"],
                1 if case["kind"] == 1 else 2,
                case["name"],
            )


if __name__ == "__main__":
    unittest.main()
