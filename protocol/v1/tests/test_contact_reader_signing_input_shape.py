# SPDX-License-Identifier: AGPL-3.0-only
"""The offline signing command's closed input structs match the shared vector.

The Rust issuer test serializes the real Pending/Prior projections and compares
their keys with the same vector. This test reads the Windows command's source
(it cannot be compiled or run here) and compares its serde field/variant lists.
Key sets only: it does not execute the parser or prove signature acceptance.
"""
import json
import re
from pathlib import Path
import unittest

PROTOCOL = Path(__file__).resolve().parents[1]
SOURCE = PROTOCOL.parents[1] / "crates/owner-cli/src/windows/contact_reader_signing.rs"


def block(text, header):
    start = text.index(header)
    open_at = text.index("{", start)
    depth = 0
    for i in range(open_at, len(text)):
        depth += text[i] == "{"
        depth -= text[i] == "}"
        if depth == 0:
            return text[open_at + 1 : i]
    raise AssertionError(header)


def fields(body, indent=4):
    return re.findall(r"^ {%d}([a-z_0-9]+):" % indent, body, re.M)


class SigningInputShape(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((PROTOCOL / "contact-reader-signing-input-shape.json").read_text(encoding="utf-8"))
        self.src = SOURCE.read_text(encoding="utf-8")

    def struct(self, name):
        header = f"struct {name}"
        self.assertIn("#[serde(deny_unknown_fields)]", self.src[self.src.index(header) - 80 : self.src.index(header)])
        return fields(block(self.src, header))

    def variants(self, name):
        body = block(self.src, f"enum {name}")
        found = {}
        for m in re.finditer(r"^\s{4}([A-Z][a-z]+)(?: \{(.*?)^ {4}\})?,?$", body, re.M | re.S):
            found[m.group(1).lower()] = ["phase"] + fields(m.group(2) or "", 8)
        return found

    def test_command_structs_match_vector_in_order(self):
        self.assertEqual(self.struct("Create"), self.vector["create"])
        self.assertEqual(self.struct("Pending"), self.vector["pending"])
        self.assertEqual(self.struct("CreationSource"), self.vector["creation_source"])
        self.assertEqual(self.struct("Record"), self.vector["record"])

    def test_phase_tagged_enums_match_vector(self):
        self.assertEqual(self.variants("Prior"), self.vector["prior"])
        self.assertEqual(self.variants("Current"), self.vector["current"])

    def test_phase_tags_are_lowercase_like_the_server(self):
        for name in ("Prior", "Current"):
            header = self.src.index(f"enum {name}")
            attr = self.src[header - 120 : header]
            self.assertIn('tag = "phase"', attr)
            self.assertRegex(attr, r"rename_all = \"(snake_case|lowercase)\"")

    def test_vector_is_key_names_only(self):
        for value in json.dumps(self.vector["pending"] + self.vector["create"]).split('"')[1::2]:
            self.assertRegex(value, r"^[a-z_0-9]+$")


if __name__ == "__main__":
    unittest.main()
