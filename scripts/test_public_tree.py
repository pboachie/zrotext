"""Regression checks for the high-confidence public-tree filters."""

import unittest

from check_public_tree import scan_line


class PublicTreeTests(unittest.TestCase):
    def test_rejects_credential_shapes_without_exposing_value(self):
        sample = "sk_" + "test_" + "A" * 24
        self.assertIn("credential-shaped token", scan_line(sample))

    def test_rejects_real_phone_shape(self):
        sample = "+1" + "9" * 10
        self.assertIn("non-synthetic US phone number", scan_line(sample))
        self.assertIn("non-synthetic US phone number", scan_line(sample[2:]))
        self.assertIn("non-synthetic US phone number", scan_line(sample[2:5] + "-" + sample[5:8] + "-" + sample[8:]))

    def test_accepts_reserved_example_number(self):
        self.assertNotIn("non-synthetic US phone number", scan_line("+12025550123"))

    def test_rejects_trailing_whitespace(self):
        self.assertIn("trailing whitespace", scan_line("text "))


if __name__ == "__main__":
    unittest.main()
