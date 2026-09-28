#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit-test the preparation probe's device serial validation."""

import unittest

from android_preparation_probe import validated_serial


class ValidatedSerialTest(unittest.TestCase):
    def test_accepts_emulator_usb_and_network_serials(self):
        for serial in ("emulator-5554", "0123456789ABCDEF", "192.168.1.2:5555", "serial-17_rev.3"):
            self.assertEqual(validated_serial(serial), serial)

    def test_returns_none_for_build_only_runs(self):
        self.assertIsNone(validated_serial(None))

    def test_rejects_argument_and_shell_separators(self):
        for serial in ("emulator;rm", "emulator -s x", "a'b", 'a"b', "a b", "$serial", "a\nb",
                       "x;y", "x|y", "x`y", "", "-leading-dash"):
            with self.assertRaises(ValueError):
                validated_serial(serial)


if __name__ == "__main__":
    unittest.main()
