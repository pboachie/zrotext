# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded stdout readiness handoff for the synthetic conversation fixture."""
import tempfile
import unittest
from pathlib import Path

from conversation_simulator import MAX_READY_BYTES, MAX_STARTUP_LOG_BYTES, READY_MARKER, read_ready


class ReadinessTests(unittest.TestCase):
    def read(self, captured):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "server.log"
            log.write_bytes(captured)
            return read_ready(log)

    def test_only_an_exact_complete_marker_is_a_readiness_record(self):
        record = READY_MARKER + b'{"port":7}\n'
        self.assertIsNone(self.read(record[:-1]))
        self.assertIsNone(self.read(b"prefix " + record))
        self.assertEqual({"port": 7}, self.read(b"running one test\n" + record))
        self.assertEqual({"port": 7}, self.read(b"test qualified_name ... \n" + record))

    def test_malformed_non_object_and_duplicate_readiness_fail_closed(self):
        for captured in (READY_MARKER + b"invalid\n", READY_MARKER + b"[]\n",
                         READY_MARKER + b"\xff\n", (READY_MARKER + b"{}\n") * 2,
                         READY_MARKER + b"{}\n" + READY_MARKER + b"{"):
            with self.subTest(captured=captured), self.assertRaises(RuntimeError):
                self.read(captured)

    def test_readiness_and_startup_log_bounds_apply_before_parsing(self):
        for captured in (READY_MARKER + b"x" * (MAX_READY_BYTES + 1),
                         b"x" * (MAX_STARTUP_LOG_BYTES + 1)):
            with self.subTest(size=len(captured)), self.assertRaises(RuntimeError):
                self.read(captured)


if __name__ == "__main__":
    unittest.main()
