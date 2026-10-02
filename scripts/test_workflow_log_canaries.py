# SPDX-License-Identifier: AGPL-3.0-only
import base64
import json
import unittest
import uuid
from workflow_log_canaries import CONTENT, OUT, ERR, split_receipt, verify


class WorkflowLogCanaryTest(unittest.TestCase):
    def setUp(self):
        self.nonce = uuid.uuid4()
        values = [CONTENT, 'ztw_synthetic', 'projection', 'archive', 'projection bytes', 'archive bytes']
        payload = base64.urlsafe_b64encode(json.dumps(values).encode()).rstrip(b'=')
        self.frame = b'workflow-test-receipt/' + str(self.nonce).encode() + b':' + payload + b'\n'

    def test_capture_preserves_binary_diagnostics_and_detects_both_stream_leaks(self):
        stderr = self.frame + b'\xff\n' + ERR
        verify(OUT, stderr, self.nonce, 'none')
        self.assertIn(b'\xff', split_receipt(stderr, self.nonce)[1])
        for mode in ('stdout', 'stderr'):
            out = OUT + (CONTENT.encode() if mode == 'stdout' else b'')
            err = stderr + (CONTENT.encode() if mode == 'stderr' else b'')
            verify(out, err, self.nonce, mode)
            with self.assertRaises(ValueError):
                verify(out, err, self.nonce, 'none')

    def test_forged_duplicate_missing_oversized_receipts_and_missing_controls_fail_closed(self):
        for stderr in (self.frame * 2, b'', self.frame.replace(str(self.nonce).encode(), str(uuid.uuid4()).encode()),
                       b'workflow-test-receipt/' + str(self.nonce).encode() + b':' + b'a' * 16385):
            with self.assertRaises(ValueError):
                split_receipt(stderr, self.nonce)
        with self.assertRaises(ValueError):
            verify(b'', self.frame + ERR, self.nonce, 'none')
        with self.assertRaises(ValueError):
            verify(OUT, self.frame, self.nonce, 'none')


if __name__ == '__main__':
    unittest.main()
