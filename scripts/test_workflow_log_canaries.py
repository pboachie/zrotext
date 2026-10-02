# SPDX-License-Identifier: AGPL-3.0-only
import base64
import json
import unittest
import uuid
from unittest.mock import patch
from types import SimpleNamespace
import workflow_log_canaries as runner
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


    def test_receipt_refuses_invalid_shape_and_noncanonical_encoding(self):
        for values in ([CONTENT] * 5, [CONTENT, 'ztw_synthetic', '', 'a', 'b', 'c'],
                       [CONTENT, 'wrong-token', 'a', 'b', 'c', 'd']):
            payload = base64.urlsafe_b64encode(json.dumps(values).encode()).rstrip(b'=')
            frame = b'workflow-test-receipt/' + str(self.nonce).encode() + b':' + payload + b'\n'
            with self.assertRaises(ValueError):
                split_receipt(frame, self.nonce)
        with self.assertRaises(ValueError):
            split_receipt(self.frame[:-1] + b'=\n', self.nonce)

    def test_top_level_runner_selects_exact_fixture_and_checks_each_stream(self):
        def child(argv, **kwargs):
            self.assertEqual(argv, ['cargo', 'test', '--locked', '--workspace', '--', '--exact',
                                    runner.TEST, '--ignored', '--nocapture'])
            env = kwargs['env']
            nonce = env['ZT_WORKFLOW_LOG_CANARY_NONCE']
            mode = env['ZT_WORKFLOW_LOG_CANARY_INJECT_LEAK']
            frame = self.frame.replace(str(self.nonce).encode(), nonce.encode())
            stdout = ('test ' + runner.TEST + ' ... ok\n').encode() + OUT
            stderr = frame + ERR
            if mode == 'stdout': stdout += CONTENT.encode()
            if mode == 'stderr': stderr += CONTENT.encode()
            return SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
        with patch.object(runner.subprocess, 'run', side_effect=child) as run, patch('builtins.print'):
            runner.main()
        self.assertEqual(run.call_count, 3)
        with patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=1)), patch('builtins.print'):
            with self.assertRaises(RuntimeError):
                runner.main()


if __name__ == '__main__':
    unittest.main()
