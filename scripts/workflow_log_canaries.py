# SPDX-License-Identifier: AGPL-3.0-only
"""Capture actual HTTP fixture output after Cargo's parent process has exited."""
import base64
import json
from pathlib import Path
import os
import subprocess
import uuid

TEST = 'workflow_runtime::http::tests::log_canaries::http_success_and_refusals_keep_content_and_credentials_out_of_process_output'
FRAME = b'workflow-test-receipt/'
CONTENT = 'synthetic workflow rejected plaintext canary'
OUT = b'workflow output capture positive control'
ERR = b'workflow diagnostic capture positive control'
FIXTURE_TIMEOUT_SECONDS = 600


def split_receipt(stderr, nonce):
    if len(stderr) > 2 * 1024 * 1024:
        raise ValueError('oversized diagnostics')
    prefix = FRAME + str(nonce).encode('ascii') + b':'
    values = None
    diagnostics = bytearray()
    for line in stderr.splitlines(keepends=True):
        if not line.startswith(FRAME):
            diagnostics.extend(line)
            continue
        if values is not None or not line.startswith(prefix):
            raise ValueError('duplicate or foreign receipt')
        payload = line.rstrip(b'\r\n')[len(prefix):]
        if len(payload) > 16384:
            raise ValueError('oversized receipt')
        decoded = base64.b64decode(payload + b'=' * (-len(payload) % 4), altchars=b'-_', validate=True)
        if base64.urlsafe_b64encode(decoded).rstrip(b'=') != payload:
            raise ValueError('noncanonical receipt')
        values = json.loads(decoded)
        if (not isinstance(values, list) or len(values) != 6
                or any(not isinstance(v, str) or not v or len(v.encode()) > 8192 for v in values)
                or values[0] != CONTENT or not values[1].startswith('ztw_')):
            raise ValueError('invalid expected canaries')
    if values is None:
        raise ValueError('missing receipt')
    return values, bytes(diagnostics)


def detects(output, values):
    return any(value.encode() in output for value in values)


def verify(stdout, stderr, nonce, mode):
    if len(stdout) > 2 * 1024 * 1024 or mode not in ('none', 'stdout', 'stderr'):
        raise ValueError('invalid capture')
    values, diagnostics = split_receipt(stderr, nonce)
    if OUT not in stdout or ERR not in diagnostics:
        raise ValueError('missing process capture positive control')
    if detects(stdout, values) != (mode == 'stdout') or detects(diagnostics, values) != (mode == 'stderr'):
        raise ValueError('unexpected content or credential output')


def main():
    # Fixed command/test and repository-owned cwd. No runtime executable or
    # receipt path is selected by a fixture environment variable.
    for mode in ('none', 'stdout', 'stderr'):
        nonce = uuid.uuid4()
        env = os.environ.copy()
        env.update(ZT_WORKFLOW_LOG_CANARY_CHILD='1', ZT_WORKFLOW_LOG_CANARY_NONCE=str(nonce),
                   ZT_WORKFLOW_LOG_CANARY_INJECT_LEAK=mode)
        try:
            result = subprocess.run(['cargo', 'test', '--locked', '--workspace', '--', '--exact', TEST,
                                     '--ignored', '--nocapture'], cwd=Path(__file__).resolve().parents[1],
                                    env=env, capture_output=True, check=False, timeout=FIXTURE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            raise RuntimeError('actual HTTP fixture timed out') from None
        # Never print captured logs: a failed fixture could contain a canary.
        if result.returncode:
            raise RuntimeError('actual HTTP fixture failed')
        if result.stdout.count(('test ' + TEST + ' ... ok').encode()) != 1:
            raise RuntimeError('exact HTTP fixture did not execute once')
        verify(result.stdout, result.stderr, nonce, mode)
    print('Actual HTTP output canary and both-stream sensitivity controls passed.')


if __name__ == '__main__':
    main()
