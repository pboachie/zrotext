"""Experimental synthetic agent adapter. Requires the built TypeScript SDK.

No network transport, credentials, plaintext input or alternate crypto exists.
"""
import base64
import json
from pathlib import Path
import subprocess


class AdapterError(Exception):
    """A bounded, redacted local adapter failure."""


def simulate_submission(envelope: bytes, responses: list, max_attempts: int = 1) -> dict:
    """Exercise the shared SDK HTTP contract using explicit synthetic responses."""
    if not isinstance(envelope, bytes) or len(envelope) > 36864:
        raise AdapterError("invalid_request")
    if not isinstance(responses, list) or len(responses) > 3:
        raise AdapterError("invalid_request")
    if type(max_attempts) is not int or not 1 <= max_attempts <= 3:
        raise AdapterError("invalid_request")
    bridge = Path(__file__).resolve().parent / "simulator-bridge.mjs"
    try:
        request = json.dumps({"envelope": base64.b64encode(envelope).decode("ascii"),
                              "responses": responses, "maxAttempts": max_attempts})
        if len(request.encode("utf-8")) > 65536:
            raise AdapterError("invalid_request")
        result = subprocess.run(["node", str(bridge)], input=request, text=True,
                                capture_output=True, timeout=15, check=True)
        return json.loads(result.stdout)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        # Never echo subprocess stderr, fixture bodies, keys or envelope bytes.
        raise AdapterError("adapter_unavailable") from None
