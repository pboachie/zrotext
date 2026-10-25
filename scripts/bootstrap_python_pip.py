#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Qualify this interpreter's pip before network package operations.

The PSF's eMudhra notice pins this wheel and its SHA-256 independently of TLS:
https://discuss.python.org/t/109576
https://pypi.org/pypi/pip/26.2.2/json

Only the hash-verified wheel runs; its installation is offline, without deps,
index/config overrides or version-check traffic. --wheel consumes a local wheel
without network; --wheel-dir retains it for subsequent offline child venvs.
--fetch-only stages that wheel before setup-python's own offline pip upgrade.
Neither option changes installed/global CA stores or adds application certifi
dependencies. This packaging mitigation is not the unreleased CPython ssl
intermediate-key defense, nor a qualification of the OS trust store. The selected
interpreter and runner account remain trusted, not sandboxed by this helper.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.request

PIP_VERSION = "26.2.2"
CERTIFI_VERSION = "2026.10.19"
WHEEL_NAME = "pip-26.2.2-py3-none-any.whl"
WHEEL_URL = (
    "https://files.pythonhosted.org/packages/3f/06/"
    "3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/"
    + WHEEL_NAME
)
WHEEL_SHA256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
MAX_WHEEL_BYTES = 4 * 1024 * 1024


def pip_environment():
    """Ignore inherited pip configuration even for an isolated pip invocation."""
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith("PIP_")}
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def stable_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", value):
        return ()
    return tuple(map(int, value.split(".")))


def qualified():
    result = subprocess.run(
        [sys.executable, "-I", "-c",
         "import json,pip,pip._vendor.certifi as certifi; "
         "print(json.dumps([pip.__version__,certifi.__version__]))"],
        env=pip_environment(), capture_output=True, text=True, check=False,
    )
    if result.returncode:
        return False
    try:
        pip_version, certifi_version = json.loads(result.stdout)
        return (stable_version(pip_version) >= stable_version(PIP_VERSION)
                and stable_version(certifi_version) >= stable_version(CERTIFI_VERSION))
    except (ValueError, TypeError):
        return False


def verify_wheel(data):
    if len(data) > MAX_WHEEL_BYTES or hashlib.sha256(data).hexdigest() != WHEEL_SHA256:
        raise ValueError("pip bootstrap wheel checksum mismatch")
    return data


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise ValueError("pip bootstrap requires HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_wheel():
    opener = urllib.request.build_opener(
        HttpsOnlyRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(WHEEL_URL, timeout=60) as response:
        return verify_wheel(response.read(MAX_WHEEL_BYTES + 1))


def read_wheel(path):
    with path.open("rb") as stream:
        return verify_wheel(stream.read(MAX_WHEEL_BYTES + 1))


def obtain_wheel(wheel=None, wheel_dir=None):
    if wheel is not None:
        return read_wheel(wheel)
    if wheel_dir is None:
        return download_wheel()
    wheel_dir.mkdir(parents=True, exist_ok=True)
    target = wheel_dir / WHEEL_NAME
    if target.exists():
        return read_wheel(target)
    data = download_wheel()
    # Never overwrite a pre-existing file or follow an output symlink. The
    # retained copy is rehashed on every use, then staged privately for execution.
    with target.open("xb") as stream:
        stream.write(data)
    return data


def bootstrap(wheel=None, wheel_dir=None):
    if sys.version_info < (3, 10):
        raise ValueError("pip bootstrap requires Python 3.10 or newer")
    if wheel is not None and wheel_dir is not None:
        raise ValueError("choose one pip wheel source")
    ready = qualified()
    if ready and wheel is None and wheel_dir is None:
        return False
    data = obtain_wheel(wheel, wheel_dir)
    if ready:
        return False
    with tempfile.TemporaryDirectory(prefix="python-pip-bootstrap-") as directory:
        target = Path(directory) / WHEEL_NAME
        target.write_bytes(verify_wheel(data))
        # Execute the verified new pip directly from its wheel, including when
        # the selected venv has no pip. Old pip never makes a network request.
        subprocess.run(
            [sys.executable, "-I", str(target / "pip"), "--isolated",
             "--disable-pip-version-check", "install", "--no-index", "--no-deps",
             "--no-cache-dir", "--force-reinstall", str(target)],
            env=pip_environment(), check=True,
        )
    if not qualified():
        raise ValueError("pip bootstrap installed versions did not qualify")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--wheel", type=Path, help="hash-pinned local wheel; never download")
    source.add_argument("--wheel-dir", type=Path, help="retain verified wheel for offline consumers")
    parser.add_argument("--fetch-only", action="store_true", help="stage the wheel without installing pip")
    args = parser.parse_args()
    if args.fetch_only:
        if args.wheel_dir is None:
            parser.error("--fetch-only requires --wheel-dir")
        obtain_wheel(wheel_dir=args.wheel_dir)
        print("Verified pip bootstrap wheel staged; interpreter unchanged")
        return
    bootstrap(args.wheel, args.wheel_dir)
    print("pip and vendored certifi meet the packaging security floors")


if __name__ == "__main__":
    main()
