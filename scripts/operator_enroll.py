#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Interactively register and verify an address-bound invited owner."""

import getpass
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError("unexpected redirect")


def main():
    if not sys.stdin.isatty():
        raise SystemExit("an interactive terminal is required")
    origin = input("Exact AUTH_ORIGIN (https://...): ").rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise SystemExit("enter a canonical HTTPS origin without a path")
    email = input("Invited email: ")
    password = getpass.getpass("New password: ")
    invite = getpass.getpass("Address-bound invite token: ")
    opener = urllib.request.build_opener(NoRedirect)

    def post(path, body, extra_headers, expected):
        request = urllib.request.Request(
            origin + "/v1/auth/" + path,
            data=json.dumps(body).encode("utf-8"),
            headers={"Origin": origin, "Content-Type": "application/json", **extra_headers},
            method="POST",
        )
        try:
            with opener.open(request, timeout=15) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            raise SystemExit(f"{path} returned HTTP {error.code}") from None
        if status != expected:
            raise SystemExit(f"{path} returned unexpected HTTP {status}")

    post("register", {"email": email, "password": password},
         {"x-zrotext-registration-token": invite}, 202)
    print("Registration request received. Check that mailbox for a code.")
    code = getpass.getpass("Emailed verification code: ")
    post("verify-email", {"token": code}, {}, 204)
    print("Email verified. Sign in at /owner/devices.html.")


if __name__ == "__main__":
    main()
