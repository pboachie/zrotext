# SPDX-License-Identifier: AGPL-3.0-only
"""Validate the Compose edge Caddyfile with the pinned Caddy image.

The Caddyfile is adapted (parsed and type-checked) by the exact Caddy build
the edge runs, so a directive or matcher that the pinned version rejects
fails here instead of at container start. Skipped when Docker is not
usable, so hosts without an engine still run the rest of the suite.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CADDYFILE = ROOT / "deploy" / "compose" / "Caddyfile"
PINNED_CADDY_IMAGE = "caddy:2.11.4"


def docker_usable() -> bool:
    try:
        return subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class CaddyfilePinnedValidateTest(unittest.TestCase):
    def test_compose_caddyfile_adapts_on_the_pinned_caddy(self):
        if not docker_usable():
            self.skipTest("docker engine unavailable")
        with tempfile.TemporaryDirectory(prefix="zrotext-caddy-") as directory:
            staged = Path(directory) / "Caddyfile"
            staged.write_text(CADDYFILE.read_text(encoding="utf-8"), encoding="utf-8")
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-e", "EDGE_DOMAIN=gw.example.test",
                    "-v", f"{staged.resolve()}:/config/Caddyfile:ro",
                    PINNED_CADDY_IMAGE,
                    "caddy", "validate", "--config", "/config/Caddyfile",
                ],
                capture_output=True,
                text=True,
                timeout=240,
            )
            combined = (result.stdout or "") + (result.stderr or "")
            self.assertIn(
                "Valid configuration",
                combined,
                f"pinned Caddy {PINNED_CADDY_IMAGE} rejected the Compose edge Caddyfile:\n{combined}",
            )


if __name__ == "__main__":
    unittest.main()
