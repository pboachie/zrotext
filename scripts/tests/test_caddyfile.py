# SPDX-License-Identifier: AGPL-3.0-only
"""Validate the Compose edge Caddyfile with the pinned Caddy image.

The Caddyfile is adapted (parsed and type-checked) by the exact Caddy build
the edge runs, so a directive or matcher that the pinned version rejects
fails here instead of at container start. The compression scope is then
checked twice: structurally in the adapted JSON, and at runtime by running
the unmodified Caddyfile in front of a synthetic upstream. Only static
dashboard assets may be compressed; API and JSON responses, which can carry
one-time secrets, must never be (a BREACH-style length side channel).
Skipped when Docker is not usable, so hosts without an engine still run the
rest of the suite.
"""

import json
import re
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CADDYFILE = ROOT / "deploy" / "compose" / "Caddyfile"
COMPOSE = ROOT / "deploy" / "compose" / "compose.yaml"

ASSET_PATHS = ["/owner/*", "/billing", "/billing/dashboard.js"]
ASSET_CONTENT_TYPES = ["text/html*", "text/css*", "text/javascript*", "font/*"]

# Large enough to clear Caddy's default minimum encode length.
BODY = "z" * 2048

# Path -> response Content-Type served by the synthetic upstream.
UPSTREAM_TYPES = {
    "/owner/devices": "text/html; charset=utf-8",
    "/owner/devices.js": "text/javascript; charset=utf-8",
    "/owner/devices.css": "text/css; charset=utf-8",
    "/owner/font.woff2": "font/woff2",
    "/billing": "text/html; charset=utf-8",
    "/billing/dashboard.js": "text/javascript; charset=utf-8",
    "/owner/events": "text/event-stream",
    "/owner/leak.json": "application/json",
    "/v1/auth/api-keys": "application/json",
    "/v1/owner/messages": "application/json",
    "/v1/owner/export.js": "text/javascript; charset=utf-8",
    "/billing/success": "text/html; charset=utf-8",
}

# (method, path, expect compressed)
RUNTIME_CASES = [
    ("GET", "/owner/devices", True),
    ("GET", "/owner/devices.js", True),
    ("GET", "/owner/devices.css", True),
    ("GET", "/owner/font.woff2", True),
    ("GET", "/billing", True),
    ("GET", "/billing/dashboard.js", True),
    # API and JSON responses, including one-time secret creation.
    ("POST", "/v1/auth/api-keys", False),
    ("GET", "/v1/owner/messages", False),
    # JSON under the asset path: the content-type gate alone must refuse it.
    ("GET", "/owner/leak.json", False),
    # JavaScript outside the asset path: the path gate alone must refuse it.
    ("GET", "/v1/owner/export.js", False),
    # A non-GET to an asset path: the method gate must refuse it.
    ("POST", "/owner/devices", False),
    # The live-update stream and non-dashboard billing pages.
    ("GET", "/owner/events", False),
    ("GET", "/billing/success", False),
]


def pinned_caddy_image(compose_text: str | None = None) -> str:
    if compose_text is None:
        compose_text = COMPOSE.read_text(encoding="utf-8")
    # Accept the upstream name and Docker's official ECR mirror, retaining the
    # complete digest for the runtime checks. Other registries are not aliases.
    matches = re.findall(
        r"^[ \t]+image:[ \t]*("
        r"(?:public\.ecr\.aws/docker/library/)?caddy:"
        r"[0-9]+\.[0-9]+\.[0-9]+-alpine(?:@sha256:[0-9a-f]{64})?"
        r")[ \t]*$",
        compose_text,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise AssertionError("compose.yaml must pin exactly one official caddy image")
    if matches[0].startswith("public.ecr.aws/") and "@sha256:" not in matches[0]:
        raise AssertionError("the official caddy mirror must retain its manifest digest")
    return matches[0]


class CaddyImageReferenceTest(unittest.TestCase):
    def test_preserves_the_complete_official_mirror_digest(self):
        image = "public.ecr.aws/docker/library/caddy:2.11.4-alpine@sha256:" + "a" * 64
        self.assertEqual(pinned_caddy_image(f"  edge:\n    image: {image}\n"), image)

    def test_accepts_the_upstream_image_name(self):
        image = "caddy:2.11.4-alpine"
        self.assertEqual(pinned_caddy_image(f"  edge:\n    image: {image}\n"), image)

    def test_rejects_another_registry_or_repository_and_incomplete_pins(self):
        for image in (
            "mirror.example.test/caddy:2.11.4-alpine",
            "public.ecr.aws/other/library/caddy:2.11.4-alpine",
            "public.ecr.aws/docker/library/not-caddy:2.11.4-alpine",
            "public.ecr.aws/docker/library/caddy:latest",
            "public.ecr.aws/docker/library/caddy:2.11.4-alpine",
            "public.ecr.aws/docker/library/caddy:2.11.4-alpine@sha256:abc",
        ):
            with self.subTest(image=image), self.assertRaises(AssertionError):
                pinned_caddy_image(f"  edge:\n    image: {image}\n")

    def test_rejects_missing_or_duplicate_official_caddy_references(self):
        with self.assertRaises(AssertionError):
            pinned_caddy_image("services:\n  app:\n    image: zrotext:local\n")
        with self.assertRaises(AssertionError):
            pinned_caddy_image("    image: caddy:2.11.4-alpine\n" * 2)


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


def docker(*args: str, timeout: int = 240, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )
    if check and result.returncode != 0:
        raise AssertionError(f"docker {' '.join(args)} failed:\n{result.stdout}{result.stderr}")
    return result


def upstream_caddyfile() -> str:
    lines = [":8080 {"]
    for index, (path, content_type) in enumerate(UPSTREAM_TYPES.items()):
        lines.append(f"\t@p{index} path {path}")
        lines.append(f'\theader @p{index} Content-Type "{content_type}"')
    lines.append(f'\trespond "{BODY}" 200')
    lines.append("}")
    return "\n".join(lines) + "\n"


class CaddyfilePinnedValidateTest(unittest.TestCase):
    def setUp(self):
        if not docker_usable():
            self.skipTest("docker engine unavailable")
        self.image = pinned_caddy_image()
        self.directory = tempfile.TemporaryDirectory(prefix="zrotext-caddy-")
        self.addCleanup(self.directory.cleanup)
        self.staged = Path(self.directory.name) / "Caddyfile"
        self.staged.write_text(CADDYFILE.read_text(encoding="utf-8"), encoding="utf-8")

    def caddy(self, *command: str, domain: str = "gw.example.test") -> str:
        result = docker(
            "run", "--rm",
            "-e", f"EDGE_DOMAIN={domain}",
            "-v", f"{self.staged.resolve()}:/config/Caddyfile:ro",
            self.image, "caddy", *command, "--config", "/config/Caddyfile",
            check=False,
        )
        return (result.stdout or "") + (result.stderr or "")

    def test_compose_caddyfile_adapts_on_the_pinned_caddy(self):
        combined = self.caddy("validate")
        self.assertIn(
            "Valid configuration",
            combined,
            f"pinned Caddy {self.image} rejected the Compose edge Caddyfile:\n{combined}",
        )

    def test_only_dashboard_assets_are_eligible_for_compression(self):
        adapted = self.caddy("adapt")
        config = json.loads(adapted[adapted.index('{"apps"'):].splitlines()[0])
        encoders = []

        def walk(routes):
            for route in routes:
                for handler in route.get("handle", []):
                    if handler.get("handler") == "encode":
                        encoders.append((route.get("match"), handler))
                    walk(handler.get("routes", []))

        for server in config["apps"]["http"]["servers"].values():
            walk(server["routes"])
        self.assertEqual(len(encoders), 1, f"expected exactly one encode handler: {encoders}")
        request_match, handler = encoders[0]
        self.assertEqual(
            request_match,
            [{
                "method": ["GET", "HEAD"],
                "not": [{"path": ["/owner/events"]}],
                "path": ASSET_PATHS,
            }],
        )
        self.assertEqual(
            handler.get("match"), {"headers": {"Content-Type": ASSET_CONTENT_TYPES}}
        )

    def test_edge_compresses_static_assets_but_never_api_or_json(self):
        suffix = uuid.uuid4().hex[:12]
        network = f"zrotext-caddy-net-{suffix}"
        upstream = f"zrotext-caddy-app-{suffix}"
        edge = f"zrotext-caddy-edge-{suffix}"
        upstream_file = Path(self.directory.name) / "Upstream"
        upstream_file.write_text(upstream_caddyfile(), encoding="utf-8")
        docker("network", "create", network)
        self.addCleanup(docker, "network", "rm", network, check=False)
        self.addCleanup(docker, "rm", "-f", upstream, edge, check=False)
        docker(
            "run", "-d", "--name", upstream, "--network", network,
            "--network-alias", "app",
            "-v", f"{upstream_file.resolve()}:/etc/caddy/Caddyfile:ro",
            self.image,
        )
        # The unmodified Compose Caddyfile, served over plain HTTP.
        docker(
            "run", "-d", "--name", edge, "--network", network,
            "-e", "EDGE_DOMAIN=:80",
            "-v", f"{self.staged.resolve()}:/etc/caddy/Caddyfile:ro",
            self.image,
        )
        ready = f"until wget -q -O /dev/null http://127.0.0.1/billing; do sleep 0.2; done"
        docker("exec", edge, "timeout", "30", "sh", "-c", ready)
        for method, path, compressed in RUNTIME_CASES:
            with self.subTest(method=method, path=path):
                command = [
                    "exec", edge, "wget", "-S", "-O", "/dev/null",
                    "--header", "Accept-Encoding: gzip",
                ]
                if method == "POST":
                    command += ["--post-data", "synthetic"]
                result = docker(*command, f"http://127.0.0.1{path}", check=False)
                headers = (result.stdout or "") + (result.stderr or "")
                self.assertIn("200 OK", headers, headers)
                encoded = re.search(r"(?im)^\s*content-encoding:\s*gzip", headers)
                if compressed:
                    self.assertIsNotNone(encoded, f"{method} {path} was not compressed:\n{headers}")
                else:
                    self.assertIsNone(encoded, f"{method} {path} was compressed:\n{headers}")


if __name__ == "__main__":
    unittest.main()
