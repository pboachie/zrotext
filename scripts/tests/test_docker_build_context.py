# SPDX-License-Identifier: AGPL-3.0-only
"""Keep compile-time web assets available in the server image build stage."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


def missing_embedded_web_assets(dockerfile: str) -> list[str]:
    build_stage = dockerfile.split("FROM rust-base AS build\n", 1)[1]
    before_compile = build_stage.split("RUN cargo build --locked", 1)[0]
    copies = []
    for source, destination in re.findall(r"^COPY (\S+) (\S+)$", before_compile, re.M):
        copies.append((ROOT / source, destination.removeprefix("./")))
    missing = []
    for source in (ROOT / "crates/server/src").rglob("*.rs"):
        for asset in re.findall(r'include_(?:str|bytes)!\(\s*"([^"\n]+)"', source.read_text(encoding="utf-8")):
            path = (source.parent / asset).resolve()
            relative = path.relative_to(ROOT.resolve()).as_posix()
            if not relative.startswith("web/"):
                continue
            covered = any(
                path.is_relative_to(copied.resolve())
                and (Path(destination) / path.relative_to(copied.resolve())).as_posix() == relative
                for copied, destination in copies
            )
            if not path.is_file() or not covered:
                missing.append(relative)
    return sorted(set(missing))


class DockerBuildContextTest(unittest.TestCase):
    def test_image_build_has_every_embedded_web_asset(self):
        dockerfile = (ROOT / "deploy/compose/Dockerfile").read_text(encoding="utf-8")
        self.assertEqual(missing_embedded_web_assets(dockerfile), [])

    def test_omitting_review_assets_is_detected_before_image_compilation(self):
        dockerfile = (ROOT / "deploy/compose/Dockerfile").read_text(encoding="utf-8")
        without_review = dockerfile.replace("COPY web/review ./web/review\n", "")
        self.assertEqual(missing_embedded_web_assets(without_review), [
            "web/review/root-material.mjs", "web/review/root.css", "web/review/root.html",
            "web/review/root.mjs", "web/review/single-flight.mjs",
        ])


if __name__ == "__main__":
    unittest.main()
