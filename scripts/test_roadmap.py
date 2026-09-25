"""Keep the generated roadmap truthful to docs/roadmap.json and well formed."""

import copy
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
import roadmap  # noqa: E402


class RoadmapTest(unittest.TestCase):
    def setUp(self):
        self.data = roadmap.load()

    def test_committed_output_matches_data(self):
        for path, expected in roadmap.rendered(self.data).items():
            current = path.read_text(encoding="utf-8").replace("\r\n", "\n")
            self.assertEqual(current, expected, f"{path.name} is stale; run scripts/roadmap.py")

    def test_svg_is_well_formed_and_accessible(self):
        svg = ET.fromstring(roadmap.render_svg(self.data))
        ns = {"s": "http://www.w3.org/2000/svg"}
        self.assertEqual(svg.find("s:desc", ns).text, roadmap.alt_text(self.data))
        rows = len(roadmap.capabilities(self.data))
        self.assertEqual(len(svg.findall(".//s:rect[@class]", ns)), rows * 4 + 3)

    def test_stage_change_updates_every_view(self):
        data = copy.deepcopy(self.data)
        cap = data["tracks"][2]["capabilities"][2]
        self.assertEqual(cap["stage"], "planned")
        cap["stage"] = "design"
        cap["done"] = ["Draft design"]
        total = roadmap.counts(data)
        self.assertEqual(total["planned"], 0)
        self.assertNotIn('"Planned"', roadmap.summary(data))
        self.assertIn(f'"Design" : {total["design"]}', roadmap.summary(data))
        self.assertNotIn(" planned", roadmap.alt_text(data))
        self.assertIn("Export and deletion<br/>· design\"]:::design", roadmap.track_map(data))
        self.assertIn("<b>Data export and account deletion</b> · design", roadmap.tracks(data))

    def test_alt_text_counts(self):
        self.assertEqual(
            roadmap.alt_text(self.data),
            "Roadmap at a glance: 15 capabilities in four tracks. Four are in a restricted "
            "pilot, seven are being built, three are in design and one is planned. None has "
            "reached general release.",
        )

    def test_rejects_misleading_data(self):
        cases = {
            "unknown stage": lambda d: d["tracks"][0]["capabilities"][0].update(stage="beta"),
            "duplicate id": lambda d: d["tracks"][1]["capabilities"][0].update(id="enrollment"),
            "missing evidence": lambda d: d["tracks"][0]["capabilities"][0].update(evidence=[]),
            "started without done work": lambda d: d["tracks"][0]["capabilities"][0].update(done=[]),
            "unknown dependency": lambda d: d["dependencies"].append(["enrollment", "nope"]),
            "incomplete map order": lambda d: d["track_map_order"].pop(),
            "overlong name": lambda d: d["tracks"][0]["capabilities"][0].update(name="x" * 60),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                data = copy.deepcopy(self.data)
                mutate(data)
                with self.assertRaises(ValueError):
                    roadmap.validate(data)

    def test_regions_must_exist_exactly_once(self):
        with self.assertRaises(ValueError):
            roadmap.replace_blocks("no markers", {"overview": "x"}, "sample.md")
        text = "<!-- roadmap:overview -->\nold\n<!-- /roadmap:overview -->"
        self.assertEqual(
            roadmap.replace_blocks(text, {"overview": "new"}, "sample.md"),
            "<!-- roadmap:overview -->\nnew\n<!-- /roadmap:overview -->",
        )

    def test_track_links_match_generated_headings(self):
        tracks = roadmap.tracks(self.data)
        for track in self.data["tracks"]:
            self.assertIn(f"## {track['title']}", tracks)
            self.assertIn(f"(#{roadmap.slug(track['title'])})", roadmap.summary(self.data))


if __name__ == "__main__":
    unittest.main()
