"""Keep the generated roadmap truthful to docs/roadmap.json and well formed."""

import copy
from pathlib import Path
import re
import sys
import unittest
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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
        cap = next(c for c in roadmap.capabilities(data) if c["id"] == "export")
        self.assertEqual(cap["stage"], "build")
        build_before = roadmap.counts(data)["build"]
        cap["stage"] = "design"
        cap["done"] = ["Draft design"]
        total = roadmap.counts(data)
        self.assertEqual(total["build"], build_before - 1)
        self.assertIn(f'"Build" : {total["build"]}', roadmap.summary(data))
        self.assertIn(f'"Design" : {total["design"]}', roadmap.summary(data))
        self.assertIn(f"{roadmap.number(total['build'])} are being built", roadmap.alt_text(data))
        self.assertIn("Export and deletion<br/>· design\"]:::design", roadmap.track_map(data))
        self.assertIn("<b>Data export and account deletion</b> · design", roadmap.tracks(data))

    def test_alt_text_counts(self):
        self.assertEqual(
            roadmap.alt_text(self.data),
            "Roadmap at a glance: 22 capabilities in five tracks. Four are in a restricted "
            "pilot, eight are being built, three are in design and seven are planned. None has "
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
            "dependency cycle": lambda d: d["dependencies"].append(["api", "enrollment"]),
            "string gate state": lambda d: d["general_send_gate"][0][0].update(done="false"),
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

    def test_use_case_edits_update_all_customer_views(self):
        data = copy.deepcopy(self.data)
        case = data["use_cases"][0]
        case["title"] = "Changed customer outcome"
        case["example"] = "Changed example"
        case["acceptance"] = ["A measurable result"]
        for path in (roadmap.README, roadmap.ROADMAP, roadmap.USE_CASES):
            blocks = roadmap.blocks_for(path, data)
            self.assertIn(case["title"], blocks["usecases"])
            self.assertIn(case["example"], blocks["usecases"])
        self.assertIn("A measurable result", roadmap.use_case_details(data))
        case["priority"] = "later"
        self.assertNotIn(case["title"], roadmap.blocks_for(roadmap.README, data)["usecases"])
        self.assertIn(case["title"], roadmap.blocks_for(roadmap.ROADMAP, data)["usecases"])

    def test_customer_outcomes_do_not_change_capability_counts(self):
        data = copy.deepcopy(self.data)
        extra = copy.deepcopy(data["use_cases"][0])
        extra["id"] = "anothercase"
        data["use_cases"].append(extra)
        roadmap.validate(data)
        self.assertEqual(roadmap.counts(data), roadmap.counts(self.data))
        self.assertEqual(roadmap.alt_text(data), roadmap.alt_text(self.data))

    def test_rejects_incomplete_or_dangling_use_cases(self):
        cases = {
            "no catalog": lambda d: d.update(use_cases=[]),
            "duplicate id": lambda d: d["use_cases"].append(copy.deepcopy(d["use_cases"][0])),
            "unknown requirement": lambda d: d["use_cases"][0].update(requires=["nope"]),
            "duplicate requirement": lambda d: d["use_cases"][0].update(requires=["api", "api"]),
            "no requirements": lambda d: d["use_cases"][0].update(requires=[]),
            "no acceptance": lambda d: d["use_cases"][0].update(acceptance=[]),
            "empty journey": lambda d: d["use_cases"][0].update(journey=[""]),
            "missing audience": lambda d: d["use_cases"][0].pop("audience"),
            "unknown availability": lambda d: d["use_cases"][0].update(availability="live"),
            "unknown priority": lambda d: d["use_cases"][0].update(priority="urgent"),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                data = copy.deepcopy(self.data)
                mutate(data)
                with self.assertRaises(ValueError):
                    roadmap.validate(data)

    def test_workflow_cannot_outpace_direct_or_transitive_requirements(self):
        data = copy.deepcopy(self.data)
        data["use_cases"][0]["availability"] = "pilot"
        with self.assertRaisesRegex(ValueError, "exceeds its prerequisites"):
            roadmap.validate(data)
        # Even if the direct requirements are released, upstream API/sealed
        # work must also be ready before a customer workflow can be available.
        for cap in roadmap.capabilities(data):
            if cap["id"] in data["use_cases"][0]["requires"]:
                cap.update(stage="released", done=["Release evidence"])
        with self.assertRaisesRegex(ValueError, "exceeds its prerequisites"):
            roadmap.validate(data)

    def test_ready_dependencies_do_not_bypass_general_sending_gates(self):
        data = copy.deepcopy(self.data)
        case = data["use_cases"][0]
        case["availability"] = "pilot"
        required = roadmap.prerequisites(data, case["requires"])
        for cap in roadmap.capabilities(data):
            if cap["id"] in required:
                cap.update(stage="released", done=["Release evidence"])
        with self.assertRaisesRegex(ValueError, "general sending gates"):
            roadmap.validate(data)
        for group in data["general_send_gate"]:
            for step in group:
                step["done"] = True
        roadmap.validate(data)
        self.assertIn("Restricted pilot", roadmap.use_case_summary(data))
        case["availability"] = "released"
        roadmap.validate(data)
        self.assertIn("General release", roadmap.use_case_details(data))

    def test_generated_local_links_resolve_to_files_and_anchors(self):
        # Check generated output in memory so this also verifies links before
        # regeneration. Include the hand-written implementation plan it links.
        files = roadmap.rendered(self.data)
        plan = roadmap.ROOT / "docs" / "PRODUCT-PLAN.md"
        files[plan] = plan.read_text(encoding="utf-8")
        for source, content in files.items():
            if source.suffix != ".md":
                continue
            for target in re.findall(r"\[[^\]\n]+\]\(([^)\s]+)\)", content):
                url = urlsplit(target)
                if url.scheme or url.netloc:
                    continue
                path = (source.parent / unquote(url.path)).resolve() if url.path else source
                with self.subTest(source=source.name, target=target):
                    self.assertTrue(path.is_file(), f"Missing local target: {target}")
                    if url.fragment:
                        text = files.get(path)
                        if text is None:
                            text = path.read_text(encoding="utf-8")
                        anchors = set(re.findall(r'<a id="([^"]+)"', text))
                        anchors.update(roadmap.slug(h) for h in re.findall(r"^#{1,6} (.+)$", text, re.M))
                        self.assertIn(unquote(url.fragment), anchors)


if __name__ == "__main__":
    unittest.main()
