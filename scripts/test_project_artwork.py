# SPDX-License-Identifier: AGPL-3.0-only
"""Keep original project SVGs self-contained, accessible and correctly sized."""

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SVG = "{http://www.w3.org/2000/svg}"
ASSETS = {"zrotext-banner.svg": (1200, 300), "zrotext-social-preview.svg": (1200, 630)}


def parse_safe_svg(source):
    if "<!DOCTYPE" in source.upper() or "<!ENTITY" in source.upper():
        raise ValueError("SVG declarations are not permitted")
    root = ET.fromstring(source)
    allowed = {SVG + name for name in ("svg", "title", "desc", "rect", "g", "path", "text")}
    for element in root.iter():
        if element.tag not in allowed:
            raise ValueError("SVG must contain only native static vectors and text")
        for name, value in element.attrib.items():
            if name.lower().startswith("on") or name in ("style", "href") or "}" in name:
                raise ValueError("SVG must not load resources or execute handlers")
            if "url(" in value.lower():
                raise ValueError("SVG paint must not reference resources")
    return root


class ProjectArtworkTests(unittest.TestCase):
    def assets(self):
        for name, dimensions in ASSETS.items():
            yield name, dimensions, parse_safe_svg((ROOT / "docs/assets" / name).read_text(encoding="utf-8"))

    def test_assets_are_static_svg_at_the_documented_dimensions(self):
        for name, (width, height), root in self.assets():
            with self.subTest(asset=name):
                self.assertEqual(root.tag, SVG + "svg")
                self.assertEqual(root.get("width"), str(width))
                self.assertEqual(root.get("height"), str(height))
                self.assertEqual(root.get("viewBox"), f"0 0 {width} {height}")

    def test_each_asset_has_a_resolved_accessible_name_and_description(self):
        for name, _, root in self.assets():
            with self.subTest(asset=name):
                self.assertEqual(root.get("role"), "img")
                ids = {element.get("id"): element for element in root.iter() if element.get("id")}
                self.assertEqual(root.get("aria-labelledby").split(), ["title", "description"])
                self.assertEqual(ids["title"].tag, SVG + "title")
                self.assertEqual(ids["description"].tag, SVG + "desc")
                self.assertTrue(ids["title"].text.strip())
                self.assertIn("Open-source Android SMS gateway", ids["description"].text)

    def test_artwork_preserves_the_native_mark_geometry_and_palette(self):
        mark = ET.parse(ROOT / "docs/assets/zrotext-mark.svg").getroot()
        for name, _, root in self.assets():
            with self.subTest(asset=name):
                group = root.find(SVG + "g")
                self.assertEqual(group.find(SVG + "path").attrib, mark.find(SVG + "path").attrib)
                self.assertEqual(group.find(SVG + "rect").attrib, mark.find(SVG + "rect").attrib)
                colors = {e.get(a) for e in root.iter() for a in ("fill", "stroke") if e.get(a)}
                self.assertEqual(colors, {"#b6f36a", "#0b100b", "none"})

    def test_visible_copy_is_only_project_identity_and_technical_descriptor(self):
        for name, _, root in self.assets():
            with self.subTest(asset=name):
                self.assertEqual([e.text for e in root.findall(SVG + "text")], ["ZROtext", "Open-source Android SMS gateway"])

    def test_readme_embeds_banner_with_meaningful_alternative_text(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('src="docs/assets/zrotext-banner.svg" alt="ZROtext: Open-source Android SMS gateway"', readme)

    def test_resource_and_active_content_regressions_are_rejected(self):
        for fragment in ('<script/>', '<image href="outside.svg"/>', '<path onclick="run()"/>', '<path fill="url(outside.svg)"/>', '<path style="fill:red"/>'):
            with self.subTest(fragment=fragment), self.assertRaises(ValueError):
                parse_safe_svg(f'<svg xmlns="http://www.w3.org/2000/svg">{fragment}</svg>')
        with self.assertRaises(ValueError):
            parse_safe_svg('<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>')


if __name__ == "__main__":
    unittest.main()
