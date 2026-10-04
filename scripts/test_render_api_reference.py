import json
import unittest
from pathlib import Path

import render_api_reference as render

SPEC = json.loads(render.SPEC.read_text(encoding="utf-8"))


class RenderApiReferenceTest(unittest.TestCase):
    def test_committed_page_is_current(self):
        self.assertEqual(render.OUTPUT.read_text(encoding="utf-8"), render.render(SPEC))

    def test_every_operation_and_schema_is_rendered(self):
        page = render.render(SPEC)
        for path, item in SPEC["paths"].items():
            for method in render.METHODS:
                if method in item:
                    self.assertIn(f"### `{method.upper()} {path}`", page)
        for name in SPEC["components"]["schemas"]:
            self.assertIn(f"### {name}\n", page)

    def test_planned_routes_are_labelled_planned(self):
        page = render.render(SPEC)
        self.assertEqual(page.count("Planned: no route exists today"),
                         sum(1 for item in SPEC["paths"].values() for op in item.values()
                             if isinstance(op, dict) and op.get("x-implemented") is False))


if __name__ == "__main__":
    unittest.main()
