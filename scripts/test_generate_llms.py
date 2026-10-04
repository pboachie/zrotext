# SPDX-License-Identifier: AGPL-3.0-only
"""The ordinary scripts unittest discovery checks generated index freshness."""

from pathlib import Path
import tempfile
import unittest

import generate_llms


class PublicDocumentationIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for _, relative in generate_llms.DOCUMENTS:
            source = self.root / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("# Synthetic public documentation\n", encoding="utf-8")
        (self.root / "README.md").write_text(
            "# Synthetic project\n\n## Project status\n\n"
            "Development only. Hosted service is unavailable.\n"
            "Simulator examples send nothing.\n\n## More\n\nLater section.\n",
            encoding="utf-8",
        )

    def test_checked_in_index_is_current(self):
        generate_llms.synchronize(check=True)

    def test_output_is_deterministic_and_has_only_allowlisted_raw_links(self):
        first = generate_llms.render(self.root)
        (self.root / "private-unlisted.md").write_text("synthetic excluded canary")
        self.assertEqual(first, generate_llms.render(self.root))
        self.assertNotIn("canary", first)
        self.assertNotIn("private-unlisted", first)
        expected = [generate_llms.RAW_BASE + path for _, path in generate_llms.DOCUMENTS]
        links = [line.split("](", 1)[1][:-1] for line in first.splitlines() if line.startswith("- [")]
        self.assertEqual(links, expected)

    def test_status_comes_from_current_readme_without_following_later_sections(self):
        rendered = generate_llms.render(self.root)
        self.assertIn(
            "Development only. Hosted service is unavailable. Simulator examples send nothing.",
            rendered,
        )
        self.assertNotIn("Later section", rendered)
        readme = self.root / "README.md"
        readme.write_text(readme.read_text().replace("Development only.", "Restricted testing."))
        self.assertIn("Restricted testing.", generate_llms.render(self.root))

    def test_unlisted_sources_are_refused(self):
        for source in ("private.md", "../outside.md", "/outside.md"):
            with self.assertRaisesRegex(ValueError, "allowlist"):
                generate_llms.read_document(self.root, source)

    def test_missing_empty_and_invalid_utf8_sources_refuse_generation(self):
        path = self.root / generate_llms.DOCUMENTS[1][1]
        for contents in (None, b"\n", b"\xff"):
            if contents is None:
                path.unlink()
            else:
                path.write_bytes(contents)
            with self.assertRaises((OSError, UnicodeError, ValueError)):
                generate_llms.synchronize(self.root)
            self.assertFalse((self.root / "llms.txt").exists())

    def test_missing_and_stale_index_fail_check_without_rewriting(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            generate_llms.synchronize(self.root, check=True)
        generate_llms.synchronize(self.root)
        generate_llms.synchronize(self.root, check=True)
        output = self.root / "llms.txt"
        output.write_bytes(b"stale synthetic index\n")
        with self.assertRaisesRegex(ValueError, "stale"):
            generate_llms.synchronize(self.root, check=True)
        self.assertEqual(output.read_bytes(), b"stale synthetic index\n")

    def test_status_changes_make_existing_index_stale(self):
        generate_llms.synchronize(self.root)
        readme = self.root / "README.md"
        readme.write_text(readme.read_text().replace("Development only.", "Restricted testing."))
        with self.assertRaisesRegex(ValueError, "stale"):
            generate_llms.synchronize(self.root, check=True)

    def test_checkout_line_endings_do_not_make_current_index_stale(self):
        generate_llms.synchronize(self.root)
        output = self.root / "llms.txt"
        output.write_bytes(output.read_bytes().replace(b"\n", b"\r\n"))
        generate_llms.synchronize(self.root, check=True)

    def test_missing_ambiguous_or_empty_status_is_refused(self):
        for contents in ("# No status\n", "## Project status\n" * 2, "## Project status\n\n## Next\n"):
            (self.root / "README.md").write_text(contents, encoding="utf-8")
            with self.assertRaises(ValueError):
                generate_llms.render(self.root)


if __name__ == "__main__":
    unittest.main()
