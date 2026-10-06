# SPDX-License-Identifier: AGPL-3.0-only
"""The ordinary scripts unittest discovery checks generated index freshness."""

from pathlib import Path
import re
import tempfile
import unittest

import generate_llms


class PublicDocumentationIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for _, relative, _ in generate_llms.DOCUMENTS:
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

    def test_existing_agent_and_api_pages_are_indexed_once(self):
        rendered = generate_llms.render(self.root)
        for relative in (
            "docs/SEND-FIRST-MESSAGE.md",
            "docs/API-REFERENCE.md",
            "docs/agent-send-guardrails.md",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    rendered.count(f"]({generate_llms.RAW_BASE}{relative})"),
                    1,
                )

    def test_current_delivery_guarantees_page_is_indexed_once(self):
        rendered = generate_llms.render(self.root)
        self.assertEqual(
            rendered.count(f"]({generate_llms.RAW_BASE}docs/GUARANTEES.md)"),
            1,
        )

    def test_output_is_deterministic_and_has_only_allowlisted_raw_links(self):
        first = generate_llms.render(self.root)
        (self.root / "private-unlisted.md").write_text("synthetic excluded canary")
        self.assertEqual(first, generate_llms.render(self.root))
        self.assertNotIn("canary", first)
        self.assertNotIn("private-unlisted", first)
        expected = [generate_llms.RAW_BASE + path for _, path, _ in generate_llms.DOCUMENTS]
        links = [line.split("](", 1)[1].split("):", 1)[0] for line in first.splitlines() if line.startswith("- [")]
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

    def test_privacy_guard_hits_refuse_generation_without_echoing_content(self):
        path = self.root / generate_llms.DOCUMENTS[1][1]
        secret = "sk_" + "live_" + "A" * 24  # synthetic, assembled to avoid a literal
        path.write_text(f"token {secret}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "privacy guard") as caught:
            generate_llms.render(self.root)
        self.assertNotIn(secret, str(caught.exception))

    def test_relative_status_links_become_absolute(self):
        readme = self.root / "README.md"
        readme.write_text(
            "## Project status\n\nSee the [roadmap](docs/ROADMAP.md) and [site](https://example.org/x).\n",
            encoding="utf-8",
        )
        rendered = generate_llms.render(self.root)
        self.assertIn(f"]({generate_llms.RAW_BASE}docs/ROADMAP.md)", rendered)
        self.assertIn("](https://example.org/x)", rendered)

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


class CheckedInIndexTests(unittest.TestCase):
    """Run against the real repository tree."""

    @classmethod
    def setUpClass(cls):
        cls.text = (generate_llms.ROOT / "llms.txt").read_text(encoding="utf-8")
        cls.links = re.findall(r"\]\((https?://[^)\s]+)\)", cls.text)

    def test_every_link_is_absolute_main_branch_and_exists_in_tree(self):
        self.assertTrue(self.links)
        for link in self.links:
            self.assertTrue(link.startswith(generate_llms.RAW_BASE), link)
            self.assertTrue((generate_llms.ROOT / link[len(generate_llms.RAW_BASE):]).is_file(), link)

    def test_only_allowlisted_paths_appear(self):
        allowed = {generate_llms.RAW_BASE + path for _, path, _ in generate_llms.DOCUMENTS}
        self.assertEqual(set(self.links), allowed)
        listed = [line for line in self.text.splitlines() if line.startswith("- [")]
        self.assertEqual(len(listed), len(allowed))
        bare = re.sub(r"https?://[^)\s]+", "", self.text)
        for token in re.findall(r"(?:[\w.-]+/)+[\w.-]+\.(?:md|json|sql|py)", bare):
            if token != "scripts/generate_llms.py":  # maintenance note, not a link
                self.assertIn(generate_llms.RAW_BASE + token, allowed)

    def test_states_project_status_honestly(self):
        self.assertIn("active development", self.text)
        self.assertIn("hosted SMS service is not available", self.text)
        self.assertNotRegex(self.text, r"(?i)\bcarrier delivery (?:is|are) (?:supported|available|verified)")
        self.assertIn("does not establish", self.text)

    def test_no_hosted_service_hostnames(self):
        hosts = {re.match(r"https?://([^/]+)/", link)[1] for link in self.links}
        self.assertEqual(hosts, {"raw.githubusercontent.com"})

    def test_full_text_variant_is_not_published_while_over_size_budget(self):
        total = sum(len(generate_llms.read_document(generate_llms.ROOT, path).encode()) for _, path, _ in generate_llms.DOCUMENTS)
        self.assertGreater(total, 300 * 1024)
        self.assertFalse((generate_llms.ROOT / "llms-full.txt").exists())


if __name__ == "__main__":
    unittest.main()
