# SPDX-License-Identifier: AGPL-3.0-only
"""Keep SDK qualification compilers patched without raising language floors."""
import importlib.util
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/sdk-consolidated.yml"


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WEBHOOK = load("webhook_toolchains", "sdk/native/package-webhooks-native.py")
HPKE = load("hpke_toolchains", "sdk/native/hpke-candidate/package-native.py")


class ToolchainAccepted(Exception):
    """Stop before package creation or dependency resolution in a unit test."""


class SdkToolchainTests(unittest.TestCase):
    def test_sdk_workflow_uses_patched_qualification_toolchains(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        for key, expected in (("go-version", {"1.26.10"}),
                              ("ruby-version", {"3.3.13"}),
                              ("dotnet-version", {"8.0.x", "10.0.402"}),
                              ("node-version", {"24.22.1"})):
            with self.subTest(toolchain=key):
                versions = re.findall(r"(?m)^\s+" + key + r": '([^']+)'$", text)
                self.assertTrue(versions)
                self.assertEqual(set(versions), expected)

    def test_ruby_action_catalog_includes_the_patched_runtime_on_windows(self):
        # v1.335.0 adds Ruby 3.3.13 to both the builder and Windows catalogs.
        text = WORKFLOW.read_text(encoding="utf-8")
        pins = re.findall(r"uses: ruby/setup-ruby@([0-9a-f]{40})", text)
        self.assertTrue(pins)
        self.assertEqual(set(pins), {"7f797815d8adceb1c412e7abefdd1ab4abc47a5f"})

    def test_windows_webhook_uses_setup_go_instead_of_a_download_override(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        block = text.split('name: "Native webhook installed archives [go]: '
                           'Verify bounded archive through fresh installed consumer"', 1)[1]
        block = block.split("      - name:", 1)[0]
        self.assertIn("go version", block)
        self.assertIn("package-webhooks-native.py --language 'go'", block)
        self.assertNotIn("Invoke-WebRequest", block)
        self.assertNotIn("$env:Path =", block)
        self.assertNotIn("go1.22", text)

    def test_source_language_floors_remain_separate_from_ci_compilers(self):
        for relative, floor in (("go", "1.22"), ("body-go", "1.22"),
                                ("crypto-candidate/go", "1.22"),
                                ("hpke-candidate/go", "1.26.0")):
            with self.subTest(module=relative):
                text = (ROOT / "sdk/native" / relative / "go.mod").read_text()
                self.assertRegex(text, r"(?m)^go " + re.escape(floor) + r"$")
        text = (ROOT / "sdk/native/package-webhooks-native.py").read_text()
        self.assertIn('"runtime_requirement": "Rust 1.88.0" if args.language == "rust" else "Go 1.22"', text)
        self.assertIn('"tested_toolchain": "Rust/Cargo 1.88.0" if args.language == "rust" else "Go 1.26.10"', text)

    def test_webhook_packager_rejects_stale_go_and_accepts_patched_compiler(self):
        for version in ("1.22.12", "1.26.9", "1.26.10"):
            with self.subTest(version=version), \
                    patch.object(WEBHOOK, "run", return_value=SimpleNamespace(
                        stdout=f"go version go{version} linux/amd64\n")), \
                    patch.object(WEBHOOK, "stage_source", side_effect=ToolchainAccepted) as stage:
                if version == "1.26.10":
                    with self.assertRaises(ToolchainAccepted):
                        WEBHOOK.go(Path("unused"), Path("unused"), {})
                    stage.assert_called_once()
                else:
                    with self.assertRaisesRegex(ValueError, "Go 1.26.10 required"):
                        WEBHOOK.go(Path("unused"), Path("unused"), {})
                    stage.assert_not_called()

    def test_hpke_packager_rejects_stale_go_before_dependency_resolution(self):
        for version in ("1.26.9", "1.26.10"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                stage = Path(tmp)
                project = stage / "source"
                project.mkdir()
                (project / "go.mod").write_text(f"module {HPKE.MODULE}\n\ngo 1.26.0\n")
                output = stage / "output"
                output.mkdir()
                with patch.object(HPKE, "stage_sources", return_value=project), \
                        patch.object(HPKE, "source_files", return_value=("go.mod",)), \
                        patch.object(HPKE, "HARNESSES", ()), \
                        patch.object(HPKE, "run", side_effect=[SimpleNamespace(
                            stdout=f"go version go{version} linux/amd64\n"),
                            ToolchainAccepted]) as run:
                    generator = HPKE.go_package(stage, output)
                    if version == "1.26.10":
                        with self.assertRaises(ToolchainAccepted):
                            next(generator)
                        self.assertEqual(run.call_count, 2)
                        self.assertEqual(run.call_args.args, ("go", "mod", "tidy"))
                        self.assertEqual(run.call_args.kwargs["env"]["GOTOOLCHAIN"], "local")
                    else:
                        with self.assertRaisesRegex(ValueError, "Go 1.26.10 required"):
                            next(generator)
                        run.assert_called_once_with("go", "version", capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
