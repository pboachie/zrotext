"""Archive boundary and registry dependency policy regression tests."""
import importlib.util
from pathlib import Path
import tomllib
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("packages", Path(__file__).with_name("package-native.py"))
packages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packages)


class PackagePolicy(unittest.TestCase):
    def test_closed_archives_exclude_harnesses_and_outputs(self):
        for language in ("rust", "go"):
            names = packages.source_files(language)
            self.assertIn("LICENSE", names)
            self.assertIn("README.md", names)
            self.assertFalse(any("examples/" in name or "cmd/" in name or "target/" in name for name in names))
            self.assertEqual(len(names), len(set(names)))

    def test_index_routes_transitive_dependencies_to_public_registry(self):
        manifest = tomllib.loads((packages.ROOT / "rust/Cargo.toml").read_text())
        entry = packages.index_entry(manifest, "0" * 64)
        self.assertTrue(entry["deps"])
        self.assertTrue(all(d["registry"] == "https://github.com/rust-lang/crates.io-index" for d in entry["deps"]))
        self.assertEqual(entry["rust_version"], "1.97.1")

    def test_dependency_override_refused(self):
        manifest = tomllib.loads((packages.ROOT / "rust/Cargo.toml").read_text())
        for field in ("path", "git", "registry", "workspace"):
            manifest["dependencies"]["aes-gcm"] = {"version": "0.11.1", field: "unexpected"}
            with self.assertRaises(ValueError):
                packages.index_entry(manifest, "0" * 64)

    def test_original_gates_use_installed_binaries_without_source_build_fallback(self):
        binaries = {name: Path("installed") / name for name in packages.HARNESSES}
        with patch.object(packages, "run", return_value=SimpleNamespace(stdout="synthetic fixture")) as run:
            packages.original_acceptance(binaries, Path("maintained-producer"))
        calls = run.call_args_list
        self.assertEqual(len(calls), 9)
        self.assertEqual([call.args[0] for call in calls[1:3]], [binaries["original"], binaries["reply_checkpoint"]])
        self.assertEqual(len(calls[3:]), 6)
        for call, name in zip(calls[3:], packages.ORIGINAL_TLS):
            self.assertEqual(call.args[2:4], ("--binary", binaries["reply_" + name]))
            self.assertNotIn("--language", call.args)
        self.assertFalse(any(call.args[0] in ("cargo", "go") for call in calls))


if __name__ == "__main__":
    unittest.main()
