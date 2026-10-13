"""Archive boundary and registry dependency policy regression tests."""
import importlib.util
from pathlib import Path
import tomllib
import unittest

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


if __name__ == "__main__":
    unittest.main()
