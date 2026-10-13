"""Reject damaged or incomplete package metadata before consumer qualification."""
import importlib.util
import io
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile

spec = importlib.util.spec_from_file_location("artifacts", Path(__file__).resolve().parents[1]
                                            / "sdk/tungsten/package-artifacts.py")
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)
managed = artifacts.load("managed_packages", artifacts.CONFIG / "package-managed.py")
native = artifacts.load("native_packages", artifacts.CONFIG / "package-native.py")


class PackageTests(unittest.TestCase):
    def test_direct_cargo_refuses_mixed_or_wrong_toolchain(self):
        for versions in (("cargo 1.97.1 (test)",), ("cargo 1.88.0 (test)", "rustc 1.97.1 (test)")):
            with patch.object(native, "run", side_effect=[SimpleNamespace(stdout=v) for v in versions]):
                with self.assertRaisesRegex(ValueError, "both be Rust 1.88.0"):
                    native.cargo_command(Path("toolchain/cargo"), {})

    def test_direct_cargo_binds_verified_sibling_compiler(self):
        env = {"RUSTC": "other-compiler", "RUSTDOC": "other-doc"}
        with patch.object(native, "run", side_effect=[SimpleNamespace(stdout=v) for v in
                          ("cargo 1.88.0 (test)", "rustc 1.88.0 (test)")]):
            command = native.cargo_command(Path("toolchain/cargo"), env)
        self.assertEqual(command, [str(Path("toolchain/cargo").resolve())])
        suffix = ".exe" if native.os.name == "nt" else ""
        self.assertEqual(env["RUSTC"], str(Path("toolchain/rustc" + suffix).resolve()))
        self.assertEqual(env["RUSTDOC"], str(Path("toolchain/rustdoc" + suffix).resolve()))

    def test_missing_or_wrong_license_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "candidate.whl"
            for content in (b"", b"wrong"):
                with zipfile.ZipFile(wheel, "w") as archive:
                    if content:
                        archive.writestr("sdk.dist-info/licenses/LICENSE", content)
                with self.assertRaisesRegex(ValueError, "license"):
                    artifacts.check_wheel(wheel, b"expected")

    def test_install_artifacts_fail_even_with_license(self):
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "candidate.whl"
            for extra in ("sdk/__pycache__/x.pyc", "sdk.dist-info/direct_url.json"):
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr("sdk.dist-info/licenses/LICENSE", b"expected")
                    archive.writestr(extra, b"unwanted")
                with self.assertRaisesRegex(ValueError, "checkout/install"):
                    artifacts.check_wheel(wheel, b"expected")

    def test_metadata_drift_fails_instead_of_silently_omitting_license(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "metadata"
            path.write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unexpected package"):
                artifacts.replace_once(path, "original", "replacement")
            self.assertEqual(path.read_text(), "unexpected")

    def test_managed_archive_license_and_content_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            archive_path = Path(temp) / "candidate.nupkg"
            for extra in ("../escape", ".git/config", "obj/cache"):
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr("LICENSE", b"expected")
                    archive.writestr(extra, b"unexpected")
                with self.assertRaisesRegex(ValueError, "Unexpected package"):
                    managed.check_zip_license(archive_path, b"expected", "LICENSE")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("LICENSE", b"wrong")
            with self.assertRaisesRegex(ValueError, "Incorrect archive license"):
                managed.check_zip_license(archive_path, b"expected", "LICENSE")

    def test_go_replacement_is_rejected_including_block_and_tab_forms(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            for directive in ("replace x => ../x", "replace\tx => ../x", "replace (\n x => ../x\n)"):
                (project / "go.mod").write_text("module example.invalid/client\n" + directive)
                with self.assertRaisesRegex(ValueError, "replace directives"):
                    native.go_archive(project, Path(temp) / "feed")

    def test_workspace_and_path_become_explicit_registry_dependency(self):
        original = {"package": {"name": "zrotext-api-cli", "version": {"workspace": True}},
                    "dependencies": {"zrotext-sdk": {"path": "../zrotext-sdk"}}}
        result = native.standalone_manifest(original, {"package": {"version": "0.1.0"}}, "AGPL-3.0-only")
        self.assertEqual(result["dependencies"]["zrotext-sdk"], {"version": "=0.1.0", "registry": "candidate"})
        self.assertEqual(result["package"]["rust-version"], "1.88")
        self.assertFalse(result["package"]["publish"])
        self.assertIn("path", original["dependencies"]["zrotext-sdk"])
        entry = native.index_entry(result, "synthetic-checksum")
        self.assertIsNone(entry["deps"][0]["registry"])

    def test_unhandled_source_dependency_is_not_silently_packaged(self):
        original = {"package": {"name": "sdk", "version": "0.1.0"},
                    "dependencies": {"other": {"path": "../other"}}}
        with self.assertRaisesRegex(ValueError, "Unresolved source"):
            native.standalone_manifest(original, {}, "AGPL-3.0-only")

    def test_crate_rejects_source_dependency_even_with_valid_license(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "candidate.crate"
            with tarfile.open(path, "w:gz") as archive:
                for name, value in {"LICENSE": b"license", "Cargo.toml":
                                    b'[dependencies]\nother = {path="../other"}\n'}.items():
                    info = tarfile.TarInfo("candidate-0.1.0/" + name)
                    info.size = len(value)
                    archive.addfile(info, io.BytesIO(value))
            with self.assertRaisesRegex(ValueError, "source dependency"):
                native.check_crate(path, "candidate", b"license")


if __name__ == "__main__":
    unittest.main()
