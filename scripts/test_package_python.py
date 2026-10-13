"""Public Python artifacts must be installable, bounded and source-exact."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

import package_python as package


class PythonArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.wheel, self.source = package.build(self.root / "artifacts")

    def rewrite_wheel(self, change):
        with zipfile.ZipFile(self.wheel) as archive:
            entries = [(entry, archive.read(entry)) for entry in archive.infolist()]
        entries = change(entries)
        with zipfile.ZipFile(self.wheel, "w") as archive:
            for entry, data in entries:
                archive.writestr(entry, data)

    def test_offline_install_imports_without_source_checkout_or_node(self):
        target = self.root / "installed"
        subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
                        "--no-compile", "--target", str(target), str(self.wheel)],
                       check=True, capture_output=True)
        program = """import sys
sys.path.insert(0, sys.argv[1])
from zrotext_client import AlphaClient, verify_webhook, requires_reconciliation
assert requires_reconciliation('unknown')
assert requires_reconciliation('delivery_unknown')
assert not requires_reconciliation('delivered')
import importlib.util
assert importlib.util.find_spec('workflow_client') is None
"""
        subprocess.run([sys.executable, "-I", "-c", program, str(target)],
                       cwd=self.root, check=True, capture_output=True)

    def test_source_rebuild_matches_reviewed_wheel_without_repository(self):
        unpacked = self.root / "source"
        unpacked.mkdir()
        with tarfile.open(self.source) as archive:
            # Archive was built and verified above; no untrusted extraction.
            for member in archive:
                target = unpacked / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
        backend_path = next(unpacked.glob("*/_build_backend.py"))
        spec = importlib.util.spec_from_file_location("rebuilt_backend", backend_path)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        rebuilt = self.root / builder.build_wheel(self.root)
        package.verify(rebuilt)
        self.assertEqual(self.wheel.read_bytes(), rebuilt.read_bytes())

    def test_pep517_frontend_builds_source_archive_offline(self):
        destination = self.root / "frontend"
        destination.mkdir()
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps",
                        "--no-build-isolation", "--no-cache-dir", "--wheel-dir", str(destination),
                        str(self.source)], cwd=self.root, check=True, capture_output=True)
        rebuilt = destination / self.wheel.name
        package.verify(rebuilt)
        self.assertEqual(self.wheel.read_bytes(), rebuilt.read_bytes())

    def test_modified_module_is_rejected_even_with_valid_zip(self):
        self.rewrite_wheel(lambda entries: [(e, b"# replaced\n" if e.filename.endswith("alpha.py") else data)
                                            for e, data in entries])
        with self.assertRaisesRegex(ValueError, "reviewed source"):
            package.verify(self.wheel)

    def test_unlisted_entries_are_rejected(self):
        self.rewrite_wheel(lambda entries: entries + [("../workflow_bridge.mjs", b"unexpected")])
        with self.assertRaisesRegex(ValueError, "allowlist"):
            package.verify(self.wheel)

    def test_duplicate_entries_are_rejected(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.rewrite_wheel(lambda entries: entries + [entries[0]])
        with self.assertRaisesRegex(ValueError, "allowlist"):
            package.verify(self.wheel)

    def test_wheel_symlink_is_rejected(self):
        def linked(entries):
            entries[0][0].external_attr = 0o120777 << 16
            return entries
        self.rewrite_wheel(linked)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            package.verify(self.wheel)

    def test_source_links_are_rejected_without_extracting(self):
        stem = package.backend().identity()[0]
        with tarfile.open(self.source, "w:gz") as archive:
            entry = tarfile.TarInfo(stem + "/LICENSE")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../elsewhere"
            archive.addfile(entry)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            package.verify(self.source)

    def test_output_never_overwrites_or_enters_checkout(self):
        with self.assertRaisesRegex(ValueError, "must not exist"):
            package.build(self.root / "artifacts")
        with self.assertRaisesRegex(ValueError, "outside"):
            package.build(package.ROOT / "dist")


if __name__ == "__main__":
    unittest.main()
