"""Mutation checks for the public artifact boundary; no npm writes."""

import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
import uuid

import package_npm as package


class PackageBoundaryTests(unittest.TestCase):
    def setUp(self):
        # Normal inherited permissions also work in the Windows sandbox, where
        # tempfile's restrictive directory ACL prevents child-process access.
        self.base = Path(tempfile.gettempdir()) / ("zrotext-package-test-" + uuid.uuid4().hex)
        self.base.mkdir()
        self.addCleanup(shutil.rmtree, self.base)
        self.root = self.base / "repo"
        source = self.root / "sdk" / "npm"
        source.mkdir(parents=True)
        for name in ("package.json", "package-lock.json", "README.md", "CHANGELOG.md"):
            shutil.copyfile(package.PACKAGE / name, source / name)
        shutil.copyfile(package.ROOT / "LICENSE", self.root / "LICENSE")
        self.compiled = self.base / "compiled"
        self.compiled.mkdir()
        for name in package.MODULES:
            for suffix in ("js", "d.ts"):
                code = 'export * from "./alpha-client.js";\nexport * from "./webhook-verify.js";\n' if name == "index" else "export const sample = 1;\n"
                (self.compiled / f"{name}.{suffix}").write_text(code, encoding="utf-8")
        self.staged = self.base / "package"
        package.stage(self.compiled, self.staged, self.root)
        self.contents = {name: (self.staged / name).read_bytes() for name in package.FILES}

    def tarball(self, extra=None):
        path = self.base / "package.tgz"
        with tarfile.open(path, "w:gz") as archive:
            for name, data in self.contents.items():
                info = tarfile.TarInfo("package/" + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b""))
        return path

    def test_exact_artifact_returns_digest_and_private_metadata(self):
        result = package.verify_tarball(self.tarball(), self.root)
        self.assertEqual(result["files"], sorted(package.FILES))
        self.assertTrue(result["metadata"]["private"])
        self.assertEqual(len(result["sha256"]), 64)
        self.assertTrue(result["integrity"].startswith("sha512-"))

    def test_license_must_be_full_and_unchanged(self):
        self.contents["LICENSE"] = b"AGPL-3.0-only"
        with self.assertRaisesRegex(ValueError, "license"):
            package.verify_tarball(self.tarball(), self.root)

    def test_external_import_and_dynamic_import_are_rejected(self):
        for code in (b'import "dependency";', b'export { x } from "./sealed.js";', b'import("./alpha-client.js");', b'require("dependency");'):
            with self.subTest(code=code):
                self.contents["dist/alpha-client.js"] = code
                with self.assertRaisesRegex(ValueError, "import|loading"):
                    package.verify_tarball(self.tarball(), self.root)

    def test_changed_metadata_is_rejected(self):
        metadata = json.loads(self.contents["package.json"])
        metadata["scripts"] = {"postinstall": "unexpected"}
        self.contents["package.json"] = json.dumps(metadata).encode()
        with self.assertRaisesRegex(ValueError, "metadata"):
            package.verify_tarball(self.tarball(), self.root)

    def test_paths_links_extra_and_duplicate_entries_are_rejected(self):
        for name in ("package/../escape", "package/.npmrc", "package/package.json", "/package/LICENSE"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    package.verify_tarball(self.tarball(tarfile.TarInfo(name)), self.root)
        link = tarfile.TarInfo("package/dist/sealed.js")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../secret"
        with self.assertRaisesRegex(ValueError, "link"):
            package.verify_tarball(self.tarball(link), self.root)

    def test_missing_file_is_rejected(self):
        del self.contents["dist/webhook-verify.d.ts"]
        with self.assertRaisesRegex(ValueError, "file list"):
            package.verify_tarball(self.tarball(), self.root)

    def test_credential_shape_in_allowed_compiled_file_is_rejected(self):
        token = "gh" + "p_" + "A" * 40
        self.contents["dist/alpha-client.js"] = ('export const sample = "' + token + '";\n').encode()
        with self.assertRaisesRegex(ValueError, "security scan"):
            package.verify_tarball(self.tarball(), self.root)

    def test_lock_version_must_match_manifest(self):
        path = self.root / "sdk/npm/package-lock.json"
        lock = json.loads(path.read_text())
        lock["version"] = "1.0.0"
        path.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, "lockfile version"):
            package.verify_tarball(self.tarball(), self.root)

    def test_stage_refuses_checkout_paths_existing_destination_and_extra_compilation(self):
        for target in (self.root / "output", self.staged):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    package.stage(self.compiled, target, self.root)
        (self.compiled / "sealed.js").write_text("export {};")
        with self.assertRaisesRegex(ValueError, "six"):
            package.stage(self.compiled, self.base / "extra", self.root)

    def test_development_manifest_cannot_be_publishable(self):
        path = self.root / "sdk/npm/package.json"
        manifest = json.loads(path.read_text())
        manifest["private"] = False
        path.write_text(json.dumps(manifest))
        self.contents["package.json"] = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "sentinel"):
            package.verify_tarball(self.tarball(), self.root)


if __name__ == "__main__":
    unittest.main()
