"""Public generation policy and provenance regression checks."""
import json
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import tungsten_sdk as sdk

spec = importlib.util.spec_from_file_location("source_packages", sdk.CONFIG / "package-sources.py")
packages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packages)


class GenerationPolicyTests(unittest.TestCase):
    def test_callable_surface_excludes_planned_routes(self):
        config = json.loads((sdk.CONFIG / "tungsten.yml").read_text())
        public = next(i for i in config["inputs"] if i["namespace"] == "public")
        self.assertEqual(public["include"], {"extension": "x-implemented", "equals": True})
        self.assertEqual(public["planned_from"], {"extension": "x-implemented", "equals": False})
        self.assertEqual(set(config["targets"]), {
            "typescript", "python", "rust", "go", "java", "csharp", "ruby", "mcp", "webmcp", "docs"})
        for item in config["inputs"]:
            self.assertTrue((sdk.CONFIG / item["spec"]).is_file())

    def test_retries_and_confirmation_preserve_send_boundaries(self):
        agent = json.loads((sdk.CONFIG / "agent.yml").read_text())
        for tier in ("read_only", "mutating"):
            self.assertEqual(agent["defaults"]["retries"][tier]["max"], 0)
        tools = {t["operation"]: t for t in agent["tools"]}
        submit = tools["public.submitAlphaMessage"]
        self.assertEqual(submit["safety"], "irreversible")
        self.assertEqual(submit["idempotency"]["policy"], "caller_owned")
        self.assertNotIn("format", submit["idempotency"])
        self.assertIn("confirmation", submit)
        self.assertEqual(tools["sealed.submitSealedOutbound"]["idempotency"]["policy"], "content_identity")

    def test_rejects_wrong_or_dirty_generator_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            lock = {"revision": "expected", "runtime_revision": "expected"}
            with patch.object(sdk, "run", return_value=subprocess.CompletedProcess([], 0, stdout="wrong")):
                with self.assertRaisesRegex(ValueError, "match"):
                    sdk.verify_source(source, lock)
            answers = [subprocess.CompletedProcess([], 0, stdout="expected"),
                       subprocess.CompletedProcess([], 0, stdout="?? injected.rs")]
            with patch.object(sdk, "run", side_effect=answers):
                with self.assertRaisesRegex(ValueError, "clean"):
                    sdk.verify_source(source, lock)

    def test_inventory_detects_changes_without_hashing_installed_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "typescript"
            metadata = target / ".tungsten"
            metadata.mkdir(parents=True)
            (metadata / "manifest.json").write_text(json.dumps({"files": [{"path": "client.ts"}]}))
            (target / "client.ts").write_text("original")
            first = sdk.output_inventory(root)
            (target / "ignored.cache").write_text("unrelated")
            self.assertEqual(first, sdk.output_inventory(root))
            (target / "client.ts").write_text("changed")
            self.assertNotEqual(first, sdk.output_inventory(root))

    def test_inventory_rejects_manifest_path_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "typescript" / ".tungsten"
            metadata.mkdir(parents=True)
            (metadata / "manifest.json").write_text(json.dumps({"files": [{"path": "../../secret"}]}))
            with self.assertRaisesRegex(ValueError, "outside"):
                sdk.output_inventory(root)

    def test_source_archive_is_deterministic_and_contains_only_allowed_bytes(self):
        files = {"LICENSE": b"license", "src/client.py": b"client"}
        first = packages.source_archive(files)
        self.assertEqual(first, packages.source_archive(files))
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            self.assertEqual(archive.getnames(), sorted(files))
            for item in archive.getmembers():
                self.assertEqual(item.mtime, 0)
                self.assertEqual(archive.extractfile(item).read(), files[item.name])

    def test_preserved_custom_modules_are_staged_hashed_and_packaged(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            extensions = base / "extensions"
            generated = base / "generated"
            stub = extensions / "python/custom/__init__.py"
            stub.parent.mkdir(parents=True)
            stub.write_bytes(b"# approved extension\n")
            metadata = generated / "python/.tungsten/manifest.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(json.dumps({"files": [{"path": "client.py"}]}))
            (generated / "python/client.py").write_bytes(b"client")
            sdk.stage_extensions(generated, extensions)
            first = sdk.output_inventory(generated, extensions)
            self.assertIn("python/custom/__init__.py", first)
            self.assertIn("custom/__init__.py", packages.reviewed_files(generated, first)["python"])
            (generated / "python/custom/__init__.py").write_bytes(b"tampered")
            self.assertNotEqual(first, sdk.output_inventory(generated, extensions))

    def test_source_packaging_rejects_tampered_or_unbounded_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "python").mkdir()
            (root / "python/client.py").write_bytes(b"client")
            inventory = {"python/client.py": hashlib.sha256(b"client").hexdigest()}
            self.assertEqual(packages.reviewed_files(root, inventory), {"python": {"client.py": b"client"}})
            (root / "python/client.py").write_bytes(b"modified")
            with self.assertRaisesRegex(ValueError, "differs"):
                packages.reviewed_files(root, inventory)
            with self.assertRaisesRegex(ValueError, "Invalid"):
                packages.reviewed_files(root, {"python/../../outside": "unused"})


if __name__ == "__main__":
    unittest.main()
