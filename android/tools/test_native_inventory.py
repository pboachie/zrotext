# SPDX-License-Identifier: AGPL-3.0-only
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import native_inventory as inventory


def packaged_fixture(base, entries):
    graphics_ref = "pkg:maven/androidx.graphics/graphics-path@1.0.1?type=aar"
    base.setdefault("components", []).append({
        "type": "library", "name": "graphics-path", "version": "1.0.1",
        "purl": graphics_ref, "bom-ref": graphics_ref,
        "hashes": [{"alg": "SHA-256", "content": "e" * 64}],
        "licenses": [{"license": {"id": "Apache-2.0"}}],
    })
    return {"vendor": {"version": inventory.WOLF_VERSION, "upstream_commit": inventory.WOLF_COMMIT,
                       "license": "GPL-3.0-or-later", "provenance_sha256": "f" * 64,
                       "files_sha256": "d" * 64, "file_count": 232},
            "bridge_sources": {name: "a" * 64 for name in inventory.BRIDGE_FILES},
            "graphics": {"ref": graphics_ref, "version": "1.0.1", "aar_sha256": "e" * 64,
                         "entries": {f"lib/{abi}/{inventory.GRAPHICS_LIBRARY}": entries[f"lib/{abi}/{inventory.GRAPHICS_LIBRARY}"] for abi in inventory.ABIS}}}


def fixture(base, entries, commit, repo):
    base = copy.deepcopy(base)
    packaged = packaged_fixture(base, entries)
    lock = ('''version = 4
[[package]]
name = "zrotext-android-owner-custody"
version = "0.1.0"
[[package]]
name = "zrotext-root-material"
version = "0.1.0"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "''' + "b" * 64 + '''"
[[package]]
name = "unused-dev-test"
version = "1.0.0"
''').encode()
    tree = (f"0zrotext-android-owner-custody v0.1.0 ({repo / 'crates/android-owner-custody'})|AGPL-3.0-only|\n"
            f"1zrotext-root-material v0.1.0 ({repo / 'crates/root-material'})|AGPL-3.0-only|unlock\n"
            "2serde v1.0.0|MIT OR Apache-2.0|derive\n"
            "1serde v1.0.0|MIT OR Apache-2.0|derive (*)\n")
    trees = {abi: tree for abi in inventory.ABIS}
    return inventory.merge_inventory(base, lock, trees, entries, commit, repo, packaged=packaged), lock, trees


class NativeInventoryTest(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.repo = Path.cwd()
        self.entries = {f"lib/{abi}/{library}": "c" * 64 for abi in inventory.ABIS for library in inventory.LIBRARIES}
        self.base = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": {"type": "application", "bom-ref": "app"}},
            "components": [{"type": "library", "purl": "pkg:maven/example/library@1", "bom-ref": "maven"}],
            "dependencies": [{"ref": "app", "dependsOn": ["maven"]}],
        }
        self.bom, self.lock, self.trees = fixture(self.base, self.entries, self.commit, self.repo)

    def test_locked_graph_preserves_edges_features_checksums_and_source_identity(self):
        inventory.verify_inventory(self.bom, self.entries, self.commit)
        components = {c["purl"]: c for c in self.bom["components"]}
        root = components["pkg:cargo/zrotext-android-owner-custody@0.1.0"]
        self.assertEqual(inventory.properties(root)["zrotext:workspace-source-commit"], self.commit)
        self.assertNotIn("hashes", root)
        self.assertEqual(len([p for p in root["properties"] if "cargo-features" in p["name"]]), 4)
        self.assertEqual(components["pkg:cargo/serde@1.0.0"]["hashes"],
                         [{"alg": "SHA-256", "content": "b" * 64}])
        self.assertFalse(any("unused-dev" in identity for identity in components))
        graph = {d["ref"]: d["dependsOn"] for d in self.bom["dependencies"]}
        self.assertEqual(set(graph[root["purl"]]),
                         {"pkg:cargo/zrotext-root-material@0.1.0", "pkg:cargo/serde@1.0.0"})
        self.assertTrue({root["purl"] + f"?arch={abi}" for abi in inventory.ABIS}.issubset(graph["app"]))
        self.assertNotIn(str(self.repo), json.dumps(self.bom))
        self.assertEqual(self.base["components"], [{"type": "library", "purl": "pkg:maven/example/library@1", "bom-ref": "maven"}])

    def test_each_actual_target_is_resolved_locked_with_normal_and_build_edges(self):
        outputs = [subprocess.CompletedProcess([], 0, self.trees[abi], "") for abi in inventory.ABIS]
        base = copy.deepcopy(self.base)
        packaged_fixture(base, self.entries)
        with patch.object(inventory.subprocess, "run", side_effect=outputs) as run, \
             patch.object(Path, "read_bytes", return_value=self.lock), \
             patch.object(inventory, "collect_packaged_sources", return_value=self.packaged()):
            result = inventory.collect_inventory(base, self.entries, self.commit, self.repo, {})
        self.assertEqual(result, self.bom)
        for call, target in zip(run.call_args_list, inventory.ABIS.values()):
            command = call.args[0]
            self.assertIn("--locked", command)
            self.assertIn("--offline", command)
            self.assertEqual(command[command.index("--target") + 1], target)
            self.assertEqual(command[command.index("--edges") + 1], "normal,build")
            self.assertFalse(call.kwargs["shell"])

    def test_missing_or_substituted_library_is_refused_even_if_all_are_removed(self):
        for entries in ({}, {k: v for k, v in self.entries.items() if "arm64" not in k},
                        {**self.entries, next(iter(self.entries)): "d" * 64}):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                inventory.verify_inventory(self.bom, entries, self.commit)

    def test_missing_inventory_wrong_source_or_target_is_refused(self):
        for mutation in ("missing", "source", "target"):
            bom = copy.deepcopy(self.bom)
            if mutation == "missing":
                bom["metadata"]["properties"] = []
            else:
                manifest = json.loads(bom["metadata"]["properties"][0]["value"])
                if mutation == "source":
                    manifest["source_commit"] = "d" * 40
                else:
                    manifest["targets"].pop("x86")
                bom["metadata"]["properties"][0]["value"] = json.dumps(manifest)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                inventory.verify_inventory(bom, self.entries, self.commit)

    def test_missing_root_material_dangling_edges_or_duplicate_refs_are_refused(self):
        for mutation in ("material", "edge", "duplicate", "node", "application"):
            bom = copy.deepcopy(self.bom)
            if mutation == "material":
                removed = "pkg:cargo/zrotext-root-material@0.1.0"
                bom["components"] = [c for c in bom["components"] if c["purl"] != removed]
                bom["dependencies"] = [d for d in bom["dependencies"] if d["ref"] != removed]
                for d in bom["dependencies"]:
                    d["dependsOn"] = [r for r in d["dependsOn"] if r != removed]
            elif mutation == "edge":
                bom["dependencies"][-1]["dependsOn"] = ["missing"]
            elif mutation == "duplicate":
                bom["components"].append(copy.deepcopy(bom["components"][-1]))
            elif mutation == "node":
                bom["dependencies"] = [d for d in bom["dependencies"] if d["ref"] != "pkg:cargo/serde@1.0.0"]
            else:
                next(d for d in bom["dependencies"] if d["ref"] == "app")["dependsOn"] = ["maven"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                inventory.verify_inventory(bom, self.entries, self.commit)

    def test_unlocked_package_unsupported_registry_and_invalid_depth_are_refused(self):
        for mutation in ("unlocked", "registry", "depth"):
            lock, trees = self.lock, self.trees.copy()
            if mutation == "unlocked":
                trees["x86"] = trees["x86"].replace("serde v1.0.0", "absent v1.0.0")
            elif mutation == "registry":
                lock = lock.replace(inventory.REGISTRY.encode(), b"registry+https://example.invalid/index")
            else:
                trees["x86"] = trees["x86"].replace("2serde", "5serde")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                inventory.merge_inventory(self.base, lock, trees, self.entries, self.commit, self.repo, packaged=self.packaged())

    def packaged(self):
        return json.loads(inventory.properties(self.bom["metadata"])[inventory.PROPERTY])["packaged"]

    def test_all_twelve_libraries_bind_to_their_real_source_graphs(self):
        components = {c["bom-ref"]: c for c in self.bom["components"]}
        graph = {d["ref"]: set(d["dependsOn"]) for d in self.bom["dependencies"]}
        mapped = {inventory.properties(c)["zrotext:apk-entry"]: c for c in components.values()
                  if "zrotext:apk-entry" in inventory.properties(c)}
        self.assertEqual(set(mapped), set(self.entries))
        self.assertEqual(len(mapped), 12)
        bridge = f"pkg:generic/zrotext-hpke-keystore@{self.commit}"
        self.assertEqual(graph[bridge], {inventory.WOLF_REF})
        self.assertEqual(components[inventory.WOLF_REF]["licenses"], [{"license": {"id": "GPL-3.0-or-later"}}])
        for entry, component in mapped.items():
            self.assertEqual(component["hashes"], [{"alg": "SHA-256", "content": self.entries[entry]}])
            self.assertIn(component["bom-ref"], graph["app"])
            if entry.endswith(inventory.HPKE_LIBRARY):
                self.assertEqual(graph[component["bom-ref"]], {bridge})
            elif entry.endswith(inventory.GRAPHICS_LIBRARY):
                self.assertEqual(graph[component["bom-ref"]], {self.packaged()["graphics"]["ref"]})

    def test_every_library_missing_substituted_extra_or_wrong_abi_is_refused(self):
        for name in self.entries:
            for mutation in ("missing", "digest", "abi"):
                entries = self.entries.copy()
                if mutation == "missing":
                    entries.pop(name)
                elif mutation == "digest":
                    entries[name] = "9" * 64
                else:
                    entries[name.replace("lib/", "lib/unsupported/", 1)] = entries.pop(name)
                with self.subTest(entry=name, mutation=mutation), self.assertRaises(ValueError):
                    inventory.verify_inventory(self.bom, entries, self.commit)
        for name in ("lib/x86/libunexpected.so", "assets/libunexpected.so", "lib/x86/unrecognized"):
            with self.subTest(extra=name), self.assertRaises(ValueError):
                inventory.verify_inventory(self.bom, {**self.entries, name: "c" * 64}, self.commit)

    def test_vendor_bridge_and_graphics_nodes_edges_and_source_facts_are_required(self):
        for mutation in ("vendor", "bridge", "graphics", "edge", "license", "version", "commit", "count", "provenance", "files", "sources", "aar", "mapping", "generic", "duplicate-entry", "app"):
            bom = copy.deepcopy(self.bom)
            manifest = json.loads(inventory.properties(bom["metadata"])[inventory.PROPERTY])
            generic = [c for c in bom["components"] if c["purl"].startswith("pkg:generic/")]
            if mutation in ("vendor", "bridge", "graphics"):
                node = next(c for c in generic if (c["name"] == {"vendor": "wolfssl", "bridge": "zrotext-hpke-keystore", "graphics": "androidx-graphics-path"}[mutation]))
                bom["components"].remove(node)
            elif mutation == "edge":
                next(d for d in bom["dependencies"] if d["ref"] == f"pkg:generic/zrotext-hpke-keystore@{self.commit}")["dependsOn"] = []
            elif mutation in ("license", "version", "commit", "count", "provenance", "files"):
                key = {"license": "license", "version": "version", "commit": "upstream_commit", "count": "file_count", "provenance": "provenance_sha256", "files": "files_sha256"}[mutation]
                manifest["packaged"]["vendor"][key] = ({"license": "MIT", "version": "5.9.3", "commit": "a" * 40,
                                                          "count": 231, "provenance": "b" * 64, "files": "b" * 64}[mutation])
            elif mutation == "sources":
                manifest["packaged"]["bridge_sources"].pop("user_settings.h")
            elif mutation == "aar":
                manifest["packaged"]["graphics"]["aar_sha256"] = "b" * 64
            elif mutation == "mapping":
                manifest["packaged"]["graphics"]["entries"][f"lib/x86/{inventory.GRAPHICS_LIBRARY}"] = "b" * 64
            elif mutation == "generic":
                bom["components"].append({"type": "library", "purl": "pkg:generic/unreviewed@1", "bom-ref": "pkg:generic/unreviewed@1"})
            elif mutation == "duplicate-entry":
                bom["components"][0]["properties"] = [{"name": "zrotext:apk-entry", "value": next(iter(self.entries))}]
            else:
                next(d for d in bom["dependencies"] if d["ref"] == "app")["dependsOn"] = [c for c in next(d for d in bom["dependencies"] if d["ref"] == "app")["dependsOn"] if "pkg:generic" not in c]
            bom["metadata"]["properties"][0]["value"] = json.dumps(manifest)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                inventory.verify_inventory(bom, self.entries, self.commit)

    @staticmethod
    def source_fixture(repo):
        cpp = repo / "android/app/src/main/cpp"
        vendor = cpp / "wolfssl"
        for name in inventory.BRIDGE_FILES:
            path = cpp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic bridge source")
        files = {"LICENSING": b"synthetic license file", "wolfssl/version.h": f'#define LIBWOLFSSL_VERSION_STRING "{inventory.WOLF_VERSION}"'.encode()}
        files.update({f"wolfcrypt/src/synthetic{index}.c": b"synthetic vendored source" for index in range(230)})
        for name, raw in files.items():
            path = vendor / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        provenance = ("Vendored wolfSSL subset for the ZROtext AndroidKeyStore HPKE bridge.\n"
                      f"Upstream: https://github.com/wolfSSL/wolfssl tag v{inventory.WOLF_VERSION}-stable\n"
                      f"Commit: {inventory.WOLF_COMMIT}\n"
                      "License: GPLv3-or-later (see LICENSING); unmodified copies.\n\n" +
                      "".join(f"{hashlib.sha256(raw).hexdigest()}  {name}\n" for name, raw in sorted(files.items())))
        (vendor / "PROVENANCE").write_text(provenance, encoding="utf-8", newline="\n")
        return vendor, provenance

    def test_complete_vendor_source_collection_refuses_tampering_unsafe_and_unlisted_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            vendor, original = self.source_fixture(repo)
            self.assertEqual(inventory.collect_vendor(repo)["vendor"]["file_count"], 232)
            for name, changed in (("hash", original.replace("  LICENSING", "  absent")),
                                  ("traversal", original.replace("  LICENSING", "  ../LICENSING")),
                                  ("duplicate", original + original.split("\n\n", 1)[1].splitlines()[0] + "\n"),
                                  ("commit", original.replace(inventory.WOLF_COMMIT, "a" * 40)),
                                  ("license", original.replace("GPLv3-or-later", "MIT"))):
                (vendor / "PROVENANCE").write_text(changed, encoding="utf-8", newline="\n")
                with self.subTest(mutation=name), self.assertRaises(ValueError):
                    inventory.collect_vendor(repo)
            (vendor / "PROVENANCE").write_text(original, encoding="utf-8", newline="\n")
            (vendor / "LICENSING").write_bytes(b"substituted")
            with self.assertRaises(ValueError):
                inventory.collect_vendor(repo)
            (vendor / "LICENSING").write_bytes(b"synthetic license file")
            (vendor / "unexpected.c").write_bytes(b"unlisted")
            with self.assertRaises(ValueError):
                inventory.collect_vendor(repo)

    @staticmethod
    def aar_fixture():
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for abi in inventory.ABIS:
                archive.writestr(f"jni/{abi}/{inventory.GRAPHICS_LIBRARY}", ("synthetic graphics " + abi).encode())
        return stream.getvalue()

    def test_actual_resolved_aar_bytes_are_required_before_graphics_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.source_fixture(repo)
            raw = self.aar_fixture()
            entries = {**self.entries, **inventory.graphics_entries(raw)}
            bom = copy.deepcopy(self.base)
            packaged_fixture(bom, entries)
            bom["components"][-1]["hashes"][0]["content"] = inventory.digest(raw)
            cache = repo / "gradle-cache"
            path = cache / "caches/modules-2/files-2.1/androidx.graphics/graphics-path/1.0.1/synthetic/graphics-path-1.0.1.aar"
            path.parent.mkdir(parents=True)
            path.write_bytes(raw)
            facts = inventory.collect_packaged_sources(bom, entries, repo, {"GRADLE_USER_HOME": str(cache)})
            self.assertEqual(facts["graphics"]["entries"], inventory.graphics_entries(raw))
            with self.assertRaisesRegex(ValueError, "Packaged graphics bytes"):
                inventory.collect_packaged_sources(bom, self.entries, repo, {"GRADLE_USER_HOME": str(cache)})
            path.write_bytes(b"substituted archive")
            with self.assertRaisesRegex(ValueError, "AAR digest"):
                inventory.collect_packaged_sources(bom, entries, repo, {"GRADLE_USER_HOME": str(cache)})
            path.unlink()
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                inventory.collect_packaged_sources(bom, entries, repo, {"GRADLE_USER_HOME": str(cache)})

    def test_linked_vendor_cpp_and_repository_roots_refuse_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "source"
            self.source_fixture(repo)
            for linked in (repo / "android/app/src/main/cpp/wolfssl", repo / "android/app/src/main/cpp", repo):
                for kind in ("is_symlink", "is_junction"):
                    with self.subTest(root=linked.name, kind=kind), \
                         patch.object(Path, kind, new=lambda current: current == linked, create=True), \
                         patch.object(Path, "read_bytes") as read:
                        with self.assertRaisesRegex(ValueError, "linked"):
                            inventory.collect_vendor(repo)
                        read.assert_not_called()
            link = Path(directory) / "source-link"
            try:
                link.symlink_to(repo, target_is_directory=True)
            except OSError:
                # Windows may forbid link creation; the six pre-read controls above
                # still execute and assert the actual source-file boundary.
                return
            with self.assertRaisesRegex(ValueError, "linked"):
                inventory.collect_vendor(link)

    def test_graphics_archive_missing_extra_or_duplicate_library_is_refused(self):
        for mutation in ("missing", "extra", "duplicate"):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for abi in inventory.ABIS:
                    if mutation != "missing" or abi != "x86":
                        archive.writestr(f"jni/{abi}/{inventory.GRAPHICS_LIBRARY}", b"synthetic")
                if mutation == "extra":
                    archive.writestr("jni/x86/libunexpected.so", b"synthetic")
                elif mutation == "duplicate":
                    with self.assertWarns(UserWarning):
                        archive.writestr(f"jni/x86/{inventory.GRAPHICS_LIBRARY}", b"duplicate")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                inventory.graphics_entries(stream.getvalue())


if __name__ == "__main__":
    unittest.main()
