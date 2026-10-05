# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import native_inventory as inventory


def fixture(base, entries, commit, repo):
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
    return inventory.merge_inventory(base, lock, trees, entries, commit, repo), lock, trees


class NativeInventoryTest(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.repo = Path.cwd()
        self.entries = {f"lib/{abi}/{inventory.LIBRARY}": "c" * 64 for abi in inventory.ABIS}
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
        with patch.object(inventory.subprocess, "run", side_effect=outputs) as run, \
             patch.object(Path, "read_bytes", return_value=self.lock):
            result = inventory.collect_inventory(self.base, self.entries, self.commit, self.repo, {})
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
                inventory.merge_inventory(self.base, lock, trees, self.entries, self.commit, self.repo)


if __name__ == "__main__":
    unittest.main()
