# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed PostgreSQL partition tests and a tiny real Cargo runner smoke test."""
import copy
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import ci_rust_postgresql as ci

ROOT = Path(__file__).resolve().parents[1]
SERVER_CASES = ["server_case_a", "server_case_a_extra", "server_case_b", "server_case_c",
                "server_case_d", "server_case_e", "server_case_f", "server_case_m"]


def job(workflow, name):
    text = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
    match = re.search(r"^  " + re.escape(name) + r":\n([\s\S]*?)(?=^  [a-zA-Z0-9_-]+:|\Z)", text, re.MULTILINE)
    if match is None:
        raise AssertionError("Missing workflow job: " + name)
    return match.group(1)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.metadata = {"workspace_root": str(self.root), "target_directory": str(self.root / "target"),
                         "workspace_members": [], "packages": []}
        for name in ("zrotext-delivery-store", "zrotext-server", "zrotext-migrator"):
            self.add_package(name)

    def add_package(self, name, kinds=None):
        directory = self.root / name
        directory.mkdir()
        (directory / "src").mkdir()
        manifest = directory / "Cargo.toml"
        manifest.write_text('[package]\nname="' + name + '"\nversion="0.1.0"\n', encoding="utf-8")
        target = {"name": name.replace("-", "_"), "kind": kinds or ["lib"], "test": True,
                  "src_path": str(directory / "src/lib.rs")}
        package = {"name": name, "id": "package:" + name, "manifest_path": str(manifest), "targets": [target]}
        self.metadata["workspace_members"].append(package["id"])
        self.metadata["packages"].append(package)
        return package

    def inventory(self, suite="default"):
        return ci.workspace_inventory(self.metadata, self.root, suite)

    def receipts(self, suite="default"):
        inventory, targets = self.inventory(suite)
        identity = {"commit": "a" * 40, "tree": "b" * 40, "run": "7", "attempt": "1"}
        receipts = []
        for lane in ci.LANES:
            records = {}
            for key, target in targets.items():
                package = target["description"]["package"]
                tests = SERVER_CASES.copy() if package == "zrotext-server" else ["database_case"]
                assigned = ci.assigned_tests(package, tests, lane)
                executed = lane in ci.lanes_for(package) and (package != "zrotext-server" or bool(assigned))
                features = ["conversation-simulator-tests"] if suite == "conversation" and package == "zrotext-server" else []
                records[key] = {"description": target["description"], "features": features,
                                "tests": tests, "assigned": assigned, "executed": executed,
                                "passed": assigned}
            receipt = {"version": 2, "source": identity, "suite": suite, "lane": lane,
                       "workspace": inventory, "records": records,
                       "doctests": suite == "default" and lane == "remaining"}
            receipt["inventory_digest"] = ci.digest({"workspace": inventory, "targets": {
                key: {k: v for k, v in item.items() if k not in ("assigned", "executed", "passed")}
                for key, item in records.items()}})
            receipts.append(receipt)
        return receipts, identity, inventory, targets

    def test_new_packages_are_automatically_assigned_to_remaining(self):
        self.add_package("new-workspace-package", ["rlib", "cdylib"])
        inventory, targets = self.inventory()
        added = next(p for p in inventory if p["name"] == "new-workspace-package")
        self.assertEqual(added["lanes"], ["remaining"])
        self.assertEqual(len(targets), 4)

    def test_binary_only_packages_stay_explicit_in_library_inventory(self):
        self.add_package("binary-only", ["bin"])
        inventory, targets = self.inventory("conversation")
        package = next(p for p in inventory if p["name"] == "binary-only")
        self.assertFalse(package["targets"][0]["selected"])
        self.assertEqual(len(inventory), 4)
        self.assertEqual(len(targets), 3)

    def test_same_named_library_binary_and_integration_targets_are_distinct(self):
        package = self.metadata["packages"][1]
        for kind in ("bin", "test"):
            target = dict(package["targets"][0], kind=[kind], src_path=str(self.root / package["name"] / (kind + ".rs")))
            package["targets"].append(target)
        self.assertEqual(len(self.inventory()[1]), 5)
        self.assertEqual(len(self.inventory("conversation")[1]), 3)

    def test_missing_duplicate_and_unsupported_metadata_are_refused(self):
        mutations = [lambda m: m["workspace_members"].pop(),
                     lambda m: m["workspace_members"].append(m["workspace_members"][0]),
                     lambda m: m["packages"][0]["targets"][0].update(kind=["example"]),
                     lambda m: m["packages"][0]["targets"][0].update(kind=["custom-build"]),
                     lambda m: m["packages"][0]["targets"][0].update(test=False),
                     lambda m: m["packages"][0]["targets"][0].update({"required-features": ["conditional"]})]
        for mutate in mutations:
            metadata = copy.deepcopy(self.metadata)
            mutate(metadata)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                ci.workspace_inventory(metadata, self.root, "default")

    def test_custom_manifest_harness_and_discovery_refuse(self):
        path = Path(self.metadata["packages"][0]["manifest_path"])
        original = path.read_text()
        for suffix in ('autotests=false\n', '[lib]\nharness=false\n', '[lib]\ntest=true\n', '[lib]\ndoctest=false\n', '[lib]\nrequired-features=[]\n'):
            path.write_text(original + suffix)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.inventory()

    def test_complete_receipts_pass_both_feature_matrices(self):
        for suite in ci.SUITES:
            receipts, identity, inventory, targets = self.receipts(suite)
            ci.verify_receipts(receipts, suite, identity, inventory, targets)

    def test_missing_duplicate_foreign_or_mutated_receipts_fail(self):
        valid, identity, inventory, targets = self.receipts()
        mutations = [lambda r: r.pop(), lambda r: r.append(copy.deepcopy(r[0])),
                     lambda r: r[0].update(lane=r[1]["lane"]),
                     lambda r: r[0].update(source={**identity, "attempt": "2"}),
                     lambda r: r[0].update(source={**identity, "run": "8"}),
                     lambda r: r[0].update(source={**identity, "commit": "c" * 40}),
                     lambda r: r[0].update(source={**identity, "tree": "d" * 40}),
                     lambda r: r[0].update(suite="conversation"),
                     lambda r: r[0].update(version=True),
                     lambda r: r[0].update(version=1),
                     lambda r: r[0].update(inventory_digest="0" * 64),
                     lambda r: r[0]["workspace"].pop(),
                     lambda r: r[0]["records"].pop(next(iter(targets))),
                     lambda r: r[-1].update(doctests=False)]
        for mutate in mutations:
            receipts = copy.deepcopy(valid)
            mutate(receipts)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                ci.verify_receipts(receipts, "default", identity, inventory, targets)

    def test_zero_tests_wrong_ownership_and_incomplete_execution_fail(self):
        receipts, _, _, targets = self.receipts()
        valid = receipts[0]["records"]
        owned = next(key for key, value in valid.items() if value["executed"])
        for values in ({"tests": [], "passed": []}, {"executed": False}, {"executed": 1},
                       {"passed": []}, {"tests": ["database_case", "database_case"]},
                       {"features": ["conversation-simulator-tests"]}):
            records = copy.deepcopy(valid)
            # A feature mismatch must be on the server, regardless of lane.
            key = next(k for k, v in records.items() if v["description"]["package"] == "zrotext-server") if "features" in values else owned
            records[key].update(values)
            with self.subTest(values=values), self.assertRaises(ValueError):
                ci.validate_records(records, targets, "default", "delivery-store")

    def test_successful_but_different_cross_lane_test_inventory_fails(self):
        receipts, identity, inventory, targets = self.receipts()
        receipt = receipts[0]
        other = next(item for item in receipt["records"].values() if not item["executed"])
        other["tests"].append("unaccounted_case")
        receipt["inventory_digest"] = ci.digest({"workspace": inventory, "targets": {
            key: {k: v for k, v in item.items() if k not in ("assigned", "executed", "passed")}
            for key, item in receipt["records"].items()}})
        with self.assertRaises(ValueError):
            ci.verify_receipts(receipts, "default", identity, inventory, targets)

    def test_server_shards_prove_a_disjoint_union_and_reject_tampered_assignment(self):
        for suite in ci.SUITES:
            receipts, identity, inventory, targets = self.receipts(suite)
            server = next(key for key, target in targets.items() if target["description"]["package"] == "zrotext-server")
            shards = [r["records"][server] for r in receipts if r["lane"] in ci.SERVER_LANES]
            self.assertTrue(all(len(r["passed"]) == 2 for r in shards))
            for first, second in itertools.combinations(shards, 2):
                self.assertFalse(set(first["passed"]) & set(second["passed"]))
            self.assertEqual(sorted(name for shard in shards for name in shard["passed"]), shards[0]["tests"])
            for index, mutation in itertools.product(range(len(ci.SERVER_LANES)),
                                                      ("omission", "duplicate", "wrong-shard", "invented", "empty-lane")):
                broken = copy.deepcopy(receipts)
                shards = [r["records"][server] for r in broken if r["lane"] in ci.SERVER_LANES]
                first, second = shards[index], shards[(index + 1) % len(shards)]
                if mutation == "omission":
                    first["passed"] = first["passed"][1:]
                elif mutation == "duplicate":
                    first["passed"] = first["passed"] * 2
                elif mutation == "wrong-shard":
                    first["assigned"], second["assigned"] = second["assigned"], first["assigned"]
                    first["passed"], second["passed"] = second["passed"], first["passed"]
                elif mutation == "invented":
                    first["passed"] = [*first["passed"], "unlisted_case"]
                else:
                    first.update(assigned=[], passed=[], executed=False)
                with self.subTest(suite=suite, lane=ci.SERVER_LANES[index], mutation=mutation), self.assertRaises(ValueError):
                    ci.verify_receipts(broken, suite, identity, inventory, targets)

    def test_an_entire_server_lane_without_tests_refuses_even_consistent_records(self):
        receipts, _, _, targets = self.receipts()
        for index, lane in enumerate(ci.SERVER_LANES):
            records = copy.deepcopy(next(r["records"] for r in receipts if r["lane"] == lane))
            server = next(r for r in records.values() if r["description"]["package"] == "zrotext-server")
            other_lane = ci.SERVER_LANES[(index + 1) % len(ci.SERVER_LANES)]
            names = ci.assigned_tests("zrotext-server", SERVER_CASES, other_lane)
            server.update(tests=names, assigned=[], passed=[], executed=False)
            with self.subTest(lane=lane), self.assertRaisesRegex(ValueError, "zero tests"):
                ci.validate_records(records, targets, "default", lane)

    def test_old_two_shard_receipt_sets_and_assignments_refuse(self):
        for suite in ci.SUITES:
            receipts, identity, inventory, targets = self.receipts(suite)
            old = [r for r in receipts if r["lane"] not in ("server-2", "server-3")]
            with self.assertRaisesRegex(ValueError, "Missing or additional"):
                ci.verify_receipts(old, suite, identity, inventory, targets)
            # Even with all new lane labels, old modulo-two assignment cannot
            # masquerade as current proof with unchanged schema version two.
            for receipt in receipts:
                if receipt["lane"] not in ci.SERVER_LANES:
                    continue
                for item in receipt["records"].values():
                    if item["description"]["package"] != "zrotext-server":
                        continue
                    assigned = [name for name in item["tests"]
                                if "server-" + str(ci.hashlib.sha256(name.encode()).digest()[0] % 2) == receipt["lane"]]
                    item.update(assigned=assigned, passed=assigned, executed=bool(assigned))
            with self.assertRaisesRegex(ValueError, "Incorrect deterministic test assignment"):
                ci.verify_receipts(receipts, suite, identity, inventory, targets)

    def test_aggregate_checks_union_even_if_per_lane_validation_regresses(self):
        receipts, identity, inventory, targets = self.receipts()
        server = next(key for key, target in targets.items() if target["description"]["package"] == "zrotext-server")
        for names in ([], receipts[1]["records"][server]["passed"] * 2):
            broken = copy.deepcopy(receipts)
            broken[1]["records"][server]["passed"] = names
            with mock.patch.object(ci, "validate_records"), self.assertRaisesRegex(ValueError, "disjoint complete union"):
                ci.verify_receipts(broken, "default", identity, inventory, targets)

    def test_every_server_shard_requires_unique_current_invocation_proof(self):
        for suite in ci.SUITES:
            receipts, identity, inventory, targets = self.receipts(suite)
            for lane in ci.SERVER_LANES:
                index = next(i for i, receipt in enumerate(receipts) if receipt["lane"] == lane)
                for field, stale in (("commit", "c" * 40), ("tree", "d" * 40),
                                     ("run", "8"), ("attempt", "2")):
                    broken = copy.deepcopy(receipts)
                    broken[index]["source"] = {**identity, field: stale}
                    with self.subTest(suite=suite, lane=lane, stale=field), self.assertRaisesRegex(ValueError, "Foreign workflow"):
                        ci.verify_receipts(broken, suite, identity, inventory, targets)
                for mutation in ("missing", "duplicate"):
                    broken = copy.deepcopy(receipts)
                    if mutation == "missing":
                        broken.pop(index)
                    else:
                        broken[index] = copy.deepcopy(broken[(index + 1) % len(broken)])
                    with self.subTest(suite=suite, lane=lane, mutation=mutation), self.assertRaises(ValueError):
                        ci.verify_receipts(broken, suite, identity, inventory, targets)

    def test_artifact_inventory_is_exact_and_uses_cargo_paths_not_globs(self):
        _, targets = self.inventory()
        directory = self.root / "target/debug/deps"
        directory.mkdir(parents=True)
        records = []
        for index, target in enumerate(targets.values()):
            executable = directory / str(index)
            executable.write_text("synthetic executable")
            executable.chmod(0o700)
            package = next(p for p in self.metadata["packages"] if p["id"] == target["package_id"])
            records.append({"reason": "compiler-artifact", "package_id": package["id"], "target": package["targets"][0],
                            "profile": {"test": True}, "executable": str(executable), "features": []})
        records.append({"reason": "build-finished", "success": True})
        encode = lambda rs: "\n".join(json.dumps(r) for r in rs)
        self.assertEqual(len(ci.artifacts_from_output(encode(records), self.metadata, targets, self.root)), 3)
        for broken in (records[:-1], records[1:], [*records, records[0]],
                       [*records[:-1], {"reason": "build-finished", "success": False}]):
            with self.assertRaises(ValueError):
                ci.artifacts_from_output(encode(broken), self.metadata, targets, self.root)


class HarnessAndStatusTests(unittest.TestCase):
    def test_sharding_is_stable_and_native_arguments_preserve_exclusions(self):
        self.assertEqual(ci.LANES, ("delivery-store", "server-0", "server-1", "server-2", "server-3", "remaining"))
        names = SERVER_CASES.copy()
        expected = {"server-0": ["server_case_a", "server_case_f"],
                    "server-1": ["server_case_a_extra", "server_case_m"],
                    "server-2": ["server_case_d", "server_case_e"],
                    "server-3": ["server_case_b", "server_case_c"]}
        for lane, assigned in expected.items():
            self.assertEqual(ci.assigned_tests("zrotext-server", names, lane), assigned)
            self.assertEqual(ci.assigned_tests("zrotext-server", list(reversed(names)), lane), list(reversed(assigned)))
            self.assertEqual([n for n in ci.assigned_tests("zrotext-server", [*names, "new_test"], lane) if n in names], assigned)
        for suite in ci.SUITES:
            args = ci.selection(suite)
            self.assertEqual(ci.server_arguments(args, names), [*args, "--exact", "--", *names])
            self.assertEqual(ci.server_arguments(args, names, listing=True), [*args, "--exact", "--list", "--", *names])
            with self.assertRaises(ValueError):
                ci.server_arguments(args, [])

    def test_listing_and_passed_identities_must_match_exactly(self):
        self.assertEqual(ci.listed_tests("a: test\nb: test\n\n2 tests, 0 benchmarks\n"), ["a", "b"])
        self.assertEqual(ci.listed_tests("0 tests, 0 benchmarks\n"), [])
        output = "running 1 test\ntest a ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n"
        self.assertEqual(ci.passed_tests(output, ["a"]), ["a"])
        for broken in (output.replace("test a", "test b"), output + output,
                       output.replace("1 passed", "0 passed"), output.replace("0 ignored", "1 ignored"), ""):
            with self.assertRaises(ValueError):
                ci.passed_tests(broken, ["a"])
        for broken in ("a: test\na: test\n2 tests, 0 benchmarks\n", "a: test\n0 tests, 0 benchmarks\n", "0 tests, 1 benchmarks\n", ""):
            with self.assertRaises(ValueError):
                ci.listed_tests(broken)

    def test_duplicate_json_keys_are_not_accepted(self):
        with self.assertRaises(ValueError):
            ci.decode('{"lane":"server","lane":"remaining"}')

    def test_failed_cancelled_skipped_missing_and_invalid_decisions_refuse(self):
        valid = {"changes": {"result": "success", "outputs": {"rust": "true"}},
                 "rust-workspace": {"result": "success"}, "rust-postgresql": {"result": "success"}}
        self.assertTrue(ci.prerequisite_status("default", valid))
        for name in valid:
            for result in ("failure", "cancelled", "skipped", "", None):
                needs = copy.deepcopy(valid)
                needs[name]["result"] = result
                with self.subTest(name=name, result=result), self.assertRaises(ValueError):
                    ci.prerequisite_status("default", needs)
        for decision in (None, "", "False", False, "invalid"):
            needs = copy.deepcopy(valid)
            needs["changes"]["outputs"]["rust"] = decision
            with self.assertRaises(ValueError):
                ci.prerequisite_status("default", needs)
        valid["changes"]["outputs"]["rust"] = "false"
        self.assertFalse(ci.prerequisite_status("default", valid))
        for name in valid:
            needs = copy.deepcopy(valid)
            needs[name]["result"] = "skipped"
            with self.assertRaises(ValueError):
                ci.prerequisite_status("default", needs)
        del valid["rust-postgresql"]
        with self.assertRaises(ValueError):
            ci.prerequisite_status("default", valid)

    def test_conversation_aggregator_requires_every_prerequisite(self):
        valid = {"conversation-workspace": {"result": "success"},
                 "conversation-postgresql-lanes": {"result": "success"}}
        self.assertTrue(ci.prerequisite_status("conversation", valid))
        for name in valid:
            for result in ("failure", "cancelled", "skipped", None):
                needs = copy.deepcopy(valid)
                needs[name]["result"] = result
                with self.assertRaises(ValueError):
                    ci.prerequisite_status("conversation", needs)
            needs = copy.deepcopy(valid)
            del needs[name]
            with self.assertRaises(ValueError):
                ci.prerequisite_status("conversation", needs)

    def test_only_the_original_feature_and_exclusion_matrices_are_used(self):
        self.assertEqual(ci.cargo_tests("default"), ["cargo", "test", "--locked", "--workspace", "--lib", "--bins", "--test", "*"])
        self.assertEqual(ci.cargo_tests("conversation"), ["cargo", "test", "--locked", "--workspace", "--features", "conversation-simulator-tests", "--lib"])
        self.assertEqual(ci.selection("default"), ["--ignored", "--skip", "real_stripe_", "--test-threads=4"])
        self.assertEqual(ci.selection("conversation"), ["--ignored", "--skip", "real_stripe_", "--skip", "loopback_journal_bridge", "--skip", "ordinary_setup_server_browser_fixture", "--test-threads=4"])
        self.assertEqual(ci.doctest_command(), ["cargo", "test", "--locked", "--workspace", "--doc", "--", "--ignored", "--skip", "real_stripe_", "--test-threads=4"])

    def test_existing_runner_target_and_included_configs_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = root / ".cargo"
            cargo.mkdir()
            env = {"CARGO_HOME": str(cargo)}
            ci.refuse_runner_overrides(root, env)
            for additional in ({"CARGO_BUILD_TARGET": "foreign"}, {"CARGO_TARGET_NATIVE_RUNNER": "custom"}):
                with self.assertRaises(ValueError):
                    ci.refuse_runner_overrides(root, {**env, **additional})
            for config in ('[target.x86_64-unknown-linux-gnu]\nrunner="custom"\n', '[build]\ntarget="foreign"\n', 'include="other.toml"\n', '[env]\nCARGO_TARGET_NATIVE_RUNNER="custom"\n'):
                (cargo / "config.toml").write_text(config)
                with self.assertRaises(ValueError):
                    ci.refuse_runner_overrides(root, env)


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / "package"
        self.package.mkdir()
        self.results = self.root / "results"
        self.results.mkdir()
        self.executable = self.root / "test-harness"
        self.executable.write_text('#!' + sys.executable + '\n' + '''import os,sys
assert os.environ["CI_DISPATCH_TEST_SENTINEL"] == "unchanged"
if "--list" in sys.argv:
    print("case: test")
    print()
    print("1 test, 0 benchmarks")
else:
    print("running 1 test")
    print("test case ... ok")
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s")
''')
        self.executable.chmod(0o700)
        self.arguments = [*ci.selection("default"), "--format=pretty", "--color=never"]
        self.state = {"root": str(self.root), "suite": "default", "lane": "server-3", "arguments": self.arguments,
                      "results": str(self.results), "artifacts": {"one": {"executable": str(self.executable),
                      "manifest": "package/Cargo.toml", "description": {"package": "zrotext-server"}, "features": []}}}
        self.state_path = self.root / "state.json"

    def call(self, arguments=None, cwd=None):
        self.state_path.write_text(json.dumps(self.state))
        previous = Path.cwd()
        try:
            os.chdir(cwd or self.package)
            with mock.patch.dict(os.environ, {ci.STATE_ENV: str(self.state_path), "CI_DISPATCH_TEST_SENTINEL": "unchanged"}):
                ci.dispatch(arguments or [str(self.executable), *self.arguments])
        finally:
            os.chdir(previous)

    def test_dispatch_runs_exactly_once_with_inherited_environment(self):
        self.call()
        result = ci.read_json(self.results / "one.json")
        self.assertTrue(result["executed"])
        self.assertEqual(result["tests"], ["case"])
        self.assertEqual(result["assigned"], ["case"])
        self.assertEqual(result["passed"], ["case"])
        with self.assertRaises(FileExistsError):
            self.call()

    def test_nonowned_target_is_inventoried_but_assigned_elsewhere(self):
        self.state["lane"] = "delivery-store"
        self.call()
        result = ci.read_json(self.results / "one.json")
        self.assertFalse(result["executed"])
        self.assertEqual(result["tests"], ["case"])
        self.assertEqual(result["passed"], [])

    def test_empty_server_target_subset_never_invokes_an_unfiltered_harness(self):
        self.state["lane"] = "server-0"
        with mock.patch.object(ci, "execute_harness", side_effect=AssertionError("Empty subset executed")):
            self.call()
        result = ci.read_json(self.results / "one.json")
        self.assertEqual(result["tests"], ["case"])
        self.assertEqual(result["assigned"], [])
        self.assertFalse(result["executed"])

    def test_mismatched_native_multifilter_listing_refuses_before_execution(self):
        self.executable.write_text(self.executable.read_text().replace('print("case: test")', 'print("other: test" if "--exact" in sys.argv else "case: test")'))
        with mock.patch.object(ci, "execute_harness", side_effect=AssertionError("Bad selection executed")), self.assertRaisesRegex(ValueError, "filters differ"):
            self.call()
        self.assertFalse((self.results / "one.json").exists())

    def test_unknown_executable_wrong_arguments_and_wrong_cwd_refuse(self):
        for arguments in ([str(self.root / "unknown"), *self.arguments], [str(self.executable), "--ignored"]):
            with self.assertRaises(ValueError):
                self.call(arguments)
        with self.assertRaises(ValueError):
            self.call(cwd=self.root)
        self.assertEqual(list(self.results.iterdir()), [])

    def test_failed_harness_never_writes_success(self):
        source = self.executable.read_text().replace('else:\n    print(', 'else:\n    sys.exit(1)\n    print(', 1)
        self.executable.write_text(source)
        with self.assertRaises(ValueError):
            self.call()
        self.assertFalse((self.results / "one.json").exists())


class ReceiptDestinationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = self.root / "runner-temp"
        self.runner.mkdir()
        self.other = self.root / "other"
        self.other.mkdir()
        self.environment = mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.runner)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_output_is_created_only_below_the_explicit_root(self):
        path = self.runner / "lane/coverage.json"
        with ci.receipt_destination(path) as destination:
            self.assertFalse(os.get_inheritable(destination[0]))
            self.assertFalse(path.exists())
            ci.write_receipt(destination, {"synthetic": True})
        self.assertEqual(ci.read_json(path), {"synthetic": True})
        with self.assertRaises(ValueError):
            with ci.receipt_destination(path):
                self.fail("Existing output was accepted")

    def test_outside_relative_and_parent_traversal_paths_refuse_before_creation(self):
        for path in (self.other / "coverage.json", Path("coverage.json"),
                     self.runner / ".." / "other/coverage.json", self.runner):
            with self.subTest(path=path), self.assertRaises(ValueError):
                with ci.receipt_destination(path):
                    self.fail("Invalid output was accepted")
        self.assertEqual(list(self.other.iterdir()), [])
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_linked_parents_refuse_without_creating_files_or_subdirectories(self):
        alias = self.runner / "lane"
        alias.symlink_to(self.other, target_is_directory=True)
        for path in (alias / "coverage.json", alias / "nested/coverage.json"):
            with self.subTest(path=path), self.assertRaises(OSError):
                with ci.receipt_destination(path):
                    self.fail("Linked parent was accepted")
        self.assertEqual(list(self.other.iterdir()), [])

    def test_existing_hardlink_and_dangling_symlink_leaves_are_not_overwritten(self):
        original = self.other / "existing.json"
        original.write_text("synthetic original")
        hardlink = self.runner / "hardlink.json"
        os.link(original, hardlink)
        dangling = self.runner / "dangling.json"
        dangling.symlink_to(self.other / "missing.json")
        for path in (hardlink, dangling):
            with self.subTest(path=path), self.assertRaises(ValueError):
                with ci.receipt_destination(path):
                    self.fail("Existing alias was accepted")
        self.assertEqual(original.read_text(), "synthetic original")
        self.assertFalse((self.other / "missing.json").exists())

    def test_final_creation_remains_exclusive_after_the_initial_check(self):
        path = self.runner / "coverage.json"
        with ci.receipt_destination(path) as destination:
            path.symlink_to(self.other / "missing.json")
            with self.assertRaises(FileExistsError):
                ci.write_receipt(destination, {"synthetic": True})
        self.assertFalse((self.other / "missing.json").exists())

    def test_a_later_parent_alias_does_not_redirect_the_held_descriptor(self):
        parent = self.runner / "lane"
        retained = self.runner / "retained"
        with ci.receipt_destination(parent / "coverage.json") as destination:
            parent.rename(retained)
            parent.symlink_to(self.other, target_is_directory=True)
            ci.write_receipt(destination, {"synthetic": True})
        self.assertEqual(ci.read_json(retained / "coverage.json"), {"synthetic": True})
        self.assertEqual(list(self.other.iterdir()), [])

    def test_parent_descriptor_is_closed_after_success_and_failure(self):
        with ci.receipt_destination(self.runner / "success.json") as destination:
            descriptor = destination[0]
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        try:
            with ci.receipt_destination(self.runner / "failure.json") as destination:
                descriptor = destination[0]
                raise RuntimeError("synthetic lane failure")
        except RuntimeError:
            pass
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertFalse((self.runner / "failure.json").exists())

    def test_linked_missing_or_unspecified_runner_roots_refuse(self):
        alias = self.root / "alias"
        alias.symlink_to(self.runner, target_is_directory=True)
        for value in (str(alias), str(self.root / "missing"), "relative", ""):
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": value}), self.assertRaises(ValueError):
                with ci.receipt_destination(self.runner / "coverage.json"):
                    self.fail("Invalid runner root was accepted")


class WorkflowSourceTests(unittest.TestCase):
    def test_partition_matrices_match_the_verifier_without_expanding_runner_bounds(self):
        for workflow, matrix_name, aggregate_name, budget in (
                ("ci.yml", "rust-postgresql", "rust", 45),
                ("conversation-simulator.yml", "conversation-postgresql-lanes", "conversation-postgresql", 60)):
            source = (ROOT / ".github/workflows" / workflow).read_text()
            matrix = job(workflow, matrix_name)
            aggregate = job(workflow, aggregate_name)
            lanes = re.findall(r"^        lane: \[(.+)\]$", matrix, re.MULTILINE)
            expected = ci.LANES[:-1] if workflow == "ci.yml" else ci.LANES
            self.assertEqual(lanes, [", ".join(expected)])
            self.assertEqual(re.findall(r"^      max-parallel: (.+)$", matrix, re.MULTILINE), ["3"])
            self.assertIn("    runs-on: ubuntu-24.04\n", matrix)
            self.assertIn(f"    timeout-minutes: {budget}\n", matrix)
            self.assertIn("    timeout-minutes: 10\n", aggregate)
            self.assertEqual(re.findall(r"^ *permissions:.*\n(?: +[^\n]+\n)*", source, re.MULTILINE),
                             ["permissions:\n  contents: read\n"])
            self.assertNotIn("continue-on-error", aggregate)
        documentation = (ROOT / "CONTRIBUTING.md").read_text()
        self.assertIn("rerun the complete\nworkflow rather than only failed jobs", documentation)

    def test_required_rust_is_an_always_strict_aggregator(self):
        aggregate = job("ci.yml", "rust")
        for required in ("    name: rust\n", "    if: ${{ always() }}\n", "    needs: [changes, rust-workspace, rust-postgresql]\n",
                         "CI_NEEDS_JSON: ${{ toJSON(needs) }}", "status --suite default", "verify --suite default",
                         "pattern: rust-postgresql-${{ github.run_id }}-${{ github.run_attempt }}-*"):
            self.assertIn(required, aggregate)
        self.assertNotIn("continue-on-error", aggregate)

    def test_fixed_lane_bounds_and_all_previous_core_gates_remain(self):
        core = job("ci.yml", "rust-workspace")
        matrix = job("ci.yml", "rust-postgresql")
        self.assertIn("lane: [delivery-store, server-0, server-1, server-2, server-3]", matrix)
        self.assertIn("max-parallel: 3", matrix)
        self.assertIn("fail-fast: false", matrix)
        for source in (core, matrix):
            self.assertIn("timeout-minutes: 45", source)
            self.assertIn("needs.changes.outputs.rust != 'false'", source)
            self.assertNotIn("continue-on-error", source)
            self.assertIn("if-no-files-found: error", source)
        for gate in ("scripts/check_env_example.py", "cargo fmt --all --check",
                     "cargo clippy --locked --workspace --all-targets -- -D warnings",
                     "run: cargo test --locked --workspace\n", "scripts/workflow_log_canaries.py",
                     "cargo build --locked --workspace --bin zrotext-migrator --bin zrotext-device-sim",
                     "scripts/tests/test_postgres_tls.py", "run: target/debug/zrotext-device-sim",
                     "--suite default --lane remaining", "--native-runner-smoke"):
            self.assertIn(gate, core)
        self.assertEqual(core.count("          target/debug/zrotext-migrator\n"), 2)
        self.assertLess(core.index("run: target/debug/zrotext-device-sim"), core.index("uses: actions/upload-artifact@"))

    def test_conversation_target_matrix_source_checks_and_downstream_gates_survive(self):
        workspace = job("conversation-simulator.yml", "conversation-workspace")
        lanes = job("conversation-simulator.yml", "conversation-postgresql-lanes")
        aggregate = job("conversation-simulator.yml", "conversation-postgresql")
        downstream = job("conversation-simulator.yml", "conversation-simulator")
        for gate in ("cargo clippy --locked -p zrotext-server --all-targets --features conversation-simulator-tests -- -D warnings",
                     "run: cargo test --locked --workspace --features conversation-simulator-tests\n",
                     "--features conversation-simulator-tests --bins --test '*' -- --ignored",
                     "--features conversation-simulator-tests --doc -- --ignored"):
            self.assertIn(gate, workspace)
        for gate in ("lane: [delivery-store, server-0, server-1, server-2, server-3, remaining]", "max-parallel: 3", "fail-fast: false",
                     "timeout-minutes: 60", "--suite conversation --lane '${{ matrix.lane }}'"):
            self.assertIn(gate, lanes)
        self.assertIn("needs: [conversation-workspace]", lanes)
        self.assertIn("needs: [conversation-workspace, conversation-postgresql-lanes]", aggregate)
        self.assertIn("if: ${{ always() }}", aggregate)
        self.assertIn("verify --suite conversation", aggregate)
        self.assertIn("needs: [conversation-workspace, conversation-postgresql]", downstream)
        for source in (lanes, downstream):
            self.assertIn('test "$source_commit" = "$EXPECTED_SOURCE_COMMIT"', source)
            self.assertIn('test "$source_tree" = "$EXPECTED_SOURCE_TREE"', source)
        for source in (workspace, lanes, aggregate, downstream):
            self.assertNotIn("continue-on-error", source)
        workflow = (ROOT / ".github/workflows/conversation-simulator.yml").read_text()
        for path in ("scripts/ci_rust_postgresql.py", "scripts/test_ci_rust_postgresql.py", "scripts/test_registered_control_databases.py"):
            self.assertIn("      - '" + path + "'", workflow)


def native_runner_smoke():
    """No dependencies or database: exercise the real pinned native Cargo hook."""
    with tempfile.TemporaryDirectory(prefix="ci-native-runner-") as directory:
        root = Path(directory)
        runner_temp = root / "runner-temp"
        runner_temp.mkdir()
        names = ("zrotext-delivery-store", "zrotext-server", "zrotext-migrator", "zrotext-empty")
        (root / "Cargo.toml").write_text('[workspace]\nresolver="3"\nmembers=' + json.dumps(names) + '\n')
        test = '''#[test]
#[ignore]
fn cargo_runtime_is_preserved() {
    assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    assert_eq!(std::env::var("CARGO_MANIFEST_DIR").unwrap(), env!("CARGO_MANIFEST_DIR"));
    assert_eq!(std::env::var("CI_RUNNER_SENTINEL").unwrap(), "unchanged");
    let libraries = std::env::var("LD_LIBRARY_PATH").unwrap();
    assert!(libraries.contains("/deps"));
    assert!(libraries.contains("inherited-library-sentinel"));
}
'''
        server_test = test + '''#[test] #[ignore]
fn server_case_a() { assert!(std::env::var_os("CI_SHARD_FORCE_FAILURE").is_none()); }
#[test] #[ignore] fn server_case_a_extra() {}
#[test] #[ignore] fn server_case_b() {}
#[test] #[ignore] fn server_case_c() {}
#[test] #[ignore] fn server_case_d() {}
#[test] #[ignore] fn server_case_e() {}
#[test] #[ignore] fn server_case_f() {}
#[test] #[ignore] fn real_stripe_excluded() { panic!("original Stripe exclusion escaped"); }
#[test] fn ordinary_not_selected() { panic!("nonignored selection escaped"); }
#[test] #[ignore] #[cfg(feature="conversation-simulator-tests")]
fn loopback_journal_bridge_excluded() { panic!("original loopback exclusion escaped"); }
#[test] #[ignore] #[cfg(feature="conversation-simulator-tests")]
fn ordinary_setup_server_browser_fixture_excluded() { panic!("original browser exclusion escaped"); }
'''
        for name in names:
            package = root / name
            (package / "src").mkdir(parents=True)
            manifest = '[package]\nname="' + name + '"\nversion="0.1.0"\nedition="2024"\n'
            if name == "zrotext-delivery-store":
                manifest += '[features]\nunified=[]\n'
            if name == "zrotext-server":
                manifest += '[features]\nconversation-simulator-tests=[]\n[dependencies]\nzrotext-delivery-store={path="../zrotext-delivery-store",features=["unified"]}\n'
                (package / "src/main.rs").write_text('fn main() {}\n' + server_test)
                (package / "tests").mkdir()
                (package / "tests/integration.rs").write_text(server_test)
            (package / "Cargo.toml").write_text(manifest)
            if name == "zrotext-empty":
                (package / "src/main.rs").write_text('fn main() {}\n')
            else:
                source = server_test if name == "zrotext-server" else test
                if name == "zrotext-server":
                    source += '#[test]\n#[ignore]\n#[cfg(feature="conversation-simulator-tests")]\nfn simulator_feature_runs() {}\n'
                if name == "zrotext-delivery-store":
                    source += '#[test]\n#[ignore]\nfn workspace_features_are_unified() { assert!(cfg!(feature="unified")); }\n'
                if name == "zrotext-migrator":
                    # A standalone doctest proves the body executes; merged 2024
                    # doctest accounting is not a substitute for that proof.
                    source = '/// ```ignore,standalone_crate\n/// std::fs::write(std::env::var("CI_DOCTEST_PROOF").unwrap(), b"executed").unwrap();\n/// ```\npub fn documented() {}\n' + source
                (package / "src/lib.rs").write_text(source)
        toolchain = ci.tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        subprocess.run(["cargo", "+" + toolchain, "generate-lockfile", "--offline"], cwd=root, check=True)
        git = ["git", "-c", "user.name=CI Test", "-c", "user.email=ci@example.invalid", "-c", "commit.gpgsign=false"]
        for args in (["init", "-q"], ["add", "."], ["commit", "-qm", "Synthetic runner fixture"]):
            subprocess.run([*git, *args], cwd=root, check=True)
        commit = ci.capture(["git", "rev-parse", "HEAD"], root).strip()
        env = {"GITHUB_SHA": commit, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1",
               "CI_RUNNER_SENTINEL": "unchanged", "LD_LIBRARY_PATH": "inherited-library-sentinel",
               "CI_DOCTEST_PROOF": str(root / "doctest-proof"), "CARGO_TARGET_DIR": str(root / "target"),
               "CARGO_NET_OFFLINE": "true", "RUSTUP_TOOLCHAIN": toolchain, "RUNNER_TEMP": str(runner_temp)}
        with mock.patch.dict(os.environ, env):
            for suite in ci.SUITES:
                receipts = []
                for lane in ci.LANES:
                    path = runner_temp / (suite + "-" + lane + ".json")
                    ci.run_lane(root, suite, lane, path)
                    receipts.append(ci.read_json(path))
                inventory, targets = ci.workspace_inventory(ci.read_metadata(root), root, suite)
                ci.verify_receipts(receipts, suite, ci.source_identity(root), inventory, targets)
                server_receipts = [r for r in receipts if r["lane"] in ci.SERVER_LANES]
                for key, target in targets.items():
                    if target["description"]["package"] != "zrotext-server":
                        continue
                    shards = [r["records"][key] for r in server_receipts]
                    first, second = shards[:2]
                    if not all(len(r["passed"]) >= 2 for r in shards):
                        raise AssertionError("Native smoke did not execute multiple exact filters per shard")
                    if "server_case_a" not in first["passed"] or "server_case_a_extra" not in second["passed"]:
                        raise AssertionError("Native exact selection did not separate overlapping names")
                    if any("excluded" in name for name in first["tests"]):
                        raise AssertionError("Original exclusion escaped into the full server inventory")
                broken = copy.deepcopy(receipts)
                key = next(k for k, t in targets.items() if t["description"]["package"] == "zrotext-server")
                broken[1]["records"][key]["passed"].pop()
                try:
                    ci.verify_receipts(broken, suite, ci.source_identity(root), inventory, targets)
                except ValueError:
                    pass
                else:
                    raise AssertionError("Incomplete real native shard receipt was accepted")
            if (root / "doctest-proof").read_bytes() != b"executed":
                raise AssertionError("Default ignored doctest did not actually execute")
            refusal = runner_temp / "failed-server-shard.json"
            print("Expecting the following synthetic server shard failure; no receipt may be written.", flush=True)
            with mock.patch.dict(os.environ, {"CI_SHARD_FORCE_FAILURE": "1"}):
                try:
                    ci.run_lane(root, "default", "server-0", refusal)
                except subprocess.CalledProcessError:
                    pass
                else:
                    raise AssertionError("Failing native server shard was accepted")
            if refusal.exists():
                raise AssertionError("Failed native server shard published a success receipt")
            # A real failing doctest must fail the residual lane and publish no
            # receipt. This fixture is disposable and contains no database code.
            path = root / "zrotext-migrator/src/lib.rs"
            source = path.read_text().replace('std::fs::write(std::env::var("CI_DOCTEST_PROOF").unwrap(), b"executed").unwrap();', 'panic!("synthetic doctest refusal");')
            path.write_text(source)
            subprocess.run([*git, "add", "zrotext-migrator/src/lib.rs"], cwd=root, check=True)
            subprocess.run([*git, "commit", "-qm", "Synthetic failing doctest"], cwd=root, check=True)
            os.environ["GITHUB_SHA"] = ci.capture(["git", "rev-parse", "HEAD"], root).strip()
            refusal = runner_temp / "must-not-exist.json"
            print("Expecting the following synthetic doctest failure; no receipt may be written.", flush=True)
            try:
                ci.run_lane(root, "default", "remaining", refusal)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("Failing doctest was accepted")
            if refusal.exists():
                raise AssertionError("Failed doctest published a success receipt")
        print("Native Cargo runner, exact multi-test shards, both feature matrices and real shard/doctest pass/refusal checks passed.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--native-runner-smoke"]:
        native_runner_smoke()
    else:
        unittest.main()
