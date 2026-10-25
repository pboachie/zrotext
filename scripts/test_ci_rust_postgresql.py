# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed PostgreSQL partition tests and a tiny real Cargo runner smoke test."""
import copy
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
                owned = ci.lane_for(target["description"]["package"]) == lane
                features = ["conversation-simulator-tests"] if suite == "conversation" and target["description"]["package"] == "zrotext-server" else []
                records[key] = {"description": target["description"], "features": features,
                                "tests": ["database_case"], "executed": owned,
                                "passed": ["database_case"] if owned else []}
            receipt = {"version": 1, "source": identity, "suite": suite, "lane": lane,
                       "workspace": inventory, "records": records,
                       "doctests": suite == "default" and lane == "remaining"}
            receipt["inventory_digest"] = ci.digest({"workspace": inventory, "targets": {
                key: {k: v for k, v in item.items() if k not in ("executed", "passed")}
                for key, item in records.items()}})
            receipts.append(receipt)
        return receipts, identity, inventory, targets

    def test_new_packages_are_automatically_assigned_to_remaining(self):
        self.add_package("new-workspace-package", ["rlib", "cdylib"])
        inventory, targets = self.inventory()
        added = next(p for p in inventory if p["name"] == "new-workspace-package")
        self.assertEqual(added["lane"], "remaining")
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
                     lambda r: r[0].update(suite="conversation"),
                     lambda r: r[0].update(version=True),
                     lambda r: r[0].update(inventory_digest="0" * 64),
                     lambda r: r[0]["workspace"].pop(),
                     lambda r: r[0]["records"].pop(next(iter(targets))),
                     lambda r: r[2].update(doctests=False)]
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
            key: {k: v for k, v in item.items() if k not in ("executed", "passed")}
            for key, item in receipt["records"].items()}})
        with self.assertRaises(ValueError):
            ci.verify_receipts(receipts, "default", identity, inventory, targets)

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
        del valid["rust-postgresql"]
        with self.assertRaises(ValueError):
            ci.prerequisite_status("default", valid)

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
        self.state = {"root": str(self.root), "suite": "default", "lane": "server", "arguments": self.arguments,
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


class WorkflowSourceTests(unittest.TestCase):
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
        self.assertIn("lane: [delivery-store, server]", matrix)
        self.assertIn("max-parallel: 2", matrix)
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
        for gate in ("lane: [delivery-store, server, remaining]", "max-parallel: 3", "fail-fast: false",
                     "timeout-minutes: 60", "--suite conversation --lane '${{ matrix.lane }}'"):
            self.assertIn(gate, lanes)
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
        for name in names:
            package = root / name
            (package / "src").mkdir(parents=True)
            manifest = '[package]\nname="' + name + '"\nversion="0.1.0"\nedition="2024"\n'
            if name == "zrotext-delivery-store":
                manifest += '[features]\nunified=[]\n'
            if name == "zrotext-server":
                manifest += '[features]\nconversation-simulator-tests=[]\n[dependencies]\nzrotext-delivery-store={path="../zrotext-delivery-store",features=["unified"]}\n'
                (package / "src/main.rs").write_text('fn main() {}\n' + test)
                (package / "tests").mkdir()
                (package / "tests/integration.rs").write_text(test)
            (package / "Cargo.toml").write_text(manifest)
            if name == "zrotext-empty":
                (package / "src/main.rs").write_text('fn main() {}\n')
            else:
                source = test
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
               "CARGO_NET_OFFLINE": "true", "RUSTUP_TOOLCHAIN": toolchain}
        with mock.patch.dict(os.environ, env):
            for suite in ci.SUITES:
                receipts = []
                for lane in ci.LANES:
                    path = root / (suite + "-" + lane + ".json")
                    ci.run_lane(root, suite, lane, path)
                    receipts.append(ci.read_json(path))
                inventory, targets = ci.workspace_inventory(ci.read_metadata(root), root, suite)
                ci.verify_receipts(receipts, suite, ci.source_identity(root), inventory, targets)
            if (root / "doctest-proof").read_bytes() != b"executed":
                raise AssertionError("Default ignored doctest did not actually execute")
            # A real failing doctest must fail the residual lane and publish no
            # receipt. This fixture is disposable and contains no database code.
            path = root / "zrotext-migrator/src/lib.rs"
            source = path.read_text().replace('std::fs::write(std::env::var("CI_DOCTEST_PROOF").unwrap(), b"executed").unwrap();', 'panic!("synthetic doctest refusal");')
            path.write_text(source)
            subprocess.run([*git, "add", "zrotext-migrator/src/lib.rs"], cwd=root, check=True)
            subprocess.run([*git, "commit", "-qm", "Synthetic failing doctest"], cwd=root, check=True)
            os.environ["GITHUB_SHA"] = ci.capture(["git", "rev-parse", "HEAD"], root).strip()
            refusal = root / "must-not-exist.json"
            print("Expecting the following synthetic doctest failure; no receipt may be written.", flush=True)
            try:
                ci.run_lane(root, "default", "remaining", refusal)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("Failing doctest was accepted")
            if refusal.exists():
                raise AssertionError("Failed doctest published a success receipt")
        print("Native Cargo runner, both feature matrices and real doctest pass/refusal checks passed.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--native-runner-smoke"]:
        native_runner_smoke()
    else:
        unittest.main()
