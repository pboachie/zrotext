# SPDX-License-Identifier: AGPL-3.0-only
"""Partition ignored workspace harnesses without changing Cargo feature resolution.

Cargo's command-local native runner supplies the original package cwd and runtime
environment. Every runner invocation is inventoried, including targets assigned to
another lane. Ordinary Cargo, without that runner, retains default doctest coverage.
Receipts contain structural test identities, never captured fixture output.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

SERVER_LANES = ("server-0", "server-1")
LANES = ("delivery-store", *SERVER_LANES, "remaining")
SUITES = ("default", "conversation")
LIB_KINDS = {"lib", "rlib", "cdylib", "dylib", "staticlib", "proc-macro"}
STATE_ENV = "ZT_CI_POSTGRESQL_DISPATCH_STATE"
MAX_OUTPUT = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def decode(text):
    return json.loads(text, object_pairs_hook=unique_object)


def read_json(path):
    require(path.is_file() and not path.is_symlink(), "Missing or linked JSON input")
    require(path.stat().st_size <= MAX_OUTPUT, "Oversized JSON input")
    return decode(path.read_text(encoding="utf-8"))


@contextmanager
def receipt_destination(receipt):
    """Hold a non-aliased parent below the runner's existing temporary root.

    CLI output paths may not escape that root. Descriptor-relative traversal
    refuses linked parents, including a linked final directory; exclusive final
    creation also refuses existing files, hard links and dangling leaf symlinks.
    This is an accidental-path boundary, not isolation from other same-job code.
    """
    value = os.environ.get("RUNNER_TEMP")
    require(value, "RUNNER_TEMP is required for coverage output")
    root = Path(value)
    require(root.is_absolute() and ".." not in root.parts and root != root.parent,
            "Runner temporary root must be an absolute directory")
    require(root.is_dir() and root.resolve(strict=True) == root,
            "Runner temporary root must not contain aliases")
    require(receipt.is_absolute() and ".." not in receipt.parts,
            "Coverage output must be an absolute path without parent traversal")
    parts = receipt.relative_to(root).parts
    require(parts, "Coverage output must be a file below runner temporary root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root, flags)
    try:
        for component in parts[:-1]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(component, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        try:
            os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("Refusing an existing coverage output entry")
        yield parent, parts[-1]
    finally:
        os.close(parent)


def write_receipt(destination, result):
    parent, name = destination
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         mode=0o600, dir_fd=parent)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def capture(argv, root):
    result = subprocess.run(argv, cwd=root, check=False, capture_output=True, text=True)
    require(len(result.stdout.encode()) <= MAX_OUTPUT, "Oversized command output")
    if result.returncode:
        # Preserve the compiler's diagnostics rather than replacing a real build
        # failure with only the partition helper's exception. No receipt uses them.
        print(result.stderr, end="", file=sys.stderr)
        for line in result.stdout.splitlines():
            try:
                record = decode(line)
            except ValueError:
                continue
            if isinstance(record, dict) and record.get("reason") == "compiler-message":
                print(record.get("message", {}).get("rendered", ""), end="", file=sys.stderr)
        result.check_returncode()
    return result.stdout


def source_identity(root):
    commit = capture(["git", "rev-parse", "HEAD"], root).strip()
    tree = capture(["git", "rev-parse", "HEAD^{tree}"], root).strip()
    require(re.fullmatch(r"[0-9a-f]{40}", commit) and re.fullmatch(r"[0-9a-f]{40}", tree), "Invalid source identity")
    require(commit == os.environ.get("GITHUB_SHA"), "Checkout is not the current workflow source")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=root, check=True)
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[1-9][0-9]*", run) and re.fullmatch(r"[1-9][0-9]*", attempt), "Missing workflow invocation identity")
    return {"commit": commit, "tree": tree, "run": run, "attempt": attempt}


def lanes_for(package):
    if package == "zrotext-server":
        return list(SERVER_LANES)
    return ["delivery-store" if package == "zrotext-delivery-store" else "remaining"]


def assigned_tests(package, tests, lane):
    require(lane in LANES, "Unknown lane")
    if lane not in lanes_for(package):
        return []
    if package == "zrotext-server":
        # Unlike Python's randomized hash(), this assignment is identical in
        # every job and independent of enumeration order or newly added tests.
        return [name for name in tests if SERVER_LANES[hashlib.sha256(name.encode("utf-8")).digest()[0] % 2] == lane]
    return tests


def server_arguments(arguments, tests, *, listing=False):
    # An empty filter list would run the entire harness. Never issue it.
    require(tests, "Cannot execute an empty server shard target")
    return [*arguments, "--exact", *(["--list"] if listing else []), "--", *tests]


def selection(suite):
    require(suite in SUITES, "Unknown feature selection")
    args = ["--ignored", "--skip", "real_stripe_"]
    if suite == "conversation":
        args += ["--skip", "loopback_journal_bridge", "--skip", "ordinary_setup_server_browser_fixture"]
    return args + ["--test-threads=4"]


def cargo_tests(suite):
    require(suite in SUITES, "Unknown feature selection")
    args = ["cargo", "test", "--locked", "--workspace"]
    if suite == "conversation":
        args += ["--features", "conversation-simulator-tests", "--lib"]
    else:
        args += ["--lib", "--bins", "--test", "*"]
    return args


def doctest_command():
    return ["cargo", "test", "--locked", "--workspace", "--doc", "--", *selection("default")]


def relative(path, root):
    return Path(path).resolve().relative_to(root.resolve()).as_posix()


def target_description(package, target, root):
    kinds = target["kind"]
    require(isinstance(kinds, list) and kinds and len(kinds) == len(set(kinds)), "Invalid target kinds")
    library = set(kinds) <= LIB_KINDS
    require(library or kinds in (["bin"], ["test"]), "Unsupported workspace target kind")
    require(target.get("test") is True and not target.get("required-features"), "Unsupported conditional or disabled test target")
    return {"package": package["name"], "name": target["name"], "kind": sorted(kinds),
            "source": relative(target["src_path"], root), "library": library}


def workspace_inventory(metadata, root, suite):
    require(suite in SUITES and relative(metadata["workspace_root"], root) == ".", "Wrong workspace")
    ids = metadata["workspace_members"]
    require(isinstance(ids, list) and ids and len(ids) == len(set(ids)), "Invalid workspace membership")
    packages = metadata["packages"]
    require(len(packages) == len(ids) and {p["id"] for p in packages} == set(ids), "Incomplete workspace metadata")
    require(len({p["name"] for p in packages}) == len(packages), "Duplicate package names")
    require({"zrotext-delivery-store", "zrotext-server", "zrotext-migrator"} <= {p["name"] for p in packages}, "Missing database package")
    inventory, targets, seen = [], {}, set()
    for package in packages:
        manifest_path = Path(package["manifest_path"])
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        require(not manifest.get("example") and not manifest.get("bench"), "Unmapped example or benchmark")
        require(not any((manifest_path.parent / name).exists() for name in ("examples", "benches")), "Unmapped example or benchmark directory")
        require(not any(key in manifest["package"] for key in ("autolib", "autobins", "autotests", "autoexamples", "autobenches")), "Custom target discovery requires review")
        for kind in ("lib", "bin", "test"):
            definitions = manifest.get(kind, [])
            if isinstance(definitions, dict):
                definitions = [definitions]
            require(all(not ({"test", "doctest", "harness", "required-features"} & set(t)) for t in definitions), "Custom harness selection requires review")
        descriptions = []
        for target in package["targets"]:
            description = target_description(package, target, root)
            key = digest(description)
            require(key not in seen, "Duplicate workspace target")
            seen.add(key)
            selected = suite == "default" or description["library"]
            descriptions.append({**description, "selected": selected})
            if selected:
                targets[key] = {"description": description, "package_id": package["id"],
                                "manifest": relative(manifest_path, root)}
        inventory.append({"name": package["name"], "manifest": relative(manifest_path, root),
                          "lanes": lanes_for(package["name"]), "targets": sorted(descriptions, key=lambda t: digest(t))})
    return sorted(inventory, key=lambda p: p["name"]), targets


def read_metadata(root):
    return decode(capture(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], root))


def refuse_runner_overrides(root, env):
    require(not env.get("CARGO_BUILD_TARGET"), "Custom Cargo build target requires review")
    require(not any(value for key, value in env.items() if key.startswith("CARGO_TARGET_") and key.endswith("_RUNNER")), "Existing Cargo runner requires review")
    directories = [root, *root.parents]
    config_dirs = [directory / ".cargo" for directory in directories]
    config_dirs.append(Path(env.get("CARGO_HOME", Path.home() / ".cargo")))
    for directory in set(config_dirs):
        for name in ("config", "config.toml"):
            path = directory / name
            if not path.exists():
                continue
            config = tomllib.loads(path.read_text(encoding="utf-8"))
            require("include" not in config, "Included Cargo configuration requires review")
            require("target" not in config.get("build", {}), "Configured Cargo build target requires review")
            require(all("runner" not in value for value in config.get("target", {}).values()), "Configured Cargo runner requires review")
            require(not any(key == "CARGO_BUILD_TARGET" or (key.startswith("CARGO_TARGET_") and key.endswith("_RUNNER"))
                            for key in config.get("env", {})), "Configured Cargo runner environment requires review")


def artifacts_from_output(output, metadata, targets, root):
    artifacts, finished = {}, 0
    packages = {p["id"]: p for p in metadata["packages"]}
    for line in output.splitlines():
        record = decode(line)
        if record.get("reason") == "build-finished":
            require(record.get("success") is True, "Cargo build failed")
            finished += 1
        if record.get("reason") != "compiler-artifact" or record.get("profile", {}).get("test") is not True:
            continue
        require(record.get("package_id") in packages, "Unknown test artifact package")
        description = target_description(packages[record["package_id"]], record["target"], root)
        key = digest(description)
        require(key in targets and key not in artifacts, "Unexpected or duplicate test artifact")
        require(record.get("executable"), "Test artifact has no executable")
        executable = Path(record["executable"])
        require(executable.is_file() and not executable.is_symlink() and os.access(executable, os.X_OK), "Invalid test executable")
        executable.resolve().relative_to(Path(metadata["target_directory"]).resolve())
        features = record["features"]
        require(isinstance(features, list) and all(isinstance(f, str) for f in features) and len(features) == len(set(features)), "Invalid artifact features")
        artifacts[key] = {**targets[key], "executable": str(executable.resolve()), "features": sorted(features)}
    require(finished == 1 and set(artifacts) == set(targets), "Missing complete Cargo artifact inventory")
    require(len({a["executable"] for a in artifacts.values()}) == len(artifacts), "Executable assigned to multiple targets")
    return artifacts


def listed_tests(output):
    names = []
    summaries = []
    for line in output.splitlines():
        if line.endswith(": test"):
            names.append(line[:-6])
        elif line:
            match = re.fullmatch(r"([0-9]+) tests?, 0 benchmarks", line)
            require(match is not None, "Unsupported libtest listing")
            summaries.append(int(match[1]))
    require(summaries == [len(names)] and len(names) == len(set(names)) and all(names), "Invalid libtest inventory")
    return sorted(names)


def passed_tests(output, expected):
    passed = re.findall(r"^test (.+) \.\.\. ok$", output, re.MULTILINE)
    summaries = re.findall(r"^test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s$", output, re.MULTILINE)
    running = re.findall(r"^running ([0-9]+) tests?$", output, re.MULTILINE)
    require(sorted(passed) == expected and len(passed) == len(set(passed)), "Executed test identities differ from inventory")
    require(summaries == [str(len(expected))] and running == [str(len(expected))], "Missing or inconsistent libtest summary")
    return passed


def execute_harness(argv):
    # Cargo already supplied cwd, dynamic-library paths and package/build-script
    # variables to this runner. Inherit them without reconstructing or replacing.
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding="utf-8")
    chunks, size = [], 0
    try:
        for line in process.stdout:
            size += len(line.encode())
            require(size <= MAX_OUTPUT, "Harness output exceeded its bound")
            print(line, end="", flush=True)
            chunks.append(line)
        require(process.wait() == 0, "PostgreSQL harness failed")
        return "".join(chunks)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process.stdout.close()


def dispatch(argv):
    state = read_json(Path(os.environ[STATE_ENV]))
    require(argv and argv[1:] == state["arguments"], "Unexpected Cargo harness arguments")
    matches = [(key, item) for key, item in state["artifacts"].items() if item["executable"] == str(Path(argv[0]).resolve())]
    require(len(matches) == 1, "Cargo dispatched an unreported executable")
    key, artifact = matches[0]
    root = Path(state["root"])
    require(Path.cwd().resolve() == (root / artifact["manifest"]).parent.resolve(), "Cargo package working directory changed")
    directory = Path(state["results"])
    with (directory / (key + ".started")).open("x", encoding="utf-8") as claim:
        claim.write("started\n")
    tests = listed_tests(capture([argv[0], *state["arguments"], "--list"], Path.cwd()))
    package = artifact["description"]["package"]
    assigned = assigned_tests(package, tests, state["lane"])
    owned = state["lane"] in lanes_for(package)
    executed = owned and (package != "zrotext-server" or bool(assigned))
    passed = []
    if executed:
        command = argv
        if package == "zrotext-server":
            # --exact also changes libtest's skip matching. Keep the unchanged
            # exclusions in both commands, and prove the exact OR-filter list
            # selects only the subset of the original full excluded inventory.
            selected = listed_tests(capture([argv[0], *server_arguments(state["arguments"], assigned, listing=True)], Path.cwd()))
            require(selected == assigned, "Native server filters differ from assigned test inventory")
            command = [argv[0], *server_arguments(state["arguments"], assigned)]
        passed = passed_tests(execute_harness(command), assigned)
    else:
        print("Inventoried target has no tests assigned to this PostgreSQL lane.", flush=True)
    result = {"description": artifact["description"], "features": artifact["features"],
              "tests": tests, "assigned": assigned, "executed": executed, "passed": sorted(passed)}
    with (directory / (key + ".json")).open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True)


def validate_records(records, targets, suite, lane):
    require(suite in SUITES and lane in LANES, "Unknown suite or lane")
    require(isinstance(records, dict) and set(records) == set(targets), "Missing or unexpected target receipt")
    total = 0
    for key, target in targets.items():
        item = records[key]
        require(set(item) == {"description", "features", "tests", "assigned", "executed", "passed"}, "Invalid target receipt schema")
        require(item["description"] == target["description"], "Wrong target receipt identity")
        tests, features = item["tests"], item["features"]
        require(isinstance(tests, list) and all(isinstance(t, str) and t and "\n" not in t for t in tests) and tests == sorted(set(tests)), "Invalid receipt test inventory")
        require(isinstance(features, list) and all(isinstance(f, str) for f in features) and features == sorted(set(features)), "Invalid receipt feature inventory")
        if target["description"]["package"] == "zrotext-server":
            require(("conversation-simulator-tests" in features) == (suite == "conversation"), "Wrong simulator feature selection")
        package = target["description"]["package"]
        assigned = assigned_tests(package, tests, lane)
        executed = lane in lanes_for(package) and (package != "zrotext-server" or bool(assigned))
        require(item["assigned"] == assigned, "Incorrect deterministic test assignment")
        require(type(item["executed"]) is bool and item["executed"] == executed, "Incorrect lane execution ownership")
        require(item["passed"] == assigned, "Incomplete or duplicate executed coverage")
        total += len(assigned)
    require(total > 0, "PostgreSQL lane executed zero tests")


def run_lane(root, suite, lane, receipt):
    require(lane in LANES, "Unknown lane")
    with receipt_destination(receipt) as destination:
        _run_lane(root, suite, lane, destination)


def _run_lane(root, suite, lane, destination):
    identity = source_identity(root)
    refuse_runner_overrides(root, os.environ)
    host = re.findall(r"^host: (.+)$", capture(["rustc", "-vV"], root), re.MULTILINE)
    require(host == ["x86_64-unknown-linux-gnu"], "Unsupported native runner host")
    metadata = read_metadata(root)
    inventory, targets = workspace_inventory(metadata, root, suite)
    output = capture([*cargo_tests(suite), "--no-run", "--message-format=json"], root)
    artifacts = artifacts_from_output(output, metadata, targets, root)
    with tempfile.TemporaryDirectory(prefix="ci-rust-postgresql-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        directory = Path(temporary)
        results = directory / "results"
        results.mkdir()
        arguments = [*selection(suite), "--format=pretty", "--color=never"]
        state = {"root": str(root), "suite": suite, "lane": lane, "artifacts": artifacts,
                 "arguments": arguments, "results": str(results)}
        state_path = directory / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        runner = json.dumps([sys.executable, str(Path(__file__).resolve()), "dispatch"])
        command = [*cargo_tests(suite), "--config", f"target.{host[0]}.runner={runner}", "--", *arguments]
        subprocess.run(command, cwd=root, env={**os.environ, STATE_ENV: str(state_path)}, check=True)
        require({p.name for p in results.iterdir()} == {key + suffix for key in targets for suffix in (".started", ".json")}, "Missing or duplicate Cargo runner dispatch")
        records = {key: read_json(results / (key + ".json")) for key in targets}
        validate_records(records, targets, suite, lane)
    # --no-run does not establish doctest execution. Keep the real, complete
    # Cargo command; do not infer coverage from compiled harness inventories.
    doctests = suite == "default" and lane == "remaining"
    if doctests:
        subprocess.run(doctest_command(), cwd=root, check=True)
    require(source_identity(root) == identity, "Workflow source changed during testing")
    result = {"version": 2, "source": identity, "suite": suite, "lane": lane,
              "workspace": inventory, "records": records, "doctests": doctests}
    result["inventory_digest"] = digest({"workspace": inventory, "targets": {
        key: {k: v for k, v in item.items() if k not in ("assigned", "executed", "passed")}
        for key, item in records.items()}})
    write_receipt(destination, result)
    print(f"Verified PostgreSQL lane: {lane}")


def prerequisite_status(suite, needs):
    expected = {"changes", "rust-workspace", "rust-postgresql"} if suite == "default" else {"conversation-workspace", "conversation-postgresql-lanes"}
    require(set(needs) == expected, "Missing or unexpected prerequisite")
    require(all(item.get("result") == "success" for item in needs.values()), "Prerequisite did not succeed")
    if suite == "default":
        decision = needs["changes"].get("outputs", {}).get("rust")
        require(decision in ("true", "false"), "Missing or invalid change-filter decision")
        return decision == "true"
    return True


def verify_receipts(receipts, suite, identity, inventory, targets):
    require(len(receipts) == len(LANES), "Missing or additional lane receipt")
    require({r.get("lane") for r in receipts} == set(LANES), "Missing or duplicate lane receipt")
    inventories = set()
    for receipt in receipts:
        require(set(receipt) == {"version", "source", "suite", "lane", "workspace", "records", "doctests", "inventory_digest"}, "Invalid coverage receipt schema")
        require(type(receipt["version"]) is int and receipt["version"] == 2, "Unsupported receipt version")
        require(receipt["source"] == identity and receipt["suite"] == suite, "Foreign workflow coverage receipt")
        require(receipt["workspace"] == inventory, "Dropped or changed workspace package/target")
        validate_records(receipt["records"], targets, suite, receipt["lane"])
        require(type(receipt["doctests"]) is bool and receipt["doctests"] == (suite == "default" and receipt["lane"] == "remaining"), "Missing or misplaced default doctest gate")
        actual = digest({"workspace": inventory, "targets": {
            key: {k: v for k, v in item.items() if k not in ("assigned", "executed", "passed")}
            for key, item in receipt["records"].items()}})
        require(receipt["inventory_digest"] == actual, "Altered coverage inventory digest")
        inventories.add(actual)
    require(len(inventories) == 1, "Lanes did not inventory identical features and tests")
    for key in targets:
        passed = [name for receipt in receipts for name in receipt["records"][key]["passed"]]
        require(len(passed) == len(set(passed)) and sorted(passed) == receipts[0]["records"][key]["tests"],
                "Lane execution is not a disjoint complete union of the target inventory")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "dispatch":
        dispatch(sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "status", "verify"))
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--lane", choices=LANES)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--receipts", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.operation == "run":
        require(args.lane is not None and args.receipt is not None, "Missing lane or receipt destination")
        run_lane(root, args.suite, args.lane, args.receipt)
    elif args.operation == "status":
        enabled = prerequisite_status(args.suite, decode(os.environ["CI_NEEDS_JSON"]))
        print("run=" + str(enabled).lower())
    else:
        require(prerequisite_status(args.suite, decode(os.environ["CI_NEEDS_JSON"])), "Verification requested for a no-op change")
        require(args.receipts is not None, "Missing receipt directory")
        files = list(args.receipts.glob("**/*"))
        require(all(not p.is_symlink() and (p.is_dir() or (p.is_file() and p.name == "coverage.json")) for p in files), "Unexpected coverage artifact content")
        receipts = [read_json(p) for p in files if p.is_file()]
        inventory, targets = workspace_inventory(read_metadata(root), root, args.suite)
        verify_receipts(receipts, args.suite, source_identity(root), inventory, targets)
        print("Every PostgreSQL lane and current workspace target is accounted for.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"PostgreSQL CI coverage refused: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
