#!/usr/bin/env python3
"""Validate the machine-readable device-compatibility matrix.

The matrix in docs/device-compatibility.json is the supported-device list.
This script re-checks it against android/app/build.gradle.kts, the repository
tree, docs/DEVICE-COMPATIBILITY.md, and the CI no-radio allowlist in
scripts/android_device_smoke.py so the list cannot silently drift from the
evidence that backs it. It verifies recorded claims and referenced paths
only; it does not run any device, emulator, or simulator, and passing it says
nothing about hardware behavior. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "docs" / "device-compatibility.json"
DEFAULT_GRADLE = ROOT / "android" / "app" / "build.gradle.kts"
DEFAULT_DOC = ROOT / "docs" / "DEVICE-COMPATIBILITY.md"

SCHEMA_VERSION = 2
STATUSES = ("supported", "partial", "excluded", "unevaluated")
SIM_TYPES = ("physical", "esim", "none", "unknown")
EVIDENCE_LEVELS = ("physical", "emulator", "device-sim", "none")
RUN_KINDS = ("ci-job", "documented-command", "opt-in-radio")
NO_RADIO_RUN_KINDS = ("ci-job", "documented-command")
CI_EMULATOR_RUN_ID = "selected-device-tests"
SMOKE_SCRIPT = "scripts/android_device_smoke.py"
PROBE_TEST = "android/app/src/preparationProbeTest/java/org/zrotext/gateway/PreparationProbeDeviceTest.kt"
TOP_LEVEL_KEYS = {
    "schema_version",
    "note",
    "statuses",
    "sim_types",
    "evidence_levels",
    "repeatable_runs",
    "devices",
}
DEVICE_KEYS = {
    "id",
    "name",
    "api",
    "sim",
    "status",
    "evidence",
    "tests",
    "no_radio_run",
    "radio_run",
    "notes",
    "source",
}
RUN_COMMON_KEYS = {"id", "kind", "name", "notes"}
RUN_KIND_KEYS = {
    "ci-job": {"workflow", "job", "runs", "tests"},
    "documented-command": {"doc", "tests"},
    "opt-in-radio": {"doc", "tests"},
}
API_KEYS = {"min", "max"}
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
HEADING_PATTERN = re.compile(r"^#{1,6} (.+)$")
WORKFLOW_JOB_PATTERN = "  {job}:"


def parse_sdk_bounds(gradle_text: str) -> tuple[int, int]:
    """Return the (minSdk, targetSdk) pair from the app Gradle build file."""
    minimum = re.findall(r"\bminSdk\s*=\s*(\d+)\b", gradle_text)
    target = re.findall(r"\btargetSdk\s*=\s*(\d+)\b", gradle_text)
    if len(minimum) != 1 or len(target) != 1:
        raise ValueError("expected exactly one minSdk and one targetSdk assignment")
    return int(minimum[0]), int(target[0])


def _heading_title(line: str) -> str | None:
    match = HEADING_PATTERN.match(line.strip())
    return None if match is None else match.group(1).strip().lower()


def has_physical_section(doc_text: str) -> bool:
    """Return whether the doc still carries a 'Physical devices' section."""
    return any(_heading_title(line) == "physical devices" for line in doc_text.splitlines())


def physical_table_devices(doc_text: str) -> list[str]:
    """Return first-column device names from the 'Physical devices' table.

    A continuation row with an empty first column, the header row, and the
    alignment row contribute nothing. Only the model family before the first
    comma is kept, so qualifiers such as ', one active SIM' are dropped.
    """
    devices: list[str] = []
    in_section = False
    for line in doc_text.splitlines():
        title = _heading_title(line)
        if title is not None:
            in_section = title == "physical devices"
            continue
        stripped = line.strip()
        if not in_section or not stripped.startswith("|"):
            continue
        first = stripped.strip("|").split("|")[0].strip()
        if not first or first == "Device" or set(first) <= {"-", ":", " "}:
            continue
        devices.append(first.split(",")[0].strip())
    return devices


def _path_error(repo_root: Path, value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return "must be a non-empty string"
    if "\\" in value or value.startswith("/") or ".." in Path(value).parts:
        return f"must be a relative forward-slash repository path: {value!r}"
    if not (repo_root / value).is_file():
        return f"no such repository file: {value}"
    return None


def _workflow_job_error(repo_root: Path, workflow: object, job: object) -> str | None:
    """Return why a CI-job reference is invalid, or None if it holds.

    The workflow must live under .github/workflows/ and the job id must
    appear as a top-level job key in it, so a renamed job or workflow
    invalidates the matrix instead of silently unlinking it.
    """
    if not isinstance(workflow, str) or not workflow.startswith(".github/workflows/") \
            or not workflow.endswith(".yml"):
        return f"workflow must be a .github/workflows/*.yml path: {workflow!r}"
    path_error = _path_error(repo_root, workflow)
    if path_error:
        return f"workflow {path_error}"
    if not isinstance(job, str) or not ID_PATTERN.match(job or ""):
        return f"job must match {ID_PATTERN.pattern}"
    text = (repo_root / workflow).read_text(encoding="utf-8")
    if not re.search(rf"^{re.escape(WORKFLOW_JOB_PATTERN.format(job=job))}\s*$", text, re.MULTILINE):
        return f"the workflow {workflow} has no job named {job!r}"
    return None


def ci_emulator_allowlist(repo_root: Path) -> set[str]:
    """Map the CI smoke allowlist to repository test files.

    Imports scripts/android_device_smoke.py, the same module the
    selected-device-tests CI job executes, and maps each allowlisted
    instrumentation class to its source file. The preparation probe run by
    scripts/android_preparation_probe.py in the same job is included.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import android_device_smoke  # noqa: PLC0415 (local sibling of this script)
    finally:
        try:
            sys.path.remove(str(Path(__file__).resolve().parent))
        except ValueError:
            pass
    classes = android_device_smoke.selected_tests(root=repo_root)
    paths = {
        f"android/app/src/androidTest/java/org/zrotext/gateway/{name.split('.')[-1]}.kt"
        for name in classes
    }
    paths.add(PROBE_TEST)
    return paths


def _run_reference_error(repo_root: Path, run: object) -> str | None:
    """Return why a repeatable-run entry's references are invalid, or None."""
    if not isinstance(run, dict):
        return "each run must be an object"
    kind = run.get("kind")
    if kind not in RUN_KIND_KEYS:
        return None  # the kind itself is reported separately
    for reference in run.get("tests") if isinstance(run.get("tests"), list) else []:
        problem = _path_error(repo_root, reference)
        if problem:
            return f"tests entry {problem}"
    if kind == "ci-job":
        problem = _workflow_job_error(repo_root, run.get("workflow"), run.get("job"))
        if problem:
            return problem
        if "runs" in run:
            problem = _path_error(repo_root, run.get("runs"))
            if problem:
                return f"runs {problem}"
    else:
        doc = run.get("doc")
        problem = _path_error(repo_root, doc)
        if problem:
            return f"doc {problem}"
        # The documented procedure is the run; the id must appear in the doc
        # so the catalog and the procedure cannot drift apart silently.
        doc_text = (repo_root / doc).read_text(encoding="utf-8")
        if run.get("id") not in doc_text:
            return f"the doc {doc} does not mention the run id {run.get('id')!r}"
    return None


def _validate_runs(runs: object, *, repo_root: Path, errors: list[str]) -> dict:
    """Validate the repeatable-run catalog and return its id-to-entry index."""
    if not isinstance(runs, list) or not runs:
        errors.append("repeatable_runs must be a non-empty list")
        return {}
    run_index: dict[str, dict] = {}
    for index, run in enumerate(runs):
        label = f"repeatable_runs[{index}]"
        if not isinstance(run, dict):
            errors.append(f"{label} must be an object")
            continue
        run_id = run.get("id")
        if isinstance(run_id, str):
            label = f"run {run_id!r}"
        if not isinstance(run_id, str) or not ID_PATTERN.match(run_id or ""):
            errors.append(f"{label}: id must match {ID_PATTERN.pattern}")
        elif run_id in run_index:
            errors.append(f"{label}: duplicate id")
        else:
            run_index[run_id] = run
        kind = run.get("kind")
        if kind not in RUN_KIND_KEYS:
            errors.append(f"{label}: kind must be one of {list(RUN_KINDS)}")
            continue
        for missing in sorted(RUN_KIND_KEYS[kind] - set(run)):
            errors.append(f"{label}: missing key for kind {kind!r}: {missing}")
        for unexpected in sorted(set(run) - RUN_COMMON_KEYS - RUN_KIND_KEYS[kind]):
            errors.append(f"{label}: unexpected key for kind {kind!r}: {unexpected}")
        for field in ("name", "notes"):
            value = run.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{label}: {field} must be a non-empty string")
        tests = run.get("tests")
        if not isinstance(tests, list) or not tests:
            errors.append(f"{label}: tests must be a non-empty list")
        elif len(tests) != len(set(tests)):
            errors.append(f"{label}: tests must not repeat a reference")
        reference_error = _run_reference_error(repo_root, run)
        if reference_error:
            errors.append(f"{label}: {reference_error}")
    ci_run = run_index.get(CI_EMULATOR_RUN_ID)
    if ci_run is not None:
        try:
            allowlist = ci_emulator_allowlist(repo_root)
        except (ImportError, OSError) as error:
            errors.append(f"run {CI_EMULATOR_RUN_ID!r}: cannot read the CI allowlist: {error}")
        else:
            tests = ci_run.get("tests")
            if not isinstance(tests, list) or set(tests or []) != allowlist:
                errors.append(
                    f"run {CI_EMULATOR_RUN_ID!r}: tests must equal the exact no-radio "
                    f"allowlist executed by {SMOKE_SCRIPT} plus the preparation probe"
                )
    return run_index


def _validate_run_links(device: dict, *, run_index: dict, errors: list[str], label: str) -> None:
    """Validate a device's no_radio_run and radio_run linkage.

    The core rule of the supported-device list: a configuration recorded as
    supported or partial must link at least one repeatable no-radio run, and
    a run link is a re-verification procedure, never by itself a claim that
    it executed. Radio runs are opt-in instrumentation only and can never be
    a CI job, a SIM-less configuration, or virtual evidence.
    """
    status = device.get("status")
    evidence = device.get("evidence")
    no_radio = device.get("no_radio_run")
    if not isinstance(no_radio, list) or not all(isinstance(ref, str) for ref in no_radio):
        errors.append(f"{label}: no_radio_run must be a list of run ids")
        no_radio = None
    if no_radio is not None:
        if len(no_radio) != len(set(no_radio)):
            errors.append(f"{label}: no_radio_run must not repeat a reference")
        for ref in no_radio:
            run = run_index.get(ref)
            if run is None:
                errors.append(f"{label}: no_radio_run references an unknown run: {ref!r}")
            elif run.get("kind") not in NO_RADIO_RUN_KINDS:
                errors.append(
                    f"{label}: no_radio_run must not reference the opt-in radio run {ref!r}"
                )
        if isinstance(status, str):
            if status in ("supported", "partial") and not no_radio:
                errors.append(
                    f"{label}: the {status!r} status needs at least one repeatable "
                    "no-radio run reference"
                )
            if status in ("excluded", "unevaluated") and no_radio:
                errors.append(
                    f"{label}: the {status!r} status must not link a repeatable run"
                )
        tests = device.get("tests")
        if evidence in ("emulator", "device-sim") and isinstance(tests, list):
            union: set = set()
            for ref in no_radio:
                run = run_index.get(ref)
                if run is not None and isinstance(run.get("tests"), list):
                    union.update(run["tests"])
            if set(tests) != union:
                errors.append(
                    f"{label}: tests must equal the union of the tests executed by "
                    "the referenced no-radio runs"
                )
    radio = device.get("radio_run")
    if radio is not None:
        run = run_index.get(radio) if isinstance(radio, str) else None
        if not isinstance(radio, str) or run is None:
            errors.append(f"{label}: radio_run must be null or a defined run id")
        elif run.get("kind") != "opt-in-radio":
            errors.append(f"{label}: radio_run must reference an opt-in-radio run")
        if device.get("sim") == "none":
            errors.append(f"{label}: a SIM-less configuration has no radio run")
        if evidence in ("emulator", "device-sim"):
            errors.append(f"{label}: {evidence} evidence cannot claim a radio run")
        if isinstance(status, str) and status in ("excluded", "unevaluated"):
            errors.append(f"{label}: the {status!r} status must not claim a radio run")


def _api_error(device: dict, min_sdk: int, target_sdk: int) -> str | None:
    """Return why the entry's API claim is invalid, or None if it holds.

    Supported and partial device classes must sit inside the app's tested
    bounds [minSdk, targetSdk]. An excluded class that still records a range
    must sit outside those bounds, because exclusion is defined by them. The
    host simulator has no Android level at all.
    """
    api = device.get("api")
    status = device.get("status")
    if api is None:
        if status in ("supported", "partial") and device.get("evidence") != "device-sim":
            return "an API range is required for supported and partial devices"
        return None
    if not isinstance(api, dict) or set(api) != API_KEYS:
        return "api must be null or an object with exactly 'min' and 'max'"
    for bound in ("min", "max"):
        if not isinstance(api[bound], int) or isinstance(api[bound], bool):
            return f"api.{bound} must be an integer"
    if api["min"] > api["max"]:
        return "api.min must not exceed api.max"
    if status == "excluded":
        if api["max"] < min_sdk or api["min"] > target_sdk:
            return None
        return "an excluded device must sit outside the tested API bounds"
    if api["min"] < min_sdk or api["max"] > target_sdk:
        return (
            f"API range {api['min']}..{api['max']} falls outside the app bounds "
            f"{min_sdk}..{target_sdk} from android/app/build.gradle.kts"
        )
    return None


def validate(
    matrix: object,
    *,
    repo_root: Path,
    min_sdk: int,
    target_sdk: int,
    doc_text: str,
) -> list[str]:
    """Return human-readable problems; an empty list means the matrix is valid."""
    if not isinstance(matrix, dict):
        return ["the matrix must be a JSON object"]
    errors: list[str] = []
    keys = set(matrix)
    for missing in sorted(TOP_LEVEL_KEYS - keys):
        errors.append(f"missing top-level key: {missing}")
    for unexpected in sorted(keys - TOP_LEVEL_KEYS):
        errors.append(f"unexpected top-level key: {unexpected}")
    if errors:
        return errors
    if matrix["schema_version"] != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if not isinstance(matrix["note"], str) or not matrix["note"].strip():
        errors.append("note must be a non-empty string")
    for field, expected in (
        ("statuses", STATUSES),
        ("sim_types", SIM_TYPES),
        ("evidence_levels", EVIDENCE_LEVELS),
    ):
        value = matrix[field]
        if (
            not isinstance(value, list)
            or not all(isinstance(item, str) for item in value)
            or sorted(value) != sorted(expected)
        ):
            errors.append(f"{field} must be exactly {list(expected)}")
    devices = matrix["devices"]
    if not isinstance(devices, list) or not devices:
        errors.append("devices must be a non-empty list")
        return errors

    run_index = _validate_runs(matrix["repeatable_runs"], repo_root=repo_root, errors=errors)

    seen_ids: set[str] = set()
    for index, device in enumerate(devices):
        label = f"devices[{index}]"
        if not isinstance(device, dict):
            errors.append(f"{label} must be an object")
            continue
        device_id = device.get("id")
        if isinstance(device_id, str):
            label = f"device {device_id!r}"
        for missing in sorted(DEVICE_KEYS - set(device)):
            errors.append(f"{label}: missing key: {missing}")
        for unexpected in sorted(set(device) - DEVICE_KEYS):
            errors.append(f"{label}: unexpected key: {unexpected}")
        if not isinstance(device_id, str) or not ID_PATTERN.match(device_id or ""):
            errors.append(f"{label}: id must match {ID_PATTERN.pattern}")
        elif device_id in seen_ids:
            errors.append(f"{label}: duplicate id")
        else:
            seen_ids.add(device_id)
        for field in ("name", "notes"):
            value = device.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{label}: {field} must be a non-empty string")
        status = device.get("status")
        if status not in STATUSES:
            errors.append(f"{label}: status must be one of {list(STATUSES)}")
        if device.get("sim") not in SIM_TYPES:
            errors.append(f"{label}: sim must be one of {list(SIM_TYPES)}")
        evidence = device.get("evidence")
        if evidence not in EVIDENCE_LEVELS:
            errors.append(f"{label}: evidence must be one of {list(EVIDENCE_LEVELS)}")
        if isinstance(status, str) and isinstance(evidence, str):
            if (evidence == "none") != (status in ("excluded", "unevaluated")):
                errors.append(
                    f"{label}: evidence 'none' is required exactly for the "
                    "excluded and unevaluated statuses"
                )
            if evidence == "device-sim" and device.get("api") is not None:
                errors.append(f"{label}: device-sim evidence must not claim an API range")
            if evidence in ("emulator", "device-sim") and device.get("tests") == []:
                errors.append(
                    f"{label}: {evidence} evidence needs at least one repeatable "
                    "repository test reference"
                )
        api_error = _api_error(device, min_sdk, target_sdk)
        if api_error:
            errors.append(f"{label}: {api_error}")
        tests = device.get("tests")
        if not isinstance(tests, list):
            errors.append(f"{label}: tests must be a list")
        else:
            if len(tests) != len(set(tests)):
                errors.append(f"{label}: tests must not repeat a reference")
            for reference in tests:
                problem = _path_error(repo_root, reference)
                if problem:
                    errors.append(f"{label}: tests entry {problem}")
        _validate_run_links(device, run_index=run_index, errors=errors, label=label)
        source = device.get("source")
        source_problem = _path_error(repo_root, source)
        if source_problem:
            errors.append(f"{label}: source {source_problem}")
        elif evidence == "physical":
            if not isinstance(source, str) or not source.startswith("docs/") or not source.endswith(".md"):
                errors.append(f"{label}: physical evidence must cite a docs/*.md record")
            elif not isinstance(device.get("name"), str):
                pass
            elif device["name"] not in (repo_root / source).read_text(encoding="utf-8"):
                errors.append(
                    f"{label}: the physical record {source} does not mention the device name"
                )

    physical = [
        device
        for device in devices
        if isinstance(device, dict) and device.get("evidence") == "physical"
    ]
    if physical and not has_physical_section(doc_text):
        errors.append(
            "docs/DEVICE-COMPATIBILITY.md lost its 'Physical devices' section "
            "while the matrix still claims physical evidence"
        )
    physical_names = {
        device["name"] for device in physical if isinstance(device.get("name"), str)
    }
    for name in physical_table_devices(doc_text):
        if name not in physical_names:
            errors.append(
                f"a device recorded in the 'Physical devices' table is missing from "
                f"the matrix: {name!r}"
            )
    for device in physical:
        name = device.get("name")
        if isinstance(name, str) and name not in doc_text:
            errors.append(
                f"device {device.get('id')!r}: physical evidence is not recorded in "
                "docs/DEVICE-COMPATIBILITY.md"
            )
    for device in devices:
        if isinstance(device, dict) and device.get("status") == "excluded":
            name = device.get("name")
            if isinstance(name, str) and name in doc_text:
                errors.append(
                    f"device {device.get('id')!r} is excluded but still named in "
                    "docs/DEVICE-COMPATIBILITY.md"
                )
    if not re.search(rf"API {min_sdk}\)? or later", doc_text):
        errors.append(
            f"docs/DEVICE-COMPATIBILITY.md must state the gateway floor as "
            f"API {min_sdk} or later, matching the Gradle minSdk"
        )
    if "device-compatibility.json" not in doc_text:
        errors.append(
            "docs/DEVICE-COMPATIBILITY.md must reference docs/device-compatibility.json"
        )
    if CI_EMULATOR_RUN_ID not in doc_text:
        errors.append(
            "docs/DEVICE-COMPATIBILITY.md must name the "
            f"{CI_EMULATOR_RUN_ID} CI run that backs the repeatable no-radio linkage"
        )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the device-compatibility matrix.")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--gradle", type=Path, default=DEFAULT_GRADLE)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    args = parser.parse_args(argv)
    try:
        matrix = json.loads(args.matrix.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"cannot read the matrix {args.matrix}: {error}", file=sys.stderr)
        return 1
    try:
        min_sdk, target_sdk = parse_sdk_bounds(args.gradle.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"cannot read the Gradle bounds from {args.gradle}: {error}", file=sys.stderr)
        return 1
    try:
        doc_text = args.doc.read_text(encoding="utf-8")
    except OSError as error:
        print(f"cannot read {args.doc}: {error}", file=sys.stderr)
        return 1
    errors = validate(
        matrix,
        repo_root=ROOT,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        doc_text=doc_text,
    )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"{args.matrix}: {len(errors)} problem(s)", file=sys.stderr)
        return 1
    devices = matrix["devices"] if isinstance(matrix.get("devices"), list) else []
    runs = matrix["repeatable_runs"] if isinstance(matrix.get("repeatable_runs"), list) else []
    status_counts = {status: sum(1 for d in devices if d.get("status") == status) for status in STATUSES}
    evidence_counts = {
        level: sum(1 for d in devices if d.get("evidence") == level) for level in EVIDENCE_LEVELS
    }
    run_counts = {kind: sum(1 for r in runs if isinstance(r, dict) and r.get("kind") == kind) for kind in RUN_KINDS}
    print(
        f"{args.matrix.name}: {len(devices)} device classes, "
        + ", ".join(f"{status_counts[status]} {status}" for status in STATUSES)
        + "; evidence: "
        + ", ".join(f"{evidence_counts[level]} {level}" for level in EVIDENCE_LEVELS)
        + "; repeatable runs: "
        + ", ".join(f"{run_counts[kind]} {kind}" for kind in RUN_KINDS)
        + f"; app bounds API {min_sdk}..{target_sdk}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
