#!/usr/bin/env python3
"""Validate the machine-readable device-compatibility matrix.

The matrix in docs/device-compatibility.json is the supported-device list.
This script re-checks it against android/app/build.gradle.kts, the repository
tree, and docs/DEVICE-COMPATIBILITY.md so the list cannot silently drift from
the evidence that backs it. It verifies recorded claims and referenced paths
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

SCHEMA_VERSION = 1
STATUSES = ("supported", "partial", "excluded", "unevaluated")
SIM_TYPES = ("physical", "esim", "none", "unknown")
EVIDENCE_LEVELS = ("physical", "emulator", "device-sim", "none")
TOP_LEVEL_KEYS = {
    "schema_version",
    "note",
    "statuses",
    "sim_types",
    "evidence_levels",
    "devices",
}
DEVICE_KEYS = {"id", "name", "api", "sim", "status", "evidence", "tests", "notes", "source"}
API_KEYS = {"min", "max"}
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
HEADING_PATTERN = re.compile(r"^#{1,6} (.+)$")


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
    devices = matrix["devices"]
    status_counts = {status: sum(1 for d in devices if d.get("status") == status) for status in STATUSES}
    evidence_counts = {
        level: sum(1 for d in devices if d.get("evidence") == level) for level in EVIDENCE_LEVELS
    }
    print(
        f"{args.matrix.name}: {len(devices)} device classes, "
        + ", ".join(f"{status_counts[status]} {status}" for status in STATUSES)
        + "; evidence: "
        + ", ".join(f"{evidence_counts[level]} {level}" for level in EVIDENCE_LEVELS)
        + f"; app bounds API {min_sdk}..{target_sdk}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
