# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed checks for real KSP work in cold and reused Gradle task graphs."""

import argparse
import json
import os
from pathlib import Path
import re
import stat


PREFIX = "ZROTEXT_KSP_TRACE "
TASKS = frozenset({
    ":app:kspDebugKotlin", ":app:kspReleaseKotlin",
    ":app:kspDebugUnitTestKotlin", ":app:kspDebugAndroidTestKotlin",
})
REQUIRED_ACTIVE = frozenset({":app:kspDebugKotlin", ":app:kspReleaseKotlin"})
MAX_LOG_BYTES = 64 * 1024 * 1024
LOG_DIRECTORY = "ksp-qualification"
LOG_FILENAMES = {"cold": "cold.log", "reuse": "reuse.log"}
OUTCOME = re.compile(r"^> Task (:[^\s]+)(?: ([A-Z-]+))?$")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate trace field")
        result[key] = value
    return result


def parse(text, reused, expected=None):
    """Return the configured active task set, rejecting incomplete evidence."""
    require("BUILD FAILED" not in text, "Gradle build failed")
    require(len(re.findall(r"^BUILD SUCCESSFUL in .+$", text, re.M)) == 1,
            "Missing or ambiguous successful build")
    stored = len(re.findall(r"^Configuration cache entry stored\.$", text, re.M))
    cached = len(re.findall(r"^Configuration cache entry reused\.$", text, re.M))
    require((stored, cached) == ((0, 1) if reused else (1, 0)),
            "Expected reused configuration cache" if reused else "Expected cold configuration cache")
    configuration = {}
    intervals = {}
    outcomes = {}
    for line in text.splitlines():
        if line.startswith(PREFIX.rstrip()):
            require(line.startswith(PREFIX), "Malformed trace prefix")
            try:
                record = json.loads(line[len(PREFIX):], object_pairs_hook=unique_object)
            except (ValueError, TypeError) as exc:
                raise ValueError("Malformed KSP trace") from exc
            require(isinstance(record, dict), "Trace must be an object")
            kind = record.get("event")
            task = record.get("task")
            require(isinstance(task, str) and task in TASKS, "Unexpected KSP task")
            if kind == "config":
                require(set(record) == {"event", "task", "processors", "gated"},
                        "Unexpected configuration fields")
                require(not reused, "Configuration ran instead of cache reuse")
                require(task not in configuration, "Duplicate task configuration")
                require(type(record["processors"]) is int and record["processors"] >= 0,
                        "Invalid processor count")
                require(record["gated"] is True, "KSP task lacks shared gate")
                configuration[task] = record["processors"] > 0
            else:
                require(kind in ("start", "end"), "Unknown trace event")
                require(set(record) == {"event", "task", "nano"}, "Unexpected interval fields")
                nano = record["nano"]
                require(type(nano) is int and -(2**63) <= nano < 2**63, "Invalid monotonic timestamp")
                events = intervals.setdefault(task, {})
                require(kind not in events, "Duplicate task interval event")
                events[kind] = nano
        elif line.startswith("> Task "):
            match = OUTCOME.fullmatch(line)
            if match and match[1] in TASKS:
                # Plain-console grouping can repeat the same header when a
                # task's output resumes. Execution receipts remain unique.
                if match[1] in outcomes:
                    require(outcomes[match[1]] == match[2], "Conflicting task outcomes")
                outcomes[match[1]] = match[2]
            elif ":ksp" in line:
                raise ValueError("Unrecognized KSP task outcome")
    if reused:
        require(expected is not None and REQUIRED_ACTIVE <= expected <= TASKS,
                "Missing cold-run inventory")
        active = frozenset(expected)
    else:
        require(set(configuration) == TASKS, "Incomplete KSP task inventory")
        active = frozenset(task for task, processing in configuration.items() if processing)
        require(REQUIRED_ACTIVE <= active, "Debug and release processors must execute")
    require(active <= set(intervals) <= TASKS, "Missing or unexpected KSP execution")
    require(set(outcomes) == TASKS, "Missing KSP task outcome")
    ordered = []
    for task in TASKS:
        if outcomes[task] in ("SKIPPED", "NO-SOURCE"):
            require(task not in active, "KSP task did not execute fresh work")
            require(task not in intervals, "Skipped task has execution receipts")
            continue
        require(outcomes[task] is None, "KSP task did not execute fresh work")
        # An explicitly inventoried zero-processor task may still execute a
        # no-op action. Validate its complete interval and shared-gate exclusion
        # exactly like a processing task; never count it as main processing.
        require(task in intervals, "Missing KSP execution interval")
        require(set(intervals[task]) == {"start", "end"}, "Incomplete KSP interval")
        start, end = intervals[task]["start"], intervals[task]["end"]
        require(start < end, "Invalid KSP execution interval")
        ordered.append((start, end))
    ordered.sort()
    for previous, current in zip(ordered, ordered[1:]):
        require(previous[1] <= current[0], "Concurrent KSP worker executions")
    return active


def not_link(info):
    return not stat.S_ISLNK(info.st_mode) and not (
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def regular_log(info):
    return not_link(info) and stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def checked_log_path(role):
    require(role in LOG_FILENAMES, "Unknown log role")
    # RUNNER_TEMP is the job's trusted temporary root, not a caller-selected
    # filename. The command-line interface accepts neither roots nor paths.
    location = os.environ.get("RUNNER_TEMP")
    require(bool(location), "Job temporary directory is required")
    root = Path(location)
    require(root.is_absolute(), "Job temporary directory must be absolute")
    root_info = root.lstat()
    require(not_link(root_info) and stat.S_ISDIR(root_info.st_mode), "Invalid job temporary directory")
    require(root.resolve(strict=True) == root, "Job temporary directory must be canonical")
    directory = root / LOG_DIRECTORY
    info = directory.lstat()
    require(not_link(info) and stat.S_ISDIR(info.st_mode), "Invalid log directory")
    resolved_directory = directory.resolve(strict=True)
    require(resolved_directory.parent == root and resolved_directory == directory,
            "Log directory escaped job temporary directory")
    path = directory / LOG_FILENAMES[role]
    before = path.lstat()
    require(regular_log(before), "Log must be a single-link regular file")
    resolved = path.resolve(strict=True)
    require(resolved.parent == directory and resolved == path, "Log escaped its directory")
    return path, before


def read_log(role):
    try:
        path, before = checked_log_path(role)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            require(regular_log(opened) and (opened.st_dev, opened.st_ino) ==
                    (before.st_dev, before.st_ino), "Log changed before opening")
            require(opened.st_size <= MAX_LOG_BYTES, "Log exceeds size limit")
            raw = stream.read(MAX_LOG_BYTES + 1)
            require(len(raw) <= MAX_LOG_BYTES, "Log exceeds size limit")
            after = os.fstat(stream.fileno())
            require(regular_log(after) and (after.st_size, after.st_mtime_ns) ==
                    (opened.st_size, opened.st_mtime_ns) and len(raw) == opened.st_size,
                    "Log changed while reading")
            named = path.lstat()
            require(regular_log(named) and (named.st_dev, named.st_ino) ==
                    (opened.st_dev, opened.st_ino), "Log name changed while reading")
        try:
            return raw.decode("utf-8", errors="strict").replace("\r\n", "\n")
        except UnicodeError:
            raise ValueError("Log must contain valid UTF-8") from None
    except OSError:
        raise ValueError("Cannot read job-local log") from None


def verify(cold, reuse):
    active = parse(cold, reused=False)
    parse(reuse, reused=True, expected=active)
    return active


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify")
    parser.parse_args()
    try:
        active = verify(read_log("cold"), read_log("reuse"))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"KSP execution qualification failed: {exc}\n")
    print(f"KSP execution qualification passed: {len(active)} active tasks serialized in both passes; "
          "configuration cache stored then reused")


if __name__ == "__main__":
    main()
