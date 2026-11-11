"""Fast wiring checks plus an offline, executable Gradle concurrency regression.

The explicit Android CI verification task invokes --integration through the pinned wrapper.
Ordinary unittest discovery does not download or start Gradle.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

import ksp_execution_trace


ANDROID = Path(__file__).resolve().parents[1]
BUILD = ANDROID / "build.gradle.kts"
BEGIN = "// BEGIN KSP execution gate"
END = "// END KSP execution gate."


def gate_source():
    source = BUILD.read_text(encoding="utf-8")
    return source[source.index(BEGIN):source.index(END) + len(END)]


class WiringTests(unittest.TestCase):
    def test_guard_is_typed_and_build_wide(self):
        guard = gate_source()
        self.assertIn("allprojects {", guard)
        self.assertIn("tasks.withType<KspAATask>().configureEach", guard)
        self.assertIn("usesService(kspExecutionGate)", guard)
        self.assertIn("maxParallelUsages.set(1)", guard)

    def test_full_ci_explicitly_runs_regression_without_changing_other_test_graphs(self):
        source = BUILD.read_text(encoding="utf-8")
        self.assertNotIn('tasks.withType<Test>()', source)
        self.assertNotIn('dependsOn(verifyKspSerialization)', source)
        self.assertIn('tasks.register<Exec>("verifyKspSerialization")', source)
        self.assertIn('"--integration")', source)
        self.assertNotIn('--gradle-home', source)
        workflow = (ANDROID.parent / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        full = re.search(r"^          args=\(\n([\s\S]*?)^          \)", workflow, re.MULTILINE)
        narrow = re.search(r"^          ksp_args=\(\n([\s\S]*?)^          \)", workflow, re.MULTILINE)
        self.assertIsNotNone(full)
        self.assertIsNotNone(narrow)
        self.assertIn(':verifyKspSerialization', full[1].split())
        self.assertNotIn(':verifyKspSerialization', narrow[1].split())


# A synthetic KSP-shaped task deliberately submits asynchronous no-isolation
# work, like the pinned KSP plugin. The task action does NOT await the worker.
# Each worker records its own interval; no shared logging lock can serialize it.
JAVA_TASK = r"""
package com.google.devtools.ksp.gradle;
import java.io.*;
import java.nio.file.*;
import javax.inject.Inject;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.*;
import org.gradle.workers.*;
public abstract class KspAATask extends DefaultTask {
    @OutputFile public abstract RegularFileProperty getReceipt();
    @Internal public abstract DirectoryProperty getTraceDir();
    @Input public abstract Property<String> getLabel();
    @Inject public abstract WorkerExecutor getWorkers();
    @TaskAction public void submit() {
        try {
            File receipt = getReceipt().get().getAsFile();
            receipt.getParentFile().mkdirs();
            Files.writeString(receipt.toPath(), "executed");
        } catch (IOException e) { throw new RuntimeException(e); }
        getWorkers().noIsolation().submit(Probe.class, p -> {
            p.getTraceDir().set(getTraceDir()); p.getLabel().set(getLabel());
        });
    }
    public interface Params extends WorkParameters {
        DirectoryProperty getTraceDir(); Property<String> getLabel();
    }
    public abstract static class Probe implements WorkAction<Params> {
        public void execute() {
            try {
                Path dir = getParameters().getTraceDir().get().getAsFile().toPath();
                Files.createDirectories(dir);
                String label = getParameters().getLabel().get();
                long start = System.nanoTime();
                Files.writeString(dir.resolve(label + ".start"), Long.toString(start));
                // Wait for an independent ordinary task: this is a positive
                // concurrency control, not a timing-only absence-of-overlap test.
                String peer = label.equals("ordinary") ? "first" : "ordinary";
                long deadline = System.nanoTime() + 15000000000L;
                while (!Files.exists(dir.resolve(peer + ".start")) &&
                       !(label.equals("ordinary") && Files.exists(dir.resolve("second.start")))) {
                    if (System.nanoTime() > deadline) throw new IllegalStateException("No concurrent peer");
                    Thread.sleep(20);
                }
                if (Files.exists(dir.resolve("require-ksp-overlap"))) {
                    while (!Files.exists(dir.resolve("first.start")) ||
                           !Files.exists(dir.resolve("second.start"))) {
                        if (System.nanoTime() > deadline) throw new IllegalStateException("No KSP overlap control");
                        Thread.sleep(20);
                    }
                }
                Thread.sleep(800);
                Files.writeString(dir.resolve(label + ".end"), Long.toString(System.nanoTime()));
            } catch (Exception e) { throw new RuntimeException(e); }
        }
    }
}
"""

JAVA_ORDINARY = r"""
package fixture;
import javax.inject.Inject;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.tasks.*;
import org.gradle.workers.WorkerExecutor;
import com.google.devtools.ksp.gradle.KspAATask;
public abstract class OrdinaryTask extends DefaultTask {
    @Internal public abstract DirectoryProperty getTraceDir();
    @Inject public abstract WorkerExecutor getWorkers();
    @TaskAction public void submit() {
        getWorkers().noIsolation().submit(KspAATask.Probe.class, p -> {
            p.getTraceDir().set(getTraceDir()); p.getLabel().set("ordinary");
        });
    }
}
"""


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def resolved_path(path):
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        raise AssertionError("Cannot resolve wrapper path") from None


def reparse_attributes(path):
    try:
        return getattr(path.lstat(), "st_file_attributes", 0)
    except (OSError, RuntimeError, ValueError):
        raise AssertionError("Cannot inspect wrapper path") from None


def reject_links(path, boundary):
    """Reject links/junctions within the selected cache or repository subtree."""
    require(path.is_absolute() and boundary.is_absolute(), "Invalid wrapper boundary")
    require(path.is_relative_to(boundary), "Wrapper path escapes its boundary")
    require(resolved_path(path).is_relative_to(resolved_path(boundary)), "Resolved wrapper path escapes its boundary")
    while True:
        require(not path.is_symlink() and not path.is_junction(), "Linked wrapper path refused")
        if path.exists():
            require(not reparse_attributes(path) &
                    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400), "Reparse wrapper path refused")
        if path == boundary:
            break
        path = path.parent


def wrapper_command():
    """Select only the repository wrapper, refusing an uninstalled distribution.

    Gradle PathAssembler hashes the distribution URL with MD5 and renders the
    positive integer in base 36. This is a cache key, NOT an integrity hash.
    Install's completed-cache fast path requires its .ok marker, one extracted
    directory and a launcher JAR. Check these before allowing wrapper startup.
    """
    executable = ANDROID / ("gradlew.bat" if os.name == "nt" else "gradlew")
    properties = ANDROID / "gradle/wrapper/gradle-wrapper.properties"
    for file in (executable, properties, ANDROID / "gradle/wrapper/gradle-wrapper.jar"):
        reject_links(file, ANDROID)
        require(file.is_file() and file.stat().st_size > 0, "Missing repository wrapper file")
    values = {}
    for line in properties.read_text(encoding="ascii").splitlines():
        if not line.strip() or line.lstrip().startswith(("#", "!")):
            continue
        key, separator, value = line.partition("=")
        require(separator and key not in values, "Ambiguous wrapper properties")
        values[key] = value.replace(r"\:", ":")
    url = values.get("distributionUrl", "")
    match = re.fullmatch(r"https://services\.gradle\.org/distributions/gradle-(\d+\.\d+(?:\.\d+)?)-bin\.zip", url)
    require(match is not None, "Unsupported pinned wrapper distribution")
    checksum = values.get("distributionSha256Sum", "")
    require(re.fullmatch(r"[0-9a-f]{64}", checksum), "Missing pinned wrapper checksum")
    require(all(values.get(key) == value for key, value in {
        "distributionBase": "GRADLE_USER_HOME", "distributionPath": "wrapper/dists",
        "zipStoreBase": "GRADLE_USER_HOME", "zipStorePath": "wrapper/dists",
    }.items()), "Unsupported wrapper cache layout")
    for key in ("JAVA_OPTS", "GRADLE_OPTS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        require(not re.search(r'''(?:^|\s|["'])-Dgradle\.user\.home(?:=|\s|$)''',
                              os.environ.get(key, "")), "Conflicting Gradle cache override")
    configured_home = os.environ.get("GRADLE_USER_HOME")
    require(configured_home is None or configured_home.strip(), "Empty Gradle user home")
    home = Path(configured_home) if configured_home is not None else Path.home() / ".gradle"
    require(home.is_absolute(), "Gradle user home must be absolute")
    require(home == resolved_path(home), "Gradle user home must be canonical")
    reject_links(home, Path(home.anchor))
    # Match Gradle's BigInteger(1, MD5(url)).toString(36).
    number = int.from_bytes(hashlib.md5(url.encode("utf-8"), usedforsecurity=False).digest(), "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 36)
        encoded = "0123456789abcdefghijklmnopqrstuvwxyz"[digit] + encoded
    archive_name = url.rsplit("/", 1)[1]
    cache = home / "wrapper/dists" / archive_name.removesuffix(".zip") / (encoded or "0")
    distribution = cache / ("gradle-" + match[1])
    marker = cache / (archive_name + ".ok")
    launcher = distribution / "lib" / ("gradle-launcher-" + match[1] + ".jar")
    for path in (cache, marker, distribution, launcher):
        reject_links(path, home)
    require(cache.is_dir() and marker.is_file(), "Pinned wrapper distribution is not already cached")
    require([item for item in cache.iterdir() if item.is_dir()] == [distribution],
            "Unexpected extracted wrapper distribution")
    require(launcher.is_file() and launcher.stat().st_size > 0, "Missing pinned Gradle launcher")
    archive = cache / archive_name
    reject_links(archive, home)
    if archive.exists():
        require(archive.is_file(), "Invalid cached wrapper archive")
        with archive.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == checksum,
                    "Cached wrapper archive checksum mismatch")
    return [str(executable), "--gradle-user-home", str(home)]


def run_fixture(root):
    return subprocess.run(
        wrapper_command() + [":first:probe", "--rerun", ":second:probe", "--rerun", ":ordinary:probe",
            "--init-script", str(ANDROID / "gradle/ksp-execution-trace.init.gradle"),
            "--parallel", "--max-workers=4", "--configuration-cache",
            "--configuration-cache-problems=fail", "--offline", "--no-daemon", "--console=plain"],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240,
    )


def integration():
    with tempfile.TemporaryDirectory(prefix="zrotext-ksp-gate-") as temp:
        root = Path(temp)
        write(root / "settings.gradle.kts", 'rootProject.name = "gate-fixture"\ninclude("first", "second", "ordinary")\n')
        write(root / "buildSrc/build.gradle.kts", 'plugins { `java-library` }\n')
        write(root / "buildSrc/src/main/java/com/google/devtools/ksp/gradle/KspAATask.java", JAVA_TASK)
        write(root / "buildSrc/src/main/java/fixture/OrdinaryTask.java", JAVA_ORDINARY)
        for name in ("first", "second", "ordinary"):
            (root / name).mkdir()
        imports = """import com.google.devtools.ksp.gradle.KspAATask
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters
"""
        tasks = r'''
subprojects {
    val processorClasspath = configurations.create("probeProcessorClasspath")
    dependencies.add(processorClasspath.name, files("synthetic-processor"))
    if (name == "ordinary") {
        tasks.register<fixture.OrdinaryTask>("probe") {
            traceDir.set(rootProject.layout.projectDirectory.dir("trace"))
        }
    } else {
        tasks.register<KspAATask>("probe") {
            traceDir.set(rootProject.layout.projectDirectory.dir("trace"))
            label.set(project.name)
            receipt.set(layout.buildDirectory.file("receipt"))
        }
    }
}
'''
        def run(guarded, reuse=False):
            trace = root / "trace"
            if trace.exists():
                for file in trace.iterdir():
                    file.unlink()
            if not reuse:
                write(root / "build.gradle.kts", imports + (gate_source() if guarded else "") + tasks)
            if not guarded:
                write(trace / "require-ksp-overlap", "")
            result = run_fixture(root)
            if result.returncode:
                raise AssertionError(result.stdout)
            expected = "Configuration cache entry reused" if reuse else "Configuration cache entry stored"
            require(expected in result.stdout, result.stdout)
            intervals = {name: tuple(int((trace / (name + suffix)).read_text())
                                    for suffix in (".start", ".end"))
                         for name in ("first", "second", "ordinary")}
            # Trace actions must surround the asynchronous WORK, not just the
            # submission action, and remain present on configuration-cache reuse.
            for name in ("first", "second"):
                observations = {}
                for line in result.stdout.splitlines():
                    if not line.startswith("ZROTEXT_KSP_TRACE "):
                        continue
                    event = json.loads(line.removeprefix("ZROTEXT_KSP_TRACE "))
                    if event["task"] == f":{name}:probe" and event["event"] != "config":
                        require(event["event"] not in observations, result.stdout)
                        observations[event["event"]] = event["nano"]
                require(set(observations) == {"start", "end"}, result.stdout)
                require(observations["start"] <= intervals[name][0] <
                        intervals[name][1] <= observations["end"], result.stdout)
            return intervals, result.stdout

        def overlap(a, b):
            return max(a[0], b[0]) < min(a[1], b[1])

        logs = []
        for reused in (False, True):
            intervals, log = run(True, reused)
            logs.append(log)
            require(not overlap(intervals["first"], intervals["second"]), intervals)
            require(any(overlap(intervals[ksp], intervals["ordinary"])
                        for ksp in ("first", "second")), intervals)
        # Mutation control: remove the exact production guard. The mutual
        # exclusion assertion above MUST fail with the same tasks and workers.
        intervals, mutation_log = run(False)
        require(overlap(intervals["first"], intervals["second"]), intervals)
        # Exercise the production parser on real console output, substituting
        # only this fixture's task identities for the production app inventory.
        identities = frozenset({":first:probe", ":second:probe"})
        with patch.multiple(ksp_execution_trace, TASKS=identities, REQUIRED_ACTIVE=identities):
            require(ksp_execution_trace.verify(*logs) == identities, logs)
            with unittest.TestCase().assertRaises(ValueError):
                ksp_execution_trace.parse(mutation_log, reused=False)
        print("KSP gate: cold/reused cache serialize workers; ordinary work and unguarded KSP overlap")


if __name__ == "__main__":
    if "--integration" in sys.argv:
        parser = argparse.ArgumentParser()
        parser.add_argument("--integration", action="store_true")
        args = parser.parse_args()
        integration()
    else:
        unittest.main()
