"""Fast wiring checks plus an offline, executable Gradle concurrency regression.

The Android JVM test lifecycle invokes --integration with its own distribution.
Ordinary unittest discovery does not download or start Gradle.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
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

    def test_existing_jvm_test_lifecycle_runs_executable_regression(self):
        source = BUILD.read_text(encoding="utf-8")
        self.assertIn('tasks.withType<Test>().configureEach', source)
        self.assertIn('dependsOn(verifyKspSerialization)', source)
        self.assertIn('"--integration", "--gradle-home"', source)


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


def integration(gradle_home):
    executable = Path(gradle_home) / "bin" / ("gradle.bat" if os.name == "nt" else "gradle")
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
            result = subprocess.run(
                [str(executable), ":first:probe", "--rerun", ":second:probe", "--rerun", ":ordinary:probe",
                 "--init-script", str(ANDROID / "gradle/ksp-execution-trace.init.gradle"),
                 "--parallel", "--max-workers=4", "--configuration-cache",
                 "--configuration-cache-problems=fail", "--offline", "--no-daemon", "--console=plain"],
                cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240,
            )
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
        parser.add_argument("--gradle-home", required=True)
        args = parser.parse_args()
        integration(args.gradle_home)
    else:
        unittest.main()
