# SPDX-License-Identifier: AGPL-3.0-only
"""The full Android gate needs a bounded cold-build and isolated-JVM budget."""

from pathlib import Path
import os
import re
import shutil
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AndroidCiBudgetTests(unittest.TestCase):
    def setUp(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        match = re.search(
            r"^  android:\n([\s\S]*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
            workflow.split("\njobs:\n", 1)[1], re.MULTILINE,
        )
        self.assertIsNotNone(match)
        self.job = match.group(1)

    def test_cold_build_and_isolated_classes_have_the_reviewed_finite_budget(self):
        # Cold compilation plus one JVM per class can exceed the former 25 minutes.
        # Keep the reviewed cap explicit rather than silently accepting longer jobs.
        self.assertEqual(
            re.findall(r"^    timeout-minutes: (\d+)\s*$", self.job, re.MULTILINE),
            ["45"],
        )

    def test_all_four_gradle_gates_remain_mandatory_without_error_suppression(self):
        arguments = re.search(r"args=\(\n([\s\S]*?)\n\s*\)", self.job)
        self.assertIsNotNone(arguments)
        self.assertEqual(shlex.split(arguments.group(1)), [
            ":app:lintDebug", ":app:testDebugUnitTest",
            ":app:assembleDebug", ":app:assembleDebugAndroidTest",
            ":app:lintRelease", ":app:assembleRelease", ":app:cyclonedxDirectBom", ":verifyKspSerialization",
            ":app:kspDebugKotlin", "--rerun", ":app:kspReleaseKotlin", "--rerun",
            ":app:kspDebugUnitTestKotlin", "--rerun", ":app:kspDebugAndroidTestKotlin", "--rerun",
            "--init-script", "gradle/ksp-execution-trace.init.gradle",
            "--project-cache-dir", "$RUNNER_TEMP/ksp-project-cache",
            "--configuration-cache", "--configuration-cache-problems=fail",
            "--parallel", "--max-workers=4", "--no-build-cache", "--no-daemon", "--console=plain",
            "-PzrotextSourceCommit=$source_commit",
        ])
        self.assertEqual(self.job.count('./gradlew "${args[@]}"'), 1)
        narrow = re.search(r"ksp_args=\(\n([\s\S]*?)\n\s*\)", self.job)
        self.assertIsNotNone(narrow)
        self.assertEqual(shlex.split(narrow.group(1)), shlex.split(arguments.group(1))[8:])
        self.assertEqual(self.job.count('./gradlew "$@"'), 2)
        self.assertIn('set -euo pipefail', self.job)
        self.assertIn('export GRADLE_USER_HOME="$RUNNER_TEMP/ksp-gradle-home"', self.job)
        self.assertIn('mkdir "$GRADLE_USER_HOME" "$RUNNER_TEMP/ksp-project-cache" "$RUNNER_TEMP/ksp-qualification"', self.job)
        self.assertIn('source_commit="$(git rev-parse HEAD)"', self.job)
        self.assertIn('test "$source_commit" = "$GITHUB_SHA"', self.job)
        self.assertIn('python3 tools/ksp_execution_trace.py verify', self.job)
        self.assertNotIn('--cold-log', self.job)
        self.assertNotIn('--reuse-log', self.job)
        self.assertNotRegex(self.job, r"(?m)^\s*continue-on-error:")

    def shared_phase_body(self, job):
        command = re.search(
            r"^\s*timeout (\d+)m bash -euo pipefail -c '\n([\s\S]*?)\n"
            r'\s*\' _ "\$\{ksp_args\[@\]\}"$', job, re.MULTILINE)
        self.assertIsNotNone(command)
        self.assertEqual(command.group(1), "5")
        return command.group(2)

    def assert_shared_budget(self, job):
        self.assertEqual(re.findall(r"^\s*timeout (\d+)m ", job, re.MULTILINE), ["38", "5"])
        phases = [int(value) for value in re.findall(r"^\s*timeout (\d+)m ", job, re.MULTILINE)]
        self.assertEqual(sum(phases), 43)
        job_caps = re.findall(r"^    timeout-minutes: (\d+)\s*$", job, re.MULTILINE)
        self.assertEqual(job_caps, ["45"])
        self.assertEqual(int(job_caps[0]) - sum(phases), 2)
        self.assertIn('timeout 38m ./gradlew "${args[@]}" 2>&1 | tee -a '
                      '"$RUNNER_TEMP/ksp-qualification/cold.log"', job)
        body = self.shared_phase_body(job)
        self.assertEqual([line.strip() for line in body.splitlines()], [
            'printf "%s\\n" "ZROTEXT_KSP_PASS store" > "$RUNNER_TEMP/ksp-qualification/ksp-store.log"',
            './gradlew "$@" 2>&1 | tee -a "$RUNNER_TEMP/ksp-qualification/ksp-store.log"',
            'printf "%s\\n" "ZROTEXT_KSP_PASS reuse" > "$RUNNER_TEMP/ksp-qualification/reuse.log"',
            './gradlew "$@" 2>&1 | tee -a "$RUNNER_TEMP/ksp-qualification/reuse.log"',
        ])

    def test_two_narrow_graphs_share_one_deadline_within_the_unchanged_job_budget(self):
        self.assert_shared_budget(self.job)
        self.assertIn("printf '%s\\n' 'ZROTEXT_KSP_PASS full' > "
                      '"$RUNNER_TEMP/ksp-qualification/cold.log"', self.job)

    def test_budget_guard_rejects_unbounded_individual_or_expanded_phase_limits(self):
        changes = [
            self.job.replace("timeout 5m bash", "bash"),
            self.job.replace("timeout 5m bash", "timeout 6m bash"),
            self.job.replace('            ./gradlew "$@"', '            timeout 5m ./gradlew "$@"'),
            self.job.replace("timeout-minutes: 45", "timeout-minutes: 46"),
        ]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(AssertionError):
                self.assert_shared_budget(changed)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash") and shutil.which("timeout"),
                         "The CI shell lifecycle is exercised natively on Linux")
    def test_shared_shell_phase_preserves_arguments_receipts_and_failure_status(self):
        body = self.shared_phase_body(self.job)
        for failed_call in (0, 1, 2):
            with self.subTest(failed_call=failed_call), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                logs = root / "ksp-qualification"
                logs.mkdir()
                wrapper = root / "gradlew"
                wrapper.write_text("""#!/bin/sh
set -eu
count=1
if test -f "$RUNNER_TEMP/calls"; then count=2; fi
printf '%s\\n' "$count" >> "$RUNNER_TEMP/calls"
printf '%s\\n' "$@" > "$RUNNER_TEMP/args-$count"
echo "synthetic invocation $count"
if test "$FAIL_CALL" = "$count"; then exit 17; fi
""")
                wrapper.chmod(0o700)
                arguments = [":app:kspDebugKotlin", "--rerun", "argument with spaces"]
                result = subprocess.run(
                    ["timeout", "5s", "bash", "-euo", "pipefail", "-c", body, "_", *arguments],
                    cwd=root, env=dict(os.environ, RUNNER_TEMP=str(root), FAIL_CALL=str(failed_call)),
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                self.assertEqual(result.returncode, 17 if failed_call else 0, result.stdout)
                self.assertEqual((root / "args-1").read_text().splitlines(), arguments)
                self.assertEqual((logs / "ksp-store.log").read_text().splitlines(),
                                 ["ZROTEXT_KSP_PASS store", "synthetic invocation 1"])
                if failed_call == 1:
                    self.assertFalse((logs / "reuse.log").exists())
                    self.assertEqual((root / "calls").read_text().splitlines(), ["1"])
                else:
                    self.assertEqual((root / "args-2").read_text().splitlines(), arguments)
                    self.assertEqual((logs / "reuse.log").read_text().splitlines(),
                                     ["ZROTEXT_KSP_PASS reuse", "synthetic invocation 2"])
                    self.assertEqual((root / "calls").read_text().splitlines(), ["1", "2"])

    def test_jvm_isolation_and_strict_dependency_verification_remain_enabled(self):
        app = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
        properties = (ROOT / "android/gradle.properties").read_text(encoding="utf-8")
        self.assertRegex(app, r"(?m)^\s*it\.forkEvery = 1\s*$")
        self.assertNotRegex(app, r"\bignoreFailures\s*=\s*true\b")
        self.assertRegex(properties, r"(?m)^org\.gradle\.dependency\.verification=strict\s*$")


if __name__ == "__main__":
    unittest.main()
