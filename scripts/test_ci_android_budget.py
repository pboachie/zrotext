# SPDX-License-Identifier: AGPL-3.0-only
"""The full Android gate needs a bounded cold-build and isolated-JVM budget."""

from pathlib import Path
import re
import shlex
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
        commands = re.findall(r"^        run: (\./gradlew .+)$", self.job, re.MULTILINE)
        self.assertEqual(len(commands), 1)
        self.assertEqual(shlex.split(commands[0]), [
            "./gradlew", ":app:lintDebug", ":app:testDebugUnitTest",
            ":app:assembleDebug", ":app:assembleDebugAndroidTest", "--no-daemon",
        ])
        self.assertNotRegex(self.job, r"(?m)^\s*continue-on-error:")

    def test_jvm_isolation_and_strict_dependency_verification_remain_enabled(self):
        app = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
        properties = (ROOT / "android/gradle.properties").read_text(encoding="utf-8")
        self.assertRegex(app, r"(?m)^\s*it\.forkEvery = 1\s*$")
        self.assertNotRegex(app, r"\bignoreFailures\s*=\s*true\b")
        self.assertRegex(properties, r"(?m)^org\.gradle\.dependency\.verification=strict\s*$")


if __name__ == "__main__":
    unittest.main()
