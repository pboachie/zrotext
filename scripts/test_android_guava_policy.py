# SPDX-License-Identifier: AGPL-3.0-only
"""Keep the full Guava library patched and outside the shipped application."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MINIMUM = (33, 7, 2)


def guava_locks(text):
    return [(version, set(configs.split(','))) for version, configs in
            re.findall(r'^com\.google\.guava:guava:([^=]+)=(.+)$', text, re.M)]


def patched(version):
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)-(?:jre|android)', version)
    return bool(match and tuple(map(int, match.groups())) >= MINIMUM)


class AndroidGuavaPolicyTests(unittest.TestCase):
    def test_version_floor_rejects_vulnerable_and_unknown_versions(self):
        for version in ('32.0.1-jre', '33.7.1-jre', '33.7.1-android',
                        '33.7.2-rc1', 'latest.release', '33.7.2'):
            self.assertFalse(patched(version), version)
        for version in ('33.7.2-jre', '33.7.2-android', '33.8.0-jre', '34.0.0-jre'):
            self.assertTrue(patched(version), version)

    def test_every_locked_full_guava_selection_is_patched_and_tool_only(self):
        selections = guava_locks((ROOT / 'android/app/gradle.lockfile').read_text())
        self.assertTrue(selections, 'Expected the build and test tool dependencies')
        for version, configs in selections:
            self.assertTrue(patched(version), version)
            for config in configs:
                self.assertTrue('UnitTest' in config or 'kspClasspath' in config or
                                'KotlinProcessorClasspath' in config or
                                config.startswith('_internal-unified-test-platform-') or
                                config == 'androidLintTool', config)

    def test_scoped_constraints_cover_every_locked_tool_configuration(self):
        source = (ROOT / 'android/app/build.gradle.kts').read_text()
        block = re.search(r'val guavaToolingConfigurations = setOf\((.*?)\n\)', source, re.S)
        self.assertIsNotNone(block)
        allowed = set(re.findall(r'"([^"\n]+)"', block.group(1)))
        selected = set().union(*(configs for _, configs in guava_locks(
            (ROOT / 'android/app/gradle.lockfile').read_text())))
        self.assertTrue(selected <= allowed, selected - allowed)
        self.assertIn('if (name in guavaToolingConfigurations)', source)
        self.assertIn('project.dependencies.constraints.add(name, "com.google.guava:guava:33.7.2-jre")', source)
        self.assertNotIn('resolutionStrategy.force', source)
        self.assertNotIn('releaseRuntimeClasspath', allowed)
        self.assertNotIn('debugRuntimeClasspath', allowed)

    def test_current_tool_closures_are_present_not_vacuously_patched(self):
        text = (ROOT / 'android/app/gradle.lockfile').read_text()
        selected = set().union(*(configs for _, configs in guava_locks(text)))
        expected = {
            '_agp_internal_debug_kspClasspath', '_agp_internal_release_kspClasspath',
            'androidLintTool', 'kspDebugKotlinProcessorClasspath',
            'kspReleaseKotlinProcessorClasspath',
            'debugUnitTestCompileClasspath', 'debugUnitTestRuntimeClasspath',
            'debugUnitTestLintChecksClasspath', 'releaseUnitTestCompileClasspath',
            'releaseUnitTestRuntimeClasspath', 'releaseUnitTestLintChecksClasspath',
        }
        self.assertTrue(expected <= selected, expected - selected)
        work_action = re.findall(
            r'^com\.android\.tools\.utp:gradle-work-action:[^=]+=([^\n]+)$', text, re.M)
        self.assertEqual(len(work_action), 1)
        self.assertIn('unified-test-platform-gradle-work-action', work_action[0].split(','))

    def test_buildscript_constraint_is_patched_without_global_force(self):
        source = (ROOT / 'android/build.gradle.kts').read_text()
        versions = re.findall(r'classpath\("com.google.guava:guava:([^"\n]+)"\)', source)
        self.assertEqual(len(versions), 1)
        self.assertTrue(patched(versions[0]))
        self.assertNotIn('resolutionStrategy.force', source)


if __name__ == '__main__':
    unittest.main()
