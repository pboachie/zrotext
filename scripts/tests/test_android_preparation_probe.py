# SPDX-License-Identifier: AGPL-3.0-only
import sys
from pathlib import Path
import unittest
from unittest import mock
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_preparation_probe as probe


def manifest(test=False):
    package = probe.TEST_APP if test else probe.APP
    instrumentation = (f'<instrumentation android:name="{probe.RUNNER}" '
                       f'android:targetPackage="{probe.APP}" />') if test else ""
    return (f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}">'
            '<uses-sdk android:minSdkVersion="28" />'
            '<application android:name="android.app.Application" android:allowBackup="false" '
            f'android:testOnly="true" />{instrumentation}</manifest>')


def fake_sdk(root):
    for directory, name in probe.TOOLS.values():
        tool = Path(root) / directory / name
        tool.parent.mkdir(parents=True, exist_ok=True)
        tool.write_bytes(b'')


class PreparationProbeTest(unittest.TestCase):
    def test_serial_must_be_a_plain_adb_identifier(self):
        for good in ['emulator-5562', 'synthetic-device', 'ABCDEF0123456789', 'localhost:5555', 'adb-X1.local']:
            self.assertEqual(good, probe.validated_serial(good))
        for bad in ['', '-s', '--install', 'emulator-5562 extra', 'a;reboot', 'a&&reboot', '$(reboot)',
                    'a|b', 'serial\n', 'a/b', 'a\\b', '"quoted"', 'x' * 65, 5562]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.validated_serial(bad)

    def test_sdk_must_be_absolute_existing_and_contain_every_fixed_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            for bad in [None, '', 'relative/sdk', str(Path(temporary) / 'absent')]:
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    probe.tool_environment(bad, base={})
            with self.assertRaises(ValueError):
                probe.tool_environment(temporary, base={})
            fake_sdk(temporary)
            for directory, name in probe.TOOLS.values():
                missing = Path(temporary) / directory / name
                missing.unlink()
                with self.subTest(missing=name), self.assertRaises(ValueError):
                    probe.tool_environment(temporary, base={})
                missing.write_bytes(b'')
            environment = probe.tool_environment(temporary, 'emulator-5562',
                                                 base={'PATH': 'inherited', 'ANDROID_SERIAL': 'stale'})
            self.assertEqual('emulator-5562', environment['ANDROID_SERIAL'])
            path = environment['PATH'].split(probe.os.pathsep)
            self.assertEqual([str(Path(temporary) / d) for d, _ in probe.TOOLS.values()] + ['inherited'], path)
            self.assertNotIn('ANDROID_SERIAL', probe.tool_environment(temporary, base={'ANDROID_SERIAL': 'stale'}))
            with self.assertRaises(ValueError):
                probe.tool_environment(temporary, 'bad serial', base={})

    def test_unsafe_serial_or_sdk_stops_before_any_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_sdk(temporary)
            for serial, sdk in [('a;reboot', temporary), ('-s', temporary), ('emulator-5562', 'relative')]:
                with self.subTest(serial=serial, sdk=sdk), \
                        mock.patch.dict(probe.os.environ, {'ANDROID_HOME': sdk}), \
                        mock.patch.object(sys, 'argv', ['probe', '--serial', serial]), \
                        mock.patch.object(probe.subprocess, 'run') as command, mock.patch('sys.stderr'):
                    with self.assertRaises(SystemExit):
                        probe.main()
                    command.assert_not_called()

    def test_physical_execution_requires_reviewed_hashes_before_any_subprocess(self):
        with mock.patch.object(sys, 'argv', ['probe', '--serial', 'synthetic-device', '--allow-physical']), \
                mock.patch.object(probe.subprocess, 'run') as command, mock.patch('sys.stderr'):
            with self.assertRaises(SystemExit):
                probe.main()
            command.assert_not_called()

    def test_existing_package_and_unapproved_physical_target_are_never_installed(self):
        for physical, existing in [(True, False), (False, True)]:
            with self.subTest(physical=physical), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for relative in ['debug/app-debug.apk', 'androidTest/debug/app-debug-androidTest.apk']:
                    apk = root / 'android/app/build/outputs/apk' / relative
                    apk.parent.mkdir(parents=True, exist_ok=True)
                    apk.write_bytes(b'synthetic APK for host control-flow test')
                fake_sdk(temporary)
                calls = []

                def command(args, **options):
                    calls.append(args)
                    # Constant program names; the serial travels only in the child environment.
                    self.assertIn(args[0], {name for _, name in probe.TOOLS.values()})
                    self.assertNotIn('synthetic-device', args)
                    self.assertNotIn('-s', args)
                    self.assertFalse(any(temporary in str(a) for a in args[:1]))
                    self.assertEqual('synthetic-device', options['env']['ANDROID_SERIAL'])
                    if 'manifest' in args:
                        result = manifest(str(args[-1]).endswith('.test.apk'))
                    elif 'verify' in args:
                        result = 'V2 Signer: certificate SHA-256 digest: ' + 'a' * 64 + '\n'
                    elif 'ro.kernel.qemu' in args:
                        result = '0' if physical else '1'
                    elif 'ro.build.version.sdk' in args:
                        result = '36'
                    elif 'packages' in args:
                        result = 'package:' + probe.APP if existing else ''
                    else:
                        self.fail('Unexpected device operation before preflight completed')
                    return SimpleNamespace(returncode=0, stdout=result)

                with mock.patch.object(probe, 'ROOT', root), mock.patch.dict(probe.os.environ, {'ANDROID_HOME': temporary}), \
                        mock.patch.object(probe.subprocess, 'run', side_effect=command), \
                        mock.patch.object(sys, 'argv', ['probe', '--serial', 'synthetic-device']), mock.patch('builtins.print'):
                    with self.assertRaises(ValueError):
                        probe.main()
                self.assertFalse(any('install' in call or 'uninstall' in call for call in calls))

    def test_runner_rejection_must_precede_any_test_discovery(self):
        output = 'INSTRUMENTATION_RESULT: probeRejected=selector\nINSTRUMENTATION_CODE: 0\n'
        probe.validate_rejection(output)
        for bad in [output.replace('selector', 'unknown'), output.replace('CODE: 0', 'CODE: -1'),
                    output + 'INSTRUMENTATION_STATUS: class=anything\n']:
            with self.assertRaises(ValueError):
                probe.validate_rejection(bad)

    def test_only_two_isolated_identities_and_plain_applications_are_admitted(self):
        probe.validate_manifest(manifest(), probe.APP)
        probe.validate_manifest(manifest(True), probe.TEST_APP, True)
        for bad in [manifest().replace(probe.APP, "org.zrotext.gateway"),
                    manifest().replace('package=', 'android:sharedUserId="shared" package='),
                    manifest().replace('android.app.Application', '.GatewayApplication'),
                    manifest().replace('allowBackup="false"', 'allowBackup="true"'),
                    manifest().replace('testOnly="true"', 'testOnly="false"'),
                    manifest().replace('android:name=', 'android:appComponentFactory="unexpected.Factory" android:name='),
                    manifest().replace('android:name=', 'android:process="shared" android:name=')]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.validate_manifest(bad, probe.APP)

    def test_every_permission_query_or_component_fails_closed(self):
        for node in ['uses-permission', 'uses-permission-sdk-23', 'permission', 'queries', 'uses-feature']:
            bad = manifest().replace('</manifest>', f'<{node} /></manifest>')
            with self.subTest(node=node), self.assertRaises(ValueError):
                probe.validate_manifest(bad, probe.APP)
        for node in ['activity', 'service', 'receiver', 'provider', 'meta-data']:
            bad = manifest().replace('android:testOnly="true" />', f'android:testOnly="true"><{node}/></application>')
            with self.subTest(node=node), self.assertRaises(ValueError):
                probe.validate_manifest(bad, probe.APP)

    def test_wrong_runner_target_or_broad_processes_are_rejected(self):
        for old, new in [(probe.RUNNER, 'androidx.test.runner.AndroidJUnitRunner'),
                         ('targetPackage="' + probe.APP, 'targetPackage="org.zrotext.gateway'),
                         ('<instrumentation', '<instrumentation android:targetProcesses="*"')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                probe.validate_manifest(manifest(True).replace(old, new), probe.TEST_APP, True)

    def test_exact_methods_counts_and_hardware_marker_required(self):
        methods = ['independentTinkWrapOpensThroughExistingKeystoreAndLostKeyCannotBeRecreated',
                   'preparationRequiresActualReportedHardwareAndNeverProducesAlphaState']
        output = ''.join(f'INSTRUMENTATION_STATUS: class={probe.TEST}\nINSTRUMENTATION_STATUS: test={m}\n'
                         'INSTRUMENTATION_STATUS_CODE: 0\n' for m in methods)
        output += 'INSTRUMENTATION_RESULT: preparationCustody=unsupported\nINSTRUMENTATION_CODE: -1\n'
        self.assertEqual('unsupported', probe.validate_results(output))
        for bad in [output.replace('unsupported', 'passed'), output.replace(methods[0], 'unknown'),
                    output.replace('CODE: 0', 'CODE: -3'), output.replace(probe.TEST, 'another.Test'),
                    output + 'INSTRUMENTATION_RESULT: preparationCustody=unsupported\n',
                    output.replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0')]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.validate_results(bad)


INSTALLED = '/data/app/~~AbC-_12==/org.zrotext.gateway.preparationprobe-Xy_9-==/base.apk'


class InstalledApkPullTest(unittest.TestCase):
    def pull(self, reads, pulls, **options):
        """Run pull_installed with scripted `pm path` outputs and pull results."""
        reads, pulls, pulled, slept = list(reads), list(pulls), [], []

        def read():
            return reads.pop(0)

        def pull(path):
            pulled.append(path)
            outcome = pulls.pop(0)
            if outcome is not None:
                raise probe.ProbeCommandError(outcome)

        result = probe.pull_installed(read, pull, slept.append, **options)
        return result, pulled, slept

    def test_installed_path_accepts_only_one_safe_data_app_apk(self):
        for good in ['package:' + INSTALLED, 'package:/data/app/org.zrotext.gateway.preparationprobe-1/base.apk',
                     '  package:' + INSTALLED + '\r\n']:
            self.assertTrue(probe.installed_apk_path(good).endswith('/base.apk'))
        with self.assertRaises(probe.PathNotReady):
            probe.installed_apk_path(' \r\n')
        for bad in ['package:/sdcard/base.apk', 'package:/data/app/../system/base.apk',
                    'package:/data/app/./x/base.apk', 'package:/data/app/x/other.apk', '/data/app/x/base.apk',
                    'package:/data/app/x y/base.apk', 'package:/data/app/x/base.apk;reboot',
                    'package:' + INSTALLED + '\npackage:' + INSTALLED, 'package:/data/app/base.apk',
                    'package:/data/app/a/b/c/d/base.apk', 'package:/data/app/$(reboot)/base.apk']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.installed_apk_path(bad)

    def test_first_stable_path_is_pulled_without_waiting(self):
        (used, seen), pulled, slept = self.pull(['package:' + INSTALLED] * 2, [None])
        self.assertEqual((1, []), (used, seen))
        self.assertEqual([INSTALLED], pulled)
        self.assertEqual([], slept)

    def test_post_install_races_are_retried_with_bounded_backoff(self):
        path = 'package:' + INSTALLED
        moved = 'package:' + INSTALLED.replace('Xy_9', 'Zz_1')
        reads = ['', path, moved, path, path, path, path, moved, moved]
        (used, seen), pulled, slept = self.pull(reads, ['permission', 'missing', None])
        self.assertEqual(5, used)
        self.assertEqual(['path-not-ready', 'path-moving', 'pull-permission', 'pull-missing'], seen)
        self.assertEqual([INSTALLED, INSTALLED, moved.removeprefix('package:')], pulled)
        self.assertEqual([1, 2, 3, 5], slept)

    def test_persistent_failure_stops_after_the_attempt_bound_without_raw_output(self):
        reads = ['package:' + INSTALLED] * 2 * probe.PULL_ATTEMPTS
        with self.assertRaises(RuntimeError) as raised:
            self.pull(reads, ['transport'] * probe.PULL_ATTEMPTS)
        message = str(raised.exception)
        self.assertIn('no raw device output published', message)
        self.assertEqual(probe.PULL_ATTEMPTS, message.count('transport'))
        self.assertNotIn(INSTALLED, message)

    def test_malformed_package_manager_output_is_never_retried(self):
        slept, pulled = [], []
        with self.assertRaises(ValueError):
            probe.pull_installed(lambda: 'package:/sdcard/evil.apk', pulled.append, slept.append)
        self.assertEqual(([], []), (pulled, slept))

    def test_package_manager_command_failures_are_retried_and_staged(self):
        outcomes = [probe.ProbeCommandError('service'), 'package:' + INSTALLED, 'package:' + INSTALLED]
        slept, pulled = [], []

        def read():
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        used, seen = probe.pull_installed(read, pulled.append, slept.append)
        self.assertEqual((2, ['path-service']), (used, seen))
        self.assertEqual(([INSTALLED], [1]), (pulled, slept))

    def test_failures_are_reported_as_fixed_classes_only(self):
        secret = 'synthetic-device-text-7f3a'
        for raw, kind in [(f'adb: error: failed to stat remote object {secret}: No such file or directory', 'missing'),
                          (f'adb: error: {secret}: Permission denied', 'permission'),
                          ('adb: device offline', 'device-offline'),
                          ('error: no devices/emulators found', 'device-offline'),
                          (f'protocol fault (couldn\'t read status): Connection reset by peer {secret}', 'transport'),
                          ("cmd: Can't find service: package", 'service'),
                          (secret, 'other'), ('', 'silent'), (' \n', 'silent'), (None, 'silent')]:
            with self.subTest(kind=kind):
                self.assertEqual(kind, probe.failure_class(raw))
                self.assertNotIn(secret, str(probe.ProbeCommandError(probe.failure_class(raw))))


if __name__ == '__main__':
    unittest.main()
