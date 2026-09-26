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


class PreparationProbeTest(unittest.TestCase):
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
                calls = []

                def command(args, **_):
                    calls.append(args)
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


if __name__ == '__main__':
    unittest.main()
