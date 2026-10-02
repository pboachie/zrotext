# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import conversation_emulator as probe

class ProbeIsolationTests(unittest.TestCase):
    def invoke(self, package=probe.APP, permissions=("android.permission.INTERNET",), test_only=True):
        calls=[]
        def fake(command, **unused):
            calls.append(command)
            if command[0]=="adb":
                if command[-3:]==["emu","avd","name"]: return SimpleNamespace(stdout="ZROtext_Conversation_API28\nOK\n")
                if command[-3:]==["shell","getprop","ro.kernel.qemu"]: return SimpleNamespace(stdout="1\n")
                raise RuntimeError("Install reached")
            instrument="androidTest" in command[-1] or (len(command)>4 and "androidTest" in command[-2])
            if command[2]=="badging":
                identity=probe.APP+".test" if instrument else package
                requested=() if instrument else permissions
                return SimpleNamespace(stdout="package: name='"+identity+"'\n"+"\n".join("uses-permission: name='"+value+"'" for value in requested))
            marker="android:testOnly(0x01010272)=(type 0x12)0xffffffff" if test_only else ""
            return SimpleNamespace(stdout=marker+'\nandroid:targetPackage="'+probe.APP+'"')
        argv=["probe","--serial","emulator-5596","--adb","adb","--aapt","aapt","--skip-build"]
        with patch("sys.argv",argv),patch.object(probe,"run",side_effect=fake):
            with self.assertRaises(RuntimeError) as caught: probe.main()
        return calls,str(caught.exception)
    def test_stale_gateway_artifact_is_refused_before_install(self):
        calls,error=self.invoke(package="org.zrotext.gateway")
        self.assertIn("preflight",error);self.assertFalse(any("install" in command for command in calls))
    def test_radio_permission_is_refused_before_install(self):
        calls,error=self.invoke(permissions=("android.permission.INTERNET","android.permission.SEND_SMS"))
        self.assertIn("preflight",error);self.assertFalse(any("install" in command for command in calls))
    def test_non_test_artifact_is_refused_before_install(self):
        calls,error=self.invoke(test_only=False)
        self.assertIn("preflight",error);self.assertFalse(any("install" in command for command in calls))
    def test_both_apks_are_verified_before_first_install(self):
        calls,error=self.invoke();self.assertEqual("Install reached",error)
        self.assertEqual(4,sum(command[0]=="aapt" for command in calls[:-1]))
    def test_physical_selector_cannot_reach_adb(self):
        with patch("sys.argv",["probe","--serial","physical-fixture","--adb","adb","--aapt","aapt"]),patch.object(probe,"run") as called,contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): probe.main()
            called.assert_not_called()
    def test_host_unicode_transport_explicitly_decodes_utf8(self):
        with patch.object(probe.subprocess,"run") as called:
            probe.run(["fixture"]);self.assertEqual("utf-8",called.call_args.kwargs["encoding"])


class FixtureDiagnosticsTests(unittest.TestCase):
    def capture(self, content, ready=None):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "server.log"
            log.write_bytes(content)
            return probe.fixture_failure_details(log, ready)

    def test_failure_keeps_child_exit_and_panic_after_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "server.log"
            log.write_text('ZT_CONVERSATION_SIM_READY_V1 {"token":"synthetic-secret"}\n'
                "thread 'fixture' panicked at fixture.rs:12:\n"
                "fixture server stopped\ntest result: FAILED\n", encoding="utf-8")
            server = SimpleNamespace(wait=lambda timeout: 101)
            with self.assertRaisesRegex(RuntimeError, "exit 101") as caught:
                probe.require_fixture_exit(server, log, {"token": "synthetic-secret"})
            self.assertIn("fixture server stopped", str(caught.exception))
            self.assertNotIn("synthetic-secret", str(caught.exception))
            self.assertNotIn("ZT_CONVERSATION_SIM_READY_V1", str(caught.exception))

    def test_huge_readiness_is_removed_before_tail_is_bounded(self):
        details = self.capture(probe.READY_MARKER + b"synthetic-secret" * 2000 + b"\nfixture failed\n")
        self.assertEqual("fixture failed", details)

    def test_echoed_tokens_and_private_scalars_are_redacted(self):
        details = self.capture(b"failure synthetic-token synthetic-scalar\n",
            {"token": "synthetic-token", "eventScalar": "synthetic-scalar"})
        self.assertNotIn("synthetic-token", details)
        self.assertNotIn("synthetic-scalar", details)

    def test_diagnostics_are_bounded_and_oversized_log_is_refused(self):
        self.assertLessEqual(len(self.capture(b"x" * 9000).encode("utf-8")), 4096)
        self.assertEqual("Fixture log exceeded the diagnostic capture bound",
            self.capture(b"x" * (probe.MAX_STARTUP_LOG_BYTES + 1)))

    def test_multibyte_diagnostic_tail_remains_within_byte_bound(self):
        details = self.capture((chr(0x20ac) * 3000 + "fixture failed").encode("utf-8"))
        self.assertLessEqual(len(details.encode("utf-8")), 4096)
        self.assertTrue(details.endswith("fixture failed"))

    def test_success_does_not_read_or_export_fixture_log(self):
        server = SimpleNamespace(wait=lambda timeout: 0)
        with patch.object(probe, "fixture_failure_details") as details:
            probe.require_fixture_exit(server, Path("not-read"), {"token": "synthetic-token"})
            details.assert_not_called()
