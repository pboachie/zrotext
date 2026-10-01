# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import io
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
