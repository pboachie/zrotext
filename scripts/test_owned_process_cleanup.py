# SPDX-License-Identifier: AGPL-3.0-only
import ctypes
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import owned_process_cleanup as cleanup


class OwnedProcessCleanupTest(unittest.TestCase):
    def test_process_arguments_are_canonical_bounded_numbers(self):
        self.assertEqual(cleanup.owned_pid("123"), 123)
        for value in ("0", "01", "-1", "1 /T", str(2 ** 32), "other"):
            with self.assertRaises(ValueError):
                cleanup.owned_pid(value)

    def kernel(self, status=259):
        def exit_code(_handle, value):
            ctypes.cast(value, ctypes.POINTER(wintypes.DWORD)).contents.value = status
            return True
        return SimpleNamespace(OpenProcess=Mock(return_value=123),
                               GetExitCodeProcess=Mock(side_effect=exit_code),
                               CloseHandle=Mock())

    def test_unrelated_or_exited_process_is_never_terminated(self):
        for owner, status in ((8, 259), (7, 0)):
            kernel = self.kernel(status)
            with patch.object(cleanup.ctypes, "windll", SimpleNamespace(kernel32=kernel), create=True), \
                    patch.object(cleanup.os, "getppid", return_value=7), \
                    patch.object(cleanup, "parent_process_id", return_value=owner), \
                    patch.object(cleanup.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    cleanup.terminate_owned_child(42)
                run.assert_not_called()
                kernel.CloseHandle.assert_called_once_with(123)

    def test_live_owned_process_is_pinned_until_exact_pid_cleanup_finishes(self):
        kernel = self.kernel()
        def finished(command, **_options):
            kernel.CloseHandle.assert_not_called()
            self.assertEqual(command, ["fixture-tool", "/PID", "42", "/T", "/F"])
        with patch.object(cleanup.ctypes, "windll", SimpleNamespace(kernel32=kernel), create=True), \
                patch.object(cleanup.os, "getppid", return_value=7), \
                patch.object(cleanup, "parent_process_id", return_value=7), \
                patch.object(cleanup, "system_cleanup_tool", return_value=Path("fixture-tool")), \
                patch.object(cleanup.subprocess, "run", side_effect=finished):
            cleanup.terminate_owned_child(42)
        kernel.CloseHandle.assert_called_once_with(123)

    def test_missing_handle_prevents_any_termination(self):
        kernel = self.kernel()
        kernel.OpenProcess.return_value = None
        with patch.object(cleanup.ctypes, "windll", SimpleNamespace(kernel32=kernel), create=True), \
                patch.object(cleanup.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                cleanup.terminate_owned_child(42)
            run.assert_not_called()
            kernel.CloseHandle.assert_not_called()


if __name__ == "__main__":
    unittest.main()
