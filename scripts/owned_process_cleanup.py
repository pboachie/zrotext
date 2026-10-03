#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Terminate only a direct child of this fixture helper's parent on Windows."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import subprocess
import sys


class ProcessEntry(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD),
                ("pid", wintypes.DWORD), ("heap", ctypes.c_size_t),
                ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                ("parent", wintypes.DWORD), ("priority", wintypes.LONG),
                ("flags", wintypes.DWORD), ("executable", wintypes.WCHAR * 260)]


def owned_pid(value):
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value):
        raise ValueError("Canonical process identifier required")
    result = int(value)
    if result >= 2 ** 32:
        raise ValueError("Process identifier outside Windows bounds")
    return result


def parent_process_id(pid):
    kernel = ctypes.windll.kernel32
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for name in ("Process32FirstW", "Process32NextW"):
        function = getattr(kernel, name)
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        function.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot in (None, ctypes.c_void_p(-1).value):
        raise ValueError("Process ownership unavailable")
    try:
        entry = ProcessEntry()
        entry.size = ctypes.sizeof(entry)
        available = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while available:
            if entry.pid == pid:
                return entry.parent
            available = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        raise ValueError("Owned process no longer available")
    finally:
        kernel.CloseHandle(snapshot)


def system_cleanup_tool():
    buffer = ctypes.create_unicode_buffer(32768)
    kernel = ctypes.windll.kernel32
    kernel.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetSystemDirectoryW.restype = wintypes.UINT
    length = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise ValueError("System cleanup tool unavailable")
    directory = Path(buffer.value).resolve(strict=True)
    tool = directory / "taskkill.exe"
    if tool.is_symlink() or not tool.is_file() or tool.resolve().parent != directory:
        raise ValueError("System cleanup tool unavailable")
    return tool


def terminate_owned_child(pid):
    kernel = ctypes.windll.kernel32
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # Keep the process object referenced through termination; its PID cannot
    # be recycled between the ownership check and the exact-PID command.
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise ValueError("Owned process unavailable")
    try:
        status = wintypes.DWORD()
        if (not kernel.GetExitCodeProcess(handle, ctypes.byref(status))
                or status.value != 259 or parent_process_id(pid) != os.getppid()):
            raise ValueError("Caller does not own a live target process")
        subprocess.run([str(system_cleanup_tool()), "/PID", str(pid), "/T", "/F"],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15, check=True)
    finally:
        kernel.CloseHandle(handle)


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if os.name != "nt" or len(arguments) != 1:
            raise ValueError("Windows owned process fixture required")
        terminate_owned_child(owned_pid(arguments[0]))
    except (ValueError, OSError, subprocess.SubprocessError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
