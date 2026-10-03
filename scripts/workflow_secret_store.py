# SPDX-License-Identifier: AGPL-3.0-only
"""OS-protected custody for narrow workflow credentials; no plaintext fallback."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import os
import re
import shutil
import subprocess


class SecretStoreError(Exception):
    pass


def reference(value):
    if not isinstance(value, str) or not re.fullmatch(r"zrotext-workflow-[0-9a-f]{32}", value):
        raise SecretStoreError("invalid_secret_reference")
    return value


def credential(value):
    if not isinstance(value, str) or not re.fullmatch(r"ztw_[A-Za-z0-9_-]{43}", value):
        raise SecretStoreError("invalid_narrow_credential")
    return value


class WindowsCredentialStore:
    """Current-user generic Credential Manager entries, not owner sessions."""
    class Entry(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                    ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                    ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
                    ("UserName", wintypes.LPWSTR)]

    def __init__(self):
        if os.name != "nt":
            raise SecretStoreError("secret_store_unavailable")
        self.api = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        entry = self.Entry
        self.api.CredWriteW.argtypes = [ctypes.POINTER(entry), wintypes.DWORD]
        self.api.CredWriteW.restype = wintypes.BOOL
        self.api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      ctypes.POINTER(ctypes.POINTER(entry))]
        self.api.CredReadW.restype = wintypes.BOOL
        self.api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        self.api.CredDeleteW.restype = wintypes.BOOL
        self.api.CredFree.argtypes = [ctypes.c_void_p]

    def put(self, name, value):
        name, value = reference(name), credential(value)
        raw = bytearray(value.encode("ascii"))
        data = (ctypes.c_ubyte * len(raw)).from_buffer(raw)
        entry = self.Entry(Type=1, TargetName=name, CredentialBlobSize=len(raw),
                           CredentialBlob=data, Persist=2, UserName="zrotext-workflow")
        try:
            if not self.api.CredWriteW(ctypes.byref(entry), 0):
                raise SecretStoreError("secret_store_unavailable")
        finally:
            raw[:] = bytes(len(raw))

    def get(self, name):
        result = ctypes.POINTER(self.Entry)()
        if not self.api.CredReadW(reference(name), 1, 0, ctypes.byref(result)):
            raise SecretStoreError("secret_store_unavailable")
        try:
            if result.contents.CredentialBlobSize != 47:
                raise SecretStoreError("secret_store_unavailable")
            return credential(ctypes.string_at(result.contents.CredentialBlob, 47).decode("ascii"))
        except (ValueError, UnicodeError):
            raise SecretStoreError("secret_store_unavailable") from None
        finally:
            self.api.CredFree(result)

    def delete(self, name):
        if not self.api.CredDeleteW(reference(name), 1, 0):
            if ctypes.get_last_error() != 1168:
                raise SecretStoreError("secret_store_unavailable")


class SecretServiceStore:
    """Desktop Secret Service via its installed CLI; absence refuses setup."""
    def __init__(self):
        self.tool = shutil.which("secret-tool")
        if not self.tool:
            raise SecretStoreError("secret_store_unavailable")

    def _run(self, args, value=None):
        try:
            result = subprocess.run([self.tool, *args], input=value,
                                    capture_output=True, timeout=10, check=False)
            if result.returncode or len(result.stdout) > 128:
                raise SecretStoreError("secret_store_unavailable")
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            raise SecretStoreError("secret_store_unavailable") from None

    def put(self, name, value):
        self._run(["store", "--label=ZROtext narrow workflow", "application", "zrotext",
                   "reference", reference(name)], credential(value).encode("ascii"))

    def get(self, name):
        try:
            return credential(self._run(["lookup", "application", "zrotext", "reference",
                                         reference(name)]).decode("ascii").strip())
        except UnicodeError:
            raise SecretStoreError("secret_store_unavailable") from None

    def delete(self, name):
        self._run(["clear", "application", "zrotext", "reference", reference(name)])


def operating_system_store():
    return WindowsCredentialStore() if os.name == "nt" else SecretServiceStore()
