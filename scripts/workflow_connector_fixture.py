# SPDX-License-Identifier: AGPL-3.0-only
"""Owned synthetic fixture custody and CA injection; never production configuration."""
import contextlib
import ctypes
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from workflow_secret_store import operating_system_store, SecretStoreError, reference


def windows_fixture_compiler():
    """Find the fixed fixture compiler from the OS, never a process environment."""
    from ctypes import wintypes
    api = ctypes.WinDLL('kernel32.dll', use_last_error=True)
    api.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    api.GetWindowsDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = api.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer) or not os.path.isabs(buffer.value):
        raise ValueError('fixture_compiler_unavailable')
    compiler = Path(buffer.value) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    if not compiler.is_file() or compiler.is_symlink():
        raise ValueError('fixture_compiler_unavailable')
    return compiler


class OwnedFixtureVault:
    """Only names first created by this fixture may be deleted, including on error."""
    def __init__(self):
        self.store = operating_system_store()
        self.names = set()
        descriptor, receipt = tempfile.mkstemp(prefix='zrotext-fixture-custody-', suffix='.json')
        self.receipt = Path(receipt)
        self.receipt_identity = os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino
        self.receipt_stream = os.fdopen(descriptor, 'w+b')
        self.record()
    def record(self):
        self.receipt_stream.seek(0)
        self.receipt_stream.write(json.dumps({'v': 1, 'owned_names': sorted(self.names)}).encode())
        self.receipt_stream.truncate()
        self.receipt_stream.flush()
        os.fsync(self.receipt_stream.fileno())
    def require_absent(self, name):
        reference(name)
        if os.name == 'nt':
            existing = ctypes.POINTER(self.store.Entry)()
            found = self.store.api.CredReadW(name, 1, 0, ctypes.byref(existing))
            if found:
                self.store.api.CredFree(existing)
                raise ValueError('fixture_name_already_exists')
            if ctypes.get_last_error() != 1168:
                raise SecretStoreError('fixture_custody_unavailable')
        else:
            # Includes locked/malformed entries. Never overwrite a name merely
            # because reading it as a valid credential failed.
            if self.store._run(['search', '--all', 'application', 'zrotext', 'reference', name]):
                raise ValueError('fixture_name_already_exists')
    def put(self, name, value):
        if name not in self.names:
            self.require_absent(name)
            # Receipt precedes a write which may succeed but fail to report it.
            self.names.add(name)
            self.record()
        self.store.put(name, value)
    def get(self, name):
        if name not in self.names:
            raise ValueError('fixture_name_not_owned')
        return self.store.get(name)
    def delete(self, name):
        if name not in self.names:
            # Ambiguous issuance can have an intent name never written to OS
            # custody. Confirm absence without deleting anything unowned.
            self.require_absent(name)
            return
        self.store.delete(name)
        self.names.remove(name)
        self.record()
    def close(self):
        try:
            for name in tuple(self.names):
                self.delete(name)
        finally:
            self.receipt_stream.close()
        # Failed cleanup leaves the private receipt outside the ephemeral
        # fixture directory, for precise later cleanup of only these names.
        info = self.receipt.stat(follow_symlinks=False)
        if (info.st_dev, info.st_ino) != self.receipt_identity or self.receipt.is_symlink():
            raise ValueError('fixture_receipt_changed')
        self.receipt.unlink()


@contextlib.contextmanager
def fixture_node(root, certificate, broker):
    """Add the fixture's CA only in its PATH shim; launch() remains unchanged."""
    node = shutil.which('node')
    if not node:
        raise ValueError('fixture_node_required')
    directory = Path(root) / 'fixture-node'
    directory.mkdir()
    children = directory / 'children.txt'
    if os.name == 'nt':
        compiler = windows_fixture_compiler()
        # No credential goes through this shim. Standard handles are inherited;
        # the SDK attempts Windows Job containment. Observe the fixture's
        # exact child IDs independently; never terminate a process by name.
        source = directory / 'NodeFixture.cs'
        source.write_text('''using System;
using System.Diagnostics;
using System.IO;
class NodeFixture {
  static int Main(string[] args) {
    if (args.Length != 1) return 2;
    string command;
    if (args[0] == "--version") command = "--dns-result-order=ipv4first --version";
    else if (args[0] == __BROKER_PATH__) command = __BROKER_COMMAND__;
    else return 2;
    // Only generated fixed arguments reach the actual Node process.
    var start = new ProcessStartInfo(__NODE_PATH__, command);
    start.UseShellExecute = false;
    start.EnvironmentVariables["NODE_EXTRA_CA_CERTS"] = __CERT_PATH__;
    using (var child = Process.Start(start)) {
      File.AppendAllText(__CHILD_PATH__, Process.GetCurrentProcess().Id.ToString() + " " + child.Id.ToString() + Environment.NewLine);
      child.WaitForExit(); return child.ExitCode;
    }
  }
}'''.replace('__NODE_PATH__', json.dumps(node)).replace('__CERT_PATH__', json.dumps(str(certificate)))
              .replace('__BROKER_PATH__', json.dumps(str(broker)))
              .replace('__BROKER_COMMAND__', json.dumps('--dns-result-order=ipv4first ' + subprocess.list2cmdline([str(broker)])))
              .replace('__CHILD_PATH__', json.dumps(str(children))))
        subprocess.run([str(compiler), '/nologo', '/out:' + str(directory / 'node.exe'), str(source)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    else:
        shim = directory / 'node'
        shim.write_text('#!/bin/sh\n[ "$#" = 1 ] || exit 2\ncase "$1" in\n' +
                        '--version) set -- --version ;;\n' + shlex.quote(str(broker)) + ') set -- ' +
                        shlex.quote(str(broker)) + ' ;;\n*) exit 2 ;;\nesac\n' +
                        'printf "%s\\n" "$$" >> ' + shlex.quote(str(children)) + '\nNODE_EXTRA_CA_CERTS=' + shlex.quote(str(certificate)) +
                        ' exec ' + shlex.quote(node) + ' --dns-result-order=ipv4first "$@"\n')
        shim.chmod(0o700)
    original = os.environ.get('PATH', '')
    try:
        os.environ['PATH'] = str(directory) + os.pathsep + original
        yield children
    finally:
        os.environ['PATH'] = original


def observed_children_stopped(receipt):
    """Read only fixture-owned observations; never kill or enumerate user processes."""
    ids = {int(value) for value in receipt.read_text().split()}
    assert ids and all(value > 0 for value in ids)
    if os.name == 'nt':
        from ctypes import wintypes
        api = ctypes.WinDLL('kernel32.dll', use_last_error=True)
        api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenProcess.restype = wintypes.HANDLE
        api.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        api.GetExitCodeProcess.restype = wintypes.BOOL
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        for pid in ids:
            handle = api.OpenProcess(0x1000, False, pid)
            if not handle:
                assert ctypes.get_last_error() == 87
                continue
            try:
                status = wintypes.DWORD()
                assert api.GetExitCodeProcess(handle, ctypes.byref(status))
                assert status.value != 259
            finally:
                api.CloseHandle(handle)
    else:
        for pid in ids:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise AssertionError('fixture_child_still_present')
