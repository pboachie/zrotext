# SPDX-License-Identifier: AGPL-3.0-only
"""Only fixed, bounded job-local log files are accepted by the verifier."""

from contextlib import contextmanager
import io
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import tempfile

import ksp_execution_trace as trace


class KspLogBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.folder = self.root / trace.LOG_DIRECTORY
        self.folder.mkdir()
        self.path = self.folder / "cold.log"
        self.path.write_bytes(b"original")
        self.environment = patch.dict(os.environ, RUNNER_TEMP=str(self.root))
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_only_fixed_role_names_select_log_files(self):
        (self.folder / "ksp-store.log").write_bytes(b"stored")
        (self.folder / "reuse.log").write_bytes(b"warm")
        self.assertEqual(trace.LOG_FILENAMES,
                         {"cold": "cold.log", "store": "ksp-store.log", "reuse": "reuse.log"})
        self.assertEqual(trace.read_log("cold"), "original")
        self.assertEqual(trace.read_log("store"), "stored")
        self.assertEqual(trace.read_log("reuse"), "warm")
        for role in ("", "../cold.log", "cold.log", str(self.path), "other"):
            with self.subTest(role=role), patch.object(trace.os, "open") as opened:
                with self.assertRaises(ValueError):
                    trace.read_log(role)
                opened.assert_not_called()

    def test_job_root_must_exist_be_absolute_and_canonical(self):
        for root in ("", "relative", str(self.root / "missing"),
                     str(self.folder / "..")):
            with self.subTest(root=root), patch.dict(os.environ, RUNNER_TEMP=root), \
                 patch.object(trace.os, "open") as opened:
                with self.assertRaises(ValueError):
                    trace.read_log("cold")
                opened.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            trace.read_log("cold")

    def test_parent_or_file_link_and_reparse_metadata_is_rejected(self):
        original = Path.lstat
        for target in (self.root, self.folder, self.path):
            for mode, attributes in ((stat.S_IFLNK, 0),
                                     (stat.S_IFREG, getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))):
                def metadata(path, *args, **kwargs):
                    if path == target:
                        return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
                    return original(path, *args, **kwargs)
                with self.subTest(target=target, mode=mode), \
                     patch.object(Path, "lstat", metadata), patch.object(trace.os, "open") as opened:
                    with self.assertRaises(ValueError):
                        trace.read_log("cold")
                    opened.assert_not_called()

    def test_resolved_file_or_directory_cannot_escape(self):
        original = Path.resolve
        for target in (self.folder, self.path):
            def resolve(path, *args, **kwargs):
                if path == target:
                    return self.root.parent / "outside"
                return original(path, *args, **kwargs)
            with self.subTest(target=target), patch.object(Path, "resolve", resolve), \
                 patch.object(trace.os, "open") as opened:
                with self.assertRaises(ValueError):
                    trace.read_log("cold")
                opened.assert_not_called()

    def test_nonregular_and_multiple_link_files_are_rejected_before_open(self):
        original = Path.lstat
        for mode, links in ((stat.S_IFIFO, 1), (stat.S_IFDIR, 1),
                            (stat.S_IFCHR, 1), (stat.S_IFREG, 2)):
            def metadata(path, *args, **kwargs):
                if path == self.path:
                    return SimpleNamespace(st_mode=mode, st_nlink=links)
                return original(path, *args, **kwargs)
            with self.subTest(mode=mode, links=links), patch.object(Path, "lstat", metadata), \
                 patch.object(trace.os, "open") as opened:
                with self.assertRaises(ValueError):
                    trace.read_log("cold")
                opened.assert_not_called()

    @unittest.skipIf(os.name == "nt", "Native link creation is exercised by Linux CI")
    def test_native_symlink_and_hardlink_files_are_rejected(self):
        outside = self.root / "outside.log"
        outside.write_bytes(b"outside")
        self.path.unlink()
        self.path.symlink_to(outside)
        with self.assertRaises(ValueError):
            trace.read_log("cold")
        self.path.unlink()
        os.link(outside, self.path)
        with self.assertRaises(ValueError):
            trace.read_log("cold")

    @unittest.skipIf(os.name == "nt", "Native FIFO creation is exercised by Linux CI")
    def test_native_fifo_is_rejected_without_opening_it(self):
        self.path.unlink()
        os.mkfifo(self.path)
        with patch.object(trace.os, "open") as opened:
            with self.assertRaises(ValueError):
                trace.read_log("cold")
            opened.assert_not_called()

    def test_opened_descriptor_identity_is_verified_before_read(self):
        other = self.folder / "other.log"
        other.write_bytes(b"different")
        original = os.open
        with patch.object(trace.os, "open", side_effect=lambda path, flags: original(other, flags)):
            with self.assertRaisesRegex(ValueError, "changed before opening"):
                trace.read_log("cold")

    def test_read_is_bounded_even_if_file_grows_after_fstat(self):
        original = os.fdopen
        requested = []
        @contextmanager
        def growing(fd, mode):
            with original(fd, mode) as stream:
                def read(limit):
                    requested.append(limit)
                    with self.path.open("ab") as writer:
                        writer.write(b"growth")
                    return stream.read(limit)
                yield SimpleNamespace(fileno=stream.fileno, read=read)
        with patch.object(trace, "MAX_LOG_BYTES", 8), patch.object(trace.os, "fdopen", growing):
            with self.assertRaisesRegex(ValueError, "size limit"):
                trace.read_log("cold")
        self.assertEqual(requested, [9])

    def test_growth_within_limit_and_short_read_are_rejected(self):
        original = os.fdopen
        for growth in (False, True):
            self.path.write_bytes(b"original")
            @contextmanager
            def changed(fd, mode):
                with original(fd, mode) as stream:
                    def read(limit):
                        if growth:
                            with self.path.open("ab") as writer:
                                writer.write(b"more")
                            return stream.read(limit)
                        return stream.read(2)
                    yield SimpleNamespace(fileno=stream.fileno, read=read)
            with self.subTest(growth=growth), patch.object(trace.os, "fdopen", changed):
                with self.assertRaisesRegex(ValueError, "changed while reading"):
                    trace.read_log("cold")

    def test_invalid_utf8_and_io_errors_do_not_echo_file_contents_or_paths(self):
        self.path.write_bytes(b"\xffprivate-marker")
        with self.assertRaisesRegex(ValueError, "^Log must contain valid UTF-8$"):
            trace.read_log("cold")
        with patch.object(trace.os, "open", side_effect=OSError("private-marker")):
            with self.assertRaisesRegex(ValueError, "^Cannot read job-local log$"):
                trace.read_log("cold")

    def test_windows_line_endings_preserve_logical_receipt_lines(self):
        self.path.write_bytes(b"first\r\nsecond\r\n")
        self.assertEqual(trace.read_log("cold"), "first\nsecond\n")

    def test_cli_no_longer_accepts_paths_or_a_root(self):
        for option in ("--cold-log", "--store-log", "--reuse-log", "--log-directory"):
            with self.subTest(option=option), patch("sys.argv", ["trace", "verify", option, "other"]), \
                 patch("sys.stderr", new_callable=io.StringIO), patch.object(trace, "read_log") as reader:
                with self.assertRaises(SystemExit) as exc:
                    trace.main()
                self.assertEqual(exc.exception.code, 2)
                reader.assert_not_called()

    def test_cli_reads_all_three_fixed_roles_in_order(self):
        with patch("sys.argv", ["trace", "verify"]), \
             patch.object(trace, "read_log", side_effect=["full", "stored", "reused"]) as reader, \
             patch.object(trace, "qualify", return_value=trace.REQUIRED_ACTIVE) as qualify, \
             patch("sys.stdout", new_callable=io.StringIO):
            trace.main()
        self.assertEqual([call.args for call in reader.call_args_list], [("cold",), ("store",), ("reuse",)])
        qualify.assert_called_once_with("full", "stored", "reused")

    def test_new_store_role_retains_regular_file_and_size_boundaries(self):
        store = self.folder / "ksp-store.log"
        with self.assertRaises(ValueError):
            trace.read_log("store")
        store.mkdir()
        with self.assertRaises(ValueError):
            trace.read_log("store")
        store.rmdir()
        store.write_bytes(b"too large")
        with patch.object(trace, "MAX_LOG_BYTES", 3), self.assertRaises(ValueError):
            trace.read_log("store")


if __name__ == "__main__":
    unittest.main()
