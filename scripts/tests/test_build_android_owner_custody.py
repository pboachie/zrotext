# SPDX-License-Identifier: AGPL-3.0-only
"""Offline rejection checks for the native custodian's Android page-size gate."""

import subprocess
import unittest
from unittest.mock import patch
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_spec = spec_from_file_location(
    "build_android_owner_custody", Path(__file__).resolve().parents[1] / "build_android_owner_custody.py"
)
build = module_from_spec(_spec)
_spec.loader.exec_module(build)


class NativePageAlignmentTests(unittest.TestCase):
    def verify_output(self, output):
        result = subprocess.CompletedProcess([], 0, stdout=output, stderr="")
        with patch.object(build.subprocess, "run", return_value=result):
            build.verify_load_alignment("synthetic-readelf", "synthetic-library")

    def test_one_under_aligned_load_segment_rejects_an_otherwise_aligned_library(self):
        with self.assertRaises(RuntimeError):
            self.verify_output(
                "  LOAD 0x000000 0x00000000 0x00000000 0x010000 0x010000 R E 0x4000\n"
                "  LOAD 0x010000 0x00010000 0x00010000 0x000100 0x000200 RW 0x1000\n"
            )

    def test_missing_load_segments_cannot_establish_compatible_native_packaging(self):
        for output in ["", "  DYNAMIC 0x001000 0x001000 0x001000 0x100 0x100 RW 0x8\n"]:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                self.verify_output(output)

    def test_all_load_segments_must_support_sixteen_kibibyte_pages(self):
        self.verify_output(
            "  LOAD 0x000000 0x00000000 0x00000000 0x010000 0x010000 R E 0x4000\n"
            "  LOAD 0x010000 0x00010000 0x00010000 0x000100 0x000200 RW 0x4000\n"
        )


class TypedJniExportTests(unittest.TestCase):
    prefix = "Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_"
    methods = ("nativeOpenTyped", "nativeReviewTyped", "nativeSignTyped", "nativeArchiveRecoveryCheck")

    def verify_output(self, methods):
        output = "\n".join("0000000000010000 T " + self.prefix + method for method in methods)
        result = subprocess.CompletedProcess([], 0, stdout=output, stderr="")
        with patch.object(build.subprocess, "run", return_value=result) as run:
            build.verify_typed_exports("synthetic-nm", "synthetic-library")
            self.assertEqual(run.call_args.args[0],
                             ["synthetic-nm", "--dynamic", "--defined-only", "synthetic-library"])

    def test_all_required_typed_exports_establish_the_current_jni_surface(self):
        self.verify_output(self.methods)

    def test_stale_library_missing_any_typed_export_is_rejected(self):
        for missing in self.methods:
            with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                self.verify_output(tuple(method for method in self.methods if method != missing))
        with self.subTest(missing="all"), self.assertRaises(RuntimeError):
            self.verify_output(())
        with self.subTest(missing="exact symbol"), self.assertRaises(RuntimeError):
            self.verify_output(tuple(method + "Old" for method in self.methods))


if __name__ == "__main__":
    unittest.main()
