"""Reject damaged or incomplete package metadata before consumer qualification."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("artifacts", Path(__file__).resolve().parents[1]
                                            / "sdk/tungsten/package-artifacts.py")
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class PackageTests(unittest.TestCase):
    def test_missing_or_wrong_license_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "candidate.whl"
            for content in (b"", b"wrong"):
                with zipfile.ZipFile(wheel, "w") as archive:
                    if content:
                        archive.writestr("sdk.dist-info/licenses/LICENSE", content)
                with self.assertRaisesRegex(ValueError, "license"):
                    artifacts.check_wheel(wheel, b"expected")

    def test_install_artifacts_fail_even_with_license(self):
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "candidate.whl"
            for extra in ("sdk/__pycache__/x.pyc", "sdk.dist-info/direct_url.json"):
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr("sdk.dist-info/licenses/LICENSE", b"expected")
                    archive.writestr(extra, b"unwanted")
                with self.assertRaisesRegex(ValueError, "checkout/install"):
                    artifacts.check_wheel(wheel, b"expected")

    def test_metadata_drift_fails_instead_of_silently_omitting_license(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "metadata"
            path.write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unexpected package"):
                artifacts.replace_once(path, "original", "replacement")
            self.assertEqual(path.read_text(), "unexpected")


if __name__ == "__main__":
    unittest.main()
