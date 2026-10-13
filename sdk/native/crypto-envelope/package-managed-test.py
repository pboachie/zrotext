"""Reject substituted, duplicate and unexpected candidate archive payloads."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

spec = importlib.util.spec_from_file_location('managed', Path(__file__).with_name('package-managed.py'))
managed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(managed)


class ArchiveTests(unittest.TestCase):
    def check(self, entries):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'candidate.zip'
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(path, 'w') as archive:
                    for name, value in entries:
                        archive.writestr(name, value)
            managed.check_zip(path, {'LICENSE', 'runtime'}, 'LICENSE', b'license')

    def test_exact_payload(self):
        self.check([('LICENSE', b'license'), ('runtime', b'code')])

    def test_unexpected_payload(self):
        with self.assertRaises(ValueError):
            self.check([('LICENSE', b'license'), ('runtime', b'code'), ('secret', b'x')])

    def test_duplicate_payload(self):
        with self.assertRaises(ValueError):
            self.check([('LICENSE', b'license'), ('runtime', b'code'), ('runtime', b'code')])

    def test_license_substitution(self):
        with self.assertRaises(ValueError):
            self.check([('LICENSE', b'other'), ('runtime', b'code')])

    def test_closed_runtime_inventory(self):
        for language in ('java', 'csharp', 'ruby'):
            paths = managed.runtime_sources(language)
            self.assertEqual(len(paths), 13)
            self.assertEqual(len(set(paths)), 13)


if __name__ == '__main__':
    unittest.main()
