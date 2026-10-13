"""Reject substituted, duplicate and unexpected candidate archive payloads."""
import importlib.util
import json
import runpy
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

spec = importlib.util.spec_from_file_location('managed', Path(__file__).with_name('package-managed.py'))
managed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(managed)
runner_spec = importlib.util.spec_from_file_location('original_runner', Path(__file__).with_name('original-reply-run.py'))
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


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
            self.assertEqual(len(paths), 17)
            self.assertEqual(len(set(paths)), 17)

    def test_installed_command_rejects_shell_strings_and_invalid_arguments(self):
        load = runpy.run_path(str(Path(__file__).with_name('installed-command.py')))['load']
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'command.json'
            path.write_text(json.dumps(['runtime', 'space in path', '--flag']), encoding='utf-8')
            self.assertEqual(load(path), ['runtime', 'space in path', '--flag'])
            for invalid in ('runtime --flag', {}, [], [''], [None], ['bad\0argument']):
                path.write_text(json.dumps(invalid), encoding='utf-8')
                with self.assertRaises(ValueError):
                    load(path)

    def test_installed_original_commands_require_both_exact_argument_lists(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'commands.json'
            commands = {'software': ['runtime', 'software consumer'], 'protected': ['runtime', 'protected consumer']}
            path.write_text(json.dumps(commands), encoding='utf-8')
            self.assertEqual(runner.installed_commands(path), (commands['software'], commands['protected']))
            for invalid in [[], {}, {'software': ['runtime']}, dict(commands, extra=[]),
                            dict(commands, software='runtime'), dict(commands, software=[]),
                            dict(commands, protected=[None]), dict(commands, protected=['']),
                            dict(commands, protected=['bad\0argument'])]:
                path.write_text(json.dumps(invalid), encoding='utf-8')
                with self.assertRaises(ValueError):
                    runner.installed_commands(path)


if __name__ == '__main__':
    unittest.main()
