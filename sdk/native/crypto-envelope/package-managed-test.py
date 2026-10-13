"""Reject substituted, duplicate and unexpected candidate archive payloads."""
import importlib.util
import json
import runpy
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

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
            expected = {'java': 23, 'csharp': 29, 'ruby': 28}[language]
            self.assertEqual(len(paths), expected)
            self.assertEqual(len(set(paths)), expected)

    def test_owner_template_gates_use_installed_commands(self):
        args = SimpleNamespace(target='java', template_producer=Path('producer'),
                               owner_template_fixture=Path('cold-fixture'), template_save_fixture=Path('save-fixture'),
                               template_save_oracle=Path('save-oracle'))
        commands = {name: Path(name + '.json') for name in ('owner-template', 'owner-template-save')}
        with patch.object(managed, 'run') as run:
            managed.owner_template_acceptance(args, Path('stage'), commands, {})
        calls = [call.args for call in run.call_args_list]
        self.assertEqual(len(calls), 2)
        for call, suite in zip(calls, commands):
            self.assertEqual(call[2:6], ('--language', 'java', '--producer', Path('producer')))
            self.assertEqual(call[-2:], ('--command-file', commands[suite]))
        self.assertEqual(calls[0][1].name, 'owner-template-run.py')
        self.assertEqual(calls[1][1].name, 'template-save-run.py')
        self.assertEqual(calls[0][6:8], ('--fixture', Path('cold-fixture')))
        self.assertEqual(calls[1][6:10], ('--fixture', Path('save-fixture'), '--save-oracle', Path('save-oracle')))

    def test_template_lifecycles_use_installed_commands_and_strict_hardware(self):
        args = SimpleNamespace(target='ruby', template_producer=Path('producer'),
                               template_opening_fixture=Path('opening-fixture'), template_opening_oracle=Path('opening-oracle'),
                               template_authoring_fixture=Path('authoring-fixture'), template_authoring_oracle=Path('authoring-oracle'))
        commands = {name: Path(name + '.json') for name in ('owner-template-opening', 'owner-template-authoring')}
        with patch.object(managed, 'run') as run:
            managed.template_lifecycle_acceptance(args, Path('stage'), commands, {})
            managed.template_lifecycle_acceptance(args, Path('stage'), commands, {}, hardware=True)
        calls = [call.args for call in run.call_args_list]
        self.assertEqual(len(calls), 3)
        for call in (calls[0], calls[2]):
            self.assertEqual(call[1].name, 'template-opening-run.py')
            self.assertEqual(call[6:12], ('--fixture', Path('opening-fixture'), '--opening-oracle', Path('opening-oracle'),
                                           '--command-file', commands['owner-template-opening']))
        self.assertEqual(calls[0][12:], ())
        self.assertEqual(calls[2][12:], ('--hardware',))
        self.assertEqual(calls[1][1].name, 'template-authoring-run.py')
        self.assertEqual(calls[1][6:], ('--fixture', Path('authoring-fixture'), '--authoring-oracle', Path('authoring-oracle'),
                                      '--command-file', commands['owner-template-authoring']))
        for call in calls:
            self.assertEqual(call[2:6], ('--language', 'ruby', '--producer', Path('producer')))
            self.assertNotIn('--allow-unqualified', call)

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
