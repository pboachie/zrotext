# SPDX-License-Identifier: AGPL-3.0-only
import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import guided_workflow_setup as setup
import workflow_connector_verify as verify
from workflow_connector_fixture import OwnedFixtureVault
from workflow_secret_store import WindowsCredentialStore, SecretStoreError

ID = '00000000-0000-4000-8000-000000000001'
SELECTED = dict(connector_id=ID, context_id=ID, contact_id=ID, purpose='operational', expires_at_ms=1)


class InstalledVerification(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'requires Windows fixture custody API shape')
    def test_unwritten_issuance_reference_cleanup_only_confirms_absence(self):
        from unittest.mock import Mock
        store = Mock()
        store.Entry = WindowsCredentialStore.Entry
        store.api.CredReadW.return_value = False
        with patch('workflow_connector_fixture.operating_system_store', return_value=store), \
             patch('workflow_connector_fixture.ctypes.get_last_error', return_value=1168):
            vault = OwnedFixtureVault()
            self.addCleanup(vault.close)
            name = 'zrotext-workflow-' + 'a' * 32
            vault.delete(name)
            store.delete.assert_not_called()
            store.api.CredReadW.return_value = True
            with self.assertRaisesRegex(ValueError, 'fixture_name_already_exists'):
                vault.delete(name)
            store.delete.assert_not_called()

    def test_only_existing_desktop_custody_hints_extend_official_host_environment(self):
        environment = {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/synthetic/bus', 'XDG_RUNTIME_DIR': '/synthetic/runtime',
                       'NODE_OPTIONS': 'private input', 'NODE_EXTRA_CA_CERTS': 'private input',
                       'EXAMPLE_OWNER_CREDENTIAL': 'private input'}
        with patch.dict(os.environ, environment, clear=True), patch.object(verify.os, 'name', 'posix'):
            self.assertEqual(verify.custody_environment(), {key: environment[key] for key in
                ('DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR')})
        with patch.dict(os.environ, {'DBUS_SESSION_BUS_ADDRESS': 'private\ninput'}, clear=True), \
             patch.object(verify.os, 'name', 'posix'), self.assertRaises(verify.VerificationRefused):
            verify.custody_environment()

    @unittest.skipUnless(os.name == 'nt', 'requires Windows fixture custody API shape')
    def test_fixture_cleanup_refusal_keeps_exact_private_owned_name_receipt(self):
        from unittest.mock import Mock
        store = Mock()
        store.Entry = WindowsCredentialStore.Entry
        store.api.CredReadW.return_value = False
        store.delete.side_effect = SecretStoreError('synthetic refusal')
        with patch('workflow_connector_fixture.operating_system_store', return_value=store), \
             patch('workflow_connector_fixture.ctypes.get_last_error', return_value=1168):
            vault = OwnedFixtureVault()
            self.addCleanup(vault.receipt.unlink)
            name = 'zrotext-workflow-' + 'a' * 32
            vault.put(name, 'ztw_' + 'a' * 43)
            with self.assertRaises(SecretStoreError):
                vault.close()
            self.assertEqual(json.loads(vault.receipt.read_bytes()), {'v': 1, 'owned_names': [name]})
            self.assertNotIn('ztw_', vault.receipt.read_text())
            store.delete.assert_called_once_with(name)

    @unittest.skipUnless(os.name == 'nt', 'requires Windows fixture custody API shape')
    def test_fixture_never_overwrites_an_existing_or_malformed_credential_name(self):
        from unittest.mock import Mock
        store = Mock()
        store.Entry = WindowsCredentialStore.Entry
        store.api.CredReadW.return_value = True
        with patch('workflow_connector_fixture.operating_system_store', return_value=store):
            vault = OwnedFixtureVault()
            with self.assertRaisesRegex(ValueError, 'fixture_name_already_exists'):
                vault.put('zrotext-workflow-' + 'a' * 32, 'ztw_' + 'a' * 43)
            vault.close()
        store.put.assert_not_called()
        store.delete.assert_not_called()
        self.assertFalse(vault.names)

    def installed(self, root):
        config = root / 'client.json'
        config.write_text('{"mcpServers":{"other":{"command":"synthetic"}},"other":1}')
        if os.name == 'posix':
            config.chmod(0o600)
        broker = Path(setup.__file__).parent.parent / 'sdk/mcp/secret-broker.mjs'
        digest = setup.local.digest(broker.read_bytes())
        fingerprint = setup.local.digest(json.dumps(setup.scope(SELECTED), sort_keys=True).encode())
        proposal, _, encoded = setup.plan(config, 'mcp-json', broker, digest, 'https://gateway.example',
                                          ID, 'zrotext-workflow-' + 'a' * 32, scope_digest=fingerprint)
        config.write_bytes(encoded)
        return config, broker, digest

    def test_success_only_reports_observed_runtime_and_preserves_configuration(self):
        with tempfile.TemporaryDirectory() as scratch, contextlib.chdir(scratch):
            config, broker, digest = self.installed(Path(scratch))
            before = config.read_bytes()
            async def exchange(launch, context, remaining):
                self.assertTrue(0 < remaining <= verify.DEADLINE_SECONDS)
                self.assertEqual(launch, json.loads(before)['mcpServers'][setup.ENTRY])
                self.assertEqual(context, ID)
                return {'protocolVersion': '2025-11-25', 'authenticatedMetadata': 'observed'}
            with patch.object(verify.importlib.metadata, 'version', return_value='2.3.0'), \
                 patch.object(setup.local, 'node_runtime', return_value=('node', 'v22.16.0')), \
                 patch.object(verify, 'exchange', side_effect=exchange):
                result = verify.verify(config, 'mcp-json', broker, digest, 'https://gateway.example', SELECTED)
            self.assertEqual(result['status'], 'verified')
            self.assertFalse(result['sendAvailable'])
            self.assertEqual(result['runtime']['mcp'], '2.3.0')
            self.assertEqual(config.read_bytes(), before)
            self.assertNotIn(ID, json.dumps(result))
            self.assertNotIn('a' * 32, json.dumps(result))

    def test_scope_origin_artifact_or_entry_changes_refuse_before_spawn(self):
        with tempfile.TemporaryDirectory() as scratch, contextlib.chdir(scratch):
            config, broker, digest = self.installed(Path(scratch))
            original = config.read_bytes()
            for change in ('scope', 'origin', 'artifact', 'command', 'extra_argument', 'env'):
                with self.subTest(change=change):
                    config.write_bytes(original)
                    selected, origin, expected = dict(SELECTED), 'https://gateway.example', digest
                    if change == 'scope':
                        selected['purpose'] = 'transactional'
                    elif change == 'origin':
                        origin = 'https://foreign.example'
                    elif change == 'artifact':
                        expected = 'b' * 64
                    else:
                        value = json.loads(original)
                        entry = value['mcpServers'][setup.ENTRY]
                        if change == 'command':
                            entry['command'] = 'foreign'
                        elif change == 'env':
                            entry['env'] = {'EXAMPLE': 'foreign'}
                        else:
                            entry['args'].append('foreign')
                        config.write_text(json.dumps(value))
                    with patch.object(verify, 'exchange') as spawned, \
                         self.assertRaises((ValueError, setup.local.SetupError)):
                        verify.verify(config, 'mcp-json', broker, expected, origin, selected)
                    spawned.assert_not_called()

    def test_missing_dependency_and_raw_failures_never_leak_or_become_success(self):
        with tempfile.TemporaryDirectory() as scratch, contextlib.chdir(scratch):
            config, broker, digest = self.installed(Path(scratch))
            before = config.read_bytes()
            for failure, code in [(TimeoutError('private input'), 'deadline_exceeded'),
                                  (RuntimeError('private input'), 'connection_unknown'),
                                  (KeyboardInterrupt(), 'interrupted')]:
                with patch.object(verify.importlib.metadata, 'version', return_value='2.3.0'), \
                     patch.object(setup.local, 'node_runtime', return_value=('node', 'v22.16.0')), \
                     patch.object(verify, 'exchange', side_effect=failure):
                    result = verify.verify(config, 'mcp-json', broker, digest, 'https://gateway.example', SELECTED)
                self.assertEqual(result['status'], 'unverified')
                self.assertEqual(result['code'], code)
                self.assertNotIn('authenticatedMetadata', result)
                self.assertNotIn('private input', json.dumps(result))
                self.assertEqual(config.read_bytes(), before)
            with patch.object(verify.importlib.metadata, 'version', return_value='foreign'), \
                 patch.object(verify, 'exchange') as spawned:
                result = verify.verify(config, 'mcp-json', broker, digest, 'https://gateway.example', SELECTED)
            spawned.assert_not_called()
            self.assertEqual(result['code'], 'client_sdk_required')

    def test_scope_changed_during_exchange_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as scratch, contextlib.chdir(scratch):
            config, broker, digest = self.installed(Path(scratch))
            async def exchange(*_):
                config.write_text('{"other":2}')
                return {'authenticatedMetadata': 'observed'}
            with patch.object(verify.importlib.metadata, 'version', return_value='2.3.0'), \
                 patch.object(setup.local, 'node_runtime', return_value=('node', 'v22.16.0')), \
                 patch.object(verify, 'exchange', side_effect=exchange):
                result = verify.verify(config, 'mcp-json', broker, digest, 'https://gateway.example', SELECTED)
            self.assertEqual(result['status'], 'unverified')
            self.assertNotIn('authenticatedMetadata', result)

    def test_cli_requires_existing_entry_and_never_prompts_or_opens_custody(self):
        with tempfile.TemporaryDirectory() as scratch, contextlib.chdir(scratch):
            config, scope = Path(scratch) / 'client.json', Path(scratch) / 'scope.json'
            config.write_text('{"mcpServers":{"other":{"command":"synthetic"}}}')
            scope.write_text(json.dumps(SELECTED))
            broker = Path(setup.__file__).parent.parent / 'sdk/mcp/secret-broker.mjs'
            before = config.read_bytes()
            argv = ['setup', 'verify', '--client', 'mcp-json', '--config', str(config), '--scope', str(scope),
                    '--broker', str(broker), '--sha256', setup.local.digest(broker.read_bytes()), '--origin', 'https://gateway.example']
            with patch('sys.argv', argv), patch.object(setup, 'operating_system_store') as vault, \
                 patch.object(setup, 'OwnerSession') as owner, patch('builtins.input') as prompt, \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(setup.main(), 2)
            vault.assert_not_called()
            owner.assert_not_called()
            prompt.assert_not_called()
            self.assertEqual(config.read_bytes(), before)
            self.assertFalse(setup.intent_path(config).exists())

    def test_readiness_success_cannot_hide_metadata_authorization_refusal(self):
        class Client:
            protocol_version = '2025-11-25'
            server_info = type('Info', (), dict(name='zrotext-scoped-tools', version='0.0.0-experimental'))()
            async def list_tools(self):
                return type('Tools', (), {'tools': [type('Tool', (), {'name': name})() for name in
                                                   ['zrotext_readiness', 'workflow.context.metadata']]})()
            async def call_tool(self, name, arguments):
                body = ({'available': True, 'scope': {'context_id': ID}, 'methods': [
                    {'method': 'workflow.context.metadata', 'permission_granted': True},
                    {'method': 'workflow.action.status', 'permission_granted': True}]} if name == 'zrotext_readiness' else
                        {'available': False, 'code': 'unauthorized', 'state': 'refused', 'attempts': 1})
                return type('Result', (), dict(structured_content=body, is_error=name != 'zrotext_readiness'))()
        for code in ('unauthorized', 'forbidden', 'conflict', 'unavailable', 'response_unknown'):
            client = Client()
            original = client.call_tool
            async def call(name, arguments):
                result = await original(name, arguments)
                if result.is_error:
                    result.structured_content['code'] = code
                return result
            client.call_tool = call
            with self.subTest(code=code), self.assertRaises(verify.VerificationRefused) as outcome:
                asyncio.run(verify.check_session(client, ID))
            self.assertEqual(outcome.exception.code, code)

    def test_wrong_scope_permissions_or_protocol_never_make_metadata_call(self):
        class Client:
            protocol_version = '2025-11-25'
            server_info = SimpleNamespace(name='zrotext-scoped-tools', version='0.0.0-experimental')
            def __init__(self):
                self.calls = []
                self.ready = {'available': True, 'scope': {'context_id': ID}, 'methods': [
                    {'method': 'workflow.context.metadata', 'permission_granted': True},
                    {'method': 'workflow.action.status', 'permission_granted': True}]}
            async def list_tools(self):
                return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in
                    ('zrotext_readiness', 'workflow.context.metadata')])
            async def call_tool(self, name, arguments):
                self.calls.append(name)
                return SimpleNamespace(structured_content=self.ready, is_error=False)
        for change in ('context', 'permissions', 'protocol', 'server'):
            client = Client()
            if change == 'context':
                client.ready['scope']['context_id'] = 'foreign'
            elif change == 'permissions':
                client.ready['methods'].append({'method': 'workflow.action.send', 'permission_granted': True})
            elif change == 'protocol':
                client.protocol_version = 'unsupported'
            else:
                client.server_info = SimpleNamespace(name='foreign', version='1')
            with self.subTest(change=change), self.assertRaises(verify.VerificationRefused):
                asyncio.run(verify.check_session(client, ID))
            self.assertNotIn('workflow.context.metadata', client.calls)

    def test_malformed_or_private_error_bodies_are_redacted(self):
        for value in (None, [], {'available': False, 'code': 'private input', 'state': 'private input'},
                      {'large': 'a' * 262145}):
            with self.subTest(value=type(value)), self.assertRaises(verify.VerificationRefused) as outcome:
                verify.body(SimpleNamespace(structured_content=value, is_error=True))
            self.assertEqual(outcome.exception.code, 'invalid_response')
            self.assertNotIn('private input', str(outcome.exception))

    def test_official_task_group_refusals_preserve_only_allowlisted_single_cause(self):
        for error, expected in [(verify.VerificationRefused('unauthorized'), 'unauthorized'),
                                (verify.VerificationRefused('forbidden'), 'forbidden'),
                                (TimeoutError('private input'), 'deadline_exceeded'),
                                (ValueError('private input'), 'connection_unknown')]:
            wrapped = ExceptionGroup('private input', [ExceptionGroup('private input', [error])])
            self.assertEqual(verify.failure(wrapped).code, expected)
            self.assertNotIn('private input', str(verify.failure(wrapped)))
        mixed = ExceptionGroup('private input', [verify.VerificationRefused('unauthorized'), ValueError('private input')])
        self.assertEqual(verify.failure(mixed).code, 'connection_unknown')


if __name__ == '__main__':
    unittest.main()
