# SPDX-License-Identifier: AGPL-3.0-only
import json
import contextlib
import io
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import guided_workflow_setup as setup
from workflow_owner_setup import OwnerSession, OwnerSetupError, scope
from workflow_secret_store import SecretServiceStore, SecretStoreError, WindowsCredentialStore

ID = "00000000-0000-4000-8000-000000000001"
SELECTED = dict(connector_id=ID, context_id=ID, contact_id=ID, purpose="operational", expires_at_ms=1)


class GuidedSetup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.config = self.root / "client.json"
        self.config.write_text(json.dumps({"mcpServers": {"other": {"command": "synthetic"}}, "other": 1}))
        self.home = self.root / "synthetic-home"
        self.artifact_directory = self.home / ".config" / "zrotext" / "workflow-artifacts"
        self.artifact_directory.mkdir(parents=True)
        root_patch = patch('workflow_paths.artifact_roots', return_value={
            'installed': os.path.normcase(str(Path(setup.__file__).parent.parent)),
            'home-config': os.path.normcase(str(self.artifact_directory))})
        root_patch.start()
        self.addCleanup(root_patch.stop)
        self.broker = self.artifact_directory / "broker.mjs"
        self.broker.write_text("// synthetic launcher")
        self.sha = setup.local.digest(self.broker.read_bytes())
        self.owner, self.store = Mock(), Mock()
        self.owner.origin = "https://gateway.example"
        self.owner.session_identity = dict(account_id=ID, user_id=ID, session_id=ID)
        self.owner.create.return_value = (ID, "ztw_" + "a" * 43)

    def install(self):
        return setup.install(self.config, setup.local.digest(self.config.read_bytes()), self.owner,
                             SELECTED, "example", "example", self.store, "mcp-json",
                             self.broker, self.sha, "https://gateway.example")

    def assert_capability_refuses_before_owner_effect(self):
        scope_file = self.root / "scope.json"
        scope_file.write_text(json.dumps(SELECTED))
        arguments = ["guided_workflow_setup.py", "connect", "--client", "mcp-json", "--origin", "https://gateway.example",
                     "--config", str(self.config), "--scope", str(scope_file), "--broker", str(self.broker), "--sha256", self.sha]
        error = io.StringIO()
        with patch.object(sys, "argv", arguments), patch.object(setup, "OwnerSession", return_value=self.owner) as session, \
             patch.object(setup, "operating_system_store", return_value=self.store) as vault, \
             patch.object(setup.getpass, "getpass") as prompt, patch("builtins.input") as confirmation, \
             contextlib.redirect_stderr(error), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(), 2)
        session.assert_not_called()
        vault.assert_not_called()
        prompt.assert_not_called()
        confirmation.assert_not_called()
        self.assertNotIn("Traceback", error.getvalue())
        self.owner.create.assert_not_called()
        self.store.put.assert_not_called()
        self.assertFalse(setup.intent_path(self.config).exists())

    def test_forbidden_artifact_capability_refuses_before_authentication_or_custody(self):
        with patch.object(setup, "setup_artifact_root", side_effect=ValueError("guided_path_refused")):
            self.assert_capability_refuses_before_owner_effect()
            with self.assertRaisesRegex(ValueError, "^guided_path_refused$"):
                self.install()

    @unittest.skipUnless(os.name == "posix", "requires POSIX artifact modes")
    def test_writable_artifact_root_and_ancestor_refuse_before_authentication(self):
        for selected in (self.artifact_directory, self.home):
            original = selected.stat().st_mode & 0o777
            try:
                selected.chmod(0o775)
                self.assert_capability_refuses_before_owner_effect()
            finally:
                selected.chmod(original)

    @unittest.skipUnless(os.name == "posix", "requires POSIX ownership checks")
    def test_foreign_artifact_root_owner_refuses_before_authentication(self):
        from types import SimpleNamespace
        real_lstat = os.lstat
        def foreign_owner(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if Path(path) == self.artifact_directory:
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                fields["st_uid"] = os.getuid() + 1
                return SimpleNamespace(**fields)
            return info
        with patch("workflow_paths.os.lstat", side_effect=foreign_owner):
            self.assert_capability_refuses_before_owner_effect()

    def test_selected_custom_cwd_accepts_inside_and_refuses_sibling_and_traversal(self):
        from workflow_paths import checked_path
        self.assertEqual(checked_path(self.config), self.config)
        sibling = self.root.with_name(self.root.name + "-foreign") / "client.json"
        for value in (sibling, self.root / ".." / "foreign.json", Path("relative.json"), Path("//foreign/share/client.json")):
            with self.assertRaisesRegex(ValueError, "guided_path_refused"):
                checked_path(value)

    def test_parent_replacement_after_remote_issuance_preserves_foreign_config(self):
        moved = self.root / "selected"
        moved.mkdir()
        selected = moved / "client.json"
        selected.write_text('{}')
        prior = self.root / "old-selected"
        def store_after_issuance(*_):
            moved.rename(prior)
            moved.mkdir()
            selected.write_text('{"foreign":true}')
        self.store.put.side_effect = store_after_issuance
        with self.assertRaisesRegex(ValueError, "guided_path_refused"):
            setup.install(selected, setup.local.digest(b'{}'), self.owner, SELECTED, "example", "example",
                          self.store, "mcp-json", self.broker, self.sha, "https://gateway.example")
        self.assertEqual(selected.read_text(), '{"foreign":true}')
        self.owner.revoke.assert_called_once_with(ID)

    def test_cli_fixed_status_never_prints_result_secret_canary(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['guided_workflow_setup.py', 'simulator']), \
             patch.object(setup.local, 'journey', return_value={'secret': 'synthetic-private-canary'}), \
             contextlib.redirect_stdout(output):
            self.assertEqual(setup.main(), 0)
        self.assertNotIn('synthetic-private-canary', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'], 'completed')

    def test_cli_unknown_recovery_never_prints_exception_metadata_canary(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['guided_workflow_setup.py', 'simulator']), \
             patch.object(setup.local, 'journey', side_effect=setup.SetupRecovery('synthetic-private-canary', 'synthetic-private-canary')), \
             contextlib.redirect_stderr(output):
            self.assertEqual(setup.main(), 2)
        self.assertNotIn('synthetic-private-canary', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['state'], 'unknown')

    def test_cli_outside_config_refuses_before_authentication(self):
        outside = self.root.with_name(self.root.name + '-outside') / 'client.json'
        args = ['guided_workflow_setup.py', 'connect', '--client', 'mcp-json', '--origin', 'https://gateway.example',
                '--config', str(outside), '--scope', str(self.config), '--broker', str(self.broker), '--sha256', self.sha]
        with patch.object(sys, 'argv', args), patch.object(setup, 'OwnerSession') as session, \
             patch.object(setup.getpass, 'getpass') as prompt, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(setup.main(), 2)
        session.assert_not_called()
        prompt.assert_not_called()

    def test_custom_cwd_only_broker_refuses_before_authentication(self):
        unsupported = self.root / 'unapproved.mjs'
        unsupported.write_text('// synthetic unsupported artifact')
        args = ['guided_workflow_setup.py', 'connect', '--client', 'mcp-json', '--origin', 'https://gateway.example',
                '--config', str(self.config), '--scope', str(self.config), '--broker', str(unsupported),
                '--sha256', setup.local.digest(unsupported.read_bytes())]
        with patch.object(sys, 'argv', args), patch.object(setup, 'OwnerSession') as session, \
             patch.object(setup.getpass, 'getpass') as prompt, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(setup.main(), 2)
        session.assert_not_called()
        prompt.assert_not_called()

    def test_malformed_stored_selector_refuses_without_new_grant(self):
        self.install()
        original = json.loads(self.config.read_text())
        for selector in (None, [], {}, 'alternate'):
            configuration = json.loads(json.dumps(original))
            configuration['mcpServers'][setup.ENTRY]['args'][13] = selector
            self.config.write_text(json.dumps(configuration))
            with self.assertRaisesRegex((ValueError, setup.local.SetupError), 'guided_path_refused|entry_conflict'):
                self.install()
        self.assertEqual(self.owner.create.call_count, 1)

    def test_malformed_existing_entry_and_servers_refuse_before_authentication(self):
        scope_file = self.root / 'scope.json'
        scope_file.write_text(json.dumps(SELECTED))
        arguments = ['guided_workflow_setup.py', 'connect', '--client', 'mcp-json', '--origin', 'https://gateway.example',
                     '--config', str(self.config), '--scope', str(scope_file), '--broker', str(self.broker), '--sha256', self.sha]
        for servers in ({setup.ENTRY: None}, {setup.ENTRY: 1}, {setup.ENTRY: []}, []):
            self.config.write_text(json.dumps({'mcpServers': servers}))
            output = io.StringIO()
            with patch.object(sys, 'argv', arguments), patch.object(setup, 'OwnerSession') as session, \
                 patch.object(setup.getpass, 'getpass') as prompt, contextlib.redirect_stderr(output):
                self.assertEqual(setup.main(), 2)
            session.assert_not_called()
            prompt.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['code'], 'guided_setup_refused')
        self.owner.create.assert_not_called()

    def test_actual_cli_malformed_recorded_arguments_refuse_without_auth_or_traceback(self):
        self.install()
        original = json.loads(self.config.read_text())
        scope_file = self.root / 'scope.json'
        scope_file.write_text(json.dumps(SELECTED))
        arguments = ['guided_workflow_setup.py', 'connect', '--client', 'mcp-json', '--origin', 'https://gateway.example',
                     '--config', str(self.config), '--scope', str(scope_file), '--broker', str(self.broker), '--sha256', self.sha]
        malformed = [None, 'not-an-array', {str(i): 'synthetic' for i in range(16)}, [None]*16]
        for args in malformed:
            configuration = json.loads(json.dumps(original))
            configuration['mcpServers'][setup.ENTRY]['args'] = args
            self.config.write_text(json.dumps(configuration))
            output = io.StringIO()
            with patch.object(sys, 'argv', arguments), patch.object(setup, 'OwnerSession') as session, \
                 patch.object(setup.getpass, 'getpass') as prompt, contextlib.redirect_stderr(output):
                self.assertEqual(setup.main(), 2)
            session.assert_not_called()
            prompt.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['code'], 'guided_setup_refused')
            self.assertNotIn('Traceback', output.getvalue())
        self.assertEqual(self.owner.create.call_count, 1)

    def test_generated_custom_broker_launcher_survives_changed_desktop_cwd(self):
        self.broker.write_text("""let raw='';process.stdin.on('data',b=>{raw+=b; if(raw.includes('\\n')){const v=JSON.parse(raw.split('\\n')[0]);if(v.v!==1||!v.credential.startsWith('ztw_'))process.exit(2); console.log(JSON.stringify({started:true,leaked:!!process.env.SYNTHETIC_OWNER_CANARY}));process.exit(0)}});""")
        self.sha = setup.local.digest(self.broker.read_bytes())
        self.install()
        selected = json.loads(self.config.read_text())['mcpServers'][setup.ENTRY]
        self.assertEqual(selected['args'][12:14], ['--artifact-root', 'home-config'])
        other = self.root / 'desktop'
        other.mkdir()
        program = """import json,sys
sys.path.insert(0,sys.argv[1])
import guided_workflow_setup as setup
class Vault:
 def get(self,name): return 'ztw_'+'a'*43
setup.operating_system_store=lambda:Vault()
args=json.loads(sys.stdin.buffer.readline())
sys.argv=args
raise SystemExit(setup.main())
"""
        env = dict(os.environ, SYNTHETIC_OWNER_CANARY='synthetic-private-canary',
                   HOME=str(self.home), USERPROFILE=str(self.home))
        result = subprocess.run([sys.executable, '-c', program, str(Path(setup.__file__).parent)],
                                input=(json.dumps(selected['args'])+'\n').encode(), capture_output=True,
                                cwd=other, env=env, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(json.loads(result.stdout), {'started': True, 'leaked': False})
        self.assertNotIn(b'ztw_', result.stdout)

    def test_launcher_capability_rejects_volume_sibling_and_changed_pin_before_vault(self):
        from workflow_paths import artifact_capability, checked_path
        with self.assertRaisesRegex(ValueError, 'guided_path_refused'):
            artifact_capability(Path(self.root.anchor))
        sibling = self.root.with_name(self.root.name + '-sibling') / 'broker.mjs'
        with self.assertRaisesRegex(ValueError, 'guided_path_refused'):
            checked_path(sibling, artifact=True, approved_artifact_root='home-config')
        with self.assertRaisesRegex(setup.local.SetupError, 'artifact_changed'):
            setup.launch(self.broker, '0'*64, 'https://gateway.example', 'zrotext-workflow-'+'a'*32,
                         self.store, 'home-config')
        self.store.get.assert_not_called()

    def test_changed_reviewed_artifact_root_refuses_resume_without_new_mint(self):
        self.install()
        configuration = json.loads(self.config.read_text())
        configuration['mcpServers'][setup.ENTRY]['args'][13] = 'installed'
        self.config.write_text(json.dumps(configuration))
        with self.assertRaisesRegex(ValueError, 'guided_path_refused'):
            self.install()
        self.assertEqual(self.owner.create.call_count, 1)

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX artifact modes')
    def test_readable_nonwritable_artifact_root_is_supported(self):
        from workflow_paths import artifact_capability
        self.artifact_directory.chmod(0o755)
        self.assertEqual(artifact_capability('home-config'), str(self.artifact_directory))

    def test_hardlinked_config_refuses_before_owner_effect_and_preserves_other_link(self):
        target = self.root / 'foreign.json'
        os.link(self.config, target)
        before = target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'guided_path_refused'):
            self.install()
        self.owner.create.assert_not_called()
        self.assertEqual(target.read_bytes(), before)

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX mode enforcement')
    def test_nested_world_writable_config_directory_refuses_before_grant(self):
        nested = self.root / 'writable'
        nested.mkdir(mode=0o777)
        nested.chmod(0o777)
        target = nested / 'client.json'
        target.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'guided_path_refused'):
            setup.install(target, setup.local.digest(b'{}'), self.owner, SELECTED, 'example', 'example',
                          self.store, 'mcp-json', self.broker, self.sha, 'https://gateway.example')
        self.owner.create.assert_not_called()

    def test_staged_file_substitution_refuses_replace_and_preserves_foreign_file(self):
        proposal, raw, encoded = setup.plan(self.config, 'mcp-json', self.broker, self.sha,
                                           'https://gateway.example', ID, 'zrotext-workflow-' + 'a' * 32)
        from workflow_paths import ParentGuard
        guard = ParentGuard(self.config)
        original_read = setup.local.read_config
        calls = 0
        foreign = None
        def read(path):
            nonlocal calls, foreign
            calls += 1
            if calls == 2:
                foreign = next(self.root.glob('.zrotext-*'))
                foreign.rename(self.root / 'owned-original-stage')
                foreign.write_text('synthetic-foreign-stage')
            return original_read(path)
        before = self.config.read_bytes()
        with patch.object(setup.local, 'read_config', side_effect=read):
            with self.assertRaisesRegex(setup.local.SetupError, 'configuration_changed'):
                setup.local.apply_plan(self.config, proposal, raw, encoded, proposal['reviewDigest'], path_check=guard.check)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(foreign.read_text(), 'synthetic-foreign-stage')

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX symlink creation')
    def test_alias_artifact_and_receipt_refused_without_reading_target(self):
        from workflow_paths import checked_path, artifact_capability
        alias = self.root / 'alias.mjs'
        alias.symlink_to(self.broker)
        with self.assertRaisesRegex(ValueError, 'guided_path_refused'):
            checked_path(alias, artifact=True)
        receipt = setup.intent_path(self.config)
        receipt.symlink_to(self.broker)
        with self.assertRaisesRegex(ValueError, 'guided_path_refused'):
            setup.read_intent(self.config)
        directory_alias = self.root / 'directory-alias'
        directory_alias.symlink_to(self.root, target_is_directory=True)
        with patch('workflow_paths.artifact_roots', return_value={'home-config': str(directory_alias)}):
            with self.assertRaisesRegex(ValueError, 'guided_path_refused'):
                artifact_capability('home-config')

    def test_actual_install_preserves_other_servers_and_never_stores_owner_or_narrow_secret_in_config(self):
        result = self.install()
        config = json.loads(self.config.read_text())
        self.assertEqual(config["mcpServers"]["other"], {"command": "synthetic"})
        self.assertEqual(config["other"], 1)
        self.assertNotIn("ztw_", self.config.read_text())
        self.store.put.assert_called_once()
        self.assertFalse(result["sendAvailable"])
        self.assertFalse(result["pairingCreated"])

    def test_config_change_refuses_before_grant_and_storage_failure_revokes(self):
        with self.assertRaises(setup.local.SetupError):
            setup.install(self.config, "changed", self.owner, SELECTED, "example", "example",
                          self.store, "mcp-json", self.broker, self.sha, "https://gateway.example")
        self.owner.create.assert_not_called()
        self.store.put.side_effect = SecretStoreError("secret_store_unavailable")
        before = self.config.read_bytes()
        with self.assertRaises(SecretStoreError):
            self.install()
        self.owner.revoke.assert_called_once_with(ID)
        self.assertEqual(self.config.read_bytes(), before)

    def test_disconnect_refusal_preserves_config_and_secret_until_remote_revoke(self):
        result = self.install()
        proposal, _, _ = setup.plan(self.config, "mcp-json", self.broker, self.sha,
                                    "https://gateway.example", ID, result["secret_reference"], True)
        self.owner.revoke.side_effect = OwnerSetupError("revocation_unconfirmed")
        before = self.config.read_bytes()
        with self.assertRaises(OwnerSetupError):
            setup.disconnect(self.config, "mcp-json", self.broker, self.sha, "https://gateway.example",
                             ID, result["secret_reference"], proposal["reviewDigest"], self.owner, self.store)
        self.assertEqual(self.config.read_bytes(), before)
        self.store.delete.assert_not_called()
        self.owner.revoke.side_effect = None
        setup.disconnect(self.config, "mcp-json", self.broker, self.sha, "https://gateway.example",
                         ID, result["secret_reference"], proposal["reviewDigest"], self.owner, self.store)
        self.assertNotIn(setup.ENTRY, json.loads(self.config.read_text())["mcpServers"])
        self.store.delete.assert_called_once()

    def test_unknown_issuance_is_durable_and_never_mints_on_restart(self):
        self.owner.create.side_effect = OwnerSetupError("owner_response_unknown")
        with self.assertRaises(OwnerSetupError):
            self.install()
        self.owner.create.side_effect = None
        with self.assertRaisesRegex(OwnerSetupError, "setup_recovery_required"):
            self.install()
        self.owner.create.assert_called_once()
        self.store.put.assert_not_called()

    def test_success_retains_only_remote_creator_and_failed_setup_does_not(self):
        self.install()
        self.assertTrue(self.owner.retain_creator)
        receipt = self.config.with_name(self.config.name + ".zrotext-grant-intent").read_text()
        self.assertNotIn("ztw_", receipt)
        self.assertNotIn("current_password", receipt)

    def test_existing_conflict_refuses_before_authentication_or_grant(self):
        self.config.write_text(json.dumps({"mcpServers": {setup.ENTRY: {"command": "foreign"}}}))
        with self.assertRaisesRegex(setup.local.SetupError, "entry_conflict"):
            setup.preflight(self.config, "mcp-json", self.broker, self.sha,
                            "https://gateway.example", SELECTED)
        self.owner.login.assert_not_called()
        self.owner.create.assert_not_called()

    def test_unsupported_client_refuses_before_grant(self):
        with self.assertRaises(setup.local.SetupError):
            setup.install(self.config, setup.local.digest(self.config.read_bytes()), self.owner,
                          SELECTED, "example", "example", self.store, "unsupported",
                          self.broker, self.sha, "https://gateway.example")
        self.owner.create.assert_not_called()

    def test_unknown_creator_revocation_preserves_receipt_and_confirmed_retry_allows_new_setup(self):
        self.owner.create.side_effect = OwnerSetupError("owner_response_unknown")
        with self.assertRaises(OwnerSetupError):
            self.install()
        receipt = setup.intent_path(self.config)
        raw = receipt.read_bytes()
        self.owner.revoke_creator.side_effect = OwnerSetupError("owner_response_unknown")
        with self.assertRaises(OwnerSetupError):
            setup.recover(self.config, setup.local.digest(raw), self.owner, self.store)
        self.assertEqual(receipt.read_bytes(), raw)
        self.store.delete.assert_not_called()
        self.owner.revoke_creator.side_effect = None
        result = setup.recover(self.config, setup.local.digest(raw), self.owner, self.store)
        self.assertTrue(result["creatorSessionRevoked"])
        self.assertFalse(receipt.exists())
        self.owner.create.side_effect = None
        self.install()
        self.assertEqual(self.owner.create.call_count, 2)

    def test_persisted_intent_and_parent_flush_precede_remote_effect_and_fail_closed(self):
        events = []
        def persisted(path):
            value = setup.read_intent(self.config)
            self.assertEqual(value["state"], "issuance_unknown")
            self.assertEqual(value["creator"], self.owner.session_identity)
            events.append("parent_flushed")
        def create(*_):
            self.assertEqual(events, ["parent_flushed"])
            events.append("remote_effect")
            return ID, "ztw_" + "a" * 43
        self.owner.create.side_effect = create
        with patch.object(setup, "persist_parent", side_effect=persisted):
            self.install()
        self.assertEqual(events, ["parent_flushed", "remote_effect"])

    def test_parent_flush_failure_never_issues_and_keeps_recovery_intent(self):
        with patch.object(setup, "persist_parent", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                self.install()
        self.owner.create.assert_not_called()
        self.assertEqual(setup.read_intent(self.config)["state"], "issuance_unknown")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named pipes")
    def test_fifo_receipt_refuses_both_reads_and_recovery_without_blocking(self):
        os.mkfifo(setup.intent_path(self.config))
        program = """import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import guided_workflow_setup as setup
try:
    if sys.argv[3] == 'read': setup.read_intent(Path(sys.argv[2]))
    else: setup.recover(Path(sys.argv[2]), 'unused', None, None)
except setup.OwnerSetupError:
    print('refused')
except ValueError as error:
    if str(error) != 'guided_path_refused': raise
    print('refused')
else:
    raise SystemExit(2)
"""
        for operation in ("read", "recover"):
            result = subprocess.run([sys.executable, "-c", program, str(Path(setup.__file__).parent),
                                     str(self.config), operation], capture_output=True, timeout=2, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), b"refused")

    def test_posix_delete_confirms_absence_and_refuses_remaining_locked_or_error_state(self):
        with patch("workflow_secret_store.shutil.which", return_value="synthetic-tool"), patch("workflow_secret_store.subprocess.run") as run:
            store = SecretServiceStore()
            name = "zrotext-workflow-" + "a" * 32
            run.side_effect = [Mock(returncode=1, stdout=b"", stderr=b""), Mock(returncode=0, stdout=b"", stderr=b"")]
            store.delete(name)
            self.assertEqual(run.call_args_list[-1].args[0][1:3], ["search", "--all"])
            for remaining in (Mock(returncode=0, stdout=b"synthetic-item", stderr=b""),
                              Mock(returncode=1, stdout=b"", stderr=b"synthetic-unavailable")):
                run.side_effect = [Mock(returncode=0, stdout=b"", stderr=b""), remaining]
                with self.assertRaisesRegex(SecretStoreError, "^secret_store_unavailable$"):
                    store.delete(name)

    def test_unknown_effect_reports_unknown_without_arbitrary_error_text_or_retry(self):
        result = setup.refusal(OwnerSetupError("owner_response_unknown"))
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["automaticRetry"])
        result = setup.refusal(OSError("synthetic-private-canary"))
        self.assertEqual(result["state"], "unknown")
        self.assertNotIn("synthetic-private-canary", json.dumps(result))

    def test_no_scope_widening_and_no_plaintext_fallback(self):
        self.assertEqual(scope(SELECTED)["permissions"], ["context_metadata", "status"])
        with self.assertRaises(OwnerSetupError):
            scope(dict(SELECTED, permissions=["send"]))
        with patch("workflow_secret_store.shutil.which", return_value=None):
            with self.assertRaises(SecretStoreError):
                SecretServiceStore()

    def test_rerun_resumes_exact_entry_without_minting_another_grant(self):
        first = self.install()
        second = self.install()
        self.assertEqual(second["action"], "resumed")
        self.assertEqual(second["grant_id"], first["grant_id"])
        self.owner.create.assert_called_once()
        self.store.get.assert_called_once_with(first["secret_reference"])

    def test_posix_adapter_passes_secret_only_on_stdin_and_errors_are_fixed(self):
        with patch("workflow_secret_store.shutil.which", return_value="synthetic-tool"), patch("workflow_secret_store.subprocess.run") as run:
            run.return_value = Mock(returncode=0, stdout=b"")
            store = SecretServiceStore()
            value = "ztw_" + "b" * 43
            store.put("zrotext-workflow-" + "a" * 32, value)
            self.assertNotIn(value, str(run.call_args.args))
            self.assertEqual(run.call_args.kwargs["input"], value.encode())
            run.side_effect = OSError("synthetic-private-canary")
            with self.assertRaisesRegex(SecretStoreError, "^secret_store_unavailable$"):
                store.get("zrotext-workflow-" + "a" * 32)

    def test_windows_native_structure_does_not_depend_on_posix_mode(self):
        import ctypes
        self.assertEqual(WindowsCredentialStore.Entry.CredentialBlob.offset % ctypes.sizeof(ctypes.c_void_p), 0)
        # No real Credential Manager access in synthetic tests.

    def test_windows_adapter_invokes_real_abi_shape_with_narrow_blob_and_current_user_persistence(self):
        import ctypes
        api = Mock()
        seen = {}
        def write(pointer, flags):
            value = ctypes.cast(pointer, ctypes.POINTER(WindowsCredentialStore.Entry)).contents
            seen.update(target=value.TargetName, kind=value.Type, persistence=value.Persist,
                        blob=ctypes.string_at(value.CredentialBlob, value.CredentialBlobSize))
            return True
        api.CredWriteW.side_effect = write
        with patch("workflow_secret_store.os.name", "nt"), patch("workflow_secret_store.ctypes.WinDLL", return_value=api, create=True):
            store = WindowsCredentialStore()
            value = "ztw_" + "a" * 43
            store.put("zrotext-workflow-" + "a" * 32, value)
            self.assertEqual(seen["blob"], value.encode())
            self.assertEqual((seen["kind"], seen["persistence"]), (1, 2))
            store.delete(seen["target"])
            api.CredDeleteW.assert_called_once_with(seen["target"], 1, 0)

    def test_windows_read_wipes_native_copy_before_free_without_real_vault(self):
        import ctypes
        api = Mock()
        raw = (ctypes.c_ubyte * 47).from_buffer_copy(("ztw_" + "a" * 43).encode())
        entry = WindowsCredentialStore.Entry(CredentialBlobSize=47, CredentialBlob=raw)
        def read(_name, _kind, _flags, result):
            pointer = ctypes.cast(result, ctypes.POINTER(ctypes.POINTER(WindowsCredentialStore.Entry)))
            pointer[0] = ctypes.pointer(entry)
            return True
        api.CredReadW.side_effect = read
        api.CredFree.side_effect = lambda _pointer: self.assertEqual(bytes(raw), bytes(47))
        with patch("workflow_secret_store.os.name", "nt"), patch("workflow_secret_store.ctypes.WinDLL", return_value=api, create=True):
            store = WindowsCredentialStore()
            self.assertEqual(store.get("zrotext-workflow-" + "a" * 32), "ztw_" + "a" * 43)
            api.CredFree.assert_called_once()

    def test_uncertain_revoke_returns_only_recoverable_identity_without_deleting_custody(self):
        self.store.put.side_effect = SecretStoreError("secret_store_unavailable")
        self.owner.revoke.side_effect = OwnerSetupError("revocation_unconfirmed")
        with self.assertRaises(setup.SetupRecovery) as error:
            self.install()
        self.assertEqual(error.exception.grant, ID)
        self.assertTrue(error.exception.secret.startswith("zrotext-workflow-"))
        self.store.delete.assert_not_called()


class OwnerHttp(unittest.TestCase):
    def test_raw_session_clock_keeps_only_original_identity(self):
        valid = {"account_id": ID, "user_id": ID, "session_id": ID,
                 "role": "owner", "server_now_ms": "9223372036854775807"}
        connection = Mock()
        login = Mock(status=204)
        login.read.return_value = b""
        login.getheaders.return_value = []
        current = Mock(status=200)
        current.read.return_value = json.dumps(valid).encode("utf-8")
        current.getheaders.return_value = []
        connection.getresponse.side_effect = [login, current]
        session = OwnerSession("https://gateway.example", connection=connection)
        session.cookies = {"__Host-zrotext_session": "example", "__Host-zrotext_csrf": "example"}
        self.assertEqual(session.login("owner@example.test", "example", lambda: "example"), ID)
        self.assertEqual(session.session_identity, {"account_id": ID, "user_id": ID, "session_id": ID})
        self.assertEqual(connection.request.call_count, 2)

    def test_raw_duplicate_or_non_utf8_session_refuses_without_retry(self):
        valid = json.dumps({"account_id": ID, "user_id": ID, "session_id": ID,
                            "role": "owner", "server_now_ms": "1"}, separators=(",", ":"))
        malformed = [
            '{"server_now_ms":"0",' + valid[1:],
            '{"\\u0073erver_now_ms":"0",' + valid[1:],
            '{"account_id":"invalid",' + valid[1:],
            '{"user_id":"invalid",' + valid[1:],
            '{"session_id":"invalid",' + valid[1:],
            '{"role":"observer",' + valid[1:],
        ]
        raw_values = [value.encode("utf-8") for value in malformed]
        raw_values += [valid.encode("utf-16"), b"\xff" + valid.encode("utf-8")]
        for raw in raw_values:
            with self.subTest(raw=raw):
                connection = Mock()
                login = Mock(status=204)
                login.read.return_value = b""
                login.getheaders.return_value = []
                current = Mock(status=200)
                current.read.return_value = raw
                current.getheaders.return_value = []
                connection.getresponse.side_effect = [login, current]
                session = OwnerSession("https://gateway.example", connection=connection)
                session.cookies = {"__Host-zrotext_session": "example", "__Host-zrotext_csrf": "example"}
                with self.assertRaisesRegex(OwnerSetupError, "^owner_response_unknown$"):
                    session.login("owner@example.test", "example", lambda: "example")
                self.assertIsNone(session.session_identity)
                self.assertEqual(connection.request.call_count, 2)

    def test_login_requires_actual_owner_session_and_separate_fresh_grant_factor(self):
        session = OwnerSession("https://gateway.example", connection=Mock())
        session.cookies = {"__Host-zrotext_session": "example", "__Host-zrotext_csrf": "example"}
        with patch.object(session, "request", side_effect=[(202, {"challenge_token": "example"}), (204, None),
              (200, {"role": "owner", "account_id": ID, "user_id": ID, "session_id": ID, "server_now_ms": "1"}), (201, {"grant_id": ID, "token": "ztw_" + "a" * 43})]) as request:
            self.assertEqual(session.login("owner@example.test", "example", lambda: "login-example"), ID)
            session.create(SELECTED, "example", "grant-example")
            self.assertEqual(request.call_args_list[1].args[2]["code"], "login-example")
            body = request.call_args_list[3].args[2]
            self.assertEqual(body["code"], "grant-example")
            self.assertEqual(body["permissions"], ["context_metadata", "status"])
            self.assertEqual(request.call_args_list[3].args[:2], ("POST", "/v1/auth/workflow-grants"))

    def test_teardown_discards_local_cookies_without_revoking_successful_creator(self):
        connection = Mock()
        session = OwnerSession("https://gateway.example", connection=connection)
        session.cookies = {"__Host-zrotext_session": "example"}
        session.retain_creator = True
        with patch.object(session, "request") as request:
            session.close()
            request.assert_not_called()
        self.assertEqual(session.cookies, {})
        connection.close.assert_called_once()
        session.cookies = {"__Host-zrotext_session": "example"}
        session.retain_creator = False
        with patch.object(session, "request") as request:
            session.close()
            request.assert_called_once_with("POST", "/v1/auth/logout")

    def test_recovery_rejects_foreign_identity_before_session_revoke(self):
        session = OwnerSession("https://gateway.example", connection=Mock())
        session.session_identity = dict(account_id=ID, user_id=ID, session_id=ID)
        foreign = dict(session.session_identity, user_id="00000000-0000-4000-8000-000000000002")
        with patch.object(session, "request", return_value=(204, None)) as request:
            with self.assertRaisesRegex(OwnerSetupError, "recovery_identity_refused"):
                session.revoke_creator(foreign)
            request.assert_not_called()
            session.revoke_creator(session.session_identity)
            # Mock does not produce a confirmed response; tested below with 204.

    def test_login_rejects_legacy_mock_success_status_before_session_read(self):
        session = OwnerSession("https://gateway.example", connection=Mock())
        with patch.object(session, "request", return_value=(200, {})) as request:
            with self.assertRaisesRegex(OwnerSetupError, "owner_authentication_refused"):
                session.login("owner@example.test", "example", lambda: "example")
            self.assertEqual(request.call_count, 1)

    def test_observer_wrong_identity_and_non_https_refuse(self):
        with self.assertRaises(OwnerSetupError):
            OwnerSession("http://gateway.example", connection=Mock())
        session = OwnerSession("https://gateway.example", connection=Mock())
        with patch.object(session, "request", side_effect=[(200, {}), (200, {"role": "observer"})]):
            with self.assertRaises(OwnerSetupError):
                session.login("owner@example.test", "example", lambda: "example")


    def test_session_time_accepts_positive_i64_without_retaining_an_authority_field(self):
        for clock in ("1", "9223372036854775807"):
            with self.subTest(clock=clock):
                session = OwnerSession("https://gateway.example", connection=Mock())
                session.cookies = {"__Host-zrotext_session": "example", "__Host-zrotext_csrf": "example"}
                value = {"account_id": ID, "user_id": ID, "session_id": ID,
                         "role": "owner", "server_now_ms": clock}
                with patch.object(session, "request", side_effect=[(204, None), (200, value)]) as request:
                    self.assertEqual(session.login("owner@example.test", "example", lambda: "example"), ID)
                    self.assertEqual(session.session_identity, {"account_id": ID, "user_id": ID, "session_id": ID})
                    self.assertEqual(request.call_count, 2)

    def test_session_time_and_exact_owner_scope_refuse_without_retry_or_identity(self):
        valid = {"account_id": ID, "user_id": ID, "session_id": ID,
                 "role": "owner", "server_now_ms": "1"}
        values = [dict(valid, server_now_ms=clock) for clock in
                  (None, True, 1, "0", "01", "-1", "1e3", "9223372036854775808", "9" * 20)]
        values += [{key: value for key, value in valid.items() if key != "server_now_ms"},
                   dict(valid, unexpected="field"), dict(valid, role="observer")]
        values += [dict(valid, **{key: "invalid"}) for key in ("account_id", "user_id", "session_id")]
        for value in values:
            with self.subTest(value=value):
                session = OwnerSession("https://gateway.example", connection=Mock())
                session.cookies = {"__Host-zrotext_session": "example", "__Host-zrotext_csrf": "example"}
                with patch.object(session, "request", side_effect=[(204, None), (200, value)]) as request:
                    with self.assertRaises(OwnerSetupError):
                        session.login("owner@example.test", "example", lambda: "example")
                    self.assertIsNone(session.session_identity)
                    self.assertEqual(request.call_count, 2)

    def test_valid_clock_does_not_replace_both_required_current_cookies(self):
        for missing in ("__Host-zrotext_session", "__Host-zrotext_csrf"):
            with self.subTest(missing=missing):
                session = OwnerSession("https://gateway.example", connection=Mock())
                session.cookies = {"__Host-zrotext_session": "example", "__Host-zrotext_csrf": "example"}
                del session.cookies[missing]
                value = {"account_id": ID, "user_id": ID, "session_id": ID,
                         "role": "owner", "server_now_ms": "1"}
                with patch.object(session, "request", side_effect=[(204, None), (200, value)]) as request:
                    with self.assertRaisesRegex(OwnerSetupError, "^invalid_session$"):
                        session.login("owner@example.test", "example", lambda: "example")
                    self.assertIsNone(session.session_identity)
                    self.assertEqual(request.call_count, 2)
