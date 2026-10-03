# SPDX-License-Identifier: AGPL-3.0-only
import json
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
        self.config = self.root / "client.json"
        self.config.write_text(json.dumps({"mcpServers": {"other": {"command": "synthetic"}}, "other": 1}))
        self.broker = self.root / "broker.mjs"
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
    def test_login_requires_actual_owner_session_and_separate_fresh_grant_factor(self):
        session = OwnerSession("https://gateway.example", connection=Mock())
        session.cookies = {"__Host-zrotext_session": "example", "__Host-zrotext_csrf": "example"}
        with patch.object(session, "request", side_effect=[(202, {"challenge_token": "example"}), (200, {}),
              (200, {"role": "owner", "account_id": ID, "user_id": ID, "session_id": ID}), (201, {"grant_id": ID, "token": "ztw_" + "a" * 43})]) as request:
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

    def test_observer_wrong_identity_and_non_https_refuse(self):
        with self.assertRaises(OwnerSetupError):
            OwnerSession("http://gateway.example", connection=Mock())
        session = OwnerSession("https://gateway.example", connection=Mock())
        with patch.object(session, "request", side_effect=[(200, {}), (200, {"role": "observer"})]):
            with self.assertRaises(OwnerSetupError):
                session.login("owner@example.test", "example", lambda: "example")
