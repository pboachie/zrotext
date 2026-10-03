# SPDX-License-Identifier: AGPL-3.0-only
import json
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
              (200, {"role": "owner", "account_id": ID}), (201, {"grant_id": ID, "token": "ztw_" + "a" * 43})]) as request:
            self.assertEqual(session.login("owner@example.test", "example", lambda: "login-example"), ID)
            session.create(SELECTED, "example", "grant-example")
            self.assertEqual(request.call_args_list[1].args[2]["code"], "login-example")
            body = request.call_args_list[3].args[2]
            self.assertEqual(body["code"], "grant-example")
            self.assertEqual(body["permissions"], ["context_metadata", "status"])
            self.assertEqual(request.call_args_list[3].args[:2], ("POST", "/v1/auth/workflow-grants"))

    def test_observer_wrong_identity_and_non_https_refuse(self):
        with self.assertRaises(OwnerSetupError):
            OwnerSession("http://gateway.example", connection=Mock())
        session = OwnerSession("https://gateway.example", connection=Mock())
        with patch.object(session, "request", side_effect=[(200, {}), (200, {"role": "observer"})]):
            with self.assertRaises(OwnerSetupError):
                session.login("owner@example.test", "example", lambda: "example")
