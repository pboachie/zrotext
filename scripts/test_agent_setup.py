import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import agent_setup

class AgentSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "client.json"
        self.server = self.root / "server.mjs"
        self.server.write_text("// synthetic fixture server\n", encoding="utf-8")
        self.sha = hashlib.sha256(self.server.read_bytes()).hexdigest()

    def plan(self, remove=False):
        return agent_setup.plan_config(self.config, "mcp-json", self.server, self.sha, remove)

    def install(self):
        plan, raw, encoded = self.plan()
        return agent_setup.apply_plan(self.config, plan, raw, encoded, plan["reviewDigest"])

    def test_preview_never_writes_and_apply_preserves_other_servers(self):
        original = {"theme": "dark", "mcpServers": {"other": {"command": "synthetic-command", "env": {"credential": "SYNTHETIC_ONLY"}}}}
        self.config.write_text(json.dumps(original), encoding="utf-8")
        before = self.config.read_bytes()
        plan, raw, encoded = self.plan()
        self.assertEqual(self.config.read_bytes(), before)
        self.assertNotIn("SYNTHETIC_ONLY", json.dumps(plan))
        agent_setup.apply_plan(self.config, plan, raw, encoded, plan["reviewDigest"])
        after = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(after["mcpServers"]["other"], original["mcpServers"]["other"])
        self.assertEqual(after["theme"], "dark")

    def test_review_is_required_and_stale_preview_cannot_overwrite_changes(self):
        plan, raw, encoded = self.plan()
        with self.assertRaisesRegex(agent_setup.SetupError, "review_required"):
            agent_setup.apply_plan(self.config, plan, raw, encoded, "not-reviewed")
        self.config.write_text('{"theme":"edited"}', encoding="utf-8")
        with self.assertRaisesRegex(agent_setup.SetupError, "configuration_changed"):
            agent_setup.apply_plan(self.config, plan, raw, encoded, plan["reviewDigest"])
        self.assertEqual(json.loads(self.config.read_text())["theme"], "edited")

    def test_repeated_install_and_disconnect_are_idempotent(self):
        self.assertEqual(self.install()["action"], "install")
        before = self.config.read_bytes()
        self.assertEqual(self.install()["action"], "unchanged")
        self.assertEqual(before, self.config.read_bytes())
        plan, raw, encoded = self.plan(remove=True)
        result = agent_setup.apply_plan(self.config, plan, raw, encoded, plan["reviewDigest"])
        self.assertEqual(result["action"], "remove")
        self.assertFalse(result["grantRevoked"])
        self.assertNotIn(agent_setup.ENTRY, json.loads(self.config.read_text())["mcpServers"])
        self.assertEqual(self.plan(remove=True)[0]["action"], "unchanged")

    def test_foreign_entry_and_unsupported_clients_are_not_overwritten(self):
        self.config.write_text(json.dumps({"mcpServers": {agent_setup.ENTRY: {"command": "other"}}}), encoding="utf-8")
        for remove in (True, False):
            with self.assertRaisesRegex(agent_setup.SetupError, "entry_conflict"):
                self.plan(remove)
        with self.assertRaisesRegex(agent_setup.SetupError, "unsupported_client"):
            agent_setup.plan_config(self.config, "unsupported", self.server, self.sha)

    def test_artifact_changes_are_refused_before_install_or_launch(self):
        self.server.write_text("// changed\n", encoding="utf-8")
        with self.assertRaisesRegex(agent_setup.SetupError, "artifact_changed"):
            self.plan()
        with self.assertRaisesRegex(agent_setup.SetupError, "artifact_changed"):
            agent_setup.doctor(self.server, self.sha)

    def test_malformed_or_duplicate_configuration_is_not_repaired_destructively(self):
        for value in ('not-json', '[]', '{"value":NaN}', '{"value":Infinity}', '{"mcpServers":[]}', '{"theme":1,"theme":2}'):
            self.config.write_text(value, encoding="utf-8")
            with self.assertRaises(agent_setup.SetupError):
                self.plan()
            self.assertEqual(self.config.read_text(), value)

    def test_interrupted_write_keeps_original_and_can_be_resumed(self):
        self.config.write_text('{"theme":"before"}', encoding="utf-8")
        plan, raw, encoded = self.plan()
        with patch("agent_setup.os.replace", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                agent_setup.apply_plan(self.config, plan, raw, encoded, plan["reviewDigest"])
        self.assertEqual(self.config.read_bytes(), raw)
        self.assertFalse(self.config.with_name(self.config.name + ".zrotext-lock").exists())
        self.assertEqual(self.install()["action"], "install")

    def test_unknown_phone_readiness_is_never_reported_healthy(self):
        with patch("agent_setup.node_runtime", return_value=("synthetic-node", "v22.0.0")):
            report = agent_setup.doctor(self.server, self.sha)
        self.assertFalse(report["liveAvailable"])
        self.assertEqual(report["gates"]["androidPermissions"], "unknown")
        self.assertEqual(report["gates"]["simReadiness"], "unknown")
        self.assertEqual(report["gates"]["pairing"], "unavailable")

    def test_concurrent_installer_refuses_existing_lock(self):
        self.config.with_name(self.config.name + ".zrotext-lock").write_text("", encoding="utf-8")
        plan, raw, encoded = self.plan()
        with self.assertRaisesRegex(agent_setup.SetupError, "setup_busy"):
            agent_setup.apply_plan(self.config, plan, raw, encoded, plan["reviewDigest"])
        self.assertFalse(self.config.exists())


    def test_demo_only_sends_fixture_readiness_and_preview(self):
        replies = [{"id": 1, "result": {}}, {"id": 2, "result": {"structuredContent": {"available": False}}},
                   {"id": 3, "result": {"structuredContent": {"code": "preview_only", "cryptoVerified": False}}}]
        completed = type("Result", (), {"stdout": "\n".join(json.dumps(item) for item in replies)})()
        with patch("agent_setup.node_runtime", return_value=("synthetic-node", "v22.0.0")), \
             patch("agent_setup.subprocess.run", return_value=completed) as run:
            result = agent_setup.demo(self.server, self.sha)
        self.assertTrue(result["synthetic"])
        self.assertFalse(result["liveAvailable"])
        request = run.call_args.kwargs["input"]
        self.assertIn("zrotext_preview", request)
        self.assertNotIn("zrotext_submit", request)
        self.assertNotIn("authorization", request)

    def test_demo_refuses_unexpected_live_or_trust_claims(self):
        completed = type("Result", (), {"stdout": "private malformed fixture"})()
        with patch("agent_setup.node_runtime", return_value=("synthetic-node", "v22.0.0")), \
             patch("agent_setup.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(agent_setup.SetupError, "connector_demo_unavailable"):
                agent_setup.demo(self.server, self.sha)

    def test_disconnect_survives_missing_artifact_without_running_it(self):
        self.install()
        self.server.unlink()
        plan, raw, encoded = self.plan(remove=True)
        result = agent_setup.apply_plan(self.config, plan, raw, encoded, plan["reviewDigest"])
        self.assertEqual(result["action"], "remove")
        self.assertFalse(result["grantRevoked"])

if __name__ == "__main__":
    unittest.main()
