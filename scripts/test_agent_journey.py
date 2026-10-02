"""Closed guided-fixture output and credential-free launcher regressions."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import agent_setup


def fixture_report():
    return {"synthetic": True, "version": 1, "mode": "guided-local-fixture", "available": False,
            "transport": "shared-synthetic-adapter", "replyTrust": "pinned-public-test-vector-only",
            "ownerApproval": "unavailable", "radioSubmission": "unavailable", "carrierDelivery": "unverified",
            "modelProviderAccess": "none", "checkpointLifetime": "one-command",
            "steps": [{"step": step, "state": state, "synthetic": True, "available": False,
                       "content": "unavailable", "modelProviderAccess": "none"}
                      for step, state in agent_setup.JOURNEY_STATES.items()],
            "accounting": {"notificationIdentities": 1, "notificationAttempts": 1,
                           "replyIdentities": 2, "replyTurns": 1, "unknownIdentities": 1, "unknownAttempts": 1}}


class AgentJourneyTests(unittest.TestCase):
    def test_complete_closed_response_rejects_preview_live_claims_extra_fields_and_duplicate_steps(self):
        self.assertEqual(agent_setup.checked_journey(fixture_report()), fixture_report())
        mutations = [lambda value: value.update(ownerApproval="approved"),
                     lambda value: value.update(available=True),
                     lambda value: value.update(privateContent="SYNTHETIC_ONLY"),
                     lambda value: value["steps"].pop(),
                     lambda value: value["steps"].__setitem__(1, value["steps"][0]),
                     lambda value: value["steps"][0].update(messageId="caller_queue_id"),
                     lambda value: value["accounting"].update(unknownAttempts=2),
                     lambda value: value["accounting"].update(unknownAttempts=True)]
        for mutate in mutations:
            value = copy.deepcopy(fixture_report())
            mutate(value)
            with self.assertRaises(agent_setup.SetupError):
                agent_setup.checked_journey(value)
        with self.assertRaises(agent_setup.SetupError):
            agent_setup.checked_journey({"firstExchange": "SDK fixture preview"})

    def test_launcher_uses_fixed_composition_without_inherited_credentials_or_node_options(self):
        completed = type("Result", (), {"stdout": json.dumps(fixture_report()), "stderr": ""})()
        with patch("agent_setup.node_runtime", return_value=("synthetic-node", "v22.0.0")), \
                patch.dict("agent_setup.os.environ", {"NODE_OPTIONS": "SYNTHETIC_ONLY", "ZROTEXT_WORKFLOW_CREDENTIAL_FILE": "SYNTHETIC_ONLY"}), \
                patch("agent_setup.subprocess.run", return_value=completed) as run:
            report = agent_setup.journey()
        self.assertEqual(report["nodeVersion"], "v22.0.0")
        self.assertTrue(run.call_args.args[0][1].endswith("guided-journey.mjs"))
        self.assertNotIn("NODE_OPTIONS", run.call_args.kwargs["env"])
        self.assertNotIn("ZROTEXT_WORKFLOW_CREDENTIAL_FILE", run.call_args.kwargs["env"])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_unexpected_stderr_and_malformed_response_are_redacted(self):
        for stdout, stderr in [(json.dumps(fixture_report()), "SYNTHETIC_PRIVATE_DIAGNOSTIC"),
                               ("malformed SYNTHETIC_PRIVATE_DIAGNOSTIC", ""), ("x" * 16385, "")]:
            completed = type("Result", (), {"stdout": stdout, "stderr": stderr})()
            with patch("agent_setup.node_runtime", return_value=("synthetic-node", "v22.0.0")), \
                    patch("agent_setup.subprocess.run", return_value=completed):
                with self.assertRaisesRegex(agent_setup.SetupError, "^synthetic_journey_unavailable$"):
                    agent_setup.journey()

    def test_parent_removes_checkpoint_after_child_timeout(self):
        owned = []

        def interrupted(*_args, **kwargs):
            directory = Path(kwargs["env"]["TMPDIR"])
            owned.append(directory)
            (directory / "checkpoint.json").write_text('{"synthetic":true}', encoding="utf-8")
            raise subprocess.TimeoutExpired("synthetic-fixture", 30)

        with patch("agent_setup.node_runtime", return_value=("synthetic-node", "v22.0.0")), \
                patch("agent_setup.subprocess.run", side_effect=interrupted):
            with self.assertRaisesRegex(agent_setup.SetupError, "^synthetic_journey_unavailable$"):
                agent_setup.journey()
        self.assertEqual(len(owned), 1)
        self.assertFalse(owned[0].exists())


if __name__ == "__main__":
    unittest.main()
