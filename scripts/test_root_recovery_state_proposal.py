"""Symbolic Q3/Q10 drills; not a crypto verifier or runtime recovery API."""

import copy
import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOMAIN = b"ZTSE/root-recovery-state-model/v1\x00"
FIELDS = ("operation", "account", "generation", "root", "manifest", "new_account",
          "new_root", "new_manifest", "backup_digest", "challenge", "expires")


def transcript_digest(request):
    # A bounded synthetic serialization, expressly not RootTransition02 bytes.
    fields = {key: request[key] for key in FIELDS}
    return hashlib.sha256(DOMAIN + json.dumps(fields, sort_keys=True,
                                             separators=(",", ":")).encode("ascii")).hexdigest()


def transition(state, request, proof, fail_before_commit=False):
    digest = transcript_digest(request)
    receipt = state["receipts"].get(request["challenge"])
    if receipt is not None:
        return "replay" if receipt == digest else "ceremony_conflict"
    if digest != proof["digest"]:
        return "transcript_refused"
    if not proof["session_current"] or not proof["factor_fresh"]:
        return "owner_refused"
    if proof["now"] >= request["expires"] or request["expires"] - proof["now"] > 300:
        return "expired"
    if not proof["independent_comparison"]:
        return "comparison_required"
    if state["fork"]:
        return "fork_refused"
    if (request["account"], request["generation"], request["root"], request["manifest"]) != (
            state["account"], state["generation"], state["root"], state["manifest"]):
        return "predecessor_refused"
    operation = request["operation"]
    staged = copy.deepcopy(state)
    if operation == "rotate":
        if not proof["old_signature"] or not proof["new_signature"]:
            return "signature_refused"
        if not proof["publication_complete"] or not proof["custody_verified"]:
            return "incomplete"
        if request["new_root"] == state["root"]:
            return "new_root_required"
        if set(proof["new_keys"]) & set(state["revoked"]):
            return "revoked_refused"
        staged.update(generation=state["generation"] + 1, root=request["new_root"],
                      manifest=request["new_manifest"], active_keys=proof["new_keys"], grants=[])
    elif operation == "restore_root":
        if not proof["backup_authenticated"] or not proof["material_matches"]:
            return "material_refused"
        if proof["backup_identity"] != [state["account"], state["generation"], state["root"]]:
            return "backup_identity_refused"
        # Restoration proves possession only; never imports keys or grants.
    elif operation == "restore_login":
        # Login recovery does not authorize a different root, manifest or account.
        if request["new_root"] != state["root"] or request["new_manifest"] != state["manifest"]:
            return "login_cannot_reset"
    elif operation == "lost_all":
        if not proof["fresh_enrollment"] or not proof["new_signature"]:
            return "fresh_enrollment_required"
        if request["new_account"] == state["account"] or request["new_root"] == state["root"]:
            return "new_identity_required"
        staged.update(account=request["new_account"], generation=1, root=request["new_root"],
                      manifest=request["new_manifest"], active_keys=[], grants=[], archive_keys=[],
                      receipts={}, revoked=[])
        # The caller must store this in a new namespace, never overwrite old.
    else:
        return "operation_refused"
    staged["receipts"][request["challenge"]] = digest
    if fail_before_commit:
        return "aborted"
    state.clear()
    state.update(staged)
    return "new_account" if operation == "lost_all" else "committed"


def readable(envelope, possessed_keys):
    return bool(set(envelope["wrap_keys"]) & set(possessed_keys))


class RootRecoveryStateProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = json.loads((ROOT / "protocol/v1/vectors/root-recovery-state-proposal.json").read_text())

    def request_proof(self, case):
        request = dict(self.v["request"], **case.get("request_changes", {}))
        proof = copy.deepcopy(self.v["proof"])
        proof.update(case.get("proof_changes", {}))
        proof["digest"] = transcript_digest(request)
        return request, proof

    def test_transcript_is_pinned_and_every_field_is_bound(self):
        request = self.v["request"]
        self.assertEqual(transcript_digest(request), self.v["transcript_sha256"])
        raw = bytes.fromhex(self.v["transcript_hex"])
        self.assertTrue(raw.startswith(DOMAIN))
        self.assertEqual(json.loads(raw[len(DOMAIN):]), request)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.v["transcript_sha256"])
        for field in FIELDS:
            with self.subTest(field=field):
                altered = dict(request)
                altered[field] = altered[field] + 1 if isinstance(altered[field], int) else altered[field] + "_altered"
                state = copy.deepcopy(self.v["state"])
                before = copy.deepcopy(state)
                proof = dict(self.v["proof"], digest=self.v["transcript_sha256"])
                self.assertEqual(transition(state, altered, proof), "transcript_refused")
                self.assertEqual(state, before)

    def test_recovery_vectors_and_refusal_atomicity(self):
        for case in self.v["cases"]:
            with self.subTest(case=case["name"]):
                state = copy.deepcopy(self.v["state"])
                state.update(case.get("state_changes", {}))
                before = copy.deepcopy(state)
                request, proof = self.request_proof(case)
                result = transition(state, request, proof)
                self.assertEqual(result, case["expected"])
                if result not in ("committed", "new_account"):
                    self.assertEqual(state, before)
                elif request["operation"] == "rotate":
                    self.assertEqual(state["generation"], before["generation"] + 1)
                    self.assertEqual(state["revoked"], before["revoked"])
                    self.assertEqual(state["archive_keys"], before["archive_keys"])
                    self.assertEqual(state["grants"], [])
                elif request["operation"].startswith("restore"):
                    for field in ("account", "generation", "root", "manifest", "revoked", "active_keys", "grants", "archive_keys"):
                        self.assertEqual(state[field], before[field])
                else:
                    self.assertNotEqual(state["account"], before["account"])
                    self.assertEqual(state["generation"], 1)
                    self.assertEqual(state["archive_keys"], [])
                    self.assertEqual(state["grants"], [])

    def test_precommit_failure_and_restart_have_no_partial_authority(self):
        state = copy.deepcopy(self.v["state"])
        before = copy.deepcopy(state)
        request, proof = self.request_proof({})
        self.assertEqual(transition(state, request, proof, fail_before_commit=True), "aborted")
        self.assertEqual(state, before)
        restarted = copy.deepcopy(state)
        self.assertEqual(transition(restarted, request, proof), "committed")
        after = copy.deepcopy(restarted)
        self.assertEqual(transition(restarted, request, proof), "replay")
        self.assertEqual(restarted, after)
        changed = dict(request, new_manifest="manifest_fork")
        changed_proof = dict(proof, digest=transcript_digest(changed))
        self.assertEqual(transition(restarted, changed, changed_proof), "ceremony_conflict")
        self.assertEqual(restarted, after)

    def test_concurrent_ceremony_and_old_backup_cannot_roll_back_generation(self):
        state = copy.deepcopy(self.v["state"])
        request, proof = self.request_proof({})
        competing = dict(request, challenge="challenge_competing")
        self.assertEqual(transition(state, request, proof), "committed")
        after = copy.deepcopy(state)
        self.assertEqual(transition(state, competing, dict(proof, digest=transcript_digest(competing))), "predecessor_refused")
        restore = dict(competing, operation="restore_root")
        self.assertEqual(transition(state, restore, dict(proof, digest=transcript_digest(restore))), "predecessor_refused")
        self.assertEqual(state, after)

    def test_old_ciphertext_depends_on_keys_not_login_or_root(self):
        envelope = self.v["historical_envelope"]
        state = copy.deepcopy(self.v["state"])
        self.assertTrue(readable(envelope, state["archive_keys"]))
        request, proof = self.request_proof({})
        self.assertEqual(transition(state, request, proof), "committed")
        self.assertTrue(readable(envelope, state["archive_keys"]))
        self.assertFalse(readable(envelope, [state["root"]]))
        self.assertFalse(readable(envelope, []))
        # A revoked recipient retains its already-held history capability.
        self.assertTrue(readable(self.v["revoked_recipient_envelope"], ["device_revoked"]))

    def test_lost_all_creates_separate_account_and_leaves_old_records_intact(self):
        old = copy.deepcopy(self.v["state"])
        old_before = copy.deepcopy(old)
        new = copy.deepcopy(old)
        request, proof = self.request_proof({"request_changes": {"operation": "lost_all"}})
        self.assertEqual(transition(new, request, proof), "new_account")
        accounts = {old["account"]: old, new["account"]: new}
        self.assertEqual(accounts[old["account"]], old_before)
        self.assertNotEqual(new["account"], old["account"])
        self.assertFalse(readable(self.v["historical_envelope"], new["archive_keys"]))

    def test_lost_archive_key_and_fresh_replacement_do_not_restore_history(self):
        state = copy.deepcopy(self.v["state"])
        state["archive_keys"] = []
        state["revoked"].append("archive_original")
        request, proof = self.request_proof({})
        proof["new_keys"].append("archive_replacement")
        self.assertEqual(transition(state, request, proof), "committed")
        self.assertIn("archive_original", state["revoked"])
        self.assertNotIn("archive_original", state["active_keys"])
        self.assertFalse(readable(self.v["historical_envelope"], ["archive_replacement"]))
        self.assertFalse(readable(self.v["historical_envelope"], state["archive_keys"]))


if __name__ == "__main__":
    unittest.main()
