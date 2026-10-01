# SPDX-License-Identifier: AGPL-3.0-only
"""Exact workflow binding/state vectors; discovered by the existing scripts CI job."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'workflow_contract_model', ROOT / 'protocol/v1/tests/workflow_contract_model.py')
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)
VECTORS = json.loads((ROOT / 'protocol/v1/vectors/workflow-action-01.json').read_text())


class WorkflowContractTests(unittest.TestCase):
    def fresh(self):
        return MODEL.Record(VECTORS['action'])

    def decide(self, record, operation='approve', **changes):
        args = dict(identity='decision-a', account=record.action['account_id'],
                    revision=record.action['revision'], digest=record.digest,
                    operation=operation, expected=record.version, now=20)
        args.update(changes)
        return record.decide(**args)

    def snapshot(self, record):
        return (dict(record.action), record.state, record.version,
                record.approved_digest, dict(record.decisions), dict(record.updates))

    def test_canonical_binding_matches_published_digest(self):
        self.assertEqual(MODEL.binding(VECTORS['action']), VECTORS['binding_digest'])
        reordered = dict(reversed(list(VECTORS['action'].items())))
        self.assertEqual(MODEL.binding(reordered), VECTORS['binding_digest'])

    def test_every_bound_field_changes_identity(self):
        for field, value in VECTORS['field_edits'].items():
            with self.subTest(field=field):
                action = dict(VECTORS['action'], **{field: value})
                self.assertNotEqual(MODEL.binding(action), VECTORS['binding_digest'])
        self.assertEqual(set(VECTORS['field_edits']), MODEL.FIELDS)

    def test_foreign_stale_revoked_and_unconfirmed_decisions_are_atomic(self):
        for vector in VECTORS['rejected_decisions']:
            with self.subTest(vector=vector):
                record = self.fresh()
                before = self.snapshot(record)
                with self.assertRaises(MODEL.Conflict):
                    self.decide(record, **vector)
                self.assertEqual(before, self.snapshot(record))

    def test_duplicate_decision_returns_original_result_without_reapplying(self):
        record = self.fresh()
        original_digest = record.digest
        result = self.decide(record)
        changed = dict(record.action, revision=2, commitment='sensitive')
        record.edit('update-a', changed, 2, 'account-a', 20)
        self.assertEqual(self.decide(record, revision=1, digest=original_digest, expected=1), result)
        self.assertEqual(record.state, 'invalidated')
        self.assertIsNone(record.approved_digest)
        with self.assertRaises(MODEL.Conflict):
            self.decide(record, operation='cancel', revision=1, digest=original_digest, expected=1)
        with self.assertRaises(MODEL.Conflict):
            self.decide(record, revision=1, digest=original_digest, expected=1, authorized=False)

    def test_each_edit_invalidates_approval_and_replay_is_noop(self):
        for field, value in VECTORS['field_edits'].items():
            if field in {'account_id', 'action_id', 'revision'}:
                continue
            with self.subTest(field=field):
                record = self.fresh()
                self.decide(record)
                action = dict(record.action, revision=2, **{field: value})
                result = record.edit('update-a', action, 2, 'account-a', 20)
                self.assertEqual(result, ('invalidated', 3))
                self.assertIsNone(record.approved_digest)
                self.assertEqual(record.edit('update-a', action, 2, 'account-a', 20), result)
                self.assertEqual(record.version, 3)
                with self.assertRaises(MODEL.Conflict):
                    record.dispatch(3, 20)
                self.decide(record, identity='decision-b')
                record.dispatch(4, 20)
                self.assertEqual(record.state, 'dispatching')

    def test_invalid_edits_cannot_partially_mutate_record(self):
        for changes in ({'account_id': 'account-b'}, {'action_id': 'action-b'},
                        {'revision': 3}, {}, {'expires_at': 5}):
            record = self.fresh()
            action = dict(record.action, revision=2)
            action.update(changes)
            before = self.snapshot(record)
            with self.assertRaises(ValueError):
                record.edit('update-a', action, 1, 'account-a', 20)
            self.assertEqual(before, self.snapshot(record))

    def test_concurrent_approve_cancel_has_exactly_one_winner(self):
        for first, second in [('approve', 'cancel'), ('cancel', 'approve')]:
            record = self.fresh()
            self.decide(record, operation=first)
            before = self.snapshot(record)
            with self.assertRaises(MODEL.Conflict):
                self.decide(record, operation=second, identity='decision-b', expected=1)
            self.assertEqual(before, self.snapshot(record))

    def test_dispatch_cancel_race_and_unknown_effect_are_not_retried(self):
        record = self.fresh()
        self.decide(record)
        record.dispatch(2, 20)
        with self.assertRaises(MODEL.Conflict):
            self.decide(record, operation='cancel', identity='decision-b', expected=2)
        record.outcome('unknown')
        with self.assertRaises(MODEL.Conflict):
            record.dispatch(record.version, 20)
        record.outcome('succeeded')
        self.assertEqual(record.state, 'succeeded')
        with self.assertRaises(MODEL.Conflict):
            record.outcome('failed')
        record = self.fresh()
        self.decide(record)
        self.decide(record, operation='cancel', identity='decision-b')
        with self.assertRaises(MODEL.Conflict):
            record.dispatch(2, 20)

    def test_timing_boundaries_and_revoked_send_authority(self):
        for now, allowed in [(9, False), (10, True), (99, True), (100, False)]:
            record = self.fresh()
            self.decide(record)
            if allowed:
                record.dispatch(2, now)
            else:
                with self.assertRaises(MODEL.Conflict):
                    record.dispatch(2, now)
        record = self.fresh()
        self.decide(record)
        with self.assertRaises(MODEL.Conflict):
            record.dispatch(2, 20, authorized=False)
        record.expire(99)
        self.assertEqual(record.state, 'approved')
        record.expire(100)
        self.assertEqual(record.state, 'expired')
        version = record.version
        record.expire(101)
        self.assertEqual(record.version, version)
        with self.assertRaises(MODEL.Conflict):
            self.decide(record, identity='decision-b', now=100)

    def test_concurrent_edits_and_reused_update_identity_conflict(self):
        record = self.fresh()
        first = dict(record.action, revision=2, recipient_id='recipient-b')
        second = dict(record.action, revision=2, purpose_id='purpose-b')
        record.edit('update-a', first, 1, 'account-a', 20)
        before = self.snapshot(record)
        for identity in ['update-a', 'update-b']:
            with self.assertRaises(MODEL.Conflict):
                record.edit(identity, second, 1, 'account-a', 20)
            self.assertEqual(before, self.snapshot(record))
        with self.assertRaises(MODEL.Conflict):
            self.decide(record, revision=1, digest=VECTORS['binding_digest'])
        with self.assertRaises(MODEL.Conflict):
            record.edit('update-a', first, 1, 'account-a', 20, authorized=False)

    def test_update_binding_identity_has_published_canonical_bytes(self):
        encoded = json.dumps(VECTORS['action'], sort_keys=True, separators=(',', ':'))
        self.assertEqual(encoded, VECTORS['canonical_utf8'])
    def test_published_state_transcripts(self):
        for transcript in VECTORS['state_transcripts']:
            record = self.fresh()
            for index, step in enumerate(transcript['steps']):
                with self.subTest(transcript=transcript['name'], step=index):
                    operation = step['op']
                    before = self.snapshot(record)
                    def apply():
                        if operation in {'approve', 'cancel'}:
                            self.decide(record, operation=operation, identity=f'decision-{index}')
                        elif operation == 'edit':
                            action = dict(record.action, revision=record.action['revision'] + 1,
                                          commitment='sensitive')
                            record.edit(f'update-{index}', action, record.version, 'account-a', 20)
                        elif operation == 'dispatch':
                            record.dispatch(record.version, 20)
                        elif operation == 'expire':
                            record.expire(step['now'])
                        else:
                            record.outcome(operation)
                    if step.get('reject'):
                        with self.assertRaises(MODEL.Conflict):
                            apply()
                        self.assertEqual(before, self.snapshot(record))
                    else:
                        apply()
                    self.assertEqual(record.state, step['expect'])
    def test_malformed_bindings_reject_before_decision(self):
        for changes in ({'revision': True}, {'authority_generation': 0},
                        {'content_digest': 'invalid'}, {'commitment': 'payment'},
                        {'recipient_id': ''}, {'timezone': 'x' * 129},
                        {'not_before': 100}, {'unexpected': 'field'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                MODEL.binding(dict(VECTORS['action'], **changes))
        action = dict(VECTORS['action'])
        action.pop('window_id')
        with self.assertRaises(ValueError):
            MODEL.binding(action)


if __name__ == '__main__':
    unittest.main()
