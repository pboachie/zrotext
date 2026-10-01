# SPDX-License-Identifier: AGPL-3.0-only
"""Managed AI synthetic boundary suite, discovered by the scripts CI job."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'managed_ai_contract_model', ROOT / 'protocol/v1/tests/managed_ai_contract_model.py')
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)
FIXTURE = json.loads((ROOT / 'protocol/v1/vectors/managed-ai-grant-01.json').read_text())


class ManagedAiContractTests(unittest.TestCase):
    def fresh(self):
        data = deepcopy(FIXTURE)
        return data, MODEL.Task(data['task'])

    def change(self, data, vector):
        selected = data[vector['target']]
        if vector['target'] == 'content':
            selected = selected['content-a']
        selected.update(vector['changes'])

    def begin(self, data, worker):
        worker.begin_call(data['grant'], data['content'], data['budget'], 20, 1)

    def output(self, data, worker):
        return worker.accept_output(data['grant'], data['content'], 20, data['response'])

    def send(self, data, worker, **changes):
        args = dict(grant=data['grant'], content=data['content'], now=20,
                    expected=worker.version, approval_digest=data['response']['encrypted_draft_digest'],
                    send_authorized=True, suppression_clear=True, send_budget_available=True)
        args.update(changes)
        worker.begin_send(**args)

    def test_selected_content_can_complete_explicitly_approved_separate_send(self):
        data, worker = self.fresh()
        self.begin(data, worker)
        self.assertEqual(worker.reserved_units, 5)
        self.assertEqual(data['budget']['remaining_units'], 5)
        self.assertEqual(self.output(data, worker), 'draft_ready')
        self.send(data, worker)
        self.assertEqual(worker.state, 'dispatching')

    def test_published_checkpoints_reject_before_call_without_partial_reservation(self):
        for vector in FIXTURE['rejected_checkpoints']:
            with self.subTest(vector=vector['name']):
                data, worker = self.fresh()
                self.change(data, vector)
                worker = MODEL.Task(data['task'])
                before = deepcopy(vars(worker)), deepcopy(data['budget'])
                with self.assertRaises(MODEL.Denied):
                    self.begin(data, worker)
                self.assertEqual(before, (vars(worker), data['budget']))

    def test_adjacent_content_is_rejected_even_if_grant_scope_was_corrupted(self):
        data, worker = self.fresh()
        data['grant']['object_ids'].append('content-adjacent')
        data['task']['objects'].append(dict(object_id='content-adjacent', version=1, digest='cd'*32))
        worker = MODEL.Task(data['task'])
        with self.assertRaises(MODEL.Denied):
            self.begin(data, worker)

    def test_empty_or_duplicate_selected_objects_are_rejected(self):
        for selected in [[], [FIXTURE['task']['objects'][0]] * 2]:
            data, worker = self.fresh()
            data['task']['objects'] = selected
            worker = MODEL.Task(data['task'])
            with self.assertRaises(MODEL.Denied):
                self.begin(data, worker)

    def test_budget_failure_or_bad_units_never_starts_call(self):
        for change in FIXTURE['rejected_budgets']:
            data, worker = self.fresh()
            data['budget'].update(change)
            with self.assertRaises(MODEL.Denied):
                self.begin(data, worker)
            self.assertEqual(worker.state, 'queued')
            self.assertEqual(worker.reserved_units, 0)
        for units in [True, 0, -1, 11]:
            data, worker = self.fresh()
            data['task']['maximum_units'] = units
            worker = MODEL.Task(data['task'])
            with self.assertRaises(MODEL.Denied):
                self.begin(data, worker)

    def test_same_budget_cannot_be_reserved_twice_when_exhausted(self):
        data, worker = self.fresh()
        data['budget']['remaining_units'] = 5
        self.begin(data, worker)
        second = MODEL.Task(data['task'])
        with self.assertRaises(MODEL.Denied):
            self.begin(data, second)
        with self.assertRaises(MODEL.Denied):
            self.begin(data, worker)
        self.assertEqual(data['budget']['remaining_units'], 0)
        self.assertEqual(worker.reserved_units, 5)

    def test_revocation_rotation_deletion_narrowing_and_expiry_discard_inflight_output(self):
        for vector in FIXTURE['rejected_checkpoints']:
            if vector['target'] == 'task':
                continue
            with self.subTest(vector=vector['name']):
                data, worker = self.fresh()
                self.begin(data, worker)
                self.change(data, vector)
                self.assertEqual(self.output(data, worker), 'discarded')
                self.assertIsNone(worker.output)
                self.assertEqual(worker.reserved_units, 5)
                with self.assertRaises(MODEL.Denied):
                    self.send(data, worker)

    def test_wrong_task_reader_provider_or_call_response_is_discarded(self):
        for field in ['task_id', 'reader_id', 'provider_id', 'call_id']:
            data, worker = self.fresh()
            self.begin(data, worker)
            data['response'][field] += '-wrong'
            self.assertEqual(self.output(data, worker), 'discarded')

    def test_approved_pending_draft_cannot_survive_revocation_or_rotation(self):
        for vector in FIXTURE['rejected_checkpoints']:
            if vector['target'] == 'task':
                continue
            with self.subTest(vector=vector['name']):
                data, worker = self.fresh()
                self.begin(data, worker)
                self.output(data, worker)
                self.change(data, vector)
                before = deepcopy(vars(worker))
                with self.assertRaises(MODEL.Denied):
                    self.send(data, worker)
                self.assertEqual(before, vars(worker))

    def test_reader_grant_never_confers_send_authority(self):
        for change in [dict(send_authorized=False), dict(suppression_clear=False),
                       dict(send_budget_available=False), dict(approval_digest='ab'*32),
                       dict(expected=1), dict(now=100)]:
            data, worker = self.fresh()
            self.begin(data, worker)
            self.output(data, worker)
            with self.assertRaises(MODEL.Denied):
                self.send(data, worker, **change)

    def test_duplicate_output_and_send_cannot_repeat_effect(self):
        data, worker = self.fresh()
        self.begin(data, worker)
        self.output(data, worker)
        with self.assertRaises(MODEL.Denied):
            self.output(data, worker)
        self.send(data, worker)
        with self.assertRaises(MODEL.Denied):
            self.send(data, worker)

    def test_deletion_outcomes_never_claim_remote_recall(self):
        for outcome in FIXTURE['deletion_outcomes']:
            self.assertEqual(MODEL.deletion_report(True, outcome['provider_status']), outcome)
        report = MODEL.deletion_report(False, 'acknowledged')
        self.assertFalse(report['local_deleted'])
        self.assertFalse(report['prior_access_recalled'])
        for status in ['completed_everywhere', 'cancelled_and_unread']:
            with self.assertRaises(MODEL.Denied):
                MODEL.deletion_report(True, status)
    def test_unreadable_budget_and_non_ciphertext_response_fail_closed(self):
        for changes in [dict(hard_ceiling=None), dict(remaining_units=True),
                        dict(remaining_tasks=-1), dict(available=None)]:
            data, worker = self.fresh()
            data['budget'].update(changes)
            with self.assertRaises(MODEL.Denied):
                self.begin(data, worker)
            self.assertEqual(worker.reserved_units, 0)
        data, worker = self.fresh()
        self.begin(data, worker)
        data['response']['encrypted_draft_digest'] = 'invalid'
        self.assertEqual(self.output(data, worker), 'discarded')
        self.assertIsNone(worker.output)
    def test_expiry_boundary_and_admitted_task_is_immutable(self):
        data, worker = self.fresh()
        data['task']['reader_id'] = 'reader-b'
        self.begin(data, worker)
        self.assertEqual(worker.task['reader_id'], 'reader-a')
        self.assertEqual(worker.accept_output(data['grant'], data['content'], 99, data['response']), 'draft_ready')
        with self.assertRaises(MODEL.Denied):
            self.send(data, worker, now=100)


if __name__ == '__main__':
    unittest.main()
