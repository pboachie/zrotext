# SPDX-License-Identifier: AGPL-3.0-only
"""Exported caller shapes cannot smuggle authority or queue identities."""
import copy
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]


class WorkflowRecipeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.export = json.loads((ROOT / 'sdk/recipes/callable-workflow-runtime.json').read_text())
        cls.vector = json.loads((ROOT / 'protocol/v1/vectors/workflow-recipe-01.json').read_text())
        cls.schema = Draft202012Validator(cls.export['inputSchema'])
        Draft202012Validator.check_schema(cls.export['inputSchema'])

    def test_all_operations_have_exact_closed_inputs(self):
        for value in self.vector['requests']:
            self.schema.validate(value)
            for field in ['verified', 'approved', 'token', 'message_id', 'dispatch_id', 'account_id']:
                changed = copy.deepcopy(value)
                changed['params'][field] = True
                self.assertFalse(self.schema.is_valid(changed), field)
            changed = copy.deepcopy(value)
            del changed['params']['request_id']
            self.assertFalse(self.schema.is_valid(changed))

    def test_prepare_binds_all_four_identity_fields(self):
        prepare = next(value for value in self.vector['requests'] if value['operation'] == 'prepare')
        for field in prepare['params']['key']:
            changed = copy.deepcopy(prepare)
            del changed['params']['key'][field]
            self.assertFalse(self.schema.is_valid(changed))
        changed = copy.deepcopy(prepare)
        changed['params']['key']['verified'] = True
        self.assertFalse(self.schema.is_valid(changed))

    def test_exports_are_disabled_and_have_no_embedded_credentials(self):
        self.assertEqual(self.export['installed_state'], 'disabled')
        workflow = json.loads((ROOT / 'sdk/recipes/n8n-workflow-runtime.json').read_text())
        self.assertFalse(workflow['active'])
        self.assertEqual(self.export['model_provider_access'], 'none')
        for node in workflow['nodes']:
            for reference in node.get('credentials', {}).values():
                self.assertEqual(set(reference), {'id', 'name'})
