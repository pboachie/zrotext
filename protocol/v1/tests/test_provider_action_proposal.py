# SPDX-License-Identifier: AGPL-3.0-only
"""Independent proposed-wire conformance; no production authority or sender."""
import hashlib
import json
from pathlib import Path
import unittest
import jsonschema
from workflow_contract_model import binding

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / 'vectors/workflow-action-02-proposal.json').read_text())
SCHEMA = json.loads((ROOT / 'workflow-action-02-proposal.schema.json').read_text())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def reject_duplicate(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def reject_float(_value):
    raise ValueError('noninteger encoding')


def parse(raw):
    if len(raw.encode()) > 4096:
        raise ValueError('size')
    value = json.loads(raw, object_pairs_hook=reject_duplicate, parse_float=reject_float)
    jsonschema.validate(value, SCHEMA)
    if value['action']['not_before'] >= value['action']['expires_at']:
        raise ValueError('time order')
    if canonical(value) != raw:
        raise ValueError('original encoding')
    return value


class ProposedProviderActionTest(unittest.TestCase):
    def test_canonical_bytes_hashes_and_every_bound_mutation_match(self):
        vectors = VECTORS['positives'] + VECTORS['binding_mutations']
        self.assertEqual(len(vectors), 37)
        for vector in vectors:
            with self.subTest(name=vector.get('name', vector.get('field'))):
                raw = vector.get('canonical', canonical(vector['descriptor']))
                self.assertEqual(canonical(parse(raw)), raw)
                self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), vector['binding_digest'])
                if 'field' in vector:
                    self.assertNotEqual(vector['binding_digest'], VECTORS['positives'][1]['binding_digest'])
        self.assertNotEqual(VECTORS['positives'][0]['binding_digest'], VECTORS['positives'][1]['binding_digest'])

    def test_malformed_original_wire_and_closed_fields_refuse(self):
        vectors = VECTORS['negative_grammar'] + VECTORS['negative_wire']
        self.assertEqual(len(vectors), 26)
        for vector in vectors:
            with self.subTest(name=vector['name']):
                raw = ''.join(vector['raw_parts']) if 'raw_parts' in vector else vector['raw'] if 'raw' in vector else canonical(vector['input'])
                with self.assertRaises((ValueError, jsonschema.ValidationError)):
                    parse(raw)

    def test_actual_legacy_oracle_rejects_profile_and_retains_vector(self):
        legacy = json.loads((ROOT / 'vectors/workflow-action-01.json').read_text())
        self.assertEqual(binding(legacy['action']), legacy['binding_digest'])
        self.assertEqual(VECTORS['legacy01_digest_unchanged'], legacy['binding_digest'])
        for vector in VECTORS['positives']:
            with self.assertRaises(ValueError):
                binding(vector['descriptor'])
