"""Independent framing/P256 fixtures; no server/phone effect acceptance."""
import copy
import json
from pathlib import Path
import struct
import unittest
import uuid
import jsonschema
from test_device_protection_origin import H, N, framed, raw, verifies

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'ZTSE/conversation/'


class ConversationEffectsTests(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((ROOT / 'vectors/conversation-effects03-v1.json').read_text(encoding='utf-8'))

    def test_closed_fixture_schema_never_claims_permission(self):
        schema = json.loads((ROOT / 'conversation-effects03-vector.schema.json').read_text(encoding='utf-8'))
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(self.vector)
        for change in [dict(self.vector, submit_once=True), dict(self.vector, enrolled_point=self.vector['enrolled_point']+'=')]:
            with self.assertRaises(jsonschema.ValidationError):
                validator.validate(change)
        missing = copy.deepcopy(self.vector)
        del missing['cases'][0]['outcomes'][0]['segment_index']
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate(missing)

    def test_all_four_layouts_and_each_evidence_code_have_independent_bytes(self):
        self.assertEqual([int(case['numbers'][5]) for case in self.vector['cases']], [1, 6])
        for case in self.vector['cases']:
            ids = [uuid.UUID(case['ids'][name]).bytes for name in ['account_id','device_id','event_id','message_id','attempt_id','closure_id','proof_request_id','challenge_id']]
            numbers = list(map(int, case['numbers']))
            self.assertTrue(all(0 < value <= 2**63-1 for value in numbers))
            d = list(map(raw, case['digests']))
            count, observed, closed = numbers[5:8]
            submit = b''.join(ids[:5]) + d[0] + d[2] + bytes([count]) + struct.pack('>Q', observed)
            self.assertEqual(len(submit), 153)
            self.assertEqual(submit, raw(case['submit']))
            self.assertEqual(H(framed(LABEL+'submit-command03/v1', submit)), d[1])
            self.assertEqual(d[1], raw(case['submit_commitment']))
            record = b''.join(ids[:6]) + d[0] + d[1] + d[2] + bytes([count]) + struct.pack('>Q', observed) + bytes([case['closed_from']]) + struct.pack('>Q', closed)
            self.assertEqual(len(record), 210)
            self.assertEqual(record, raw(case['closure_record']))
            self.assertEqual(H(framed(LABEL+'no-submit-record03/v1', record)), d[6])
            self.assertEqual(d[6], raw(case['closure_commitment']))
            core = b'ZTNS\x01\x03\x03\0' + b''.join(ids) + struct.pack('>10Q', *numbers) + b''.join(d) + bytes([case['closed_from']])
            self.assertEqual(len(core), 441)
            self.assertEqual(core, raw(case['core']))
            self.assertEqual(H(core), raw(case['core_sha256']))
            self.assertEqual(H(raw(case['nonce'])), d[5])
            self.assertEqual(numbers[4], 1)
            self.assertEqual(numbers[9]-numbers[8], 30000)
            self.assertEqual(set(outcome['evidence'] for outcome in case['outcomes']), set(range(6)))
            for outcome in case['outcomes']:
                index = outcome['segment_index']
                self.assertEqual(index is not None, outcome['evidence'] < 2)
                if index is not None:
                    self.assertLess(index, count)
                event = uuid.UUID(outcome['event_id']).bytes
                command = b''.join([ids[0],ids[1],event,ids[3],ids[4],ids[2]]) + d[1]+d[0]+d[2] + struct.pack('>Q', observed) + bytes([count,outcome['evidence']]) + struct.pack('>Q', int(outcome['observed_ms'])) + bytes([index if index is not None else 255])
                self.assertEqual(len(command), 211)
                self.assertEqual(command, raw(outcome['command']))
                self.assertEqual(H(framed(LABEL+'outcome-command03/v1', command)), raw(outcome['commitment']))

    def test_actual_low_s_proofs_reject_domain_point_scope_and_signature_changes(self):
        point = raw(self.vector['enrolled_point'])
        self.assertEqual(H(b'ZTSE/key/v1\0\x01\x01'+point), raw(self.vector['enrolled_key_id']))
        for case in self.vector['cases']:
            core, signature = raw(case['core']), raw(case['signature'])
            self.assertEqual(raw(case['digests'][4]), raw(self.vector['enrolled_key_id']))
            message = framed(LABEL+'no-submit-proof03/v1', core)
            self.assertTrue(verifies(point, signature, message))
            self.assertFalse(verifies(point, signature, framed(LABEL+'submit-command03/v1', core)))
            self.assertFalse(verifies(bytes(65), signature, message))
            self.assertFalse(verifies(point, bytes(64), message))
            high = signature[:32] + (N-int.from_bytes(signature[32:], 'big')).to_bytes(32, 'big')
            self.assertFalse(verifies(point, high, message))
            for offset in [8,24,40,56,72,88,104,120,136,152,168,176,184,192,200,208,216,248,280,312,344,376,408,440]:
                changed = bytearray(core)
                changed[offset] ^= 1
                self.assertFalse(verifies(point, signature, framed(LABEL+'no-submit-proof03/v1', changed)))


if __name__ == '__main__':
    unittest.main()
