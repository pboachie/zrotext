# SPDX-License-Identifier: AGPL-3.0-only
"""Independent synthetic protocol controls; never a runtime/authentication oracle.

Only stdlib and the existing jsonschema dependency are used. The unchanged02
structural schema is loaded locally, so schema checks cannot fetch a resource.
No server, SDK, database, provider, or accepted-authority producer is imported.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / 'vectors/provider-proposal-history-01.json').read_text(encoding='utf-8'))
SCHEMA = json.loads((ROOT / 'vectors/provider-proposal-history.schema.json').read_text(encoding='utf-8'))
DESCRIPTOR_SCHEMA = json.loads((ROOT / 'workflow-action-02-proposal.schema.json').read_text(encoding='utf-8'))
SPECIMENS = {item['name']: item for item in VECTORS['specimens']}
DOMAIN = b'ZT/provider-proposal-history/v1\0'
I64_MAX = 9223372036854775807
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
NIL = '00000000-0000-0000-0000-000000000000'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(raw):
    return hashlib.sha256(raw.encode('ascii')).hexdigest()


def locally_resolved(value):
    """Resolve only the one explicitly elected local descriptor schema."""
    if isinstance(value, dict):
        if value == {'$ref': 'urn:zrotext:workflow-action-02-proposal'}:
            return copy.deepcopy(DESCRIPTOR_SCHEMA)
        return {key: locally_resolved(item) for key, item in value.items()}
    if isinstance(value, list):
        return [locally_resolved(item) for item in value]
    return value


DOCUMENT_VALIDATOR = jsonschema.Draft202012Validator(locally_resolved(SCHEMA))
DESCRIPTOR_VALIDATOR = jsonschema.Draft202012Validator(DESCRIPTOR_SCHEMA)


def closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def refuse_number(_value):
    raise ValueError('noninteger spelling')


def original_json(raw, cap):
    # Apply the cap to retained UTF-8 bytes before decoding or normalization.
    if not isinstance(raw, bytes) or len(raw) > cap:
        raise ValueError('size')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=closed_pairs,
                      parse_float=refuse_number, parse_constant=refuse_number)


def validate_descriptor(descriptor):
    DESCRIPTOR_VALIDATOR.validate(descriptor)
    if descriptor['action']['not_before'] >= descriptor['action']['expires_at']:
        raise ValueError('time order')
    if len(canonical(descriptor).encode('ascii')) > 4096:
        raise ValueError('descriptor size')
    return descriptor


def parse_descriptor(raw):
    value = validate_descriptor(original_json(raw, 4096))
    if canonical(value).encode('ascii') != raw:
        raise ValueError('original encoding')
    return value


def valid_uuid(value):
    return isinstance(value, str) and UUID.fullmatch(value) is not None and value != NIL


def parse_proposal(raw):
    value = original_json(raw, 8192)
    if not isinstance(value, dict) or set(value) != {'descriptor', 'request_id'}:
        raise ValueError('closed envelope')
    if not valid_uuid(value['request_id']):
        raise ValueError('request id')
    validate_descriptor(value['descriptor'])
    if canonical(value).encode('ascii') != raw:
        raise ValueError('original encoding')
    return value


def whole_key(descriptor):
    return {**{field: descriptor['action'][field] for field in ['account_id', 'action_id', 'revision']},
            'binding_digest': digest(canonical(descriptor))}


def edit_reason(previous, arguments, current_record=1, current_phase='proposed'):
    """Pure conformance relation for internal arguments, with no authority claim.

    This does not implement storage, replay, context fences, or an HTTP request.
    """
    if current_phase not in ['proposed', 'invalidated']:
        return 'phase'
    expected = arguments['expected_record_version']
    if (type(expected) is not int or not 1 <= expected <= I64_MAX
            or expected != current_record or current_record == I64_MAX):
        return 'record_version'
    if arguments['previous_key'] != whole_key(previous):
        return 'previous_key'
    if not valid_uuid(arguments['request_id']):
        return 'request_id'
    next_d = arguments['next_descriptor']
    if next_d.get('profile') != previous['profile']:
        return 'profile'
    try:
        validate_descriptor(next_d)
    except (ValueError, jsonschema.ValidationError):
        return 'grammar'
    for field in ['account_id', 'action_id']:
        if next_d['action'][field] != previous['action'][field]:
            return 'identity'
    for field in ['content_ref', 'routine_id']:
        if next_d['action'][field] != previous['action'][field]:
            return 'lineage'
    if previous['action']['revision'] + 1 != next_d['action']['revision']:
        return 'revision'
    without_revision = copy.deepcopy(next_d)
    without_revision['action']['revision'] = previous['action']['revision']
    if canonical(without_revision) == canonical(previous):
        return 'unchanged'
    return None


def replay_digest(operation, actor, request, arguments, domain=DOMAIN):
    # This mirrors a specified serialization grammar, not a server call. Key
    # insertion order is ActionKey's declared Serialize order, unlike canonical02.
    raw = json.dumps([actor, request, arguments], separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(domain + operation.to_bytes(2, 'big', signed=True) + raw).hexdigest()


def replay_input(vector):
    previous_key = SPECIMENS[vector['previous_specimen']]['key']
    # Explicitly pin the struct order; descriptor sorting is a different grammar.
    if list(previous_key) != ['account_id', 'action_id', 'revision', 'binding_digest']:
        raise ValueError('key Serialize order')
    next_bytes = list(SPECIMENS[vector['next_specimen']]['canonical_descriptor'].encode('ascii'))
    if vector['name'] == 'register':
        return next_bytes
    if vector['name'] == 'cancel':
        return [previous_key, vector['expected_record_version'], 'cancel']
    return [previous_key, vector['expected_record_version'], next_bytes]


class ProviderProposalHistoryTest(unittest.TestCase):
    def test_vector_document_is_closed_and_distinct_from_request_and_state(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        DOCUMENT_VALIDATOR.validate(VECTORS)
        proposal = json.loads(SPECIMENS['owner-local']['canonical_request'])
        with self.assertRaises(jsonschema.ValidationError):
            DOCUMENT_VALIDATOR.validate(proposal)
        for extra in ['approved', 'accepted_route', 'reader_permit', 'descriptor']:
            state = {**SPECIMENS['owner-local']['state'], extra: True}
            changed = copy.deepcopy(VECTORS)
            changed['specimens'][0]['state'] = state
            with self.subTest(extra=extra), self.assertRaises(jsonschema.ValidationError):
                DOCUMENT_VALIDATOR.validate(changed)
        for path in [[], ['specimens', 0], ['specimens', 0, 'key'], ['internal_edits', 0], ['replay', 0]]:
            changed = copy.deepcopy(VECTORS)
            current = changed
            for field in path:
                current = current[field]
            current['extra'] = True
            with self.subTest(path=path), self.assertRaises(jsonschema.ValidationError):
                DOCUMENT_VALIDATOR.validate(changed)

    def test_literal_full_bytes_digest_key_and_original_request_both_readers(self):
        self.assertEqual({s['descriptor']['reader']['kind'] for s in VECTORS['specimens']},
                         {'owner_local', 'customer_selected'})
        for specimen in VECTORS['specimens']:
            with self.subTest(name=specimen['name']):
                raw = specimen['canonical_descriptor'].encode('ascii')
                self.assertEqual(parse_descriptor(raw), specimen['descriptor'])
                self.assertEqual(canonical(specimen['descriptor']).encode('ascii'), raw)
                self.assertEqual(len(raw), specimen['descriptor_bytes'])
                self.assertEqual(digest(specimen['canonical_descriptor']), specimen['binding_digest'])
                self.assertEqual(whole_key(specimen['descriptor']), specimen['key'])
                self.assertNotEqual(digest(canonical(specimen['descriptor']['action'])), specimen['binding_digest'])
                request = specimen['canonical_request'].encode('ascii')
                self.assertEqual(len(request), specimen['request_bytes'])
                self.assertEqual(parse_proposal(request), {'descriptor': specimen['descriptor'],
                                                          'request_id': specimen['request_id']})
                changed = json.loads(specimen['canonical_request'])
                changed['request_id'] = '00000000-0000-0000-0000-0000000001ff'
                self.assertEqual(whole_key(parse_proposal(canonical(changed).encode())['descriptor']), specimen['key'])

    def test_each_mutable_metadata_field_binds_independently_including_nonaction_fields(self):
        base = SPECIMENS['customer-selected']['descriptor']
        fields = {(section, field) for section in ['action', 'route', 'reader', 'disclosure']
                  for field in base[section] if field not in ['kind', 'adapter', 'role', 'mode']}
        self.assertEqual({tuple(v['field']) for v in VECTORS['binding_mutations']}, fields)
        self.assertEqual(len(fields), 36)
        for vector in VECTORS['binding_mutations']:
            section, field = vector['field']
            changed = copy.deepcopy(base)
            changed[section][field] = vector['value']
            with self.subTest(section=section, field=field):
                self.assertEqual(parse_descriptor(canonical(changed).encode()), changed)
                self.assertEqual(whole_key(changed), vector['key'])
                self.assertEqual(digest(canonical(changed)), vector['binding_digest'])
                self.assertNotEqual(vector['binding_digest'], SPECIMENS['customer-selected']['binding_digest'])
                if section != 'action':
                    self.assertEqual(changed['action'], base['action'])

    def test_complete_internal_edits_invalidate_route_reader_disclosure_and_action(self):
        for vector in VECTORS['internal_edits']:
            previous = SPECIMENS[vector['previous']]['descriptor']
            next_d = SPECIMENS[vector['next']]['descriptor']
            arguments = {field: vector[field] for field in ['previous_key', 'expected_record_version', 'request_id']}
            arguments['next_descriptor'] = next_d
            with self.subTest(name=vector['name']):
                self.assertIsNone(edit_reason(previous, arguments))
                self.assertIsNone(edit_reason(previous, arguments, current_phase='invalidated'))
                self.assertEqual(vector['expected_state'], {'key': whole_key(next_d),
                                                            'record_version': 2, 'phase': 'invalidated'})
                self.assertNotEqual(vector['previous_key']['binding_digest'], whole_key(next_d)['binding_digest'])
                without_revision = copy.deepcopy(next_d)
                without_revision['action']['revision'] = previous['action']['revision']
                self.assertNotEqual(canonical(without_revision), canonical(previous))

    def test_stale_whole_key_cas_crossprofile_lineage_and_revision_only_refusals(self):
        previous = SPECIMENS['owner-local']['descriptor']
        first = VECTORS['internal_edits'][0]
        base = {field: first[field] for field in ['previous_key', 'expected_record_version', 'request_id']}
        base['next_descriptor'] = SPECIMENS['route-next']['descriptor']
        for vector in VECTORS['internal_edit_refusals']:
            arguments = copy.deepcopy(base)
            context = {'current_record_version': 1, 'current_phase': 'proposed'}
            target = vector['target'].split('.')
            if target[0] in context:
                context[target[0]] = vector['value']
            else:
                current = arguments
                for part in target[:-1]:
                    current = current[part]
                current[target[-1]] = vector['value']
            with self.subTest(target=vector['target'], value=vector['value']):
                self.assertEqual(edit_reason(previous, arguments, context['current_record_version'],
                                             context['current_phase']), vector['expected'])
        # The limit is checked before a new revision can be admitted.
        at_limit = copy.deepcopy(previous)
        at_limit['action']['revision'] = 128
        arguments = copy.deepcopy(base)
        arguments['previous_key'] = whole_key(at_limit)
        arguments['next_descriptor']['action']['revision'] = 129
        self.assertEqual(edit_reason(at_limit, arguments), 'grammar')
        arguments = copy.deepcopy(base)
        arguments['expected_record_version'] = I64_MAX
        self.assertEqual(edit_reason(previous, arguments, I64_MAX), 'record_version')

    def test_replay_literals_bind_actor_request_operation_key_cas_and_entire_next_bytes(self):
        for vector in VECTORS['replay']:
            with self.subTest(operation=vector['name']):
                arguments = replay_input(vector)
                serialized = json.dumps([vector['actor_id'], vector['request_id'], arguments],
                                        separators=(',', ':'), ensure_ascii=True)
                if vector['name'] == 'cancel':
                    self.assertEqual(serialized, vector['serialized_tuple'])
                else:
                    self.assertNotIn('serialized_tuple', vector)
                self.assertEqual(replay_digest(vector['operation'], vector['actor_id'], vector['request_id'],
                                               arguments), vector['request_digest'])
                for field in ['actor_id', 'request_id']:
                    changed = copy.deepcopy(vector)
                    changed[field] = '00000000-0000-0000-0000-0000000001ff'
                    self.assertNotEqual(replay_digest(changed['operation'], changed['actor_id'], changed['request_id'],
                                                     replay_input(changed)), vector['request_digest'])
                self.assertNotEqual(replay_digest(vector['operation'] + 1, vector['actor_id'], vector['request_id'],
                                                 arguments), vector['request_digest'])
                self.assertNotEqual(replay_digest(vector['operation'], vector['actor_id'], vector['request_id'],
                                                 arguments, b'ZT/workflow-mutation/v1\0'), vector['request_digest'])
        edit = VECTORS['replay'][2]
        for field, value in [('account_id', '00000000-0000-0000-0000-0000000001ff'),
                             ('action_id', '00000000-0000-0000-0000-0000000001ff'),
                             ('revision', 2), ('binding_digest', 'ef' * 32)]:
            changed = copy.deepcopy(replay_input(edit))
            changed[0][field] = value
            self.assertNotEqual(replay_digest(3, edit['actor_id'], edit['request_id'], changed), edit['request_digest'])
        changed = copy.deepcopy(replay_input(edit))
        changed[1] = 2
        self.assertNotEqual(replay_digest(3, edit['actor_id'], edit['request_id'], changed), edit['request_digest'])
        # Compare one metadata mutation at a time against the same complete
        # customer-selected bytes. These hash controls do not admit an edit.
        field_base = copy.deepcopy(replay_input(edit))
        field_base[2] = list(SPECIMENS['customer-selected']['canonical_descriptor'].encode('ascii'))
        field_base_digest = replay_digest(3, edit['actor_id'], edit['request_id'], field_base)
        for mutation in VECTORS['binding_mutations']:
            changed = copy.deepcopy(field_base)
            descriptor = copy.deepcopy(SPECIMENS['customer-selected']['descriptor'])
            section, field = mutation['field']
            descriptor[section][field] = mutation['value']
            changed[2] = list(canonical(descriptor).encode('ascii'))
            self.assertNotEqual(replay_digest(3, edit['actor_id'], edit['request_id'], changed), field_base_digest)

    def test_raw_envelope_duplicate_alias_numeric_padding_order_and_caps_refuse(self):
        specimen = SPECIMENS['owner-local']
        raw = specimen['canonical_request']
        bad = [raw + ' ', ' ' + raw, raw + '{}', '\ufeff' + raw,
               raw.replace('"request_id":', '"request_id" :', 1),
               raw[:-1] + ',"request_id":"' + specimen['request_id'] + '"}',
               raw.replace('"request_id":', r'"\u0072equest_id":', 1),
               raw.replace('"profile":', r'"\u0070rofile":', 1),
               raw.replace('"profile":"workflow-action-02"',
                           '"profile":"workflow-action-02","profile":"workflow-action-02"', 1),
               raw.replace('"revision":1', '"revision":1.0', 1),
               raw.replace('"revision":1', '"revision":1e0', 1),
               raw.replace('"revision":1', '"revision":01', 1),
               raw.replace('"not_before":2000000000', '"not_before":-0', 1),
               raw.replace('"revision":1', '"revision":true', 1),
               raw.replace('"revision":1', '"revision":NaN', 1)]
        reversed_outer = {'request_id': specimen['request_id'], 'descriptor': specimen['descriptor']}
        bad.append(json.dumps(reversed_outer, separators=(',', ':')))
        # A reordered nested object remains wrong even with canonical outer keys.
        changed = copy.deepcopy(specimen['descriptor'])
        changed['action'] = dict(reversed(list(changed['action'].items())))
        bad.append(json.dumps({'descriptor': changed, 'request_id': specimen['request_id']}, separators=(',', ':')))
        for wire in bad:
            with self.subTest(wire=wire[:80]), self.assertRaises((ValueError, jsonschema.ValidationError)):
                parse_proposal(wire.encode('utf-8'))
        for parser, cap in [(parse_descriptor, 4096), (parse_proposal, 8192)]:
            with self.assertRaisesRegex(ValueError, '^size$'):
                parser(b' ' * (cap + 1))
            with self.assertRaisesRegex(ValueError, '^size$'):
                parser(('\u00e9' * (cap // 2 + 1)).encode('utf-8'))
            # Exactly the cap passes the size gate, then fails JSON parsing.
            with self.assertRaises(json.JSONDecodeError):
                parser(b' ' * cap)
        with self.assertRaises(ValueError):
            parse_proposal(b'\xff')
        envelope = json.loads(raw)
        for changed in [envelope['descriptor'], [envelope], None,
                        {**envelope, 'approved': True},
                        {'descriptor': envelope['descriptor']},
                        {'request_id': envelope['request_id']}]:
            with self.subTest(envelope=type(changed).__name__), self.assertRaises(ValueError):
                parse_proposal(canonical(changed).encode())
        for request_id in [NIL, True, [], {}, envelope['request_id'] + '\n',
                           '00000000-0000-0000-0000-00000000000A']:
            changed = {**envelope, 'request_id': request_id}
            with self.subTest(request_id=request_id), self.assertRaises(ValueError):
                parse_proposal(canonical(changed).encode())

    def test_closed_nested_fields_reader_variants_strings_and_integer_bounds_refuse(self):
        for name in ['owner-local', 'customer-selected']:
            base = SPECIMENS[name]['descriptor']
            for section in [None, 'action', 'route', 'reader', 'disclosure']:
                current = base if section is None else base[section]
                for missing in current:
                    changed = copy.deepcopy(base)
                    del (changed if section is None else changed[section])[missing]
                    with self.subTest(name=name, section=section, missing=missing), self.assertRaises(jsonschema.ValidationError):
                        parse_descriptor(canonical(changed).encode())
                changed = copy.deepcopy(base)
                (changed if section is None else changed[section])['approved'] = True
                with self.assertRaises(jsonschema.ValidationError):
                    parse_descriptor(canonical(changed).encode())
            for section in ['action', 'route', 'reader', 'disclosure']:
                for field, value in base[section].items():
                    if isinstance(value, str):
                        bad_values = [value + suffix for suffix in ['\n', '\r', '\t', '\u2028', '\u007f']]
                    elif isinstance(value, int):
                        bad_values = [True, None, [], {}, -1, 9007199254740992]
                    else:
                        self.fail('unexpected descriptor type')
                    for invalid in bad_values:
                        changed = copy.deepcopy(base)
                        changed[section][field] = invalid
                        with self.subTest(name=name, section=section, field=field, invalid=invalid), self.assertRaises(jsonschema.ValidationError):
                            parse_descriptor(canonical(changed).encode())
        owner = copy.deepcopy(SPECIMENS['owner-local']['descriptor'])
        owner['reader']['grant_id'] = '00000000-0000-0000-0000-00000000001e'
        with self.assertRaises(jsonschema.ValidationError):
            parse_descriptor(canonical(owner).encode())
        for section, field, value in [('action', 'revision', 129), ('action', 'content_version', 129),
                                      ('action', 'expires_at', 9007199254741), ('action', 'not_before', 9007199254741),
                                      ('action', 'timezone', 'unknown'), ('action', 'timezone', 'T' * 65),
                                      ('action', 'window_id', 'W' * 129), ('reader', 'key_id', '00' * 32),
                                      ('reader', 'manifest_digest', '00' * 32), ('disclosure', 'recipient_commitment', '00' * 32)]:
            changed = copy.deepcopy(SPECIMENS['owner-local']['descriptor'])
            changed[section][field] = value
            with self.subTest(field=field), self.assertRaises(jsonschema.ValidationError):
                parse_descriptor(canonical(changed).encode())
        changed = copy.deepcopy(SPECIMENS['owner-local']['descriptor'])
        changed['action']['expires_at'] = changed['action']['not_before']
        with self.assertRaisesRegex(ValueError, 'time order'):
            parse_descriptor(canonical(changed).encode())
        # Boundaries that are valid metadata still establish no authority.
        maximum = copy.deepcopy(SPECIMENS['customer-selected']['descriptor'])
        for section in ['action', 'route', 'reader']:
            for field, value in maximum[section].items():
                if type(value) is int and field not in ['revision', 'content_version', 'role', 'not_before', 'expires_at']:
                    maximum[section][field] = 9007199254740991
        maximum['action'].update(revision=128, content_version=128,
                                 not_before=9007199254739, expires_at=9007199254740,
                                 timezone='T' * 64, window_id='W' * 128)
        self.assertEqual(parse_descriptor(canonical(maximum).encode()), maximum)

    def test_legacy01_literal_bytes_and_digest_stay_separate(self):
        legacy = json.loads((ROOT / 'vectors/workflow-action-01.json').read_text(encoding='utf-8'))
        self.assertEqual(canonical(legacy['action']), legacy['canonical_utf8'])
        self.assertEqual(digest(legacy['canonical_utf8']), legacy['binding_digest'])
        self.assertEqual(VECTORS['legacy01_digest_unchanged'], legacy['binding_digest'])
        with self.assertRaises(jsonschema.ValidationError):
            parse_descriptor(legacy['canonical_utf8'].encode())


if __name__ == '__main__':
    unittest.main()
