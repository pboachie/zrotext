"""Real signed historical mutation/transition acceptance with maintained reverse verification."""
import argparse
import base64
import json
from pathlib import Path
import subprocess

PIN = 'ccf28fe445ba959aa01d99fed6bd9ee3188b749c'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--producer', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--binary', type=Path)
    choice.add_argument('--command-file', type=Path)
    args = parser.parse_args()
    source = args.producer.resolve(strict=True)
    assert subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip()
    command = [str(args.binary.resolve())] if args.binary else json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(command, list) and command and all(isinstance(s, str) and s and '\0' not in s for s in command)
    generated = json.loads(subprocess.check_output(['node', str(Path(__file__).with_name('contact-mutation-interop.mjs')), str(source)], timeout=60))
    fixture = generated['fixture']
    rows, expectations = [], []

    def add(name, accepted, authenticated=False, **request):
        rows.append(dict(fixture=fixture, **request))
        expectations.append((name, accepted, authenticated))

    for mutation in ('create', 'update', 'clear', 'converted'):
        add('verified ' + mutation, True, True, operation='verify', mutation=mutation)
        add('transition ' + mutation, True, True, operation='transition', mutation=mutation)
        add('produced ' + mutation, True, operation='produce', mutation=mutation)
        raw = base64.b64decode(fixture[mutation])
        for at in range(len(raw)):
            changed = bytearray(raw); changed[at] ^= 1
            rows.append(dict(operation='verify', mutation=mutation, fixture=dict(fixture, **{mutation: base64.b64encode(changed).decode()})))
            expectations.append((f'{mutation} byte {at}', False, False))
        high = bytearray(raw)
        order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        high[-32:] = (order - int.from_bytes(high[-32:], 'big')).to_bytes(32, 'big')
        rows.append(dict(operation='verify', mutation=mutation, fixture=dict(fixture, **{mutation: base64.b64encode(high).decode()})))
        expectations.append((mutation + ' high-S', False, False))
    for case in generated['signed']:
        rows.append(dict(operation='transition', mutation=case['mutation'], fixture=case['fixture'], statement=case.get('statement')))
        expectations.append((case['name'], False, True))
        rows.append(dict(operation='produce', mutation=case['mutation'], fixture=case['fixture'], statement=case.get('statement')))
        expectations.append(('pre-sign ' + case['name'], False, False))
    shapes = [
        ('create', 'operation', 5, b'\x04', 0),
        ('create', 'zero revision', 46, bytes(8), 0),
        ('create', 'overflow revision', 46, (1 << 63).to_bytes(8, 'big'), 0),
        ('create', 'zero request', 54, bytes(16), 0),
        ('create', 'nonzero initial predecessor', 70, bytes([9]) * 32, 0),
        ('create', 'legacy on create', 214, (7).to_bytes(8, 'big'), 7),
        ('converted', 'missing legacy generation', 214, bytes(8), 0),
        ('converted', 'overflow legacy generation', 214, (1 << 63).to_bytes(8, 'big'), 1 << 63),
        ('create', 'invalid slot tag', 222, b'\x02', 0),
        ('create', 'absent slot with identity', 222, b'\x00', 0),
        ('create', 'present slot zero revision', 223, bytes(8), 0),
        ('create', 'present slot zero digest', 231, bytes(32), 0),
        ('create', 'future seal revision', 223, (2).to_bytes(8, 'big'), 0),
        ('update', 'zero expected revision', 38, bytes(8), 0),
        ('update', 'overflow expected revision', 38, (1 << 63).to_bytes(8, 'big'), 0),
        ('update', 'zero predecessor digest', 70, bytes(32), 0),
        ('update', 'legacy on update', 214, (7).to_bytes(8, 'big'), 7),
    ]
    for mutation, name, at, value, legacy in shapes:
        raw = bytearray(base64.b64decode(fixture[mutation]))
        raw[at:at + len(value)] = value
        rows.append(dict(operation='produce', mutation=mutation, legacy=legacy,
                         fixture=dict(fixture, **{mutation: base64.b64encode(raw).decode()})))
        expectations.append(('shape ' + name, False, False))
    for raw in (base64.b64decode(fixture['create'])[:-1], base64.b64decode(fixture['create']) + b'\0'):
        rows.append(dict(operation='verify', mutation='create', fixture=dict(fixture, create=base64.b64encode(raw).decode())))
        expectations.append(('exact mutation width', False, False))
    for mutation, previous in [('create', 'create'), ('update', 'none'), ('clear', 'create'), ('converted', 'create')]:
        add('wrong predecessor ' + mutation, False, True, operation='transition', mutation=mutation, previous=previous)
    for fields in ([], ['name'], ['name', 'name'], ['name', 'notes', 'replacement'], ['replacement']):
        add('replacement set ' + str(fields), False, True, operation='transition', mutation='create', replacements=fields)
    add('unused field', False, True, operation='transition', mutation='clear', replacements=['replacement'])
    for previous_statement in ('none', 'nextStatement'):
        add('wrong previous statement', False, operation='produce', mutation='update', previousStatement=previous_statement)
    add('unexpected previous statement', False, operation='produce', mutation='create', previousStatement='statement')
    add('wrong legacy expectation', False, operation='verify', mutation='converted', legacy=0)
    add('cancelled', False, operation='produce', cancel=True)
    add('wrong software scalar', False, operation='produce', scalar=base64.b64encode(bytes(31) + b'\x08').decode())
    add('native complete chain', True, operation='produce-chain')
    results = json.loads(subprocess.check_output(command, input=json.dumps(rows).encode(), timeout=240))
    assert len(results) == len(rows)
    for (name, accepted, authenticated), result in zip(expectations, results):
        assert result['accepted'] is accepted and result['mutationVerified'] is authenticated, (name, result, accepted, authenticated)
    for row, result in zip(rows, results):
        if row['operation'] == 'transition' and row.get('mutation') == 'update' and result['accepted']:
            assert result['fields']['name'] == fixture['name'], 'Retained original field bytes changed'
        if row['operation'] == 'transition' and row.get('mutation') == 'clear' and result['accepted']:
            assert result['fields'] == {'notes': fixture['replacement']}, 'Clear must retain the unchanged notes field'
    generated_chain = results[-1]['mutations']
    consumer = source / 'sdk/native/sealed-candidate/python/contact-producer-interop.mjs'
    report = json.loads(subprocess.check_output(['node', str(consumer)], input=json.dumps(dict(fixture=fixture, fields={k: fixture[k] for k in ('name', 'notes', 'replacement')}, mutations=generated_chain)).encode(), timeout=60))
    assert report['verified'] is True and report['fields'] == 3 and report['transitions'] == 4
    print(f'{len(results)} mutation controls passed; four native transitions independently verified')


if __name__ == '__main__':
    main()
