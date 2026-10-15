"""Signed contact statement/field and WHATWG differential acceptance, synthetic only."""
import argparse
import base64
import copy
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
    source = args.producer.resolve()
    assert subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip()
    command = [str(args.binary.resolve())] if args.binary else json.loads(args.command_file.read_text())
    assert isinstance(command, list) and command and all(isinstance(v, str) and v and '\0' not in v for v in command)
    oracle = Path(__file__).with_name('contact-field-interop.mjs')
    generated = json.loads(subprocess.check_output(['node', str(oracle), str(source)], timeout=60))
    fixture = generated['fixture']
    requests, expected, names = [], [], []

    def add(name, request, accepted):
        names.append(name)
        requests.append(request)
        expected.append(accepted)

    for c in fixture['originCases']:
        add('origin ' + c['origin'], dict(operation='origin', origin=c['origin']), c['accepted'])
    for c in generated['signed']:
        add(c['name'], {k: v for k, v in c.items() if k not in ('name', 'accepted')}, c['accepted'])
    for field, statement in [('name', 'statement'), ('notes', 'statement'), ('replacement', 'nextStatement')]:
        for mode in ('verify', 'produce'):
            add(mode + field, dict(fixture=fixture, operation=mode, field=field, statement=statement), True)
    for field, mode in [('statement', 'statement'), ('name', 'verify')]:
        raw = base64.b64decode(fixture[field])
        for at in range(len(raw)):
            changed = bytearray(raw)
            changed[at] ^= 1
            f = dict(fixture, **{field: base64.b64encode(changed).decode()})
            add(f'{field} byte {at}', dict(fixture=f, operation=mode), False)
        high = bytearray(raw)
        order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        high[-32:] = (order - int.from_bytes(high[-32:], 'big')).to_bytes(32, 'big')
        f = dict(fixture, **{field: base64.b64encode(high).decode()})
        add(field + ' high-S equivalent signature', dict(fixture=f, operation=mode), False)
    for name, at, value in [('kind', 5, b'\x03'), ('zero revision', 38, bytes(8)),
                            ('overflow revision', 38, (1 << 63).to_bytes(8, 'big')),
                            ('zero request', 198, bytes(16)), ('invalid point', 246, b'\x04' + bytes(64))]:
        raw = bytearray(base64.b64decode(fixture['name']))
        raw[at:at + len(value)] = value
        f = dict(fixture, name=base64.b64encode(raw).decode())
        add('producer ' + name, dict(fixture=f, operation='produce'), False)
    add('cancelled', dict(fixture=fixture, operation='produce', cancel=True), False)
    add('wrong scalar', dict(fixture=fixture, operation='produce', scalar=base64.b64encode(bytes(31) + b'\x08').decode()), False)
    for field, size in [('account', 16), ('fingerprint', 32), ('contact', 16), ('routing', 32)]:
        f = copy.deepcopy(fixture)
        f[field] = base64.b64encode(bytes([91]) * size).decode()
        add('scope ' + field, dict(fixture=f, operation='verify'), False)
    results = json.loads(subprocess.check_output(command, input=json.dumps(requests).encode(), timeout=180))
    assert len(results) == len(requests)
    for name, result, accepted in zip(names, results, expected):
        assert result['accepted'] is accepted, (name, accepted, result)
    outputs = [dict(bytes=result['bytes'], statement=request['statement']) for request, result in zip(requests, results)
               if request['operation'] == 'produce' and result['accepted']]
    report = json.loads(subprocess.check_output(['node', str(oracle), str(source), '--consume'],
        input=json.dumps(dict(fixture=fixture, outputs=outputs)).encode(), timeout=60))
    assert report == dict(verified=True, fields=3)
    print(f'{len(results)} contact controls passed; 3 native fields independently verified by maintained SDK')


if __name__ == '__main__':
    main()
