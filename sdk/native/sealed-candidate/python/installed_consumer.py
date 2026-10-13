"""Run with isolated installed Python outside the source tree; synthetic stdin."""
import base64
import json
import os
from pathlib import Path
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric import ec
import zrotext_native_candidate as package
from zrotext_native_candidate import sealed_candidate as s, election03 as e

fixture = json.load(sys.stdin)
f, archive = fixture['election'], fixture['archive']
decode = lambda value: base64.b64decode(value, validate=True)
record = lambda value: {name: decode(item) if type(item) is str else item for name,item in value.items()}
assert Path(package.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()), 'consumer loaded source instead of installed package'
assert package.__version__ == '0.1.0a1'
pin = s.enroll_root02(decode(archive['rootPin']),decode(archive['fingerprint']))
manifest = s.verify_manifest02(decode(archive['manifest']),pin,archive['now'])
custody = package.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(archive['archiveScalar']),'big'),ec.SECP256R1()))
assert s.open_archive_candidate02(decode(archive['inbound']),manifest,manifest,custody,
    account=decode(archive['account']),device=decode(archive['device']),line=decode(archive['line']),peer='+12',
    reader_id=decode(archive['reader']),now_ms=archive['now']) == archive['text']
with tempfile.TemporaryDirectory() as directory:
    journal=package.ElectionJournal(Path(directory)/'election.db',decode(f['rootPin']),decode(f['fingerprint']))
    journal.accept_manifest(decode(f['signed02']),0,10000)
    expected=dict(expected_core=decode(f['core']),accepted_record=record(f['accepted']),
        device_signing_point=decode(f['deviceSigningPoint']),owner_approval_point=decode(f['ownerApprovalPoint']))
    journal.accept_election(expected_revision=1,signed03=decode(f['signed03']),bundle=decode(f['bundle']),**expected)
    _,manifest,proof=journal.snapshot_election(30000,**expected)
    custody=package.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(f['readerScalar']),'big'),ec.SECP256R1()))
    opened=e.open_elected_outbound03(raw=decode(f['envelope']),manifest=manifest,proof=proof,current_authority=record(f['authority']),
        custody=custody,expected_message_id=decode(f['message']),expected_peer='+12',now_ms=30000,require_hardware=False)
    assert opened.text == f['bodyText']
    args=dict(manifest=manifest,proof=proof,current_authority=record(f['authority']),now_ms=30000,message_id=decode(f['message']),
        observed_ms=30000,expires_ms=40000,peer='+12',content='Native composed 🌱',
        signer=package.SoftwareSigner(ec.derive_private_key(5,ec.SECP256R1())),
        recipients=[(k.role,k.id) for k in s._bound(s._manifests,manifest).keys if k.role in (1,2)],require_hardware=False)
    outbound=package.OutboundJournal(Path(directory)/'outbound.db',decode(f['rootPin']),decode(f['fingerprint']))
    result=outbound.compose_or_replay(**args)
    assert outbound.compose_or_replay(**args) == result
    try:
        package.compose_outbound03(**dict(args,require_hardware=True))
    except package.SealedError:
        pass
    else:
        raise AssertionError('software signer qualified as protected')
    if os.name!='nt':
        try: package.probe_platform()
        except package.CngUnavailable: pass
        else: raise AssertionError('non-Windows platform qualified')
    print(json.dumps(dict(envelope=base64.b64encode(result.envelope).decode(),installed=True)))
