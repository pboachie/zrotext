"""Shared signed policy cases consumed through the installed native package."""
import base64
import json
from pathlib import Path
import sys
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
import zrotext_native_candidate as native
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate import election03 as e
from zrotext_native_candidate import compose03 as c


def decode(value):return base64.b64decode(value,validate=True)
def record(value):return {key:decode(item) if type(item) is str else item for key,item in value.items()}
def arguments(f):
    accepted=record(f['accepted']);comparison=accepted['acceptedAtMs']
    pin=s.enroll_root02(decode(f['rootPin']),decode(f['fingerprint']))
    prior=s.verify_manifest02(decode(f['signed02']),pin,comparison)
    manifest=s.verify_manifest03(decode(f['signed03']),prior,comparison)
    proof=e.verify_accepted_election03(bundle=decode(f['bundle']),expected_core=decode(f['core']),accepted_record=accepted,
        predecessor02=prior,prior_signed02=decode(f['signed02']),accepted_signed03=decode(f['signed03']),
        device_signing_point=decode(f['deviceSigningPoint']),owner_approval_point=decode(f['ownerApprovalPoint']))
    signer=c.SoftwareSigner(ec.derive_private_key(int.from_bytes(decode(f['signerScalar']),'big'),ec.SECP256R1()))
    return dict(manifest=manifest,proof=proof,current_authority=record(f['authority']),now_ms=f['now'],message_id=decode(f['message']),
        observed_ms=f['observed'],expires_ms=f['expires'],peer='+12',content=f['bodyText'],signer=signer,
        recipients=[(r['role'],decode(r['keyId'])) for r in f['recipients']],require_hardware=False)


def open_value(f,args,envelope):
    recipient=next(r for r in f['recipients'] if r['role']==1)
    custody=s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(recipient['scalar']),'big'),ec.SECP256R1()))
    return e.open_elected_outbound03(envelope,args['manifest'],args['proof'],args['current_authority'],custody,
        expected_message_id=args['message_id'],expected_peer=args['peer'],now_ms=args['now_ms'],require_hardware=False)


def assert_self_open(f,args,result):
    opened=open_value(f,args,result.envelope)
    assert opened.text==f['bodyText'] and opened.envelope_digest==result.envelope_digest
    fixture_opened=open_value(f,args,decode(f['envelope']))
    assert fixture_opened.text==f['bodyText']


def assert_read_refused(f,args):
    with patch.object(s,'_unwrap') as unwrap:
        try:open_value(f,args,decode(f['envelope']))
        except s.SealedError:pass
        else:raise AssertionError('out-of-policy reader accepted')
        unwrap.assert_not_called()


def main():
    assert Path(native.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    outputs=[]
    for f in json.load(sys.stdin)['cases']:
        args=arguments(f)
        try:result=native.compose_outbound03(**args)
        except s.SealedError:
            assert not f['accept'],f['name']
            assert_read_refused(f,args);continue
        assert f['accept'],f['name']
        assert_self_open(f,args,result)
        outputs.append(dict(fixture=f,envelope=base64.b64encode(result.envelope).decode(),expectedText=f['bodyText']))
    print(json.dumps(dict(installed=True,outputs=outputs)))


if __name__=='__main__':main()
