"""Installed historical contact verification; no checkout imports or authority."""
import base64
import json
from pathlib import Path
import sys
import zrotext_native_candidate as n
from zrotext_native_candidate import sealed_candidate as s


def main():
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    f=json.load(sys.stdin);d=lambda k:base64.b64decode(f[k],validate=True)
    root=s.enroll_root02(d('rootPin'),d('fingerprint'))
    first=s.verify_manifest02(d('manifest'),root,10000)
    second=s.verify_manifest02(d('nextManifest'),s.advance_trust02(root,first),10000)
    statement_scope=dict(account=d('account'),origin=f['origin'],root_fingerprint=d('fingerprint'))
    assert f['origin']=='https://xn--fa-hia.invalid'
    parsed=n.parse_contact_reader_statement01(d('statement'))
    fields=('authorizationId','accountId','origin','trustGeneration','manifestVersion','readerGeneration','rootFingerprint','manifestDigest','readerId','readerPoint','issuedMs','untilMs','capability')
    values={key:parsed[key] for key in fields}
    for case in f['originCases']:
        try:encoded=n.encode_contact_reader_statement01(values|dict(origin=case['origin']))
        except n.ContactIntegrityError:assert not case['accepted']
        else:assert case['accepted'] and encoded==base64.b64decode(case['unsigned'],validate=True)
    old=n.verify_contact_reader_statement01(d('statement'),first,**statement_scope)
    new=n.verify_contact_reader_statement01(d('nextStatement'),second,**statement_scope)
    scope=dict(contact=d('contact'),routing_digest=d('routing'))
    fields={key:n.verify_contact_field01(d(key),new if key=='replacement' else old,**scope) for key in ('name','notes','replacement')}
    mutations={key:n.verify_contact_mutation01(d(key),old if key=='create' else new,**scope) for key in ('create','update','clear')}
    initial=n.verify_contact_transition01(None,mutations['create'],[fields['name'],fields['notes']])
    changed=n.verify_contact_transition01(initial,mutations['update'],[fields['replacement']])
    final=n.verify_contact_transition01(changed,mutations['clear'],[])
    assert n.contact_transition_identity(final)['digest']==d('finalDigest')
    try:n.verify_contact_transition01(initial,mutations['clear'],[])
    except n.ContactIntegrityError:pass
    else:raise AssertionError('skipped historical revision accepted')
    print(json.dumps(dict(installed=True,historical_contact_integrity=True)))


if __name__=='__main__':main()
