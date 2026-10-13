"""Installed historical contact verification; no checkout imports or authority."""
import base64
import json
from pathlib import Path
import sys
import tempfile
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
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'contacts.db';root_path=Path(directory)/'root.db'
        root_store=n.CheckpointStore(root_path,d('rootPin'),d('fingerprint'))
        root_store.accept_manifest(d('manifest'),0,10000)
        args=dict(origin=f['origin'],maximum_records=1,root_history_path=root_path)
        with n.ContactHistory(path,d('rootPin'),d('fingerprint'),create=True,**args) as history:
            accepted=history.accept(expected=None,transition=initial,statement=old)
            assert accepted['kind']=='accepted_local_history'
        root_store.accept_manifest(d('nextManifest'),1,10000)
        with n.ContactHistory(path,d('rootPin'),d('fingerprint'),**args) as history:
            restored=history.lookup(d('contact'))
            changed_result=history.accept(expected=restored['token'],transition=changed,statement=new)
            final_result=history.accept(expected=changed_result['token'],transition=final,statement=new)
            assert final_result['metadata']['digest']==d('finalDigest')
        with n.ContactHistory(path,d('rootPin'),d('fingerprint'),reduction_only=True,**args) as history:
            restored=history.lookup(d('contact'));assert restored['reason']=='reduction_only'
            assert history.mark_unavailable(expected=restored['token'])['reason']=='local_stop'
        with n.ContactHistory(path,d('rootPin'),d('fingerprint'),**args) as history:
            assert history.lookup(d('contact'))['reason']=='local_stop'
    try:n.verify_contact_transition01(initial,mutations['clear'],[])
    except n.ContactIntegrityError:pass
    else:raise AssertionError('skipped historical revision accepted')
    print(json.dumps(dict(installed=True,historical_contact_integrity=True)))


if __name__=='__main__':main()
