"""Normal installed contact producer, independently consumed in TypeScript."""
import base64
import json
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric import ec
import zrotext_native_candidate as n
from zrotext_native_candidate import contact_integrity as c, contact_producer as p, sealed_candidate as s


def decode(v):return base64.b64decode(v,validate=True)
def encode(v):return base64.b64encode(v).decode('ascii')


def material(f):
    root=s.enroll_root02(decode(f['rootPin']),decode(f['fingerprint']))
    first=s.verify_manifest02(decode(f['manifest']),root,10000)
    second=s.verify_manifest02(decode(f['nextManifest']),s.advance_trust02(root,first),10000)
    scope=dict(account=decode(f['account']),origin=f['origin'],root_fingerprint=decode(f['fingerprint']))
    return c.verify_contact_reader_statement01(decode(f['statement']),first,**scope),c.verify_contact_reader_statement01(decode(f['nextStatement']),second,**scope)


def build(f,signer,*,require_hardware):
    old,new=material(f)
    expected=dict(accountId=decode(f['account']),origin=f['origin'],rootFingerprint=decode(f['fingerprint']),contactId=decode(f['contact']),routingDigest=decode(f['routing']))
    fields={}
    for key in ('name','notes','replacement'):
        parsed=c.parse_contact_field01(decode(f[key]));field={k:parsed[k] for k in ('kind','sealRevision','requestId','encapsulation','ciphertext')}
        fields[key]=p.produce_contact_field01(signer=signer,statement=new if key=='replacement' else old,expected=expected,field=field,require_hardware=require_hardware)
    def slot(key):
        ident=c.contact_field_identity(fields[key].verified)
        return dict(tag=1,sealRevision=ident['sealRevision'],digest=ident['digest'])
    mutations={}
    for key in ('create','update','clear','converted'):
        statement=new if key in ('update','clear') else old;st=c.contact_statement_identity(statement)
        parsed=c.parse_contact_mutation01(decode(f[key]));m={k:parsed[k] for k in c._MUTATION}
        m.update(accountId=st['accountId'],manifestVersion=st['manifestVersion'],manifestDigest=st['manifestDigest'],statementDigest=st['digest'])
        previous=mutations['create'].verified if key=='update' else mutations['update'].verified if key=='clear' else None
        m['previousDigest']=bytes(32) if previous is None else c.contact_transition_identity(previous)['digest']
        m['name']=dict(tag=0,sealRevision=0,digest=bytes(32)) if key=='clear' else slot('name')
        m['notes']=slot('replacement' if key in ('update','clear') else 'notes')
        replacements=[fields['replacement'].verified] if key=='update' else [] if key=='clear' else [fields['name'].verified,fields['notes'].verified]
        mutations[key]=p.produce_contact_transition01(signer=signer,statement=statement,expected=expected|dict(legacyGeneration=7 if key=='converted' else 0),mutation=m,
            previous=previous,previous_statement=old if key=='update' else new if key=='clear' else None,replacement_fields=replacements,require_hardware=require_hardware)
    return dict(fixture=f,fields={k:encode(v.signed_bytes) for k,v in fields.items()},mutations={k:encode(v.signed_bytes) for k,v in mutations.items()})


def main():
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    signer=p.SoftwareOwnerRootSigner(ec.derive_private_key(7,ec.SECP256R1()))
    print(json.dumps(build(json.load(sys.stdin),signer,require_hardware=False)))


if __name__=='__main__':main()
