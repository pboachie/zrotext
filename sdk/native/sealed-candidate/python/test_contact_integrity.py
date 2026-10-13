"""Fresh independent TS signatures and complete historical transitions."""
import base64
import json
from pathlib import Path
import subprocess
import unittest
from zrotext_native_candidate import contact_integrity as c
from zrotext_native_candidate import sealed_candidate as s


def decode(v):return base64.b64decode(v,validate=True)
def fixture():return json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('contact-interop.mjs'))],encoding='utf-8'))
def material(f):
    trust=s.enroll_root02(decode(f['rootPin']),decode(f['fingerprint']))
    first=s.verify_manifest02(decode(f['manifest']),trust,10000)
    second=s.verify_manifest02(decode(f['nextManifest']),s.advance_trust02(trust,first),10000)
    scope=dict(account=decode(f['account']),origin=f['origin'],root_fingerprint=decode(f['fingerprint']))
    return first,second,c.verify_contact_reader_statement01(decode(f['statement']),first,**scope),c.verify_contact_reader_statement01(decode(f['nextStatement']),second,**scope)


class ContactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def setUp(self):
        self.first,self.second,self.old,self.new=material(self.f)
        self.scope=dict(contact=decode(self.f['contact']),routing_digest=decode(self.f['routing']))
    def field(self,key):return c.verify_contact_field01(decode(self.f[key]),self.new if key=='replacement' else self.old,**self.scope)
    def mutation(self,key):return c.verify_contact_mutation01(decode(self.f[key]),self.new if key in ('update','clear') else self.old,legacy_generation=7 if key=='converted' else 0,**self.scope)
    def initial(self):return c.verify_contact_transition01(None,self.mutation('create'),[self.field('name'),self.field('notes')])
    def test_complete_independent_compound_history(self):
        initial=self.initial()
        changed=c.verify_contact_transition01(initial,self.mutation('update'),[self.field('replacement')])
        final=c.verify_contact_transition01(changed,self.mutation('clear'),[])
        self.assertEqual(c.contact_transition_identity(final)['digest'],decode(self.f['finalDigest']))
        self.assertEqual(c.contact_transition_identity(final)['revision'],3)
        self.assertEqual(c.contact_transition_identity(final)['name']['tag'],0)
        c.verify_contact_transition01(None,self.mutation('converted'),[self.field('name'),self.field('notes')])
    def test_exact_unsigned_codecs(self):
        for key,parse,encode,fields in [('statement',c.parse_contact_reader_statement01,c.encode_contact_reader_statement01,c._STATEMENT),('name',c.parse_contact_field01,c.encode_contact_field01,c._FIELD),('create',c.parse_contact_mutation01,c.encode_contact_mutation01,c._MUTATION)]:
            raw=decode(self.f[key]);parsed=parse(raw)
            self.assertEqual(encode({k:parsed[k] for k in fields}),raw[:-64])
            with self.assertRaises(c.ContactIntegrityError):encode(dict({k:parsed[k] for k in fields},unknown=True))
    def test_actual_ts_origin_differential_including_idna(self):
        for case in self.f['originCases']:
            with self.subTest(origin=case['origin']):
                try:c._origin(case['origin']);accepted=True
                except Exception:accepted=False
                self.assertEqual(accepted,case['accepted'])
        self.assertEqual(self.f['origin'],'https://xn--fa-hia.invalid')
        self.assertTrue(next(x['accepted'] for x in self.f['originCases'] if x['origin']=='https://xn--fa-hia.invalid'))
    def test_unicode_contexts_scalar_sampling_and_exact_ts_unsigned_bytes(self):
        labels=['faß','bücher','δοκιμή','пример','مثال','例子','☃','a\u200cb','a\u200db','a\u0300','\u0300ab','אa','aא','\u200c']
        labels+=['a'+chr(code)+'b' for code in range(128,0x110000,257) if not 0xd800<=code<=0xdfff]
        origins=['https://xn--'+label.encode('punycode').decode('ascii')+'.invalid' for label in labels]
        origins+=['https://'+('a'*504),'https://'+('a'*505),'https://.','https://synthetic.invalid?','https://synthetic.invalid#','https://synthetic.invalid:65536','https://xn--fa-hia.invalid/','https://faß.invalid']
        f=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('contact-interop.mjs')),'--origins'],input=json.dumps(origins),encoding='utf-8'))
        parsed=c.parse_contact_reader_statement01(decode(f['statement']))
        values={key:parsed[key] for key in c._STATEMENT}
        for case in f['originCases']:
            with self.subTest(origin=case['origin']):
                if case['accepted']:
                    self.assertEqual(c.encode_contact_reader_statement01(values|dict(origin=case['origin'])),decode(case['unsigned']))
                else:
                    with self.assertRaises(c.ContactIntegrityError):c.encode_contact_reader_statement01(values|dict(origin=case['origin']))

    def test_signatures_frames_and_points_refused(self):
        for key,verify in [('statement',lambda b:c.verify_contact_reader_statement01(b,self.first,account=decode(self.f['account']),origin=self.f['origin'],root_fingerprint=decode(self.f['fingerprint']))),('name',lambda b:c.verify_contact_field01(b,self.old,**self.scope)),('create',lambda b:c.verify_contact_mutation01(b,self.old,**self.scope))]:
            raw=decode(self.f[key])
            for bad in (raw+b'\0',raw[:-1],raw[:10]+bytes([raw[10]^1])+raw[11:],raw[:-32]+(s.ORDER-int.from_bytes(raw[-32:],'big')).to_bytes(32,'big'),raw[:-64]+bytes(64)):
                with self.subTest(key=key),self.assertRaises(c.ContactIntegrityError):verify(bad)
        raw=bytearray(decode(self.f['name']));raw[246:311]=b'\4'+bytes(64)
        with self.assertRaises(c.ContactIntegrityError):c.parse_contact_field01(raw)
    def test_independent_binding_and_genuine_tokens(self):
        scope=dict(account=decode(self.f['account']),origin=self.f['origin'],root_fingerprint=decode(self.f['fingerprint']))
        for change in (dict(account=bytes([1])*16),dict(origin='https://other.invalid'),dict(root_fingerprint=bytes([1])*32),dict(comparison='now')):
            with self.assertRaises(c.ContactIntegrityError):c.verify_contact_reader_statement01(decode(self.f['statement']),self.first,**(scope|change))
        for token in ({},c.contact_statement_identity(self.old),self.first):
            with self.assertRaises(c.ContactIntegrityError):c.verify_contact_field01(decode(self.f['name']),token,**self.scope)
        with self.assertRaises(c.ContactIntegrityError):c.verify_contact_reader_statement01(decode(self.f['statement']),{},**scope)
        with self.assertRaises(c.ContactIntegrityError):c.verify_contact_field01(decode(self.f['name']),self.new,**self.scope)
        for change in (dict(contact=bytes([1])*16),dict(routing_digest=bytes([1])*32)):
            with self.assertRaises(c.ContactIntegrityError):c.verify_contact_field01(decode(self.f['name']),self.old,**(self.scope|change))
        with self.assertRaises(c.ContactIntegrityError):c.verify_contact_mutation01(decode(self.f['converted']),self.old,**self.scope)
    def test_transition_refuses_missing_stale_duplicate_and_unused_fields(self):
        initial=self.initial();name=self.field('name');notes=self.field('notes');replacement=self.field('replacement')
        cases=[(None,self.mutation('update'),[replacement]),(None,self.mutation('create'),[]),(None,self.mutation('create'),[name,name]),(initial,self.mutation('update'),[notes]),(initial,self.mutation('update'),[name,replacement]),(initial,self.mutation('clear'),[]),(initial,self.mutation('create'),[name,notes]),({},self.mutation('update'),[replacement])]
        for args in cases:
            with self.assertRaises(c.ContactIntegrityError):c.verify_contact_transition01(*args)
    def test_defensive_identity_and_closed_integer_slot_bounds(self):
        identity=c.contact_statement_identity(self.old);identity['origin']='https://other.invalid'
        self.assertEqual(c.contact_statement_identity(self.old)['origin'],self.f['origin'])
        initial=self.initial();identity=c.contact_transition_identity(initial);identity['name']['digest']=bytes(32)
        self.assertNotEqual(c.contact_transition_identity(initial)['name']['digest'],bytes(32))
        v=c.parse_contact_mutation01(decode(self.f['create']));v={k:v[k] for k in c._MUTATION}
        for change in (dict(revision=True),dict(revision=1.0),dict(revision=10**1000),dict(name=dict(tag=0,sealRevision=1,digest=bytes(32))),dict(name=dict(tag=1,sealRevision=1,digest=bytes(32))),dict(legacyGeneration=1)):
            with self.assertRaises(c.ContactIntegrityError):c.encode_contact_mutation01(v|change)


if __name__=='__main__':unittest.main()
