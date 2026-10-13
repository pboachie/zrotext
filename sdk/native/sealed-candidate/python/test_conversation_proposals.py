"""Maintained proposal byte/refusal differential; no trusted state fabrication."""
import base64
import json
from pathlib import Path
import subprocess
import unittest
from installed_conversation_proposals_consumer import inputs,invoke,encode,check
from zrotext_native_candidate import conversation_proposals as p

ROOT=Path(__file__).parent

def cases():
    rows=[]
    for operation in ('genesis','activation','refresh'):
        rows.append(dict(operation=operation))
        for origin in ('http://owner.invalid','https://owner.invalid/','https://OWNER.invalid','https://owner.invalid:443','https://owner.invalid?x'):
            rows.append(dict(operation=operation,path='origin',value=origin))
        rows.append(dict(operation=operation,path='comparedRootFingerprint',mutate=0))
        rows.append(dict(operation=operation,path='nowMs',value=0))
        prefix='review.binding' if operation=='refresh' else 'selection'
        for name in ('account','device','line'):
            rows.append(dict(operation=operation,path=prefix+'.'+name,mutate=0))
        rows.append(dict(operation=operation,path=prefix+'.generation',value=0))
        rows.append(dict(operation=operation,path=prefix+'.peer',value='not-a-peer'))
    rows+= [dict(operation='genesis',path='phoneSignerPoint',mutate=4),dict(operation='genesis',path='expiresMs',value=10000)]
    for operation in ('activation','refresh'):rows.append(dict(operation=operation,forged=True))
    for role in ('phoneReader','archiveReader','phoneSigner'):rows.append(dict(operation='activation',path='selection.'+role,mutate=0))
    for field in ('keyId','predecessorDigest','publicPoint'):rows.append(dict(operation='refresh',path='review.'+field,mutate=3))
    for offset in (5,21,29,45,53,85,150,291):rows.append(dict(operation='refresh',path='review.unsigned',mutate=offset))
    return rows

class ConversationProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=json.loads(subprocess.check_output(['node',str(ROOT/'conversation-proposals-interop.mjs')],encoding='utf-8'))
    def test_actual_maintained_bytes_and_refusals(self):
        rows=cases();expected=json.loads(subprocess.check_output(['node',str(ROOT/'conversation-proposals-interop.mjs'),'--cases'],input=json.dumps(dict(fixture=self.f,cases=rows)),encoding='utf-8'))
        self.assertEqual(len(rows),len(expected))
        for item,want in zip(rows,expected):
            with self.subTest(case=item):
                value=inputs(self.f)[item['operation']]
                if 'path' in item:
                    parts=item['path'].split('.');target=value
                    for key in parts[:-1]:target=target[key]
                    key=parts[-1]
                    if 'mutate' in item:
                        changed=bytearray(target[key]);changed[item['mutate']]^=1;target[key]=changed
                    else:target[key]=item['value']
                if item.get('forged'):value['predecessor']=object()
                try:got=dict(accepted=True,result=encode(invoke(item['operation'],value)))
                except p.ConversationProposalError:got=dict(accepted=False)
                self.assertEqual(got,want)
    def test_public_comparison_contract_and_ciphertext_not_authenticated(self):
        self.assertEqual(check(self.f),dict(installed=True,typed_proposals=3,public_comparisons=2))
        d=base64.b64decode;v=inputs(self.f)['genesis'];archive=bytearray(d(self.f['archive']));archive[-1]^=1
        self.assertEqual(p.verify_archive_public_header02(archive,v['selection']['account'],v['comparedRootFingerprint'],v['origin'],d(self.f['activation']['selection']['archiveReader'])),d(self.f['verifiedArchive']))
        for field in ('phone','archive'):
            raw=bytearray(d(self.f[field]));raw[22]^=1
            with self.assertRaises(p.ConversationProposalError):
                if field=='phone':p.verify_phone_key_export02(raw,v['selection'],d(self.f['phoneFingerprint']))
                else:p.verify_archive_public_header02(raw,v['selection']['account'],v['comparedRootFingerprint'],v['origin'],d(self.f['activation']['selection']['archiveReader']))
    def test_returned_bytes_are_immutable_and_inputs_do_not_alias(self):
        value=inputs(self.f)['genesis'];value['selection']['account']=bytearray(value['selection']['account']);result=invoke('genesis',value);before=result['proposal'];value['selection']['account'][:]=bytes(16)
        self.assertEqual(result['proposal'],before)
        with self.assertRaises(TypeError):result['proposal']=b'changed'

    def test_actual_maintained_public_header_refusals(self):
        d=base64.b64decode;f=self.f;v=inputs(f)['genesis'];head=177+len(v['origin'])
        rows=[dict(operation='phone',mutate=n) for n in (0,5,21,37,53,85,93,222)]
        rows.append(dict(operation='phone',irrelevant=True))
        rows += [dict(operation='archive',mutate=n) for n in (0,22,38,46,78,110,175,177,head+107,len(d(f['archive']))-1)]
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'conversation-proposals-interop.mjs'),'--public-cases'],input=json.dumps(dict(fixture=f,cases=rows)),encoding='utf-8'))
        self.assertEqual(len(rows),len(expected))
        for item,want in zip(rows,expected):
            with self.subTest(case=item):
                raw=bytearray(d(f[item['operation']]))
                if 'mutate' in item:raw[item['mutate']]^=1
                selection=dict(v['selection'])
                if item.get('irrelevant'):selection.update(session=bytes(16),peer='not-a-peer',extra=True)
                try:
                    result=p.verify_phone_key_export02(raw,selection,d(f['phoneFingerprint'])) if item['operation']=='phone' else p.verify_archive_public_header02(raw,v['selection']['account'],v['comparedRootFingerprint'],v['origin'],d(f['activation']['selection']['archiveReader']))
                    got=dict(accepted=True,result=encode(result))
                except p.ConversationProposalError:got=dict(accepted=False)
                self.assertEqual(got,want)
