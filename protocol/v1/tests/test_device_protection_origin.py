"""Independent public-byte and stdlib P256 controls, not provider attestation."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import unittest
import uuid
import jsonschema

ROOT=Path(__file__).resolve().parents[1]
P=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G=(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
B=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
H=lambda b:hashlib.sha256(b).digest()
def raw(text):
    b=base64.urlsafe_b64decode(text+'='*(-len(text)%4))
    assert base64.urlsafe_b64encode(b).decode().rstrip('=')==text
    return b
def framed(label,payload):return label.encode()+b'\0'+struct.pack('>I',len(payload))+payload
def add(a,b):
    if a is None:return b
    if b is None:return a
    x,y=a;u,v=b
    if x==u and (y+v)%P==0:return None
    slope=((3*x*x-3)*pow(2*y,-1,P) if a==b else (v-y)*pow(u-x,-1,P))%P
    z=(slope*slope-x-u)%P
    return z,(slope*(x-z)-y)%P
def mul(k,a):
    result=None
    while k:
        if k&1:result=add(result,a)
        a=add(a,a);k>>=1
    return result
def verifies(point,signature,message):
    if len(point)!=65 or point[0]!=4 or len(signature)!=64:return False
    q=(int.from_bytes(point[1:33],'big'),int.from_bytes(point[33:],'big'))
    if not all(0<=x<P for x in q) or (q[1]*q[1]-q[0]**3+3*q[0]-B)%P:return False
    r=int.from_bytes(signature[:32],'big');s=int.from_bytes(signature[32:],'big')
    if not(0<r<N and 0<s<=N//2):return False
    inv=pow(s,-1,N);z=int.from_bytes(H(message),'big')
    check=add(mul(z*inv%N,G),mul(r*inv%N,q))
    return check is not None and check[0]%N==r

class ProtectionOriginTests(unittest.TestCase):
    def setUp(self):
        self.v=json.loads((ROOT/'vectors/device-protection-origin-v1.json').read_text())
        self.p=self.v['parameters'];self.a=raw(self.v['association']);self.c=raw(self.v['core']);self.b=raw(self.v['bundle'])
    def test_closed_structural_schema(self):
        schema=json.loads((ROOT/'device-protection-origin-v1.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(self.v)
        changed=dict(self.v,permission=True)
        with self.assertRaises(jsonschema.ValidationError):jsonschema.Draft202012Validator(schema).validate(changed)
    def test_independent_association_core_and_probes(self):
        p=self.p;ids=b''.join(uuid.UUID(p[k]).bytes for k in ['account_id','device_id','setup_id','opening_id','command_id','source_pairing_id'])
        probe=raw(p['journal_aes_probe'])+raw(p['withdrawal_aes_probe']);self.assertEqual(probe,raw(p['aes_probe']));self.assertEqual(len(probe),120)
        expected=b'ZTPA\x01\x01\0\0'+ids+raw(p['origin_digest'])+raw(p['enrolled_key_id'])+H(raw(p['opening_nonce']))+raw(p['hmac_probe'])+H(probe)+raw(p['canary_point'])
        self.assertEqual(self.a,expected);self.assertEqual(len(expected),329)
        core=b'ZTPR\x01\x01\0\0'+expected[8:]+uuid.UUID(p['attempt_id']).bytes+struct.pack('>QQ',int(p['issued_ms']),int(p['expires_ms']))+H(raw(p['attempt_nonce']))
        self.assertEqual(self.c,core);self.assertEqual(len(core),393)
        self.assertEqual(self.b,core+raw(self.v['device_signature'])+raw(self.v['canary_signature']));self.assertEqual(len(self.b),521)
        self.assertEqual(raw(p['enrolled_key_id']),H(b'ZTSE/key/v1\0\x01\x01'+raw(p['enrolled_point'])))
        for name,data in [('association',self.a),('core',self.c),('bundle',self.b)]:self.assertEqual(raw(self.v['sha256'][name]),H(data))
    def test_closed_control_shapes_preserve_nulls_and_reject_other_protocols(self):
        schema=json.loads((ROOT/'device-protection-control-v1.schema.json').read_text());validator=jsonschema.Draft202012Validator(schema)
        p=self.p;shared=dict(v=1,connection_epoch=1,setup_id=p['setup_id'],opening_id=p['opening_id'],command_id=p['command_id'])
        request=dict(shared,type='protection_origin_proof_open',proof_request_id=p['attempt_id'],association=self.v['association'],aes_probe=p['aes_probe'],previous_attempt_id=None,previous_core_sha256=None,previous_bundle_sha256=None)
        validator.validate(request)
        for changed in [dict(request,body_digest=p['origin_digest']),dict(request,type='radio_event'),{k:v for k,v in request.items() if k!='previous_bundle_sha256'}]:
            with self.assertRaises(jsonschema.ValidationError):validator.validate(changed)
        proof=dict(shared,type='protection_origin_proof',proof_request_id=p['attempt_id'],attempt_id=p['attempt_id'],bundle=self.v['bundle']);validator.validate(proof)
        self.assertLess(len(json.dumps(proof,separators=(',',':')).encode()),4096)
        status=dict(shared,type='protection_origin_status',request_id=p['attempt_id'],proof_request_id=None,status='not_found',opening=None,challenge=None,receipt=None);validator.validate(status)
        with self.assertRaises(jsonschema.ValidationError):validator.validate(dict(status,permission=True))

    def test_two_actual_low_s_signatures_and_domain_scope_refusals(self):
        p=self.p;ds=raw(self.v['device_signature']);cs=raw(self.v['canary_signature']);dp=raw(p['enrolled_point']);cp=raw(p['canary_point'])
        first=framed('ZT/protection/first-origin-device/v1',self.c);second=framed('ZT/protection/first-origin-canary/v1',self.c+H(ds))
        self.assertTrue(verifies(dp,ds,first));self.assertTrue(verifies(cp,cs,second))
        self.assertFalse(verifies(cp,ds,first));self.assertFalse(verifies(dp,ds,second))
        self.assertFalse(verifies(cp,cs,framed('ZT/protection/first-origin-device/v1',self.c+H(ds))))
        for at in [8,104,168,200,232,264,329,345,353,361]:
            changed=bytearray(self.c);changed[at]^=1
            self.assertFalse(verifies(dp,ds,framed('ZT/protection/first-origin-device/v1',changed)))
        high_s=ds[:32]+(N-int.from_bytes(ds[32:],'big')).to_bytes(32,'big')
        self.assertFalse(verifies(dp,high_s,first));self.assertFalse(verifies(dp,bytes(64),first))

if __name__=='__main__':unittest.main()
