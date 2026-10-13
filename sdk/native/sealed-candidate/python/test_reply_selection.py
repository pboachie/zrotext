"""Independent maintained TypeScript selection producer/native archive consumer."""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate.reply_selection import verify_archive_reply_selection02
from test_sealed_candidate import b64, signed


class ReplySelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('produce-selected-reply02.mjs'))],text=True,encoding='utf-8'))

    def setUp(self):
        f=self.f
        self.pin=s.enroll_root02(b64(f['rootPin']),b64(f['fingerprint']))
        self.old=s.verify_manifest02(b64(f['predecessor']),self.pin,f['now'])
        self.trust=s.advance_trust02(self.pin,self.old)
        self.activation=s.verify_manifest02(b64(f['activation']),self.trust,f['now'])
        self.scope={k:b64(f[k]) for k in ('account','device','line','interval')}
        self.scope.update(peer='+12',archive_reader=b64(f['reader']))
        self.custody=s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(b64(f['archiveScalar']),'big'),ec.SECP256R1()))

    def selection(self,**changes):
        args=dict(raw=b64(self.f['selection']),approval=b64(self.f['approval']),installation=b64(self.f['installation']),
                  activation=self.activation,accepted_ms=self.f['now'],**self.scope)
        args.update(changes)
        return verify_archive_reply_selection02(**args)

    def open(self,selection,**changes):
        args={k:v for k,v in self.scope.items() if k!='archive_reader'}
        args.update(raw=b64(self.f['inbound']),historical=self.activation,current=self.activation,custody=self.custody,
                    reader_id=self.scope['archive_reader'],now_ms=self.f['now'],selection=selection)
        args.update(changes)
        return s.open_archive_candidate02(**args)

    def resigned(self,raw):
        return dict(raw=raw,approval=signed(raw,6,'zrotext/conversation/approve/v2')[-64:],
                    installation=signed(raw,6,'zrotext/conversation/install/v2')[-64:])

    def test_real_ts_approval_installation_and_selected_wrap_open(self):
        self.assertEqual(self.open(self.selection()),self.f['text'])
        # Acceptance expiry bounds installation, not retention of authenticated history.
        self.assertEqual(self.open(self.selection(),now_ms=25000),self.f['text'])

    def test_both_signatures_domain_and_low_s_required(self):
        for field in ('approval','installation'):
            raw=bytearray(b64(self.f[field]));raw[-1]^=1
            with self.assertRaises(s.SealedError):self.selection(**{field:raw})
            raw=bytearray(b64(self.f[field]));raw[32:]=(s.ORDER-int.from_bytes(raw[32:],'big')).to_bytes(32,'big')
            with self.assertRaises(s.SealedError):self.selection(**{field:raw})
        with self.assertRaises(s.SealedError):self.selection(installation=b64(self.f['approval']))

    def test_independent_scope_activation_and_time_required(self):
        for field in ('account','device','line','interval'):
            with self.assertRaises(s.SealedError):self.selection(**{field:bytes(16)})
        for change in ({'peer':'+13'},{'archive_reader':bytes(32)},{'activation':self.old},
                       {'activation':s.Evidence()},{'accepted_ms':0},{'accepted_ms':20000},{'accepted_ms':True}):
            with self.assertRaises(s.SealedError):self.selection(**change)

    def test_signed_malformed_payload_refuses(self):
        original=b64(self.f['selection'])
        mutations=[original+b'\0',original[:-1],b'ZTCA\x03'+original[5:],original[:5]+bytes(16)+original[21:]]
        for offset in (53,141):  # capture generation and expiry
            mutations.append(original[:offset]+bytes(8)+original[offset+8:])
        disclosure=original.index(b'conversation-content-v1')+len(b'conversation-content-v1')
        mutations.append(original[:disclosure]+bytes(32)+original[disclosure+32:])
        for raw in mutations:
            with self.subTest(size=len(raw)),self.assertRaises(s.SealedError):self.selection(**self.resigned(raw))

    def test_duplicate_and_unsorted_readers_refuse_even_signed(self):
        raw=b64(self.f['selection']);record=raw[-64:];prefix=raw[:-65]
        for extra in (record,record[:32]+bytes(32),bytes([99])*32+record[32:]):
            with self.assertRaises(s.SealedError):self.selection(**self.resigned(prefix+b'\x02'+record+extra))

    def test_opaque_snapshot_and_mutable_input_capture(self):
        raw=bytearray(b64(self.f['selection']));scope=bytearray(self.scope['interval'])
        token=self.selection(raw=raw,interval=scope);raw[:]=bytes(len(raw));scope[:]=bytes(len(scope))
        self.assertEqual(self.open(token),self.f['text'])
        for token in (s.Evidence(),{},object()):
            with self.assertRaises(s.SealedError):self.open(token)

    def test_exact_wrap_selection_and_interval_before_exchange(self):
        token=self.selection()
        with patch.object(self.custody,'exchange',side_effect=AssertionError('must not unwrap')):
            for change in ({'selection':None},{'interval':None},{'interval':bytes(16)},
                           {'raw':b64(self.f['archiveOnly'])},{'historical':self.old}):
                args=dict(change);chosen=args.pop('selection',token)
                with self.assertRaises(s.SealedError):self.open(chosen,**args)

    def test_current_revoked_archive_refuses_before_exchange(self):
        raw=bytearray(b64(self.f['activation'])[:-64]);raw[29:37]=(3).to_bytes(8,'big')
        raw[53:85]=s.manifest_identity(self.activation)['digest']
        # Expire the retained archive reader in the signed current successor.
        raw[151+140:151+148]=(11000).to_bytes(8,'big')
        current=s.verify_manifest02(signed(raw,7,'ZTSE/manifest/v2'),s.advance_trust02(self.trust,self.activation),10000)
        with patch.object(self.custody,'exchange',side_effect=AssertionError('must not unwrap')):
            with self.assertRaisesRegex(s.SealedError,'current reader revoked'):
                self.open(self.selection(),current=current,now_ms=12000)

    def test_valid_signed_activation_fork_is_not_current_history(self):
        raw=bytearray(b64(self.f['activation'])[:-64]);raw[37:45]=(9001).to_bytes(8,'big')
        fork=s.verify_manifest02(signed(raw,7,'ZTSE/manifest/v2'),self.trust,10000)
        selection=bytearray(b64(self.f['selection']))
        digest=s.manifest_identity(self.activation)['digest'];at=selection.index(digest)
        selection[at:at+32]=s.manifest_identity(fork)['digest']
        token=self.selection(activation=fork,**self.resigned(selection))
        with patch.object(self.custody,'exchange',side_effect=AssertionError('must not unwrap')):
            with self.assertRaisesRegex(s.SealedError,'activation lineage'):self.open(token)


if __name__=='__main__':unittest.main()
