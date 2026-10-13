"""Semantic currentness is not installation or exact signed-evidence replay."""
import base64
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from zrotext_native_candidate import sealed_candidate as s,election03 as e,ElectionJournal
from test_election03 import produce,prepare,decode,record
from test_sealed_candidate import signed


class Current03Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=produce()

    def setUp(self):self.current,self.proof,self.proof_args=prepare(self.f)

    def test_alternate_signature_and_refusal_corpus_match_maintained_ts(self):
        original=decode(self.f['signed03'])
        alternate=signed(original[:-64],7,'ZTSE/manifest/v3')
        self.assertNotEqual(alternate,original)
        fork=bytearray(original[:-64]);fork[39:47]=(9001).to_bytes(8,'big')
        successor=bytearray(original[:-64]);successor[6]=3;successor[31:39]=(3).to_bytes(8,'big');successor[55:87]=s.sha(original[:-64])
        high=original[:-32]+(s.ORDER-int.from_bytes(original[-32:],'big')).to_bytes(32,'big')
        bad=bytearray(original);bad[-1]^=1
        cases=[(original,10000),(alternate,10001),(original,9999),(original,100000),
               (signed(fork,7,'ZTSE/manifest/v3'),10000),(signed(successor,7,'ZTSE/manifest/v3'),10000),
               (high,10000),(bad,10000),(decode(self.f['signed02']),10000),(original+b'\0',10000)]
        payload=dict(fixture=self.f,cases=[dict(raw=base64.b64encode(raw).decode(),now=now) for raw,now in cases])
        ts=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('check-current03.mjs'))],
                                             input=json.dumps(payload),encoding='utf-8'))
        native=[]
        for raw,now in cases:
            try:
                result=s.verify_manifest03_current(raw,self.current,now)
                native.append(dict(accepted=True,digest=base64.b64encode(s.manifest_identity(result)['digest']).decode(),
                                   comparison=s._bound(s._manifests,result).comparison))
            except s.SealedError:native.append(dict(accepted=False))
        self.assertEqual(native,ts['results']);self.assertEqual(ts['originalComparison'],10000)
        self.assertEqual([r['accepted'] for r in native],[True,True]+[False]*8)

    def test_owned_bytes_and_new_comparison_floor_preserve_original(self):
        raw=bytearray(decode(self.f['signed03']))
        result=s.verify_manifest03_current(raw,self.current,30000);raw[:]=bytes(len(raw))
        self.assertEqual(s.manifest_identity(result),s.manifest_identity(self.current))
        self.assertEqual(s._bound(s._manifests,result).comparison,30000)
        self.assertEqual(s._bound(s._manifests,self.current).comparison,10000)
        self.assertEqual(s._bound(s._manifests,self.current).raw,decode(self.f['signed03']))
        with self.assertRaises(s.SealedError):s.verify_manifest03_current(decode(self.f['signed03']),result,29999)
        for fake in (s.Evidence(),{},self.proof,self.proof_args['predecessor02']):
            with self.assertRaises(s.SealedError):s.verify_manifest03_current(decode(self.f['signed03']),fake,30000)

    def test_semantic_current_signature_never_replaces_accepted_journal_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'election.db'
            journal=ElectionJournal(path,decode(self.f['rootPin']),decode(self.f['fingerprint']))
            journal.accept_manifest(decode(self.f['signed02']),0,10000)
            expectations=dict(expected_core=decode(self.f['core']),accepted_record=record(self.f['accepted']),
                device_signing_point=decode(self.f['deviceSigningPoint']),owner_approval_point=decode(self.f['ownerApprovalPoint']))
            journal.accept_election(expected_revision=1,signed03=decode(self.f['signed03']),bundle=decode(self.f['bundle']),**expectations)
            _,current,proof=journal.snapshot_election(30000,**expectations)
            alternate=signed(decode(self.f['signed03'])[:-64],7,'ZTSE/manifest/v3')
            verified=s.verify_manifest03_current(alternate,current,30000)
            e.require_current_election03(proof,verified,record(self.f['authority']),30000)
            with self.assertRaises(s.SealedError):journal.accept_manifest(alternate,2,30000,election_expectations=expectations)
            db=sqlite3.connect(path)
            try:self.assertEqual(db.execute('SELECT signed FROM manifests WHERE revision=2').fetchone()[0],decode(self.f['signed03']))
            finally:db.close()
            self.assertEqual(journal.snapshot_election(30000,**expectations)[0],2)


if __name__=='__main__':unittest.main()
