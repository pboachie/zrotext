import dataclasses
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from installed_root_bundle_consumer import exercise
from zrotext_native_candidate import root_bundle as bundle

ROOT=Path(__file__).resolve().parent


class RootBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases=json.loads(subprocess.check_output(['node',str(ROOT/'root-bundle-interop.mjs')],text=True))['cases']

    def test_maintained_byte_and_refusal_parity(self):
        self.assertEqual(exercise(self.cases),41)

    def test_inputs_captured_before_public_crypto_and_result_immutable(self):
        f=self.cases[0];pin=bytearray.fromhex(f['pin']);compared=bytearray.fromhex(f['fingerprint'])
        p={k:bytearray.fromhex(v) for k,v in f['published'].items()};expected=bytes(p['encryptedBackup'])
        original=bundle.s.enroll_root02
        def mutate(a,b):
            pin[:]=bytes(len(pin));compared[:]=bytes(len(compared))
            for value in p.values():value[:]=bytes(len(value))
            return original(a,b)
        with patch.object(bundle.s,'enroll_root02',mutate):result=bundle.verify_published_root_bundle(pin,compared,f['origin'],p)
        self.assertEqual(result.encrypted_backup,expected)
        with self.assertRaises(dataclasses.FrozenInstanceError):result.root_pin=b''

    def test_closed_native_input_types_and_extra_metadata(self):
        f=self.cases[0];pin=bytes.fromhex(f['pin']);fp=bytes.fromhex(f['fingerprint']);p={k:bytes.fromhex(v) for k,v in f['published'].items()}
        self.assertIsNotNone(bundle.verify_published_root_bundle(pin,fp,f['origin'],dict(p,irrelevant=True)))
        for bad in (None,[],memoryview(pin),pin[:-1]):
            with self.assertRaises(bundle.RootBundleError):bundle.verify_published_root_bundle(bad,fp,f['origin'],p)
        for bad in (None,{},dict(p,encryptedBackup=bytes(749)),dict(p,custodySignature=[])):
            with self.assertRaises(bundle.RootBundleError):bundle.verify_published_root_bundle(pin,fp,f['origin'],bad)


if __name__=='__main__':unittest.main()
