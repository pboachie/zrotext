"""Independent byte checks for the public, synthetic custody signature vector."""
import hashlib
import json
from pathlib import Path
import unittest

DIRECTORY=Path(__file__).resolve().parents[1]/"protocol/v1/vectors"


class RootCustodyVectorTests(unittest.TestCase):
    def test_transcript_binds_existing_exact_bundle_and_independent_root_pin(self):
        vector=json.loads((DIRECTORY/"root-custody-01.json").read_text())
        backup=json.loads((DIRECTORY/vector["backupSource"]).read_text())
        card=json.loads((DIRECTORY/vector["cardSource"]).read_text())
        self.assertEqual(vector["status"],"PROPOSED_ROOT_CUSTODY_01")
        u=bytes.fromhex(vector["unsignedHex"])
        pin=bytes.fromhex(card["rootPinHex"])
        fingerprint=hashlib.sha256(b"ZTSE/root-pin/v2\0"+pin).digest()
        self.assertEqual(u[5:21],pin[5:21])
        self.assertEqual(u[101:133],fingerprint)
        self.assertEqual(int.from_bytes(pin[21:29],"big"),1)
        ciphertext=bytes.fromhex(backup["ciphertextHex"])
        public_card=bytes.fromhex(card["cardHex"])
        transcript=(b"ZTSE/root-custody/v1\0"+len(u).to_bytes(4,"big")+u+
                    hashlib.sha256(ciphertext).digest()+hashlib.sha256(public_card).digest()+fingerprint)
        self.assertEqual(transcript.hex(),vector["transcriptHex"])
        self.assertEqual(hashlib.sha256(transcript).hexdigest(),vector["transcriptSha256Hex"])
        signature=bytes.fromhex(vector["signatureHex"])
        self.assertEqual(len(signature),64)
        order=int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16)
        self.assertTrue(0<int.from_bytes(signature[:32],"big")<order)
        self.assertTrue(0<int.from_bytes(signature[32:],"big")<=order//2)


if __name__=="__main__":
    unittest.main()
