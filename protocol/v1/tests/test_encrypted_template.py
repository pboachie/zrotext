# SPDX-License-Identifier: AGPL-3.0-only
import json
from pathlib import Path
import unittest
import jsonschema

class EncryptedTemplateWire(unittest.TestCase):
    def test_distinct_template_domain_and_authenticated_identity(self):
        root=Path(__file__).resolve().parents[1]
        template=json.loads((root/'vectors/encrypted-template-01.json').read_text())
        jsonschema.validate(template,json.loads((root/'vectors/encrypted-template.schema.json').read_text()),format_checker=jsonschema.FormatChecker())
        context=json.loads((root/'vectors/workflow-context-01.json').read_text())
        aad=bytes.fromhex(template['aad_hex'])
        self.assertEqual(len(aad),222)
        self.assertEqual(aad[:6],b'ZTWT\x01\x01')
        self.assertNotEqual(aad,bytes.fromhex(context['aad_hex']))
        self.assertEqual(bytes.fromhex(template['hpke_info_hex']),b'ZT/workflow-template/hpke/v1\0'+aad)
        self.assertEqual(aad[70:86].hex(),template['scope']['template_id'].replace('-',''))
        self.assertEqual(int.from_bytes(aad[94:102],'big'),template['scope']['revision'])
