"""Shared fourteen cases use fresh TS signatures/elections and all HPKE wraps."""
import base64
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from zrotext_native_candidate import compose03 as c
from zrotext_native_candidate import sealed_candidate as s
from installed_time_consumer import arguments

ROOT=Path(__file__).resolve().parents[4]
SOURCE=Path(os.environ.get('ZROTEXT_TIME_POLICY_SOURCE',ROOT/'time-policy-source'))
CLI=SOURCE/'sdk/typescript/test/fixtures/profile03-time-cli.mjs'


class OutboundTimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases=json.loads(subprocess.check_output(['node',str(CLI)],encoding='utf-8'))['cases']
        assert len(cls.cases)==14
    def test_shared_policy_refuses_before_randomness_or_signing_and_opens_all_recipients(self):
        for f in self.cases:
            with self.subTest(case=f['name']):
                args=arguments(f)
                if not f['accept']:
                    with patch.object(c.os,'urandom') as draw,patch.object(c.SoftwareSigner,'sign') as sign:
                        with self.assertRaises(s.SealedError):c.compose_outbound03(**args)
                        draw.assert_not_called();sign.assert_not_called()
                    continue
                result=c.compose_outbound03(**args)
                payload=dict(fixture=f,envelope=base64.b64encode(result.envelope).decode(),expectedText=f['bodyText'])
                accepted=json.loads(subprocess.check_output(['node',str(CLI),'--consume'],input=json.dumps(payload),encoding='utf-8'))
                self.assertEqual(accepted,dict(verified=True,name=f['name'],recipients=3))


if __name__=='__main__':unittest.main()
