"""Actual maintained TS metadata validation; no structural mock claim."""
import json
import base64
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from installed_lifecycle_consumer import ID,metadata
from zrotext_native_candidate.sealed_lifecycle import SealedLifecycleClient,SealedLifecycleError,SEALED_MESSAGE_STATES


class ParityTests(unittest.TestCase):
    def test_maintained_metadata_and_pagination_acceptance(self):
        cases=[]
        def add(body,method='status',status=200):cases.append(dict(body=body,method=method,status=status,argument=ID if method!='list' else None))
        for state in SEALED_MESSAGE_STATES:add(dict(metadata(),state=state))
        for field in ('state_version','created_at_ms','updated_at_ms','expires_at_ms'):
            for value in (0,1.0,1.5,(1<<53)-1,1<<53,True):add(dict(metadata(),**{field:value}))
        add(dict(metadata(),state='cancelled'),'cancel');add(metadata(),'cancel')
        add(dict(metadata(),unexpected=1));add(dict(metadata(),device_id='wrong'))
        for count,cursor in ((0,None),(1,None),(20,None),(20,ID),(19,ID),(21,None),(20,'00000000-0000-0000-0000-000000000002')):
            add(dict(messages=[metadata()]*count,next_cursor=cursor),'list')
        for code,status in (('unauthorized',401),('unavailable',503),('rate_limited',429),('cancellation_conflict',409),('not_found',503)):
            add(dict(code=code),'cancel',status)
        for prefix in (b'\xef\xbb\xbf',b'\xef\xbb\xbf'*2,b'\xff'):
            cases.append(dict(method='status',status=200,argument=ID,raw=base64.b64encode(prefix+json.dumps(metadata()).encode()).decode()))
        expected=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('lifecycle-interop.mjs'))],input=json.dumps(cases),encoding='utf-8'))
        actual=[];client=SealedLifecycleClient('https://synthetic.example.invalid','synthetic')
        for item in cases:
            raw=base64.b64decode(item['raw']) if 'raw' in item else json.dumps(item['body']).encode()
            with patch.object(client,'_exchange',return_value=(item['status'],raw)):
                try:actual.append(dict(accepted=True,value=getattr(client,item['method'])(item['argument'])))
                except SealedLifecycleError as error:actual.append(dict(accepted=False,code=error.code))
        self.assertEqual(actual,expected)
        self.assertEqual(len(cases),54)
