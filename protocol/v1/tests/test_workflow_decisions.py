# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import unittest
import jsonschema

class DecisionRequestsTest(unittest.TestCase):
    def setUp(self):
        self.schema=json.loads((Path(__file__).resolve().parents[1]/"vectors"/"workflow-decisions.schema.json").read_text(encoding="utf-8"))
        self.identity="00000000-0000-0000-0000-000000000004"
        self.key={"account_id":self.identity,"action_id":self.identity,"revision":1,"binding_digest":"05"*32}
        self.decision={"request_id":self.identity,"expected_record_version":1,"key":self.key,"decision":"approve"}

    def test_exact_approval_cancellation_correlation_and_takeover_shapes(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)
        for request in [self.decision,{**self.decision,"decision":"cancel"},{"key":self.key},{"request_id":self.identity,"context_id":self.identity},{"request_id":self.identity,"correlation":{"context_id":self.identity,"context_revision":1,"event_id":self.identity,"request_action":None}},{"request_id":self.identity,"correlation":{"context_id":self.identity,"context_revision":1,"event_id":self.identity,"request_action":self.key}}]:
            jsonschema.validate(request,self.schema)

    def test_extra_authority_flags_missing_binding_nil_ids_and_guessed_decisions_are_refused(self):
        bad=[]
        for change in [{"approved":True},{"decision":"receipt"},{"decision":"silence"},{"request_id":"00000000-0000-0000-0000-000000000000"},{"expected_record_version":True}]:
            bad.append({**self.decision,**change})
        for field,value in [("revision",129),("revision",True),("binding_digest","05"*31),("binding_digest","AA"*32)]:
            request=copy.deepcopy(self.decision);request["key"][field]=value;bad.append(request)
        request=copy.deepcopy(self.decision);del request["key"]["binding_digest"];bad.append(request)
        for request in bad:
            with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(request,self.schema)
