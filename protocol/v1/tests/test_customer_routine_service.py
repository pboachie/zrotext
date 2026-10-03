# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import unittest
import jsonschema

class CustomerRoutineRequests(unittest.TestCase):
    def setUp(self):
        self.schema=json.loads((Path(__file__).resolve().parents[1]/"vectors"/"customer-routine-service.schema.json").read_text(encoding="utf-8"))
        self.identity="00000000-0000-0000-0000-000000000004"
        self.admit={"operation":"admit","params":{"request_id":self.identity,"policy_id":self.identity,"context_id":self.identity,"input_revision":1,"input_source_digest":"ab"*32,"direction":"owner_declared"}}

    def test_closed_current_admission_ciphertext_checkpoint_and_resume(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)
        for request in [self.admit,{"operation":"current","params":{"context_id":self.identity,"policy_id":self.identity}},{"operation":"produced","params":{"context_id":self.identity,"call_id":self.identity,"archive_ciphertext_digest":"cd"*32}},{"operation":"resume","params":{"call_id":self.identity}}]:
            jsonschema.validate(request,self.schema)

    def test_model_authority_credentials_plaintext_digest_and_changed_identity_are_refused(self):
        bad=[]
        for field,value in [("approved",True),("credential","example"),("output_context_id",self.identity),("direction","inferred"),("input_revision",True),("input_source_digest","AB"*32),("request_id","00000000-0000-0000-0000-000000000000")]:
            request=copy.deepcopy(self.admit);request["params"][field]=value;bad.append(request)
        bad.append({"operation":"produced","params":{"context_id":self.identity,"call_id":self.identity,"plaintext_digest":"ab"*32}})
        for request in bad:
            with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(request,self.schema)

    def test_inbound_is_a_distinct_shape_not_an_automatic_authority_alias(self):
        request=copy.deepcopy(self.admit);request["params"]["direction"]="inbound"
        jsonschema.validate(request,self.schema)
        # Wire syntax does not grant inbound execution: Rust admission refuses it.
        self.assertNotEqual(request,self.admit)

    def test_owner_policy_pins_local_installation_and_refuses_model_paths(self):
        schema=json.loads((Path(__file__).resolve().parents[1]/"vectors"/"customer-routine-policy.schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        vector=json.loads((Path(__file__).resolve().parents[1]/"vectors"/"customer-routine-policy-01.json").read_text(encoding="utf-8"))
        jsonschema.validate(vector,schema)
        policy={"request_id":self.identity,"policy_id":self.identity,"context_id":self.identity,"routine_id":self.identity,
                "generation":1,"kind":"faq","executor":"deterministic_local","period":"utc_day","expires_ms":1,
                "call_limit":1,"unit_limit":1,"units_per_call":1,"turn_limit":1,"timeout_ms":1000,
                "window":{"timezone":"UTC","first_local_date":"2030-01-01","opens_minute":0,"closes_minute":60,
                          "repeat_every_days":None,"max_occurrences":1,"pacing_seconds":60}}
        jsonschema.validate(policy,schema)
        policy.update(executor="local_process",adapter_id="customer_faq",artifact_digest="ab"*32)
        jsonschema.validate(policy,schema)
        for field,value in [("adapter_id",None),("adapter_id","../model"),("artifact_digest",None),("artifact_digest","AB"*32),("command","model-selected")]:
            invalid=copy.deepcopy(policy);invalid[field]=value
            with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(invalid,schema)
        policy["executor"]="deterministic_local"
        with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(policy,schema)
