"""Synthetic HTTP acceptance for a generated Rust or Go SDK process."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IDENTITY = "11111111-2222-4333-8444-555555555555"

class Wire(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.reply=(200, {}, dict(message_id=IDENTITY, device_id=IDENTITY, state="unknown",state_version=1,created_at_ms=1,updated_at_ms=1))
        self.token=secrets.token_urlsafe(24)
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self): self.respond()
            def do_POST(self): self.respond()
            def respond(self):
                body=self.rfile.read(int(self.headers.get("Content-Length","0")))
                owner.calls.append((self.command,self.path,{k.lower():v for k,v in self.headers.items()},body))
                status,headers,value=owner.reply
                if self.path=="/redirected": status,headers,value=200,{},dict(message_id=IDENTITY,device_id=IDENTITY,state="unknown",state_version=1,created_at_ms=1,updated_at_ms=1)
                payload=json.dumps(value).encode()
                self.send_response(status)
                for k,v in headers.items(): self.send_header(k,v)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(payload)))
                self.end_headers();self.wfile.write(payload)
            def log_message(self,*_args): pass
        self.server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base=f"http://127.0.0.1:{self.server.server_port}"
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join()
    def invoke(self,operation="public.getAlphaMessageStatus",args=None,**extra):
        request=dict(base=self.base,token=self.token,operation=operation,args=args if args is not None else {"message_id":IDENTITY})
        # Generated dynamic argument spelling differs; wire spelling is checked below.
        if os.environ.get("ZROTEXT_NATIVE_LANGUAGE") == "go" and "message_id" in request["args"]:
            request["args"] = {("messageId" if k == "message_id" else k): v for k,v in request["args"].items()}
        request.update(extra)
        env={k:v for k,v in os.environ.items() if k.upper() not in {"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"}}
        env["NO_PROXY"]="127.0.0.1"
        process=subprocess.run([os.environ["ZROTEXT_TEST_NATIVE"]],input=json.dumps(request),capture_output=True,text=True,env=env,timeout=15)
        self.assertEqual(process.returncode,0,process.stderr)
        self.assertNotIn(self.token,process.stdout+process.stderr)
        return json.loads(process.stdout)
    def test_auth_and_wire_path(self):
        self.assertTrue(self.invoke()["ok"])
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][:2],("GET","/v1/alpha/messages/"+IDENTITY))
        self.assertEqual(self.calls[0][2]["authorization"],"Bearer "+self.token)
    def test_missing_wrong_scope_and_invalid_argument_are_preflight(self):
        for operation,args,extra,category in [
            ("public.getAlphaMessageStatus",{"message_id":IDENTITY},{"token":None},"AUTH_FAILED"),
            ("workflow.workflowReadiness",{},{},"AUTH_FAILED"),
            ("public.getAlphaMessageStatus",{"message_id":"bad"},{},"VALIDATION_FAILED")]:
            result=self.invoke(operation,args,**extra)
            self.assertFalse(result["ok"]);self.assertEqual(result["category"],category)
        self.assertEqual(self.calls,[])
    def test_malformed_success_is_rejected(self):
        self.reply=(200,{}, {})
        self.assertFalse(self.invoke()["ok"]);self.assertEqual(len(self.calls),1)
    def test_read_failure_does_not_retry(self):
        self.reply=(503,{}, {"code":"unavailable"})
        result=self.invoke();self.assertFalse(result["ok"])
        self.assertEqual(result["attempts"],1);self.assertEqual(len(self.calls),1)
    def test_uncertain_send_preserves_key_and_sends_once(self):
        self.reply=(503,{}, {"code":"unavailable"})
        args=dict(client_message_id=IDENTITY,device_id=IDENTITY,recipient_e164="+15550100001",test_case_id="synthetic",expires_at_ms=1999999999999)
        result=self.invoke("public.submitAlphaMessage",args,key="synthetic-intent",confirm=True)
        self.assertEqual(result["category"],"OUTCOME_UNKNOWN")
        self.assertEqual(result["attempts"],1);self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][2]["idempotency-key"],"synthetic-intent")
        self.assertEqual(json.loads(self.calls[0][3]),args)
    def test_cursor_query_and_page_wire(self):
        self.reply=(200,{}, {"messages":[],"next_cursor":None})
        result=self.invoke("sealed.listSealedMessages",{"cursor":IDENTITY})
        self.assertTrue(result["ok"],result)
        self.assertEqual(self.calls[0][1],"/v1/sealed/messages?cursor="+IDENTITY)
        self.assertEqual(result["value"]["messages"],[])
    def test_mutation_redirect_is_not_followed(self):
        self.reply=(307,{"Location":"/redirected"}, {})
        result=self.invoke("public.cancelAlphaMessage")
        self.assertFalse(result["ok"]);self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][0],"POST")
    def test_cross_origin_redirect_is_not_followed(self):
        self.reply=(302,{"Location":"http://localhost:"+str(self.server.server_port)+"/redirected"}, {})
        self.assertFalse(self.invoke()["ok"]);self.assertEqual(len(self.calls),1)

if __name__=="__main__": unittest.main()
