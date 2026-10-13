"""Installed managed archive HTTP checks, adapted from reviewed conformance."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[3]
FIRST = "11111111-2222-4333-8444-555555555555"
SECOND = "22222222-3333-4444-8555-666666666666"


def message(identity):
    return dict(message_id=identity, device_id=FIRST, state="queued", created_at_ms=1000,
                updated_at_ms=1000, events=[], events_truncated=False)


def exercise(command, env=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.answer()

        def do_POST(self):
            self.answer()

        def answer(self):
            size = int(self.headers.get("Content-Length", "0"))
            self.server.received.append((self.command, self.path, dict(self.headers), self.rfile.read(size)))
            mode = self.server.mode
            if mode == "lost":
                self.close_connection = True
                return
            if mode == "timeout":
                time.sleep(2.5)
            status, body, headers = 200, b'{"endpoints":[]}', {}
            if mode.startswith("pages"):
                before = parse_qs(urlsplit(self.path).query).get("before", [None])[0]
                body = json.dumps(dict(messages=[message(FIRST if before is None else SECOND)],
                                       next_cursor=FIRST if before is None else None)).encode()
                if before is not None and mode == "pages-rate":
                    status, body, headers = 429, b'{"error":"rate_limited"}', {"Retry-After": "1"}
                elif before is not None and mode == "pages-schema":
                    body = b'{"messages":[{}],"next_cursor":null}'
            elif mode == "malformed":
                body = b'{'
            elif mode == "schema":
                body = b'{}'
            elif mode == "redirect":
                status, body, headers = 302, b'', {"Location": self.server.other}
            elif mode == "disabled":
                status, body = 404, b''
            elif mode == "rate":
                status, body, headers = 429, b'{"error":"rate_limited"}', {"Retry-After": "1"}
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    servers = [ThreadingHTTPServer(("127.0.0.1", 0), Handler) for _ in range(2)]
    for server in servers:
        server.received, server.mode = [], "ok"
        threading.Thread(target=server.serve_forever, daemon=True).start()
    server, other = servers
    server.other = f"http://127.0.0.1:{other.server_port}/stolen"
    base = f"http://127.0.0.1:{server.server_port}"
    environment = {key: value for key, value in (os.environ if env is None else env).items()
                   if not key.startswith("ZROTEXT_") and key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}}
    environment["NO_PROXY"] = "127.0.0.1"

    def call(name, mode="ok", operation="public.listWebhookEndpoints", auth=True, params=None, count=1, category=None, key=None, confirm=False):
        server.mode, server.received = mode, []
        input_data = dict(base=base, operation=operation, auth=auth, args=params or {}, key=key, confirm=confirm)
        result = subprocess.run(command, input=json.dumps(input_data), text=True, capture_output=True,
                                env=environment, timeout=20, check=True)
        for credential in ("synthetic-session", "synthetic-csrf", "synthetic-bearer", "ztw_synthetic", "synthetic-idempotency"):
            assert credential not in result.stdout + result.stderr, name + " exposed a credential or key"
        value = json.loads(result.stdout)
        assert len(server.received) == count, (name, value, len(server.received))
        if category:
            assert value.get("category") == category, (name, value)
            assert value["trace"]["attempts"] == count, (name, value)
        else:
            assert value == {"ok": True}, (name, value)
        print(name + " passed", flush=True)
        return value

    def pages(name, expected, cursors, mode="pages", before=None, limit=4, auth=True):
        server.mode, server.received = mode, []
        input_data = dict(base=base, pages=True, auth=auth, args={} if before is None else {"before": before}, limit=limit)
        result = subprocess.run(command, input=json.dumps(input_data), text=True, capture_output=True,
                                env=environment, timeout=20, check=True)
        assert json.loads(result.stdout) == {"pages": expected}, (name, result.stdout, result.stderr)
        for secret in ("synthetic-session", "synthetic-csrf", "synthetic-bearer", "ztw_synthetic"):
            assert secret not in result.stdout + result.stderr, name + " exposed credentials"
        assert len(server.received) == len(cursors), (name, len(server.received))
        for request, cursor in zip(server.received, cursors):
            method, path, raw_headers, body = request
            url = urlsplit(path)
            assert method == "GET" and url.path == "/v1/owner/messages" and body == b"", name
            assert parse_qs(url.query) == ({} if cursor is None else {"before": [cursor]}), (name, path)
            headers = {key.lower(): value for key, value in raw_headers.items()}
            assert "__Host-zrotext_session=synthetic-session" in headers["cookie"], name
            assert "__Host-zrotext_csrf=synthetic-csrf" in headers["cookie"], name
            assert headers["x-zrotext-csrf"] == "synthetic-csrf" and "authorization" not in headers, name
        print(name + " passed", flush=True)

    try:
        first = {"ids": [FIRST], "cursor": FIRST}
        second = {"ids": [SECOND], "cursor": None}
        pages("typed owner pagination preserves items cursor and auth", [first, second], [None, FIRST])
        pages("explicit initial cursor is retained", [second], [FIRST], before=FIRST)
        pages("application page limit makes no speculative request", [first], [None], limit=1)
        pages("second page rate refusal ends enumeration without retry", [first, {"category": "RATE_LIMITED"}],
              [None, FIRST], mode="pages-rate")
        pages("malformed second page ends enumeration without partial success", [first, {"category": "UNEXPECTED_RESPONSE"}],
              [None, FIRST], mode="pages-schema")
        pages("pagination missing auth refuses before network", [{"category": "AUTH_FAILED"}], [], auth=False)
        call("owner cookie authentication")
        headers = {k.lower(): v for k, v in server.received[0][2].items()}
        assert "__Host-zrotext_session=synthetic-session" in headers["cookie"]
        assert "__Host-zrotext_csrf=synthetic-csrf" in headers["cookie"]
        assert headers["x-zrotext-csrf"] == "synthetic-csrf"
        assert "authorization" not in headers
        call("missing auth refuses before network", auth=False, count=0, category="AUTH_FAILED")
        call("malformed JSON is rejected", mode="malformed", category="UNEXPECTED_RESPONSE")
        call("strict response schema is enforced", mode="schema", category="UNEXPECTED_RESPONSE")
        call("read timeout has one attempt", mode="timeout", category="UPSTREAM_UNAVAILABLE")
        call("rate limit does not retry", mode="rate", category="RATE_LIMITED")
        call("cross origin redirect refuses", mode="redirect", category="UNEXPECTED_RESPONSE")
        assert not other.received, "Redirect destination received credentials"
        call("lost mutation response stays unknown", mode="lost", operation="public.createWebhookEndpoint",
             params={"callback_url": "https://example.test/hook"}, category="OUTCOME_UNKNOWN")
        headers = {k.lower(): v for k, v in server.received[0][2].items()}
        assert headers["origin"] == "https://example.test"
        call("sealed disabled response fails closed", mode="disabled", operation="sealed.listSealedDevices", category="GATE_DISABLED")
        headers = {k.lower(): v for k, v in server.received[0][2].items()}
        assert headers["authorization"] == "Bearer synthetic-bearer"
        assert "cookie" not in headers
        identity = "11111111-2222-4333-8444-555555555555"
        submission = dict(client_message_id=identity, device_id=identity, recipient_e164="+15550100001",
                          test_case_id="synthetic", expires_at_ms=1999999999999)
        call("caller owned idempotency required before send", operation="public.submitAlphaMessage",
             params=submission, count=0, category="VALIDATION_FAILED")
        call("irreversible send requires preview confirmation", operation="public.submitAlphaMessage",
             params=submission, key="synthetic-idempotency", count=0, category="CONFIRMATION_REQUIRED")
        value = call("confirmed lost send retains caller key with one attempt", operation="public.submitAlphaMessage",
                     params=submission, key="synthetic-idempotency", confirm=True, mode="lost", category="OUTCOME_UNKNOWN")
        assert value["retryable"] == "same_key_only"
        headers = {k.lower(): v for k, v in server.received[0][2].items()}
        assert headers["idempotency-key"] == "synthetic-idempotency"
        assert json.loads(server.received[0][3])["client_message_id"] == identity
        call("unknown operation refuses before network", operation="public.noSuchOperation", count=0, category="VALIDATION_FAILED")
        public = json.loads((ROOT / "protocol/v1/openapi/public-v1.json").read_text())
        planned = [operation["operationId"] for item in public["paths"].values() for operation in item.values()
                   if isinstance(operation, dict) and operation.get("x-implemented") is False]
        assert len(planned) == 6, "Review changed planned-route coverage"
        for operation in planned:
            call("planned " + operation + " refuses before network", operation="public." + operation,
                 count=0, category="VALIDATION_FAILED")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
