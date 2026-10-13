"""Synthetic scenarios for the verified Tungsten IR mock, never a live server."""
from contextlib import contextmanager
import http.client
import ipaddress
import json
from pathlib import Path
from queue import Queue, Empty
import subprocess
import tempfile
from threading import Thread
import time
from urllib.parse import urlsplit

IDENTITY = "11111111-2222-4333-8444-555555555555"
AUTH = {"Authorization": "Bearer synthetic-bearer"}
OWNER = {"Cookie": "__Host-zrotext_session=synthetic-session; __Host-zrotext_csrf=synthetic-csrf",
         "x-zrotext-csrf": "synthetic-csrf", "Origin": "https://owner.example.test"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Mock:
    def __init__(self, base):
        parsed = urlsplit(base)
        require(parsed.scheme == "http" and ipaddress.ip_address(parsed.hostname).is_loopback
                and parsed.port and not parsed.username and parsed.path in ("", "/"), "Invalid mock origin")
        self.host, self.port = parsed.hostname, parsed.port

    def request(self, method, path, body=None, headers=None, timeout=2):
        require(path.startswith("/") and not path.startswith("//"), "Invalid mock path")
        data = None if body is None else json.dumps(body,separators=(",", ":")).encode()
        values = dict(headers or {})
        if data is not None:
            values["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        try:
            conn.request(method, path, data, values)
            response = conn.getresponse()
            raw = response.read(1048577)
            require(len(raw) <= 1048576, "Mock response limit exceeded")
            return response.status, raw
        finally:
            conn.close()

    def json(self, method, path, body=None, headers=None, status=200):
        actual, raw = self.request(method, path, body, headers)
        require(actual == status, f"Mock status mismatch: {method} {path}: {actual} != {status}")
        return json.loads(raw) if raw else None


@contextmanager
def server(binary, config, env, seed, gates=()):
    # Output is bounded and never echoed: recorded calls can contain credentials.
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen([str(binary), "mock", str(config), "--json", "--seed", str(seed),
            "--max-recorded-calls", "64", "--max-idempotent-responses", "16",
            *[part for gate in gates for part in ("--gate", gate)]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, env=env)
        ready = Queue(maxsize=1)
        reader = Thread(target=lambda: ready.put(process.stdout.readline(1048577)), daemon=True)
        reader.start()
        try:
            try:
                line = ready.get(timeout=15)
            except Empty:
                raise RuntimeError("Pinned mock did not become ready within 15 seconds") from None
            require(0 < len(line) <= 1048576, "Invalid mock readiness report")
            report = json.loads(line)
            yield Mock(report["result"]["base_url"])
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=3)
            process.stdout.close(); reader.join(timeout=1)


def run(binary, config, env):
    spec = json.loads((config / "mock/scenarios.json").read_text())
    require(spec["version"] == 1, "Unknown scenario format")
    with server(binary, config, env, spec["seed"]) as mock:
        for case in spec["cases"]:
            actual, _ = mock.request(case["method"], case["path"], case.get("body"), case.get("headers"))
            require(actual == case["status"], f"Scenario failed: {case['name']} ({actual})")
        baseline = mock.json("GET", "/v1/alpha/messages/" + IDENTITY, headers=AUTH)
        require(mock.json("GET", "/v1/alpha/messages/" + IDENTITY, headers=AUTH) == baseline,
                "Seeded status differs within one server")
        mock.json("POST", "/__tungsten/reset", status=204)
        require(mock.json("GET", "/__tungsten/calls") == [], "Mock reset retained calls")
        body = dict(client_message_id=IDENTITY, device_id=IDENTITY, recipient_e164="+15550100001",
                    test_case_id="synthetic", expires_at_ms=int(time.time() * 1000) + 60000)
        headers = dict(AUTH, **{"Idempotency-Key": "synthetic.intent-1"})
        first = mock.json("POST", "/v1/alpha/messages", body, headers, status=202)
        repeated = mock.json("POST", "/v1/alpha/messages", body, headers, status=202)
        require(first == repeated or dict(first, created=False) == repeated, "Mock replay changed response identity")
        mock.json("POST", "/v1/alpha/messages", dict(body, test_case_id="changed"), headers, status=409)
        calls = mock.json("GET", "/__tungsten/calls")
        require(len(calls) == 3, "Idempotency fixture call count differs")
        require(calls[0]["body"] == calls[1]["body"], "Replay bytes changed")
        mock.json("POST", "/__tungsten/reset", status=204)
        # Loss is observed once; only a deliberate identical replay reconciles it.
        try:
            mock.request("POST", "/v1/alpha/messages", body,
                         dict(headers, **{"X-Tungsten-Inject": "drop-after-write"}))
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        else:
            raise AssertionError("Expected synthetic response loss")
        require(len(mock.json("GET", "/__tungsten/calls")) == 1, "Loss triggered automatic retry")
        replay = mock.json("POST", "/v1/alpha/messages", body, headers, status=202)
        require(replay == first or replay == dict(first, created=False), "Lost response replay changed identity")
        mock.json("POST", "/__tungsten/reset", status=204)
        mock.json("GET", "/v1/alpha/messages/" + IDENTITY,
                  headers=dict(AUTH, **{"X-Tungsten-Inject": "status=429;retry-after=1"}), status=429)
        require(len(mock.json("GET", "/__tungsten/calls")) == 1, "Rate response retried")
        try:
            mock.request("GET", "/v1/alpha/messages/" + IDENTITY,
                         headers=dict(AUTH, **{"X-Tungsten-Inject": "timeout=200"}), timeout=0.05)
        except TimeoutError:
            pass
        else:
            raise AssertionError("Expected bounded synthetic timeout")
        require(len(mock.json("GET", "/__tungsten/calls")) == 2, "Timeout response retried")
        mock.json("POST", "/__tungsten/program", [
            dict(operation="public.listOwnerMessages", status=200, body=dict(messages=[], next_cursor=IDENTITY)),
            dict(operation="public.listOwnerMessages", status=200, body=dict(messages=[], next_cursor=None))])
        page = mock.json("GET", "/v1/owner/messages", headers=OWNER)
        require(page["next_cursor"] == IDENTITY, "Scripted first cursor mismatch")
        last = mock.json("GET", "/v1/owner/messages?before=" + page["next_cursor"], headers=OWNER)
        require(last == dict(messages=[], next_cursor=None), "Scripted terminal page mismatch")
    with server(binary, config, env, spec["seed"], ["WORKFLOW_TOOLS_ENABLED", "SEALED_ADMISSION_ENABLED"]) as mock:
        require(mock.json("GET", "/v1/alpha/messages/" + IDENTITY, headers=AUTH) == baseline,
                "Seeded status differs after restart")
        mock.json("GET", "/v1/sealed/messages/" + IDENTITY, headers=AUTH)
        request = dict(method="workflow.contact.read", params=dict(request_id=IDENTITY, context_id=IDENTITY))
        mock.json("POST", "/v1/workflow/tools", request, AUTH, status=401)
        workflow = {"Authorization": "Bearer ztw_synthetic_mock_only"}
        response = mock.json("POST", "/v1/workflow/tools", request, workflow)
        require(response["kind"] == "contact", "Workflow RPC response kind mismatch")
        mock.json("POST", "/v1/workflow/tools", dict(method="workflow.not_implemented", params={}), workflow, status=400)
    print("Mock scenarios passed: route/gate/auth shapes, validation, deterministic restart, "
          "idempotency/loss, pagination and workflow RPC. Synthetic only; no server/device acceptance.")
