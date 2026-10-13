"""Run generated clients against synthetic loopback HTTP; no live ZROtext calls."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CONFIG = ROOT / "sdk/tungsten"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(args, stage):
    policy = load("generation_policy", ROOT / "scripts/tungsten_sdk.py")
    policy.verify_source(args.source.resolve(), json.loads((CONFIG / "generator.lock.json").read_text()))
    inventory = json.loads((CONFIG / "generated.lock.json").read_text())
    files = {n: h for n, h in inventory.items() if n.startswith(args.target + "/")}
    if not files:
        raise ValueError("No reviewed generated files")
    sdk = stage / "sdk"
    for name, digest in files.items():
        data = (args.generated / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Generated source hash mismatch: " + name)
        destination = sdk / Path(name).relative_to(args.target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    runtime = stage / "runtime"
    shutil.copytree(args.source / "runtimes" / args.target, runtime, ignore=shutil.ignore_patterns("bin", "obj", "target"))
    if args.target == "java":
        sources = list((sdk / "src").rglob("*.java")) + list((runtime / "src").rglob("*.java"))
        subprocess.run(["javac", "--release", "17", "-Xlint:all", "-Werror", "-d", str(stage / "classes"), *map(str, sources), str(HERE / "Probe.java")], check=True)
        # Java's generated descriptor loader uses a classpath resource.
        for resource in (sdk / "src/main/resources").rglob("*"):
            if resource.is_file():
                target = stage / "classes" / resource.relative_to(sdk / "src/main/resources")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(resource, target)
        return ["java", "-cp", str(stage / "classes"), "Probe"]
    if args.target == "csharp":
        project = next(sdk.glob("*.csproj"))
        text = project.read_text()
        package = '<PackageReference Include="Tungsten.Runtime" Version="0.1.1" />'
        if text.count(package) != 1:
            raise ValueError("Unexpected C# dependency")
        project.write_text(text.replace(package, '<ProjectReference Include="../runtime/Tungsten.Runtime.csproj" />'))
        probe = stage / "probe"
        probe.mkdir()
        shutil.copyfile(HERE / "Probe.cs", probe / "Program.cs")
        (probe / "Probe.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><Nullable>enable</Nullable><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup><ItemGroup><ProjectReference Include="../sdk/Zrotext.Sdk.csproj" /></ItemGroup></Project>')
        subprocess.run([args.dotnet, "build", str(probe / "Probe.csproj"), "--nologo"], check=True)
        return [args.dotnet, str(probe / "bin/Debug/net10.0/Probe.dll")]
    return [args.ruby, "-I", str(runtime / "lib"), "-I", str(sdk / "lib"), str(HERE / "probe.rb")]


def exercise(command):
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
            if mode == "malformed":
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
    environment = {key: value for key, value in os.environ.items()
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

    try:
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--generated", type=Path, default=CONFIG / "generated")
    parser.add_argument("--target", choices=["java", "csharp", "ruby"], required=True)
    parser.add_argument("--dotnet", default="dotnet")
    parser.add_argument("--ruby", default="ruby")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="zrotext-managed-wire-") as temporary:
        exercise(prepare(args, Path(temporary)))
    print(args.target + " synthetic wire conformance passed; no live-service acceptance")


if __name__ == "__main__":
    main()
