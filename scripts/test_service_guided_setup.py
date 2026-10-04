# SPDX-License-Identifier: AGPL-3.0-only
"""Disposable actual-server driver, invoked only by the ignored Rust fixture."""
import hashlib
import contextlib
import io
import os
from unittest.mock import patch
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit
import guided_workflow_setup as setup
from workflow_owner_setup import OwnerSession, OwnerSetupError
from workflow_connector_fixture import OwnedFixtureVault, fixture_node, observed_children_stopped


DIAGNOSTIC = {"stage": "start", "operation": "none", "status": 0}
FAILURE = None


class MemoryVault:
    def __init__(self):
        self.values = {}
    def put(self, key, value):
        self.values[key] = value
    def get(self, key):
        return self.values[key]
    def delete(self, key):
        self.values.pop(key, None)


def run(fixture):
    global FAILURE
    upstream = urlsplit(fixture['upstream'])
    if upstream.scheme != 'http' or upstream.hostname != '127.0.0.1' or upstream.path or not upstream.port:
        raise ValueError('invalid_fixture')
    allowed = {'/v1/auth/login', '/v1/auth/login/mfa', '/v1/auth/session',
               '/v1/auth/logout', '/v1/auth/workflow-grants', '/v1/workflow/tools'}
    hold_metadata, metadata_waiting, release_metadata = threading.Event(), threading.Event(), threading.Event()
    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def handle_request(self):
            if (self.path not in allowed and not re.fullmatch(r'/v1/auth/(?:sessions|workflow-grants)/[0-9a-f-]{36}', self.path)):
                self.send_error(400)
                return
            if self.command not in ('GET', 'POST', 'DELETE'):
                self.send_error(400)
                return
            length = int(self.headers.get('Content-Length', '0'))
            if length < 0 or length > 65536:
                self.send_error(400)
                return
            connection = http.client.HTTPConnection('127.0.0.1', upstream.port, timeout=10)
            try:
                payload = self.rfile.read(length)
                if self.command == 'POST' and self.path == '/v1/workflow/tools' and hold_metadata.is_set():
                    value = json.loads(payload)
                    assert value['method'] == 'workflow.context.metadata'
                    assert value['params']['context_id'] == fixture['scope']['context_id']
                    metadata_waiting.set()
                    release_metadata.wait(10)
                connection.request(self.command, self.path, payload,
                                   {key: value for key, value in self.headers.items() if key.lower() not in ('host', 'connection')})
                response = connection.getresponse()
                body = response.read(65537)
                assert len(body) <= 65536
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                        self.send_header(key, value)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                connection.close()
        do_GET = do_POST = do_DELETE = handle_request
    with tempfile.TemporaryDirectory(prefix='zrotext-guided-service-') as scratch, contextlib.chdir(scratch):
        root = Path(scratch)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', 'key.pem', '-out', 'cert.pem'], cwd=root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(root / 'cert.pem', root / 'key.pem')
        server = ThreadingHTTPServer(('127.0.0.1', fixture['proxy_port']), Proxy)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        origin = 'https://localhost:' + str(fixture['proxy_port'])
        trust = ssl.create_default_context(cafile=str(root / 'cert.pem'))
        sessions = []
        def session():
            owner = OwnerSession(origin, http.client.HTTPSConnection('localhost', fixture['proxy_port'], context=trust, timeout=10))
            sessions.append(owner)
            original = owner.request
            def observed(method, path, body=None):
                operation = {'/v1/auth/login': 'login', '/v1/auth/login/mfa': 'login_mfa',
                             '/v1/auth/session': 'session', '/v1/auth/logout': 'logout',
                             '/v1/auth/workflow-grants': 'grant'}.get(path,
                             'session_revoke' if path.startswith('/v1/auth/sessions/') else 'grant_revoke')
                if operation != 'logout':
                    DIAGNOSTIC.update(operation=operation, status=0)
                status, value = original(method, path, body)
                if operation != 'logout':
                    DIAGNOSTIC['status'] = status
                return status, value
            owner.request = observed
            return owner
        def login(code):
            owner = session()
            owner.login(fixture['email'], fixture['password'], lambda: code)
            return owner
        def readiness(value):
            connection = http.client.HTTPSConnection('localhost', fixture['proxy_port'], context=trust, timeout=10)
            try:
                connection.request('GET', '/v1/workflow/tools', headers={'Authorization': 'Bearer ' + value})
                response = connection.getresponse()
                body = json.loads(response.read(65536))
                DIAGNOSTIC.update(operation="readiness", status=response.status)
                return response.status, body
            finally:
                connection.close()
        try:
            DIAGNOSTIC["stage"] = "install"
            config = root / 'client.json'
            config.write_text('{"mcpServers":{"unrelated":{"command":"synthetic"}}}')
            scope_file = root / 'scope.json'
            scope_file.write_text(json.dumps(fixture['scope']))
            broker = Path(fixture['broker'])
            vault = OwnedFixtureVault() if fixture.get('verify_installed') else MemoryVault()
            def verify_installed():
                from mcp.client import stdio
                processes = []
                create = stdio._create_platform_compatible_process
                async def observe(*args, **kwargs):
                    process = await create(*args, **kwargs)
                    processes.append(process)
                    return process
                before = config.read_bytes(), setup.intent_path(config).read_bytes(), vault.get(installed['secret_reference'])
                output = io.StringIO()
                with patch.object(sys, 'argv', [arguments[0], 'verify', *arguments[2:]]), \
                     patch.object(setup, 'OwnerSession', side_effect=AssertionError('verification logged in')), \
                     patch.object(setup, 'operating_system_store', side_effect=AssertionError('parent opened custody')), \
                     patch.object(stdio, '_create_platform_compatible_process', side_effect=observe), \
                     contextlib.redirect_stdout(output):
                    code = setup.main()
                result = json.loads(output.getvalue())
                DIAGNOSTIC['verification'] = result.get('code', 'none')
                if len(processes) != 1 or processes[0].returncode is None:
                    DIAGNOSTIC['verification'] = 'owned_launcher_still_running'
                    raise AssertionError('owned launcher cleanup refused')
                try:
                    observed_children_stopped(child_receipt)
                except AssertionError:
                    DIAGNOSTIC['verification'] = 'owned_node_still_running'
                    raise
                assert before == (config.read_bytes(), setup.intent_path(config).read_bytes(), vault.get(installed['secret_reference']))
                assert narrow not in output.getvalue() and fixture['password'] not in output.getvalue()
                assert result['sendAvailable'] is False and result['clientAppCompatibility'] == 'unverified'
                return code, result
            shim = contextlib.ExitStack()
            if fixture.get('verify_installed'):
                child_receipt = shim.enter_context(fixture_node(root, root / 'cert.pem'))
            preview_digest = setup.local.digest(config.read_bytes())
            arguments = ['guided_workflow_setup.py', 'connect', '--client', 'mcp-json',
                         '--config', str(config), '--scope', str(scope_file), '--broker', str(broker),
                         '--sha256', setup.local.digest(broker.read_bytes()), '--origin', origin]
            captured = io.StringIO()
            with patch.object(sys, 'argv', arguments), patch.object(setup, 'operating_system_store', return_value=vault), \
                 patch.object(setup, 'OwnerSession', side_effect=lambda requested: session() if requested == origin else None), \
                 patch('builtins.input', side_effect=[preview_digest, fixture['email']]), \
                 patch.object(setup.getpass, 'getpass', side_effect=[fixture['password'], fixture['login_factor'], fixture['grant_factor']]), \
                 contextlib.redirect_stdout(captured):
                assert setup.main() == 0
            public = json.loads(captured.getvalue().splitlines()[-1])
            assert public['status'] == 'completed' and public['operation'] == 'connect'
            installed = setup.read_intent(config)
            owner = sessions[-1]
            assert fixture['password'] not in captured.getvalue()
            narrow = vault.get(installed['secret_reference'])
            assert narrow not in captured.getvalue()
            creator = owner.session_identity.copy()
            DIAGNOSTIC["stage"] = "teardown"
            owner.close()
            assert not owner.cookies
            DIAGNOSTIC["stage"] = "teardown_readiness"
            status, body = readiness(narrow)
            assert status == 200 and body['available'] is True
            assert {item['method'] for item in body['methods'] if item['permission_granted']} == {'workflow.context.metadata', 'workflow.action.status'}
            # Actual private bootstrap -> MCP -> HTTPS current-authority request.
            env = dict(__import__('os').environ, NODE_EXTRA_CA_CERTS=str(root / 'cert.pem'))
            DIAGNOSTIC["stage"] = "bootstrap"
            child = subprocess.run(['node', '--dns-result-order=ipv4first', str(broker)], input=(json.dumps({'v': 1, 'origin': origin, 'credential': narrow}) + '\n' +
                json.dumps({'jsonrpc': '2.0', 'id': 0, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'synthetic-guided', 'version': '1'}}}) + '\n' +
                json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n' +
                json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'zrotext_readiness', 'arguments': {}}}) + '\n').encode(),
                capture_output=True, env=env, timeout=15)
            assert child.returncode == 0
            reply = json.loads(child.stdout.splitlines()[-1])
            assert reply['result']['structuredContent']['available'] is True
            assert narrow.encode() not in child.stdout
            if fixture.get('verify_installed'):
                DIAGNOSTIC['stage'] = 'installed_verify'
                code, result = verify_installed()
                assert code == 0 and result['status'] == 'verified'
                assert result['authenticatedMetadata'] == 'observed'
                assert result['runtime']['mcp'] == '2.3.0'
                DIAGNOSTIC['stage'] = 'timeout_verify'
                hold_metadata.set()
                started = time.monotonic()
                try:
                    with patch('workflow_connector_verify.DEADLINE_SECONDS', 2):
                        code, result = verify_installed()
                    elapsed = time.monotonic() - started
                    if not metadata_waiting.is_set():
                        DIAGNOSTIC['verification'] = 'metadata_not_waiting'
                        raise AssertionError('timeout did not reach metadata')
                    assert code == 2 and result['status'] == 'unverified'
                    assert result['code'] == 'deadline_exceeded'
                    assert 'authenticatedMetadata' not in result
                    # Includes official SDK shutdown grace, beyond operation deadline.
                    if elapsed >= 10:
                        DIAGNOSTIC['verification'] = 'timeout_too_slow'
                        raise AssertionError('timeout cleanup exceeded bound')
                finally:
                    hold_metadata.clear()
                    release_metadata.set()
            DIAGNOSTIC["stage"] = "recovery_login"
            recovery = login(fixture['recovery_login_factor'])
            # Missing CSRF and foreign target cannot mutate the creator.
            DIAGNOSTIC["stage"] = "missing_csrf"
            saved = recovery.cookies.pop('__Host-zrotext_csrf')
            try:
                assert recovery.request('DELETE', '/v1/auth/sessions/' + creator['session_id'])[0] == 403
            finally:
                recovery.cookies['__Host-zrotext_csrf'] = saved
            DIAGNOSTIC["stage"] = "foreign_revoke"
            assert recovery.request('DELETE', '/v1/auth/sessions/' + fixture['foreign_session'])[0] == 204
            assert recovery.request('DELETE', '/v1/auth/sessions/' + fixture['other_account_session'])[0] == 204
            assert readiness(narrow)[0] == 200
            DIAGNOSTIC["stage"] = "creator_recovery"
            recovery.revoke_creator(creator)
            recovery.revoke_creator(creator)
            assert readiness(narrow)[0] == 401
            if fixture.get('verify_installed'):
                DIAGNOSTIC['stage'] = 'revoked_verify'
                code, result = verify_installed()
                assert code == 2 and result['status'] == 'unverified'
                assert result['code'] == 'unauthorized' and 'authenticatedMetadata' not in result
                DIAGNOSTIC['verification'] = 'none'
            # Confirmed cleanup of the exact installed grant and receipt.
            proposal, _, _ = setup.plan(config, 'mcp-json', broker, setup.local.digest(broker.read_bytes()), origin,
                                         installed['grant_id'], installed['secret_reference'], True)
            DIAGNOSTIC["stage"] = "disconnect"
            setup.disconnect(config, 'mcp-json', broker, setup.local.digest(broker.read_bytes()), origin,
                             installed['grant_id'], installed['secret_reference'], proposal['reviewDigest'], recovery, vault)
            assert not setup.intent_path(config).exists()
            DIAGNOSTIC["stage"] = "second_create"
            second_id, second_token = recovery.create(fixture['scope'], fixture['password'], fixture['second_grant_factor'])
            assert readiness(second_token)[0] == 200
            DIAGNOSTIC["stage"] = "creator_logout"
            recovery.close()
            assert readiness(second_token)[0] == 401
            DIAGNOSTIC["stage"] = "unknown_login"
            final_owner = login(fixture['final_login_factor'])
            original_create = final_owner.create
            issued_unknown = []
            def lost_create(*args):
                issued_unknown.append(original_create(*args))
                raise OwnerSetupError('owner_response_unknown')
            DIAGNOSTIC["stage"] = "unknown_create"
            final_owner.create = lost_create
            try:
                setup.install(config, setup.local.digest(config.read_bytes()), final_owner,
                              fixture['scope'], fixture['password'], fixture['unknown_grant_factor'], vault,
                              'mcp-json', broker, setup.local.digest(broker.read_bytes()), origin)
                raise AssertionError('unknown issuance accepted')
            except OwnerSetupError:
                pass
            DIAGNOSTIC["stage"] = "unknown_replay"
            assert len(issued_unknown) == 1
            assert readiness(issued_unknown[0][1])[0] == 200
            try:
                setup.install(config, setup.local.digest(config.read_bytes()), final_owner,
                              fixture['scope'], fixture['password'], fixture['unknown_grant_factor'], vault,
                              'mcp-json', broker, setup.local.digest(broker.read_bytes()), origin)
                raise AssertionError('unknown issuance replayed')
            except OwnerSetupError:
                pass
            assert len(issued_unknown) == 1
            receipt = setup.intent_path(config)
            DIAGNOSTIC["stage"] = "unknown_recovery"
            setup.recover(config, setup.local.digest(receipt.read_bytes()), final_owner, vault)
            assert readiness(issued_unknown[0][1])[0] == 401
            assert not receipt.exists()
            return {'creator_logout_fenced': True, 'unknown_recovered': True, 'creator_session':  creator['session_id'], 'foreign_session': fixture['foreign_session'],
                    'after_teardown': True, 'bootstrap_current': True, 'recovery_fenced': True,
                    'installed_verified': bool(fixture.get('verify_installed'))}
        except Exception:
            FAILURE = dict(DIAGNOSTIC)
            raise
        finally:
            try:
                for owner in sessions:
                    owner.close()
            finally:
                try:
                    if 'vault' in locals() and isinstance(vault, OwnedFixtureVault):
                        vault.close()
                finally:
                    try:
                        if 'shim' in locals():
                            shim.close()
                    finally:
                        server.shutdown()
                        server.server_close()
                        thread.join(timeout=5)
                        assert not thread.is_alive()


if __name__ == '__main__':
    try:
        data = sys.stdin.buffer.read(65537)
        assert len(data) <= 65536
        print(json.dumps(run(json.loads(data))))
    except Exception:
        print(json.dumps({'failed': FAILURE or DIAGNOSTIC}))
        raise SystemExit(2)
