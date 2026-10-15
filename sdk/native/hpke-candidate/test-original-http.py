"""Actual local TLS transport controls; no credentials or keys leave TEMP."""
import argparse
import base64
import datetime
import http.server
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit, urlunsplit
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def certificates(folder):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic test CA')])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address(socket.gethostbyname('localhost')))]), False)
            .sign(ca_key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    (folder/'cert.pem').write_bytes(pem)
    (folder/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM).decode()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address):
        pass  # Expected bounded client cancellation closes synthetic sockets.


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass
    def do_POST(self):
        s = self.server
        raw = self.rfile.read(int(self.headers['Content-Length']))
        s.calls.append((self.path, dict(self.headers), json.loads(raw)))
        method = json.loads(raw)['method']
        if s.mode == 'drop':
            self.close_connection = True
            return
        if s.mode == 'delayed-success':
            time.sleep(.5)
        body = json.dumps({'kind':method, 'result':{'untrusted':True}}).encode()
        if s.mode == 'malformed': body = b'not JSON'
        if s.mode == 'wrong-kind': body = b'{"kind":"other","result":{}}'
        if s.mode == 'duplicate': body = ('{"kind":"other","kind":'+json.dumps(method)+',"result":{}}').encode()
        if s.mode == 'extra': body = ('{"kind":'+json.dumps(method)+',"result":{},"extra":0}').encode()
        if s.mode == 'invalid-utf8': body = b'{"kind":"current","result":"\xff"}'
        if s.mode == 'oversize': body = b' '*524289
        status = 307 if s.mode == 'redirect' else 503 if s.mode == 'unavailable' else 200
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain' if s.mode == 'wrong-type' else 'application/json')
        if s.mode == 'redirect': self.send_header('Location', '/again')
        self.send_header('Content-Length', str(len(body)+(100 if s.mode == 'truncated' else 0)))
        self.end_headers()
        if s.mode == 'trickle':
            for byte in body:
                self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(.08)
        else:
            self.wfile.write(body); self.wfile.flush()
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser()
    command = parser.add_mutually_exclusive_group(required=True)
    command.add_argument('--binary')
    command.add_argument('--command-file', help='Trusted local JSON argv for a native runtime probe; never server data')
    args = parser.parse_args()
    if args.binary:
        argv = [str(Path(args.binary).resolve(strict=True))]
    else:
        argv = json.loads(Path(args.command_file).read_text(encoding='utf-8'))
        if not isinstance(argv, list) or not argv or any(not isinstance(v, str) or not v or '\0' in v for v in argv):
            parser.error('command file must contain nonempty string arguments without NUL')
    count = 0
    with tempfile.TemporaryDirectory(prefix='zrotext-reply-tls-') as directory:
        folder = Path(directory)
        roots = certificates(folder)
        with Server(('localhost', 0), Handler) as server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(folder/'cert.pem', folder/'key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            origin = f'https://{server.server_address[0]}:{server.server_port}'
            grant = 'ztr_'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            def run(mode='success', method='current', expected='untrusted', calls=1, **changes):
                nonlocal count
                server.mode, server.calls = mode, []
                # Ordinary responses include cold runtime/TLS startup on CI.
                # Keep the trickle control's short total deadline independent.
                timeout = 300 if mode == 'trickle' else 4000
                payload = dict(Origin=origin, Roots=roots, Grant=grant, Method=method, Invalid='', Timeout=timeout)
                payload.update(changes)
                env = {k:v for k,v in os.environ.items() if not k.upper().endswith('_PROXY') and k.upper() != 'NO_PROXY'}
                # A broken proxy must have no influence on this explicit direct transport.
                env['HTTPS_PROXY'] = 'http://invalid.invalid:1'
                result = subprocess.run(argv, input=json.dumps(payload), text=True, encoding='utf-8',
                    capture_output=True, check=True, timeout=10, env=env)
                actual = json.loads(result.stdout)
                assert actual['state'] == expected, (mode,method,actual,len(server.calls))
                assert len(server.calls) == calls, (mode,method,len(server.calls))
                if calls:
                    path, headers, request = server.calls[0]
                    headers = {k.lower():v for k,v in headers.items()}
                    assert path == '/v1/reply-events' and request['v'] == 1
                    assert headers['authorization'] == 'Bearer '+grant
                    assert headers['cache-control'] == 'no-store'
                    assert 'cookie' not in headers and 'x-zrotext-output-authorization' not in headers
                    expected_fields = {'v','method','accepted_manifest_version'} | {
                        'current':set(), 'read':{'event_id'}, 'status':{'consumption_id'},
                        'page':{'limit','cursor'}, 'consume':{'params'}}[method]
                    assert set(request) == expected_fields
                    if method == 'consume':
                        # Server RequestBody::Consume and maintained TS client
                        # both require this nested object, never flat fields.
                        assert set(request['params']) == {'event_id','request_id','active_request_id','descriptor'}
                        assert request['params']['descriptor'] is None
                if mode == 'trickle': assert actual['elapsed'] < .8, actual
                assert grant not in result.stdout and grant not in result.stderr
                count += 1
            for method in ('current','page','read','consume','status'): run(method=method)
            # Valid bounded latency must not be confused with the short trickle
            # deadline. The former 300 ms normal budget fails these controls.
            for method in ('current', 'consume'): run(mode='delayed-success', method=method)
            for mode in ('redirect','unavailable','drop','malformed','wrong-kind','duplicate','extra','invalid-utf8','oversize','truncated','wrong-type','trickle'):
                run(mode=mode, expected='unavailable')
                run(mode=mode, method='consume', expected='unknown')
            run(expected='unavailable', calls=0, Roots='')
            run(method='consume', expected='unknown', calls=0, Roots='')
            parts = urlsplit(origin)
            userinfo_origin = urlunsplit(parts._replace(netloc='user@'+parts.netloc))
            for origin_bad in ('http://localhost', origin+'/a/../', origin+'?x=1', origin+'#fragment', userinfo_origin, origin+'\n'):
                run(expected='unavailable', calls=0, Origin=origin_bad)
            for credential in ('', grant+'=', grant.replace('ztr_','ztw_'), 'Bearer '+grant):
                run(expected='unavailable', calls=0, Grant=credential)
            run(method='consume', expected='unavailable', calls=0, Invalid='version')
            run(method='consume', expected='unavailable', calls=0, Grant=grant.replace('ztr_','ztw_'))
            run(method='consume', expected='unavailable', calls=0, Timeout=0)
            run(method='read', expected='unavailable', calls=0, Invalid='uuid')
            server.shutdown()
    print(f'{count} actual TLS original transport checks passed')


if __name__ == '__main__': main()
