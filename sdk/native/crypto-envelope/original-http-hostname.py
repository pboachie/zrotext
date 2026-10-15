"""Supplement shared transport controls with a trusted CA / wrong hostname."""
import argparse
import base64
import datetime
import importlib.util
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--command-file', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('shared_tls', args.fixture / 'sdk/native/hpke-candidate/test-original-http.py')
    shared = importlib.util.module_from_spec(spec); spec.loader.exec_module(shared)
    argv = json.loads(args.command_file.read_text(encoding='utf-8'))
    if not isinstance(argv, list) or not argv or any(not isinstance(v, str) or not v or '\0' in v for v in argv):
        raise ValueError('Invalid trusted command arguments')
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic hostname CA')])
    wrong = 'wrong.invalid'
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, wrong)])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(wrong)]), False).sign(ca_key, hashes.SHA256()))
    with tempfile.TemporaryDirectory(prefix='zrotext-http-hostname-') as directory:
        folder = Path(directory)
        (folder / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (folder / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with shared.Server(('localhost', 0), shared.Handler) as server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2; context.load_cert_chain(folder / 'cert.pem', folder / 'key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.mode = 'success'; server.calls = []
            threading.Thread(target=server.serve_forever, daemon=True).start()
            grant = 'ztr_' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            origin = f'https://{server.server_address[0]}:{server.server_port}'
            for method, state, target in [('current', 'unavailable', origin), ('consume', 'unknown', origin),
                                          ('consume', 'unavailable', origin.replace('https://', 'https://@'))]:
                payload = dict(Origin=target,
                               Roots=ca.public_bytes(serialization.Encoding.PEM).decode(), Grant=grant,
                               Method=method, Invalid='', Timeout=1000)
                env = {k: v for k, v in os.environ.items() if not k.upper().endswith('_PROXY')}
                result = subprocess.run(argv, input=json.dumps(payload), text=True, encoding='utf-8',
                                        capture_output=True, check=True, timeout=10, env=env)
                assert json.loads(result.stdout)['state'] == state and not server.calls, (method, state, json.loads(result.stdout)['state'], len(server.calls))
                assert grant not in result.stdout and grant not in result.stderr
            server.shutdown()
    print('2 trusted-CA wrong-hostname and 1 empty-userinfo preflight controls passed')


if __name__ == '__main__':
    main()
