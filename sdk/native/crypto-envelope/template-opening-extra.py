"""Concrete dedicated-client binding and preclosed-client refusal controls."""
import argparse
import base64
import importlib.util
import json
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--fixture', type=Path, required=True)
    p.add_argument('--producer', type=Path, required=True)
    p.add_argument('--command-file', type=Path, required=True)
    args = p.parse_args()
    spec = importlib.util.spec_from_file_location('cold', args.fixture / 'sdk/native/hpke-candidate/test-owner-template.py')
    cold = importlib.util.module_from_spec(spec); spec.loader.exec_module(cold)
    fixture = json.loads(subprocess.check_output(['node', str(args.producer / 'sdk/native/sealed-candidate/python/owner-template-interop.mjs')], text=True, encoding='utf-8', timeout=60))
    command = json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(command, list) and command and all(isinstance(v, str) and v and '\0' not in v for v in command)
    with tempfile.TemporaryDirectory(prefix='zrotext-opening-extra-') as directory:
        folder = Path(directory); roots = cold.tls.certificates(folder)
        with cold.tls.Server((socket.gethostbyname('localhost'), 0), cold.Handler) as server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(folder / 'cert.pem', folder / 'key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                for flag in ('DedicatedMismatch', 'ClientInitiallyClosed'):
                    server.calls = []; server.mode = 'normal'; server.status = 200; server.content = cold.CONTENT
                    server.bodies = [base64.b64decode(fixture['envelope'])]
                    data = dict(Fixture=fixture, Origin='https://' + server.server_address[0] + ':' + str(server.server_address[1]), Roots=roots,
                                Cookie='synthetic-owner=opaque', CSRF='synthetic-csrf', Enabled=True, TimeoutMS=4000, ValidForMS=10000,
                                Reads=1, Now=[10000], Mode='')
                    data[flag] = True
                    out = subprocess.run(command, input=json.dumps(data), text=True, encoding='utf-8', capture_output=True, check=True, timeout=20)
                    result = json.loads(out.stdout)
                    assert len(result['results']) == 1 and not result['results'][0]['accepted'] and 'text' not in result['results'][0]
                    assert server.calls == [], flag
            finally:
                server.shutdown()
    print('2 dedicated-client binding/closure controls passed with zero HTTP')


if __name__ == '__main__':
    main()
