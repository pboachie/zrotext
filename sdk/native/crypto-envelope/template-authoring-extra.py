"""Ruby exact-boolean review and lease controls against synthetic TLS."""
import argparse
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--fixture', type=Path, required=True)
    p.add_argument('--producer', type=Path, required=True)
    p.add_argument('--command-file', type=Path, required=True)
    args = p.parse_args()
    spec = importlib.util.spec_from_file_location('save', args.fixture / 'sdk/native/hpke-candidate/test-template-save.py')
    save = importlib.util.module_from_spec(spec); spec.loader.exec_module(save)
    fixture = json.loads(subprocess.check_output(['node', str(args.producer / 'sdk/native/sealed-candidate/python/owner-template-interop.mjs')], text=True, encoding='utf-8', timeout=60))
    command = json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(command, list) and command and all(isinstance(v, str) and v and '\0' not in v for v in command)
    with tempfile.TemporaryDirectory(prefix='zrotext-authoring-boolean-') as directory:
        folder = Path(directory); roots = save.cold.tls.certificates(folder)
        with save.cold.tls.Server((socket.gethostbyname('localhost'), 0), save.Handler) as server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(folder / 'cert.pem', folder / 'key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                for flag in ('EvilReview', 'EvilCustody'):
                    server.calls = []; server.responses = [{}]; server.envelope = fixture['envelope']; server.deadline_ms = 4000
                    data = dict(Fixture=fixture, Origin='https://' + server.server_address[0] + ':' + str(server.server_address[1]), Roots=roots,
                                Cookie='synthetic-owner=opaque', CSRF='synthetic-csrf', Enabled=True, TimeoutMS=4000, ValidForMS=10000,
                                Now=[10000], Template=fixture['content']['template'], Values=fixture['content']['values'], CustodyLive=True, Decision=True, Repeat=1)
                    data[flag] = True
                    out = subprocess.run(command, input=json.dumps(data), text=True, encoding='utf-8', capture_output=True, check=True, timeout=20)
                    result = json.loads(out.stdout)
                    assert result['accepted'] == [False] and result['seals'] == 0 and result['metadata'] == 0 and server.calls == [], (flag, result)
            finally:
                server.shutdown()
    print('2 adversarial Ruby equality controls passed with zero sealing and HTTP')


if __name__ == '__main__':
    main()
