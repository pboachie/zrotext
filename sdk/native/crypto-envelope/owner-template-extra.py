"""Managed-only lifecycle and single-connection HTTP framing regressions."""
import argparse
import base64
import hashlib
import http.server
import importlib.util
import json
import math
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading


def measured_phases(actual, reads, *, constructed=True):
    phases = actual['phases']
    assert set(phases) == {'constructorSeconds', 'requestSeconds', 'disposalSeconds'}, actual
    def seconds(value):
        assert isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0, actual
    seconds(phases['constructorSeconds'])
    assert len(phases['requestSeconds']) == reads, actual
    for value in phases['requestSeconds']:
        seconds(value)
    if constructed:
        seconds(phases['disposalSeconds'])
    else:
        assert phases['disposalSeconds'] is None, actual
    measured = phases['constructorSeconds'] + sum(phases['requestSeconds']) + (phases['disposalSeconds'] or 0)
    assert measured <= actual['elapsed'], actual


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.calls += 1
        body = self.server.bodies[min(self.server.calls - 1, len(self.server.bodies) - 1)]
        content = b'Content-Type: application/vnd.zrotext.workflow-template.v1\r\n'
        length = b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
        chunked = b'Transfer-Encoding: chunked\r\n'
        chunks = hex(len(body))[2:].encode() + b'\r\n' + body + b'\r\n0\r\n\r\n'
        cases = {
            'chunked': (chunked, chunks),
            'until-close': (b'', body),
            'duplicate-length': (length + length, body),
            'length-transfer': (length + chunked, chunks),
            'duplicate-type': (content + length, body),
            'bad-chunk': (chunked, b'no\r\n'),
            'large-chunk': (chunked, b'10000\r\n'),
            'bad-crlf': (chunked, b'1\r\nx!\n0\r\n\r\n'),
            'large-header': (b'X-Large: ' + b'x' * 17000 + b'\r\n' + length, body),
            'nonempty-trailer': (chunked, chunks[:-2] + b'X-Trailer: value\r\n\r\n'),
        }
        headers, payload = cases[self.server.mode]
        self.connection.sendall(b'HTTP/1.1 200 OK\r\n' + content + headers + b'Connection: close\r\n\r\n' + payload)
        self.close_connection = True
        # EOF-delimited bodies require an orderly TLS close, not truncation.
        self.connection.settimeout(2)
        try:
            self.connection.unwrap().close()
        except (OSError, ssl.SSLError):
            pass


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    p.add_argument('--fixture', type=Path, required=True)
    p.add_argument('--producer', type=Path, required=True)
    p.add_argument('--command-file', type=Path, required=True)
    args = p.parse_args()
    spec = importlib.util.spec_from_file_location('shared_owner', args.fixture / 'sdk/native/hpke-candidate/test-owner-template.py')
    shared = importlib.util.module_from_spec(spec); spec.loader.exec_module(shared)
    assert subprocess.check_output(['git', '-C', str(args.producer), 'rev-parse', 'HEAD'], text=True).strip() == shared.PIN
    assert not subprocess.check_output(['git', '-C', str(args.producer), 'status', '--porcelain'], text=True).strip()
    fixture = json.loads(subprocess.check_output(['node', str(args.producer / 'sdk/native/sealed-candidate/python/owner-template-interop.mjs')], text=True, encoding='utf-8', timeout=60))
    command = json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(command, list) and command and all(isinstance(x, str) and x and '\0' not in x for x in command)
    with tempfile.TemporaryDirectory(prefix='zrotext-owner-framing-') as directory:
        folder = Path(directory); roots = shared.tls.certificates(folder)
        with shared.tls.Server((socket.gethostbyname('localhost'), 0), Handler) as server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(folder / 'cert.pem', folder / 'key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.bodies = [base64.b64decode(fixture['envelope'])]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            value = dict(Fixture=fixture, Origin='https://' + server.server_address[0] + ':' + str(server.server_address[1]),
                         Roots=roots, Cookie='synthetic-owner=opaque', CSRF='synthetic-csrf', Enabled=True,
                         TimeoutMS=2000, ValidForMS=10000, Reads=1, Now=[10000], Mode='')
            try:
                server.calls = 0
                result = subprocess.run(command, input=json.dumps({**value, 'Lifecycle': True}), text=True, encoding='utf-8', capture_output=True, timeout=30)
                if result.returncode:
                    raise RuntimeError(result.stderr)
                assert json.loads(result.stdout) == {'lifecycle': 4} and server.calls == 0
                modes = ['chunked', 'until-close']
                if args.language != 'ruby':
                    modes += ['duplicate-length', 'length-transfer', 'duplicate-type', 'bad-chunk', 'large-chunk', 'bad-crlf', 'large-header', 'nonempty-trailer']
                for mode in modes:
                    server.mode = mode; server.calls = 0
                    result = subprocess.run(command, input=json.dumps(value), text=True, encoding='utf-8', capture_output=True, check=True, timeout=15)
                    output = json.loads(result.stdout)
                    if args.language != 'ruby':
                        measured_phases(output, 1)
                    actual = output['results'][0]
                    assert actual['accepted'] == (mode in modes[:2]), (mode, actual)
                    assert server.calls == 1, (mode, server.calls)
                    if actual['accepted']:
                        assert actual['digest'] == hashlib.sha256(server.bodies[0]).hexdigest() and not actual['ack'] and not actual['pending']
                    assert value['Cookie'] not in result.stdout + result.stderr and value['CSRF'] not in result.stdout + result.stderr
                changed = bytearray(server.bodies[0]); changed[-1] ^= 1
                server.bodies.append(bytes(changed)); server.mode = 'chunked'; server.calls = 0
                result = subprocess.run(command, input=json.dumps({**value, 'Reads': 2}), text=True, encoding='utf-8', capture_output=True, check=True, timeout=15)
                output = json.loads(result.stdout)
                if args.language != 'ruby':
                    measured_phases(output, 2)
                assert [v['accepted'] for v in output['results']] == [True, False], 'Same revision contradiction accepted'
                assert server.calls == 2
                if args.language != 'ruby':
                    server.mode = 'chunked'; server.calls = 0
                    result = subprocess.run(command, input=json.dumps({**value, 'Origin': value['Origin'] + '/invalid'}), text=True, encoding='utf-8', capture_output=True, check=True, timeout=15)
                    output = json.loads(result.stdout)
                    measured_phases(output, 0, constructed=False)
                    assert not output['results'][0]['accepted'] and server.calls == 0, output
                    for at, budget, sleep, calls in [(1, 100, 400, 0), (2, 1000, 1400, 1)]:
                        server.calls = 0
                        result = subprocess.run(command, input=json.dumps({**value, 'CurrentSleepAt': at, 'SleepMS': sleep, 'TimeoutMS': budget, 'SettleMS': sleep + 50}), text=True, encoding='utf-8', capture_output=True, check=True, timeout=15)
                        output = json.loads(result.stdout)
                        measured_phases(output, 1)
                        assert not output['results'][0]['accepted'] and output['currentCalls'] >= at and server.calls == calls, output
                        assert output['phases']['requestSeconds'][0] >= budget / 1000 * .75, output
                        assert value['Cookie'] not in result.stdout + result.stderr and value['CSRF'] not in result.stdout + result.stderr
            finally:
                server.shutdown()
    print(f'4 managed admission/lifecycle controls and {len(modes)} HTTP framing controls and one contradictory-head control passed')
    if args.language != 'ruby':
        print('Measured constructor/request/disposal phases checked on framing, two-read, constructor refusal and two actual callback deadline controls')


if __name__ == '__main__':
    main()
