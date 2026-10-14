"""Synthetic native contact metadata and separate signed-history acceptance."""
import argparse
from contextlib import closing
import base64
import hashlib
import json
from pathlib import Path
import queue
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

PIN = 'ccf28fe445ba959aa01d99fed6bd9ee3188b749c'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--producer', type=Path, required=True)
    choice = p.add_mutually_exclusive_group(required=True)
    choice.add_argument('--binary')
    choice.add_argument('--command-file', type=Path)
    args = p.parse_args()
    source = args.producer.resolve()
    assert subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip()
    fixture = json.loads(subprocess.check_output(['node', str(source / 'sdk/native/sealed-candidate/python/contact-interop.mjs')], timeout=30))
    fixture = {k:v for k,v in fixture.items() if type(v) is str}
    command = json.loads(args.command_file.read_text()) if args.command_file else [args.binary]
    assert isinstance(command, list) and command and all(type(x) is str and x and '\0' not in x for x in command)
    checks = 0
    with tempfile.TemporaryDirectory(prefix='contact-history-') as temporary:
        folder = Path(temporary)
        root, path = folder / 'root.sqlite', folder / 'metadata.sqlite'
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, text=True, encoding='utf-8', bufsize=1)
        answers = queue.Queue()
        def read():
            for line in proc.stdout:
                answers.put(json.loads(line))
        threading.Thread(target=read, daemon=True).start()
        def send(operation, **kw):
            row = dict(operation=operation, fixture=fixture, root=str(root), path=str(path), adapter='a', maximum=4)
            row.update(kw)
            proc.stdin.write(json.dumps(row) + '\n'); proc.stdin.flush()
        def response(ok=True, **fields):
            nonlocal checks
            value = answers.get(timeout=20)
            assert value['accepted'] is ok, (checks, value, ok, fields)
            for key, expected in fields.items():
                assert value.get(key) == expected, (checks, value, key, expected)
            checks += 1
            return value
        def call(operation, ok=True, want=None, **kw):
            send(operation, **kw)
            return response(ok, **(want or {}))
        def mutate(db, sql, values=()):
            with closing(sqlite3.connect(db)) as c:
                c.execute(sql, values)
                c.commit()
        def query(db, sql):
            with closing(sqlite3.connect(db)) as c:
                return c.execute(sql).fetchall()
        try:
            call('open', False)
            call('open', False, create=True)
            # Failed creation never becomes implicit enrollment; clean up only this
            # explicitly named temporary metadata file, if created by the adapter.
            if path.exists(): path.unlink()
            call('root')
            call('open', create=True)
            call('lookup', want={'kind':'unavailable','reason':'unobserved'})
            call('accept', False, mutation='update')
            digest = base64.b64encode(hashlib.sha256(base64.b64decode(fixture['create'])).digest()).decode()
            call('accept', mutation='create', save='initial', want={'kind':'accepted_local_history','revision':1,'digest':digest})
            call('accept', False, mutation='create')
            call('accept', mutation='create', expected='initial', save='same', want={'kind':'accepted_local_history','revision':1})
            alternate=json.loads(subprocess.check_output(['node',str(source/'sdk/native/sealed-candidate/python/contact-interop.mjs')],timeout=30))
            alternate={k:v for k,v in alternate.items() if type(v) is str}
            call('open',adapter='fork',path=str(folder/'fork.sqlite'),create=True)
            call('accept',adapter='fork',mutation='create',fixture=alternate,want={'kind':'accepted_local_history'})
            call('close',adapter='fork')
            call('accept',False,mutation='create',expected='initial',fixture=alternate)
            call('lookup', save='observed', want={'kind':'accepted_local_history','revision':1})
            call('open', adapter='b')
            call('accept', False, adapter='b', mutation='update', expected='initial')
            call('lookup', adapter='b', save='foreign', want={'kind':'accepted_local_history'})
            call('accept', mutation='update', expected='observed', save='updated', want={'kind':'accepted_local_history','revision':2})
            call('accept', False, adapter='b', mutation='update', expected='foreign')
            call('accept', False, mutation='clear', expected='initial')
            call('close', adapter='b')
            call('close')
            call('open')
            call('accept', False, mutation='clear', expected='updated')
            call('lookup', save='reopened', want={'kind':'accepted_local_history','revision':2})
            call('accept', mutation='clear', expected='reopened', save='cleared', want={'kind':'accepted_local_history','revision':3,'name':base64.b64encode(bytes(32)).decode()})
            # Exact same revision is idempotent, not a fresh write identity.
            call('accept', mutation='clear', expected='cleared', want={'kind':'accepted_local_history','revision':3})
            saved_root = query(root, 'SELECT revision,comparison,signed FROM manifests ORDER BY revision')
            mutate(root, 'DELETE FROM manifests WHERE revision=2')
            call('lookup', save='missing', want={'kind':'unavailable','reason':'history_missing'})
            mutate(root, 'INSERT INTO manifests VALUES(?,?,?)', saved_root[1])
            call('lookup', want={'kind':'accepted_local_history','revision':3})
            mutate(root, 'UPDATE manifests SET comparison=9999 WHERE revision=2')
            call('lookup', want={'kind':'unavailable','reason':'history_missing'})
            mutate(root, 'UPDATE manifests SET comparison=10000 WHERE revision=2')
            altered = bytearray(saved_root[1][2]); altered[-1] ^= 1
            mutate(root, 'UPDATE manifests SET signed=? WHERE revision=2', (bytes(altered),))
            call('lookup', want={'kind':'unavailable','reason':'history_missing'})
            mutate(root, 'UPDATE manifests SET signed=? WHERE revision=2', (saved_root[1][2],))
            root_identity=query(root,'SELECT root,fingerprint FROM identity')[0]
            mutate(root,'UPDATE identity SET fingerprint=?',(bytes(32),))
            call('lookup',want={'kind':'unavailable','reason':'root_mismatch'})
            mutate(root,'UPDATE identity SET fingerprint=?',(root_identity[1],))
            mutate(root,'INSERT INTO transitions VALUES(2,?)',(bytes(343),))
            call('lookup',want={'kind':'unavailable','reason':'history_missing'})
            mutate(root,'DELETE FROM transitions')
            old = query(path, 'SELECT payload FROM contacts')[0][0]
            mutate(path, 'UPDATE contacts SET payload=?', (old[:-1],))
            call('lookup', False)
            mutate(path, 'UPDATE contacts SET payload=?', (old,))
            for at,width in ((17,8),(219,8),(291,8),(331,8),(339,8)):
                altered=bytearray(old);altered[at:at+width]=bytes(width)
                mutate(path,'UPDATE contacts SET payload=?',(bytes(altered),))
                call('lookup',False)
            mutate(path,'UPDATE contacts SET payload=?',(old,))
            mutate(path,'CREATE VIEW injected AS SELECT 1')
            call('lookup',False)
            mutate(path,'DROP VIEW injected')
            # A crashed SQLite writer must not expose an uncommitted replacement.
            crash="import sqlite3,os,sys;c=sqlite3.connect(sys.argv[1]);c.execute('BEGIN IMMEDIATE');c.execute('UPDATE contacts SET payload=?',(bytes(17),));os._exit(0)"
            subprocess.run([sys.executable,'-c',crash,str(path)],check=True,timeout=15)
            call('lookup',want={'kind':'accepted_local_history','revision':3})
            mutate(path, 'UPDATE header SET count=0')
            call('lookup', False)
            mutate(path, 'UPDATE header SET count=1')
            call('lookup', save='stop', want={'kind':'accepted_local_history'})
            call('stop', expected='stop', save='stopped', want={'kind':'unavailable','reason':'local_stop'})
            call('accept', False, mutation='clear', expected='stopped')
            call('close')
            call('open', reduction=True, root=str(folder/'missing-root'))
            call('lookup', save='reduced', want={'kind':'unavailable','reason':'local_stop'})
            call('stop', expected='reduced', want={'kind':'unavailable','reason':'local_stop'})
            call('accept', False, mutation='create')
            call('close')
            call('open', False, maximum=3)
            call('open', False, origin='https://other.invalid')
            call('open', False, create=True)
            call('open',False,maximum=0)
            call('open',False,maximum=257)
            # Reduction-only exposes no accepted evidence even for an otherwise
            # valid row, and remains able to apply a terminal local stop.
            call('open',adapter='reduction',path=str(folder/'fork.sqlite'),reduction=True,root=str(folder/'absent.sqlite'))
            call('lookup',adapter='reduction',save='reduce-only',want={'kind':'unavailable','reason':'reduction_only'})
            call('accept',False,adapter='reduction',mutation='create',expected='reduce-only')
            call('stop',adapter='reduction',expected='reduce-only',want={'reason':'local_stop'})
            call('close',adapter='reduction')
            # Four live adapters, exact close releases one admission slot.
            for name in ('a','b','c','d'):call('open',adapter=name)
            call('open',False,adapter='e')
            call('close-keep',adapter='d');call('lookup',False,adapter='d');call('open',adapter='e')
            for name in ('a','b','c','d','e'):call('close',adapter=name)
            # The root can change while the metadata write waits for admission to
            # SQLite. A committed row must report recheck, never fresh evidence.
            path = folder/'race.sqlite'
            call('open',create=True)
            lock=sqlite3.connect(path);lock.execute('BEGIN IMMEDIATE')
            try:
                send('accept',mutation='create',save='raced')
                time.sleep(.4)
                mutate(root,'UPDATE manifests SET comparison=10001 WHERE revision=2')
                lock.commit()
                response(kind='recorded_needs_recheck')
            finally:lock.close()
            call('lookup',save='after-race',want={'kind':'accepted_local_history','revision':1})
            call('close')
            # Restart the actual consumer process. Only newly looked-up tokens
            # are accepted; the database never recreates cryptographic tokens.
        finally:
            proc.stdin.close()
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.terminate();proc.wait(timeout=5)
        assert proc.returncode==0
        restart=[dict(operation='open',fixture=fixture,root=str(root),path=str(path),adapter='a',maximum=4),dict(operation='lookup',fixture=fixture,adapter='a')]
        result=subprocess.run(command,input=''.join(json.dumps(v)+'\n' for v in restart),text=True,encoding='utf-8',capture_output=True,timeout=30,check=True)
        values=[json.loads(v) for v in result.stdout.splitlines()]
        assert values[0]['accepted'] and values[1]['kind']=='accepted_local_history' and values[1]['revision']==1
        checks+=1
    print(f'{checks} native contact history controls passed; metadata is not current authority')


if __name__=='__main__':main()
