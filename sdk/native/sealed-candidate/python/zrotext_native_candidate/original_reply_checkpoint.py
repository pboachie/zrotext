"""Explicitly initialized, scope-bound original-reply history and clock CAS.

SQLite provides local atomic durability, not protection against restoration of
an older whole database. Independent pins and scope are required on every open.
Live grants, credentials, selected event bodies and plaintext are never stored.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
from . import sealed_candidate as s
from .original_reply_reader import capture_scope

APP_ID=0x5a545248
CAPACITY=64


def _positive(value):
    s.require(type(value) is int and 0<value<=2**53-1,'reply checkpoint integer');return value


def _scope_digest(scope):
    captured=capture_scope(scope)
    return s.sha(json.dumps({k:v.hex() if type(v) is bytes else v for k,v in captured.items()},
                            sort_keys=True,separators=(',',':')).encode('utf-8'))


class OriginalReplyCheckpoint:
    """Use create once, then open existing state; missing state never resets trust.

    Bootstrap requires the complete, independently accepted profile02 history
    from the supplied generation-one root. Rotations require another explicitly
    reviewed adapter; neither persisted bytes nor TLS proofs enroll new roots.
    """
    def __init__(self,path,root_pin,independently_compared_fingerprint,*,scope):
        self._pin=s.capture(root_pin,94);self._fingerprint=s.capture(independently_compared_fingerprint,32)
        trust=s._bound(s._trusts,s.enroll_root02(self._pin,self._fingerprint))
        s.require(trust.account==capture_scope(scope)['account'],'reply checkpoint account')
        self._scope=_scope_digest(scope);self.path=Path(path).absolute()
        with self._connection() as db:self._load(db)

    @classmethod
    def create(cls,path,root_pin,independently_compared_fingerprint,*,scope,accepted_history,comparison_ms):
        """Create only a new file; failure leaves a refused file, never resets it."""
        pin=s.capture(root_pin,94);fingerprint=s.capture(independently_compared_fingerprint,32)
        root=s.enroll_root02(pin,fingerprint);scope_hash=_scope_digest(scope)
        s.require(s._bound(s._trusts,root).account==capture_scope(scope)['account'],'reply checkpoint account')
        now=_positive(comparison_ms);rows=cls._capture(accepted_history)
        cls._verify(rows,pin,fingerprint,now)
        path=Path(path).absolute();s.require(not path.is_symlink(),'reply checkpoint symlink')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
        instance=object.__new__(cls);instance._pin=pin;instance._fingerprint=fingerprint;instance._scope=scope_hash;instance.path=path
        with instance._connection(initializing=True) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute(f'PRAGMA application_id={APP_ID}')
                db.execute('CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL, scope BLOB NOT NULL)')
                db.execute('CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, comparison INTEGER NOT NULL)')
                db.execute('CREATE TABLE manifests (version INTEGER PRIMARY KEY, accepted INTEGER NOT NULL, signed BLOB NOT NULL)')
                db.execute('INSERT INTO identity VALUES (1,?,?,?)',(pin,fingerprint,scope_hash))
                db.execute('INSERT INTO state VALUES (1,1,?)',(now,))
                db.executemany('INSERT INTO manifests VALUES (?,?,?)',rows);db.commit()
            except BaseException:db.rollback();raise
        return cls(path,pin,fingerprint,scope=scope)

    @contextmanager
    def _connection(self,initializing=False):
        s.require(not self.path.is_symlink() and self.path.is_file() and self.path.stat().st_nlink==1,'reply checkpoint missing or changed')
        # mode=rw prevents sqlite from recreating a file removed after the check.
        db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=5,isolation_level=None)
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,10000);db.execute('PRAGMA trusted_schema=OFF')
            if not initializing:s.require(db.execute('PRAGMA application_id').fetchone()[0]==APP_ID,'foreign reply checkpoint')
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL');yield db
        finally:db.close()

    @staticmethod
    def _capture(history):
        s.require(type(history) in (list,tuple) and 1<=len(history)<=CAPACITY,'reply history capacity')
        rows=[]
        for token in history:
            m=s._bound(s._manifests,token);s.require(m.profile==2,'reply history profile')
            rows.append((m.trust.version,m.comparison,m.raw))
        return rows

    @staticmethod
    def _verify(rows,pin,fingerprint,now):
        s.require(1<=len(rows)<=CAPACITY,'reply history capacity')
        trust=s.enroll_root02(pin,fingerprint);tokens=[]
        for expected,(version,at,raw) in enumerate(rows,1):
            s.require(type(version) is int and version==expected and _positive(at)<=now+30000,'reply history order/time')
            token=s.verify_manifest02(s.capture(raw,364,9751),trust,at)
            s.require(s.manifest_identity(token)['version']==version,'reply history version')
            trust=s.advance_trust02(trust,token);tokens.append(token)
        latest=s._bound(s._manifests,tokens[-1])
        tokens[-1]=s._accept(s._manifests,s._parse_manifest(latest.raw,latest.trust,now))
        return tuple(tokens)

    def _load(self,db):
        s.require(db.execute('SELECT root,fingerprint,scope FROM identity WHERE id=1').fetchone()==
                  (self._pin,self._fingerprint,self._scope),'reply checkpoint identity')
        row=db.execute('SELECT revision,comparison FROM state WHERE id=1').fetchone()
        s.require(row is not None,'reply checkpoint state');revision,comparison=map(_positive,row)
        rows=db.execute('SELECT version,accepted,signed FROM manifests ORDER BY version LIMIT ?', (CAPACITY+1,)).fetchall()
        return revision,comparison,rows,self._verify(rows,self._pin,self._fingerprint,comparison)

    def snapshot(self,*,scope,comparison_ms):
        s.require(_scope_digest(scope)==self._scope,'reply checkpoint scope')
        now=_positive(comparison_ms)
        with self._connection() as db:
            db.execute('BEGIN');revision,comparison,rows,_=self._load(db)
            s.require(now>=comparison,'reply checkpoint clock rollback')
            history=self._verify(rows,self._pin,self._fingerprint,now);db.commit()
            return revision,comparison,history

    def accept(self,history,*,scope,expected_revision,comparison_ms,_fence=None):
        """Commit exact accepted prefix plus successors and comparison under CAS.

        An exception after commit may still mean durable acceptance. Reopen and
        explicitly recover a snapshot; never retry a consumption automatically.
        """
        s.require(_scope_digest(scope)==self._scope,'reply checkpoint scope')
        expected=_positive(expected_revision);now=_positive(comparison_ms);proposed=self._capture(history)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                revision,comparison,old,_=self._load(db)
                s.require(revision==expected and revision<2**53-1 and now>=comparison,'reply checkpoint CAS/clock')
                s.require(len(proposed)>=len(old),'reply checkpoint history rollback')
                tokens=self._verify(proposed,self._pin,self._fingerprint,now)
                for saved,candidate in zip(old,proposed):
                    # Same semantic identity may have another valid low-S signature.
                    # Keep the previously accepted bytes and acceptance time.
                    s.require(saved[0]==candidate[0] and s.sha(saved[2][:-64])==s.sha(candidate[2][:-64]),'reply checkpoint fork')
                rows=old+proposed[len(old):];tokens=self._verify(rows,self._pin,self._fingerprint,now)
                if _fence is not None:
                    # Trusted client-only fence: sample/revalidate after acquiring
                    # the write lock and replaying evidence, before publication.
                    checked=_positive(_fence(tokens[-1],now))
                    s.require(checked>=now,'reply checkpoint locked clock rollback')
                    now=checked;tokens=self._verify(rows,self._pin,self._fingerprint,now)
                db.executemany('INSERT INTO manifests VALUES (?,?,?)',rows[len(old):])
                db.execute('UPDATE state SET revision=?,comparison=? WHERE id=1',(revision+1,now));db.commit()
                return revision+1,now,tokens
            except BaseException:db.rollback();raise
