"""Atomic profile02 root-transition checkpoints with external root approvals."""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
from types import MappingProxyType

from . import sealed_candidate as s

APP_ID=0x5a545243
CAPACITY=1024


class RootCheckpointStore:
    """Replay original signed history; database values cannot approve new roots.

    approved_roots maps successor generations to independently compared public
    points. It must be supplied again on restore. Original enrollment is never
    replaced with a database-learned pin. Only profile02 transitions are covered.
    """
    def __init__(self,path,root_pin,independently_compared_fingerprint,*,approved_roots):
        self.pin=s.capture(root_pin,94);self.fingerprint=s.capture(independently_compared_fingerprint,32)
        s.enroll_root02(self.pin,self.fingerprint)
        s.require(type(approved_roots) is dict and len(approved_roots)<=CAPACITY,'independent root approvals required')
        captured={}
        for generation,point in approved_roots.items():
            s.integer(generation);s.require(generation>1,'successor root generation')
            captured[generation]=s.capture(point,65);s.point(captured[generation])
        self.approved_roots=MappingProxyType(captured)
        self.path=Path(path).absolute();s.require(not self.path.is_symlink(),'checkpoint symlink')
        created=False
        try:fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        except FileExistsError:s.require(self.path.is_file() and self.path.stat().st_nlink==1,'checkpoint file kind')
        else:os.close(fd);created=True
        with self._connection(created) as db:
            db.execute('BEGIN IMMEDIATE')
            if created:
                db.execute(f'PRAGMA application_id={APP_ID}')
                db.execute('CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL)')
                db.execute('INSERT INTO identity VALUES (1,?,?)',(self.pin,self.fingerprint))
                db.execute('CREATE TABLE checkpoints (revision INTEGER PRIMARY KEY, comparison INTEGER NOT NULL, transition BLOB, manifest BLOB NOT NULL)')
            self._load(db);db.commit()

    @contextmanager
    def _connection(self,initializing=False):
        s.require(not self.path.is_symlink() and self.path.is_file() and self.path.stat().st_nlink==1,'checkpoint path changed')
        db=sqlite3.connect(self.path,timeout=5,isolation_level=None)
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,11000);db.execute('PRAGMA trusted_schema=OFF')
            if not initializing:s.require(db.execute('PRAGMA application_id').fetchone()[0]==APP_ID,'foreign root checkpoint')
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
            yield db
        finally:db.close()

    def _step(self,trust,current,transition,manifest,comparison):
        raw=s.capture(manifest,364,9751)
        s.require(raw[4]==2,'profile02 checkpoint required')
        if transition is not None:
            raw_transition=s.capture(transition,343)
            generation=s.num(raw_transition,29)
            s.require(current is not None and generation in self.approved_roots,'independent successor root approval missing')
            trust=s.verify_root_transition02(raw_transition,trust,comparison,self.approved_roots[generation])
        accepted=s.verify_manifest02(raw,trust,comparison)
        if current is not None and transition is None:
            s.require(s.manifest_identity(accepted)['version']==s.manifest_identity(current)['version']+1,'checkpoint exact successor')
        return s.advance_trust02(trust,accepted),accepted

    def _load(self,db):
        s.require(db.execute('SELECT root,fingerprint FROM identity WHERE id=1').fetchone()==(self.pin,self.fingerprint),'original root binding')
        trust=s.enroll_root02(self.pin,self.fingerprint)
        current,revision,last_time=None,0,0
        rows=db.execute('SELECT revision,comparison,transition,manifest FROM checkpoints ORDER BY revision LIMIT ?',(CAPACITY+1,)).fetchall()
        s.require(len(rows)<=CAPACITY,'checkpoint capacity')
        for rev,comparison,transition,manifest in rows:
            s.require(type(rev) is int and rev==revision+1 and type(comparison) is int and comparison>=last_time,'checkpoint sequence/clock')
            trust,current=self._step(trust,current,transition,manifest,comparison)
            revision,last_time=rev,comparison
        return revision,current,trust,last_time

    def _accept(self,manifest,transition,expected_revision,comparison_ms):
        raw=s.capture(manifest,364,9751)
        transition=None if transition is None else s.capture(transition,343)
        expected,now=s.integer(expected_revision),s.integer(comparison_ms)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                revision,current,trust,last_time=self._load(db)
                s.require(revision==expected and revision<CAPACITY and now>=last_time,'checkpoint CAS/capacity/clock')
                _,accepted=self._step(trust,current,transition,raw,now)
                # One row is the indivisible transition + new-root genesis pair.
                db.execute('INSERT INTO checkpoints VALUES (?,?,?,?)',(revision+1,now,transition,raw))
                db.commit();return revision+1,accepted
            except BaseException:db.rollback();raise

    def accept_manifest(self,manifest,expected_revision,comparison_ms):
        return self._accept(manifest,None,expected_revision,comparison_ms)

    def accept_transition(self,transition,new_genesis,expected_revision,comparison_ms):
        return self._accept(new_genesis,s.capture(transition,343),expected_revision,comparison_ms)

    def snapshot(self,comparison_ms):
        now=s.integer(comparison_ms)
        with self._connection() as db:
            db.execute('BEGIN')
            revision,current,_,last_time=self._load(db)
            s.require(now>=last_time,'checkpoint clock rollback')
            if current is not None:
                manifest=s._bound(s._manifests,current);s.window(manifest.issued,manifest.expires,now)
            db.commit();return revision,current
