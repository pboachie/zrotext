"""Atomic profile02 ciphertext replay; independent current authority required."""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
from . import compose02 as c, sealed_candidate as s

APP_ID = 0x5a544f32


class OutboundJournal02:
    def __init__(self, path, root_pin, independently_compared_fingerprint):
        self.pin=s.capture(root_pin,94);self.fingerprint=s.capture(independently_compared_fingerprint,32)
        self.trust=s._bound(s._trusts,s.enroll_root02(self.pin,self.fingerprint))
        self.path=Path(path).absolute()
        s.require(not self.path.is_symlink(),'journal symlink')
        created=False
        try:fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        except FileExistsError:s.require(self.path.is_file() and self.path.stat().st_nlink==1,'journal path')
        else:os.close(fd);created=True
        with self._connection(created) as db:
            db.execute('BEGIN IMMEDIATE')
            if created:
                db.execute(f'PRAGMA application_id={APP_ID}')
                db.execute('CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL)')
                db.execute('INSERT INTO identity VALUES (1,?,?)',(self.pin,self.fingerprint))
                db.execute('CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, comparison INTEGER NOT NULL)')
                db.execute('INSERT INTO state VALUES (1,0,0)')
                db.execute('CREATE TABLE outbound (intent BLOB PRIMARY KEY, identity BLOB UNIQUE NOT NULL, request BLOB NOT NULL, envelope BLOB NOT NULL)')
            self._identity(db);db.commit()

    @contextmanager
    def _connection(self,initializing=False):
        s.require(not self.path.is_symlink() and self.path.is_file() and self.path.stat().st_nlink==1,'journal path changed')
        db=sqlite3.connect(self.path,timeout=5,isolation_level=None)
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,40000);db.execute('PRAGMA trusted_schema=OFF')
            if not initializing:s.require(db.execute('PRAGMA application_id').fetchone()[0]==APP_ID,'foreign outbound02 journal')
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
            yield db
        finally:db.close()

    def _identity(self,db):
        s.require(db.execute('SELECT root,fingerprint FROM identity WHERE id=1').fetchone()==(self.pin,self.fingerprint),'journal root binding')

    def _state(self,db):
        self._identity(db)
        row=db.execute('SELECT revision,comparison FROM state WHERE id=1').fetchone()
        s.require(row is not None,'journal state missing')
        return tuple(s.integer(v) for v in row)

    def revision(self):
        """Local CAS observation; not an authority or external rollback anchor."""
        with self._connection() as db:return self._state(db)[0]

    def compose_or_replay(self,*,intent_id,expected_revision,current_manifest,**inputs):
        """Return (new_revision, Composition) only after FULL-synchronous commit.

        Retain the caller's intent and original composition inputs across unknown
        outcomes. Read revision after contention/lost results, then retry the same
        intent. A different intent cannot mint new bytes for the same message.
        Current manifest/time are independently supplied on every call; neither
        the journal nor its ciphertext establishes live delivery permission.
        """
        intent=s.capture(intent_id,16);s.require(any(intent),'zero caller intent')
        expected=s.integer(expected_revision)
        plan=c.authorize(**inputs)
        prefix,text,recipients,_,public=plan
        old=s._bound(s._manifests,inputs['manifest']);live=s._bound(s._manifests,current_manifest)
        now=s.integer(inputs['now_ms'])
        s.require(now>=live.comparison,'current comparison rollback')
        s.window(live.issued,live.expires,now)
        s.require(0<inputs['observed_ms']<=now<inputs['expires_ms'],'journal intent no longer current')
        s.require(live.profile==2 and (old.trust.account,old.trust.generation,old.trust.root)==
                  (live.trust.account,live.trust.generation,live.trust.root)==
                  (self.trust.account,self.trust.generation,self.trust.root),'journal manifest root/profile')
        s.require((old.trust.generation,old.trust.version,old.trust.digest) in live.trust.lineage,'original manifest not current lineage')
        # Revalidate identical signer and recipient points against CURRENT evidence.
        c.authorize(**dict(inputs,manifest=current_manifest))
        identity=prefix[10:74]
        request=s.sha(s.label('ZTSE/native-outbound02-intent/v1')+prefix+s.sha(text)+
                     b''.join(bytes([role])+ident+point for role,ident,point in recipients))
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                revision,comparison=self._state(db)
                s.require(revision==expected and revision<s.MAX,'outbound02 revision conflict')
                s.require(now>=comparison,'journal comparison rollback')
                row=db.execute('SELECT identity,request,envelope FROM outbound WHERE intent=?',(intent,)).fetchone()
                if row is None:
                    s.require(db.execute('SELECT 1 FROM outbound WHERE identity=?',(identity,)).fetchone() is None,'message already has another intent')
                    s.require(db.execute('SELECT COUNT(*) FROM outbound').fetchone()[0]<10000,'journal capacity')
                    result=c._compose(plan)
                    db.execute('INSERT INTO outbound VALUES (?,?,?,?)',(intent,identity,request,result.envelope))
                else:
                    s.require(row[:2]==(identity,request),'outbound02 intent conflict')
                    raw=s.capture(row[2],557,34213);parsed=s.parse_envelope(raw)
                    s.require(parsed.prefix==prefix and tuple(w[:2] for w in parsed.wraps)==
                              tuple((role,ident) for role,ident,_ in recipients),'stored outbound02 plan mismatch')
                    s.verify_signature(public,raw[-64:],'ZTSE/sign/v2',raw[:-64])
                    result=c.Composition(raw,s.sha(raw[:-64]),s.sha(raw))
                db.execute('UPDATE state SET revision=?,comparison=? WHERE id=1',(revision+1,now))
                db.commit()
                return revision+1,result
            except BaseException:
                db.rollback();raise
