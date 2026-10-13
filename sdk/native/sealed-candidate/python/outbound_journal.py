"""Commit exact outbound ciphertext before exposure; no dispatch/replay grant."""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3

import compose03 as c
import sealed_candidate as s

APP_ID = 0x5a544f43


class OutboundJournal:
    def __init__(self, path, root_pin, independently_compared_fingerprint):
        self.pin=s.capture(root_pin,94)
        self.fingerprint=s.capture(independently_compared_fingerprint,32)
        self.trust=s._bound(s._trusts,s.enroll_root02(self.pin,self.fingerprint))
        self.path=Path(path).absolute()
        s.require(not self.path.is_symlink(),'journal symlink')
        created=False
        try:
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        except FileExistsError:
            s.require(self.path.is_file() and self.path.stat().st_nlink==1,'journal path')
        else:
            os.close(fd);created=True
        with self._connection(created) as db:
            db.execute('BEGIN IMMEDIATE')
            if created:
                db.execute(f'PRAGMA application_id={APP_ID}')
                db.execute('CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB NOT NULL, fingerprint BLOB NOT NULL)')
                db.execute('INSERT INTO identity VALUES (1,?,?)',(self.pin,self.fingerprint))
                db.execute('CREATE TABLE outbound (identity BLOB PRIMARY KEY, request BLOB NOT NULL, envelope BLOB NOT NULL)')
            self._identity(db)
            db.commit()

    @contextmanager
    def _connection(self,initializing=False):
        s.require(not self.path.is_symlink() and self.path.is_file() and self.path.stat().st_nlink==1,'journal path changed')
        db=sqlite3.connect(self.path,timeout=5,isolation_level=None)
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,40000)
            db.execute('PRAGMA trusted_schema=OFF')
            if not initializing:
                s.require(db.execute('PRAGMA application_id').fetchone()[0]==APP_ID,'foreign outbound journal')
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
            yield db
        finally:
            db.close()

    def _identity(self,db):
        s.require(db.execute('SELECT root,fingerprint FROM identity WHERE id=1').fetchone()==(self.pin,self.fingerprint),'outbound journal root binding')

    def compose_or_replay(self,**inputs):
        """Always validate current authority; an exact retry returns stored bytes.

        Returned bytes are committed before exposure. An application must retain
        this database across unknown transport outcomes and never reset it to
        force a retry. It does not record carrier effects or authorize transport.
        """
        plan=c.authorize(**inputs)
        prefix,text,recipients,_,public,bound=plan
        manifest=s._bound(s._manifests,inputs['manifest'])
        s.require((manifest.trust.account,manifest.trust.generation,manifest.trust.root)==
                  (self.trust.account,self.trust.generation,self.trust.root),'outbound manifest root')
        identity=prefix[10:74]  # account, message, device and line
        request=s.sha(s.label('ZTSE/native-outbound-intent/v1')+prefix+s.sha(text)+
            b''.join(bytes([role])+ident+point for role,ident,point in recipients)+
            bound['bindingId']+bound['bindingGeneration'].to_bytes(8,'big')+bound['electionCommitment']+bound['electionBundleSha256'])
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                self._identity(db)
                row=db.execute('SELECT request,envelope FROM outbound WHERE identity=?',(identity,)).fetchone()
                if row is not None:
                    s.require(row[0]==request,'outbound intent identity conflict')
                    raw=s.capture(row[1],557,34213)
                    parsed=s.parse_envelope(raw)
                    s.require(parsed.prefix==prefix and tuple((role,ident) for role,ident,_,_ in parsed.wraps)==
                              tuple((role,ident) for role,ident,_ in recipients),'stored outbound plan mismatch')
                    s.verify_signature(public,raw[-64:],'ZTSE/sign/v3',raw[:-64])
                    result=c.Composition(raw,s.sha(raw[:-64]),s.sha(raw))
                else:
                    s.require(db.execute('SELECT COUNT(*) FROM outbound').fetchone()[0]<10000,'outbound journal capacity')
                    result=c._compose(plan)
                    db.execute('INSERT INTO outbound VALUES (?,?,?)',(identity,request,result.envelope))
                db.commit()
                return result
            except BaseException:
                db.rollback()
                raise
