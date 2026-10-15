"""Bounded local contact metadata, never permission or remote acknowledgement."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from weakref import WeakKeyDictionary, WeakSet

from . import contact_integrity as c
from . import sealed_candidate as s
from .checkpoint_store import APP_ID as ROOT_APP_ID

APP_ID = 0x5a544348
_live = WeakSet()
_live_lock = threading.Lock()
_ROW = ('schema','state','contactId','revision','digest','requestId','routingDigest','name','notes',
        'statementDigest','manifestVersion','manifestDigest','readerId','readerGeneration','rootWriterId','comparisonMs','rootStamp')


class ContactHistoryError(ValueError):
    def __init__(self): super().__init__('Contact local history unavailable')


class _RootMismatch(ValueError):pass


def _dump(value):
    def encode(v):
        if type(v) is bytes:return v.hex()
        if type(v) is dict:return {k:encode(x) for k,x in v.items()}
        return v
    return json.dumps(encode(value),sort_keys=True,separators=(',',':'))


def _parse(raw,limit):
    s.require(type(raw) is str and len(raw.encode('utf-8'))<=limit,'history payload bound')
    def pairs(items):
        v={}
        for k,x in items:s.require(k not in v,'duplicate history property');v[k]=x
        return v
    v=json.loads(raw,object_pairs_hook=pairs)
    s.require(_dump(v)==raw,'canonical history encoding');return v


def _hex(value,width,zero=False):
    s.require(type(value) is str and len(value)==width*2,'history byte encoding')
    result=bytes.fromhex(value);s.require(result.hex()==value,'history lowercase bytes')
    return c._bytes(result,width,zero)


def _row(raw):
    v=_parse(raw,2048)
    s.require(type(v) is dict and v.get('schema')==1 and type(v['schema']) is int,'history schema')
    if v.get('state')=='unavailable':
        c._object(v,('schema','state','contactId'));v['contactId']=_hex(v['contactId'],16);return v
    c._object(v,_ROW);s.require(v['state']=='accepted','history state')
    for key,width in (('contactId',16),('requestId',16),('digest',32),('routingDigest',32),('statementDigest',32),('manifestDigest',32),('readerId',32),('rootWriterId',32)):
        v[key]=_hex(v[key],width)
    for key in ('revision','manifestVersion','readerGeneration','comparisonMs'):c._integer(v[key])
    for key in ('name','notes'):
        slot=v[key];c._object(slot,('tag','sealRevision','digest'));slot['digest']=_hex(slot['digest'],32,True)
        c._slot(slot);s.require(slot['sealRevision']<=v['revision'],'history slot revision')
    stamp=c._object(v['rootStamp'],('version','digest','anchorDigest','time'))
    c._integer(stamp['version']);c._integer(stamp['time'],True)
    stamp['digest']=_hex(stamp['digest'],32);stamp['anchorDigest']=_hex(stamp['anchorDigest'],32,True)
    s.require(not any(stamp['anchorDigest']),'generation1 anchor required');v['rootStamp']=stamp
    return v


class ContactHistory:
    """One-operation adapter over a metadata database and separate signed history.

    create is explicit. reduction_only opens an existing matching metadata file
    without root evidence and can only look up tokens or permanently reduce rows.
    root_history_path must name an existing native CheckpointStore. Its contents
    are replayed from the independently compared pin, never trusted as enrollment.
    """
    def __init__(self,path,root_pin,root_fingerprint,*,origin,maximum_records,
                 root_history_path=None,create=False,reduction_only=False):
        self._closed=False;self._busy=threading.Lock();self._born=time.monotonic()
        self._tokens=WeakKeyDictionary();self._cache={};self._deadline=0
        try:
            self._pin=s.capture(root_pin,94);self._fingerprint=s.capture(root_fingerprint,32)
            trust=s._bound(s._trusts,s.enroll_root02(self._pin,self._fingerprint))
            s.require(trust.generation==1,'generation1 enrollment');self._account=trust.account
            c._origin(origin);s.require(type(maximum_records) is int and 1<=maximum_records<=256,'history capacity')
            s.require(type(create) is bool and type(reduction_only) is bool and not(create and reduction_only),'history mode')
            self._header=dict(schema=1,accountId=self._account,rootPoint=trust.root,rootFingerprint=self._fingerprint,origin=origin,maximumRecords=maximum_records)
            self._path=Path(path).absolute();self._root_path=None if root_history_path is None else Path(root_history_path).absolute()
            s.require(self._root_path!=self._path,'separate evidence storage');self._reduction=reduction_only
            with _live_lock:s.require(len(_live)<4,'history adapter capacity');_live.add(self)
            with self._operation():
                if not reduction_only:self._root_snapshot()
                if create:
                    fd=os.open(self._path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
                with self._connection(initializing=create) as db:
                    db.execute('BEGIN IMMEDIATE')
                    if create:
                        db.execute(f'PRAGMA application_id={APP_ID}')
                        db.execute('CREATE TABLE header (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)')
                        db.execute('CREATE TABLE contacts (id BLOB PRIMARY KEY, payload TEXT NOT NULL)')
                        db.execute('INSERT INTO header VALUES (1,?)',(_dump(self._header|dict(count=0)),))
                    self._read(db);db.commit();self._check()
        except Exception:
            self.close();raise ContactHistoryError() from None

    def close(self):
        self._closed=True;self._tokens.clear();self._cache.clear()
        if not self._busy.locked():
            with _live_lock:_live.discard(self)

    def __enter__(self):return self
    def __exit__(self,*unused):self.close()

    def _check(self):
        now=time.monotonic()
        if now-self._born>=1800:self.close()
        s.require(not self._closed and now-self._born<1800 and now<self._deadline,'history lifecycle')

    @contextmanager
    def _operation(self):
        if not self._busy.acquire(blocking=False):raise ContactHistoryError()
        try:
            self._deadline=time.monotonic()+10;self._check();yield
        except Exception:raise ContactHistoryError() from None
        finally:
            self._busy.release()
            if self._closed:
                with _live_lock:_live.discard(self)

    @contextmanager
    def _connection(self,initializing=False):
        self._check();p=self._path
        s.require(not p.is_symlink() and p.is_file() and p.stat().st_nlink==1,'history file kind')
        db=sqlite3.connect(p.as_uri()+'?mode=rw',uri=True,timeout=5,isolation_level=None)
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,4096);db.execute('PRAGMA trusted_schema=OFF')
            if not initializing:s.require(db.execute('PRAGMA application_id').fetchone()[0]==APP_ID,'history application')
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL');yield db
        finally:db.close()

    def _read(self,db):
        self._check()
        s.require(set(db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall())=={('header',),('contacts',)},'history schema')
        s.require(not db.execute("SELECT name FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchall(),'history executable schema')
        headers=db.execute('SELECT id,payload FROM header LIMIT 2').fetchall()
        s.require(len(headers)==1 and headers[0][0]==1,'history header')
        header=_parse(headers[0][1],1024);count=header.pop('count',None)
        s.require(_dump(header)==_dump(self._header) and type(count) is int and 0<=count<=self._header['maximumRecords'],'history binding/count')
        rows=db.execute('SELECT id,payload FROM contacts LIMIT 257').fetchall()
        s.require(len(rows)==count,'history count mismatch');result={}
        for ident,raw in rows:
            row=_row(raw);s.require(type(ident) is bytes and row['contactId']==ident and ident not in result,'history identity')
            result[ident]=(raw,row)
        return count,result

    def _root_snapshot(self):
        self._check();p=self._root_path
        s.require(p is not None and not p.is_symlink() and p.is_file() and p.stat().st_nlink==1,'root history missing')
        db=sqlite3.connect(p.as_uri()+'?mode=rw',uri=True,timeout=5,isolation_level=None)
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,10000);db.execute('PRAGMA trusted_schema=OFF');db.execute('BEGIN')
            s.require(db.execute('PRAGMA application_id').fetchone()[0]==ROOT_APP_ID,'root history application')
            if db.execute('SELECT id,root,fingerprint FROM identity LIMIT 2').fetchall()!=[(1,self._pin,self._fingerprint)]:raise _RootMismatch()
            rows=db.execute('SELECT revision,comparison,signed FROM manifests ORDER BY revision LIMIT 65').fetchall()
            s.require(0<len(rows)<=64,'root history bound');trust=s.enroll_root02(self._pin,self._fingerprint)
            history=[];last=0
            for index,(revision,comparison,raw) in enumerate(rows,1):
                self._check();s.require(type(revision) is int and revision==index and type(comparison) is int and comparison>=last,'root history sequence/clock')
                raw=s.capture(raw,364,9751);s.require(raw[4]==2,'generation1 profile02 history')
                token=s.verify_manifest02(raw,trust,comparison);m=s._bound(s._manifests,token)
                s.require(m.trust.version==index and m.trust.generation==1,'root exact successor')
                history.append(m);trust=s.advance_trust02(trust,token);last=comparison
            db.commit();m=history[-1]
            return tuple(rows),history,dict(version=m.trust.version,digest=m.trust.digest,anchorDigest=bytes(32),time=last)
        finally:db.close()

    def _evidence(self,row,statement=None):
        before,history,stamp=self._root_snapshot();floor=row['rootStamp']
        s.require(stamp['version']>=floor['version'] and stamp['time']>=floor['time'] and stamp['anchorDigest']==floor['anchorDigest'] and
                  (stamp['version']!=floor['version'] or stamp['digest']==floor['digest']),'root history regression')
        m=next((m for m in history if m.trust.version==row['manifestVersion'] and m.trust.digest==row['manifestDigest']),None)
        s.require(m is not None,'history missing');m=s._parse_manifest(m.raw,m.trust,row['comparisonMs'])
        reader=next((k for k in m.keys if k.role==2 and k.scope==12 and k.id==row['readerId'] and k.active(row['comparisonMs'])),None)
        root=next((k for k in m.keys if k.role==6 and k.scope==0 and k.id==row['rootWriterId'] and k.active(row['comparisonMs'])),None)
        s.require(reader is not None and root is not None and root.point==self._pin[29:],'history records')
        if statement is not None:
            s.require(reader.point==statement['readerPoint'] and reader.start==statement['readerFromMs'] and reader.end==statement['readerUntilMs'] and
                      root.start==statement['rootFromMs'] and root.end==statement['rootUntilMs'],'statement history binding')
        s.require(self._root_snapshot()[0]==before,'root changed during comparison')
        return before,stamp

    def _token(self,raw,row):
        ident=row['contactId'];prior=self._cache.get(ident)
        if prior is not None and prior[0]==raw:return prior[1]
        if prior is not None:self._tokens.pop(prior[1],None)
        token=s._accept(self._tokens,raw);self._cache[ident]=(raw,token);return token

    def _expected(self,expected,existing):
        if expected is None:s.require(existing is None,'history expected absent')
        else:s.require(existing is not None and s._bound(self._tokens,expected)==existing[0],'history exact local CAS')

    def lookup(self,contact_id):
        with self._operation():
            ident=c._bytes(contact_id,16)
            with self._connection() as db:
                db.execute('BEGIN');_,rows=self._read(db);existing=rows.get(ident);db.commit()
            self._check()
            if existing is None:
                prior=self._cache.pop(ident,None)
                if prior:self._tokens.pop(prior[1],None)
                return dict(kind='unavailable',reason='unobserved')
            raw,row=existing;token=self._token(raw,row)
            if row['state']=='unavailable':return dict(kind='unavailable',reason='local_stop',token=token)
            if self._reduction:return dict(kind='unavailable',reason='reduction_only',token=token)
            try:self._evidence(row)
            except _RootMismatch:
                self._check();return dict(kind='unavailable',reason='root_mismatch',token=token)
            except Exception:
                self._check();return dict(kind='unavailable',reason='history_missing',token=token)
            self._check()
            return dict(kind='accepted_local_history',token=token,metadata=copy.deepcopy(row),evidence='available')

    def accept(self,*,expected,transition,statement):
        with self._operation():
            s.require(not self._reduction,'reduction only')
            n,st,_=s._bound(c._transitions,transition);supplied=s._bound(c._statements,statement)
            s.require(st==supplied and st['accountId']==self._account and st['origin']==self._header['origin'] and st['rootFingerprint']==self._fingerprint and st['rootPoint']==self._pin[29:],'contact history scope')
            row={key:copy.deepcopy(n[key]) for key in ('contactId','revision','digest','requestId','routingDigest','name','notes','statementDigest','manifestVersion','manifestDigest')}
            row.update({key:st[key] for key in ('readerId','readerGeneration','rootWriterId')})
            row.update(schema=1,state='accepted',comparisonMs=st['issuedMs'],rootStamp=self._root_snapshot()[2])
            before,stamp=self._evidence(row,st);row['rootStamp']=stamp
            attempted=False
            try:
                with self._connection() as db:
                    db.execute('BEGIN IMMEDIATE');count,rows=self._read(db);old=rows.get(row['contactId']);self._expected(expected,old)
                    if old is None:
                        s.require(n['operation'] in (1,3) and row['revision']==1 and count<self._header['maximumRecords'],'history initial/capacity');count+=1
                    else:
                        p=old[1];s.require(p['state']=='accepted','history terminal stop')
                        self._evidence(p)
                        if p['revision']==row['revision']:
                            row['rootStamp']=p['rootStamp'];s.require(row==p,'history same revision fork')
                        else:
                            s.require(n['operation']==2 and row['revision']==p['revision']+1 and n['previousDigest']==p['digest'] and row['routingDigest']==p['routingDigest'] and
                                (row['manifestVersion']>p['manifestVersion'] or row['manifestVersion']==p['manifestVersion'] and row['manifestDigest']==p['manifestDigest']) and
                                (row['readerGeneration']>p['readerGeneration'] or row['readerGeneration']==p['readerGeneration'] and row['readerId']==p['readerId']),'history transition continuity')
                    raw=_dump(row);_row(raw);self._check();attempted=True
                    db.execute('INSERT OR REPLACE INTO contacts VALUES (?,?)',(row['contactId'],raw))
                    db.execute('UPDATE header SET payload=? WHERE id=1',(_dump(self._header|dict(count=count)),));db.commit()
                self._check()
            except Exception:
                if attempted:return dict(kind='write_unknown')
                raise
            try:
                current=self._root_snapshot()[0];self._check()
            except Exception:
                if self._closed or time.monotonic()>=self._deadline:return dict(kind='write_unknown')
                return dict(kind='recorded_needs_recheck')
            if before!=current:return dict(kind='recorded_needs_recheck')
            return dict(kind='accepted_local_history',token=self._token(raw,row),metadata=copy.deepcopy(row),evidence='available')

    def mark_unavailable(self,*,expected):
        with self._operation():
            raw=s._bound(self._tokens,expected);old=_row(raw);attempted=False
            try:
                with self._connection() as db:
                    db.execute('BEGIN IMMEDIATE');_,rows=self._read(db);self._expected(expected,rows.get(old['contactId']))
                    row=dict(schema=1,state='unavailable',contactId=old['contactId']);raw=_dump(row);self._check();attempted=True
                    db.execute('UPDATE contacts SET payload=? WHERE id=?',(raw,row['contactId']));db.commit()
                self._check()
            except Exception:
                if attempted:return dict(kind='write_unknown')
                raise
            return dict(kind='unavailable',reason='local_stop',token=self._token(raw,row))
