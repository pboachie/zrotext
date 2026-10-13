"""Current owner template ciphertext reads, with explicit origin-bound sessions."""
import hashlib
import http.client
import math
import re
import socket
import threading
import time
import urllib.parse
import uuid
from concurrent.futures import Future,TimeoutError
from . import sealed_candidate as s
from . import encrypted_template as t
from .contact_integrity import _origin

_CONTENT='application/vnd.zrotext.workflow-template.v1'
_BINDING=('account','device','line','interval','session','generation','peer','phoneReader','archiveReader')
_IDS=('accountId','deviceId','lineId','intervalId','templateId')
_NUMBERS=('bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion')
_DIGESTS=('peerDigest','readerId','manifestDigest')
_ADMISSION=threading.BoundedSemaphore(8)


class OwnerTemplateError(Exception):
    def __init__(self,code,state='refused'):
        super().__init__('Owner template '+code);self.code,self.state=code,state


def _record(value,fields):
    s.require(type(value) is dict and set(value)==set(fields),'owner fields');return dict(value)


def _binding(value):
    value=_record(value,_BINDING)
    for key in _BINDING:
        if key not in ('generation','peer'):
            value[key]=s.capture(value[key],32 if key.endswith('Reader') else 16);s.require(any(value[key]),'owner identity')
    s.require(s.integer(value['generation'])>0 and type(value['peer']) is str and re.fullmatch(r'\+[1-9][0-9]{1,14}',value['peer']) is not None,'owner binding')
    return value


def _scope(raw):
    s.require(308<=len(raw)<=33075 and raw[:6]==b'ZTWT\x01\x01' and raw[222]==4 and s.num(raw,287,4)==len(raw)-291,'template framing')
    result={k:raw[6+i*16:22+i*16] for i,k in enumerate(_IDS)}
    result.update({k:s.num(raw,86+i*8) for i,k in enumerate(_NUMBERS)})
    result.update({k:raw[126+i*32:158+i*32] for i,k in enumerate(_DIGESTS)})
    t.encrypted_template_aad(result);return result


class OwnerTemplateReader:
    """Cold readLatest parity only; no save ticket, plaintext, or grant.

    read_current is a trusted application adapter. current_session supplies
    exactly origin/cookie/csrf, independently of workflow bearer credentials.
    Cookies are confined to the configured HTTPS origin, never stored from HTTP
    responses, and must remain identical throughout one operation. No login or
    browser cookie extraction is performed. Callbacks must not reenter methods.
    """
    def __init__(self,origin,binding,template_id,*,read_current,current_session,enabled=False,timeout_ms=10000):
        try:
            self._origin=_origin(origin);self._binding=_binding(binding);self._template=s.capture(template_id,16)
            s.require(any(self._template) and callable(read_current) and callable(current_session) and type(enabled) is bool,'owner configuration')
            s.require(type(timeout_ms) is int and 1<=timeout_ms<=10000,'owner timeout')
            parsed=urllib.parse.urlsplit(origin);self._host,self._port=parsed.hostname,parsed.port
        except Exception:raise OwnerTemplateError('invalid_request') from None
        self._current,self._session=read_current,current_session;self._timeout=timeout_ms/1000
        self._closed_code='closed';self._closed=threading.Event();self._busy=threading.Lock();self._connection=None
        self._root=None;self._generation=0;self._version=0;self._digest=None;self._now=0;self._head=0;self._head_digest=None
        if not enabled:self.close()

    def __repr__(self):return 'OwnerTemplateReader(<owner session redacted>)'

    def close(self):
        self._closed.set();connection=self._connection
        if connection is not None and connection.sock is not None:
            try:connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            connection.close()

    def _live(self,deadline):
        if self._closed.is_set():raise OwnerTemplateError(self._closed_code)
        if time.monotonic()>=deadline:self._closed_code='deadline';self.close();raise OwnerTemplateError('deadline')

    def _credentials(self,deadline):
        self._live(deadline);value=_record(self._session(),('origin','cookie','csrf'));self._live(deadline)
        s.require(value['origin']==self._origin and type(value['cookie']) is str and 1<=len(value['cookie'])<=4096 and
            re.fullmatch(r'[\x20-\x7e]+',value['cookie']) is not None and '=' in value['cookie'],'owner cookie')
        s.require(type(value['csrf']) is str and 1<=len(value['csrf'])<=256 and re.fullmatch(r'[\x21-\x7e]+',value['csrf']) is not None,'owner csrf')
        return value

    def _authorize(self,scope,deadline,credentials):
        self._live(deadline);started=time.monotonic()
        try:
            c=_record(self._current(),('binding','manifest','nowMs','ownerSessionLive','consentLive','phase','validForMs'));self._live(deadline)
            now=s.integer(c['nowMs']);valid=c['validForMs']
            s.require(_binding(c['binding'])==self._binding and c['ownerSessionLive'] is True and c['consentLive'] is True and c['phase']=='active' and now>0 and now>=self._now,'owner current')
            s.require(type(valid) in (int,float) and 0<valid<=60000 and math.isfinite(valid),'owner freshness')
            bound=s._bound(s._manifests,c['manifest']);s.require(bound.profile==2,'owner profile')
            m=s._parse_manifest(bound.raw,bound.trust,now);identity=m.trust;b=self._binding
            s.require(identity.digest==bound.trust.digest and identity.account==b['account'] and
                (self._root is None or (self._root==identity.root and self._generation==identity.generation)) and
                identity.version>=self._version and (identity.version!=self._version or self._digest is None or identity.digest==self._digest),'owner trust')
            reader=next((k for k in m.keys if k.role==2 and k.id==b['archiveReader']),None)
            phone=next((k for k in m.keys if k.role==4 and k.active(now) and k.device==b['device'] and k.line==b['line']),None)
            s.require(reader is not None and reader.active(now) and reader.scope&8 and phone is not None and phone.scope==2,'owner current keys')
            if scope is not None:
                s.require(all(scope[x]==b[y] for x,y in (('accountId','account'),('deviceId','device'),('lineId','line'),('intervalId','interval'),('readerId','archiveReader'))),'owner scope')
                s.require(scope['templateId']==self._template and scope['bindingGeneration']==b['generation'] and scope['trustGeneration']==identity.generation and
                    scope['manifestVersion']==identity.version and scope['manifestDigest']==identity.digest and 0<scope['expiresMs']-now<=30*86400000 and
                    scope['peerDigest']==hashlib.sha256(b['peer'].encode()).digest(),'owner template identity')
            expiry=min(m.expires,reader.end,phone.end,scope['expiresMs'] if scope else m.expires)
            deadline=min(deadline,started+valid/1000,started+(expiry-now)/1000);self._deadline=deadline;self._live(deadline)
            s.require(self._credentials(deadline)==credentials,'owner session changed');self._live(deadline)
            self._root,self._generation,self._version,self._digest,self._now=identity.root,identity.generation,identity.version,identity.digest,now
            return deadline
        except Exception:self._closed_code='owner_changed';self.close();raise OwnerTemplateError('owner_changed') from None

    def _read(self,deadline):
        credentials=self._credentials(deadline);deadline=self._authorize(None,deadline,credentials)
        self._live(deadline)
        if self._credentials(deadline)!=credentials:self._closed_code='owner_changed';self.close();raise OwnerTemplateError('owner_changed')
        path='/v1/owner/workflow/templates/'+str(uuid.UUID(bytes=self._template))
        connection=http.client.HTTPSConnection(self._host,self._port,timeout=max(.001,deadline-time.monotonic()));self._connection=connection
        try:
            connection.connect();self._live(deadline)
            connection.request('GET',path,headers={'Accept':_CONTENT,'x-zrotext-csrf':credentials['csrf'],'Cookie':credentials['cookie'],'Cache-Control':'no-store'})
            response=connection.getresponse();self._live(deadline)
            if 300<=response.status<400:raise OwnerTemplateError('response_unknown','unknown')
            if response.status!=200 or response.getheader('Content-Type')!=_CONTENT:
                if response.status in (401,403):self._closed_code='read_refused';self.close()
                raise OwnerTemplateError('read_refused')
            raw=response.read(33076);self._live(deadline)
            if len(raw)>33075 or response.length not in (None,0):raise OwnerTemplateError('response_unknown','unknown')
        finally:connection.close();self._connection=None
        try:scope=_scope(raw)
        except Exception:raise OwnerTemplateError('invalid_request') from None
        if scope['revision']<self._head:raise OwnerTemplateError('head_regressed')
        deadline=self._authorize(scope,deadline,credentials);s.point(raw[222:287]);digest=hashlib.sha256(raw).hexdigest()
        deadline=self._authorize(scope,deadline,credentials);self._live(deadline)
        if scope['revision']==self._head and self._head_digest is not None and digest!=self._head_digest:raise OwnerTemplateError('head_changed')
        self._head,self._head_digest=scope['revision'],digest
        return dict(state='verified_current_snapshot',requestAcknowledged=False,scope=scope,envelope=raw,encryptedDigest=digest,matchesPending=False)

    def read_latest(self):
        if not self._busy.acquire(blocking=False):raise OwnerTemplateError('busy')
        if not _ADMISSION.acquire(blocking=False):self._busy.release();raise OwnerTemplateError('capacity')
        deadline=time.monotonic()+self._timeout;self._deadline=deadline;future=Future()
        def worker():
            try:self._live(deadline);value=self._read(deadline);self._live(deadline);future.set_result(value)
            except Exception as error:future.set_exception(error if isinstance(error,OwnerTemplateError) else OwnerTemplateError('read_refused'))
            finally:_ADMISSION.release();self._busy.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except Exception:_ADMISSION.release();self._busy.release();raise OwnerTemplateError('read_refused') from None
        while True:
            self._live(min(deadline,self._deadline))
            try:value=future.result(timeout=min(.02,max(.001,deadline-time.monotonic())));self._live(deadline);return value
            except TimeoutError:continue
