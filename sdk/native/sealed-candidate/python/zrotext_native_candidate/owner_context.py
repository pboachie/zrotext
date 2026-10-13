"""Owner context ciphertext persistence, separate from browser authoring/custody."""
import hashlib
import http.client
import json
import re
import time
import uuid
from types import MappingProxyType
from . import sealed_candidate as s
from .workflow_context import workflow_context_aad
from .owner_template import OwnerTemplateError
from .owner_template_save import OwnerTemplateClient

_CONTENT='application/vnd.zrotext.workflow-context.v1'
_CODES={400:'invalid_request',401:'unauthorized',403:'forbidden',404:'not_found',409:'conflict',413:'too_large',429:'rate_limited'}


def _scope(raw):
    s.require(308<=len(raw)<=33075 and raw[:5]==b'ZTWC\x01' and raw[222]==4 and s.num(raw,287,4)==len(raw)-291,'context framing')
    result=dict(kind=raw[5])
    result.update({k:raw[6+i*16:22+i*16] for i,k in enumerate(('accountId','deviceId','lineId','intervalId','contextId'))})
    result.update({k:s.num(raw,86+i*8) for i,k in enumerate(('bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'))})
    result.update({k:raw[126+i*32:158+i*32] for i,k in enumerate(('peerDigest','readerId','manifestDigest'))})
    workflow_context_aad(result);return result


class OwnerContextError(Exception):
    def __init__(self,code,state='refused'):
        super().__init__('Owner context '+code);self.code,self.state=code,state


class _ContextSession(OwnerTemplateClient):
    def __init__(self,origin,binding,context_id,kind,**options):
        s.require(type(kind) is int and kind in (1,2,3),'context kind');self._kind=kind
        super().__init__(origin,binding,context_id,**options)

    def _authorize(self,scope,deadline,credentials):
        if scope['kind']!=self._kind:self.close();raise OwnerTemplateError('owner_changed')
        selected=dict(scope);selected['templateId']=selected.pop('contextId');selected.pop('kind')
        return super()._authorize(selected,deadline,credentials)

    def _identity(self,r):
        return dict(requestId=r['request_id'],contextId=str(uuid.UUID(bytes=r['scope']['contextId'])),revision=r['scope']['revision'],envelopeDigest=r['digest'])

    def _ticket(self,ticket):
        with self._guard:
            if self._closed.is_set() and self._pending:raise OwnerTemplateError('expired' if self._closed_code=='deadline' else 'closed','unknown')
            r=self._saved
            if r is None or r['ticket'] is not ticket:raise OwnerTemplateError('invalid_ticket')
            self._live(r['deadline']);return r

    def prepare(self,request_id,expected_revision,scope,envelope):
        if self._busy.locked():raise OwnerTemplateError('pending_write')
        with self._guard:
            if self._saved is not None or self._pending is not None:raise OwnerTemplateError('pending_write')
            self._live(time.monotonic()+self._timeout)
        try:
            raw=s.capture(envelope,308,33075);captured=_scope(raw)
            s.require(workflow_context_aad(scope)==raw[:222],'context scope')
            s.require(type(expected_revision) in (int,float) and 0<=expected_revision<=127 and int(expected_revision)==expected_revision and captured['revision']==expected_revision+1,'context CAS')
            s.require(type(request_id) is str and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',request_id) is not None and uuid.UUID(request_id).int!=0,'context request')
        except Exception:raise OwnerTemplateError('invalid_request') from None
        def run(deadline):
            r=None
            try:
                credentials=self._credentials(deadline)
                r=dict(ticket=object(),request_id=request_id,expected_revision=int(expected_revision),scope=captured,envelope=raw,digest=hashlib.sha256(raw).hexdigest(),credentials=credentials,deadline=deadline,attempts=0,verifies=0,unknown=False)
                with self._guard:
                    self._live(deadline)
                    if self._saved is not None or self._pending is not None:raise OwnerTemplateError('pending_write')
                    self._saved=r
                self._shorten(r,deadline);deadline=self._authorize(captured,deadline,credentials);s.point(raw[222:287])
                review=MappingProxyType(dict(self._identity(r),expectedRevision=int(expected_revision),scope=MappingProxyType(dict(captured))))
                s.require(self._review(review) is None,'synchronous consumed review');self._live(deadline);self._authorize(captured,deadline,credentials)
                return r['ticket']
            except Exception:
                if r is not None and self._saved is r:self._forget(r)
                raise
        return self._operation(run)

    def _fetch(self,r,post):
        deadline=r['deadline'];self._live(deadline)
        s.require(self._credentials(deadline)==r['credentials'],'owner session')
        path='/v1/owner/workflow/contexts'+('' if post else '/'+str(uuid.UUID(bytes=r['scope']['contextId'])))
        headers={'Accept':'application/json' if post else _CONTENT,'x-zrotext-csrf':r['credentials']['csrf'],'Cookie':r['credentials']['cookie'],'Cache-Control':'no-store'}
        if post:headers.update({'Content-Type':_CONTENT,'idempotency-key':r['request_id'],'x-zrotext-context-revision':str(r['expected_revision'])})
        connection=http.client.HTTPSConnection(self._host,self._port,timeout=max(.001,deadline-time.monotonic()));response=None;self._connection=connection
        try:
            connection.connect();self._live(deadline);connection.request('POST' if post else 'GET',path,body=r['envelope'] if post else None,headers=headers)
            response=connection.getresponse();self._live(deadline);status=response.status;content=response.getheader('Content-Type')
            if 300<=status<400:raise OwnerTemplateError('response_unknown','unknown')
            if status!=200:return status,content,b''
            limit=64 if post else 33075;raw=response.read(limit+1);self._live(deadline)
            if len(raw)>limit or response.length not in (None,0):raise OwnerTemplateError('response_unknown','unknown')
            return status,content,raw
        finally:
            if response is not None:response.close()
            connection.close();self._connection=None

    def _latest(self,r,acknowledged):
        self._authorize(r['scope'],r['deadline'],r['credentials'])
        status,content,raw=self._fetch(r,False)
        if status!=200 or content!=_CONTENT:raise OwnerTemplateError('response_unknown','unknown')
        if raw==r['envelope']:
            self._authorize(r['scope'],r['deadline'],r['credentials'])
            return dict(self._identity(r),state='verified_current_snapshot',requestAcknowledged=acknowledged)
        try:
            newer=_scope(raw)
            for key in ('accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId','kind','bindingGeneration','trustGeneration'):
                s.require(newer[key]==r['scope'][key],'context compatible head')
            s.require(newer['revision']>r['scope']['revision'],'context newer head');s.point(raw[222:287]);self._authorize(newer,r['deadline'],r['credentials'])
        except Exception:raise OwnerTemplateError('response_unknown','unknown') from None
        if acknowledged:return dict(_not_current=True)
        raise OwnerTemplateError('response_unknown','unknown')

    def post(self,ticket,retry):
        if self._busy.locked():raise OwnerTemplateError('busy')
        initial=self._ticket(ticket)
        def run(deadline):
            r=self._ticket(ticket);prior=r['unknown'];attempted=False
            if (retry and not prior) or (not retry and r['attempts']!=0):raise OwnerTemplateError('invalid_ticket')
            if r['attempts']>=3:raise OwnerTemplateError('attempts_exhausted','unknown' if prior else 'refused')
            try:
                self._authorize(r['scope'],r['deadline'],r['credentials'])
                with self._guard:self._live(r['deadline']);r['attempts']+=1;r['unknown']=True;attempted=True;self._pending=self._identity(r)
                status,content,raw=self._fetch(r,True)
                if status in _CODES:
                    if prior:raise OwnerTemplateError('response_unknown','unknown')
                    self._forget(r);raise OwnerTemplateError(_CODES[status])
                if status!=200 or re.fullmatch(r'application/json(?:\s*;\s*charset=utf-8)?',content or '',re.I) is None:raise OwnerTemplateError('response_unknown','unknown')
                text=raw.decode('utf-8-sig');value=json.loads(text)
                if type(value) is not dict or set(value)!={'revision'} or value['revision']!=r['scope']['revision'] or text!='{"revision":'+str(r['scope']['revision'])+'}':raise OwnerTemplateError('response_unknown','unknown')
                return self._latest(r,True)
            except Exception as error:
                if isinstance(error,OwnerTemplateError) and error.state=='refused' and self._saved is not r and self._pending is None:raise
                if attempted or prior:raise OwnerTemplateError('response_unknown','unknown') from None
                raise
        def finish(result):
            r=self._saved
            if r is None:raise OwnerTemplateError('response_unknown','unknown')
            self._forget(r)
            if result.get('_not_current'):raise OwnerTemplateError('head_changed','not_current')
        try:return self._operation(run,finish=finish,deadline=initial['deadline'])
        except OwnerTemplateError as error:
            if error.state=='unknown' and error.code not in ('attempts_exhausted','invalid_ticket'):raise OwnerTemplateError('response_unknown','unknown') from None
            raise

    def verify(self,ticket):
        if self._busy.locked():raise OwnerTemplateError('busy')
        initial=self._ticket(ticket)
        def run(deadline):
            r=self._ticket(ticket)
            if not r['unknown']:raise OwnerTemplateError('invalid_ticket')
            if r['verifies']>=3:raise OwnerTemplateError('attempts_exhausted','unknown')
            r['verifies']+=1
            try:return self._latest(r,False)
            except Exception:raise OwnerTemplateError('response_unknown','unknown') from None
        return self._operation(run,deadline=initial['deadline'])


class OwnerWorkflowContextClient:
    """Ciphertext persistence only; caller supplies independent owner authority.

    No DOM authoring, archive custody lease, cold content read or execution grant
    is implied. Use native workflow_context helpers separately for content crypto.
    """
    def __init__(self,origin,binding,context_id,kind,*,read_current,current_session,consume_write_review,enabled=False,timeout_ms=10000):
        try:self.__session=_ContextSession(origin,binding,context_id,kind,read_current=read_current,current_session=current_session,consume_ciphertext_review=consume_write_review,enabled=enabled,timeout_ms=timeout_ms)
        except Exception:raise OwnerContextError('invalid_request') from None
    def __repr__(self):return 'OwnerWorkflowContextClient(<owner session redacted>)'
    def _call(self,method,*args):
        try:return getattr(self.__session,method)(*args)
        except OwnerTemplateError as error:raise OwnerContextError('expired' if error.code=='deadline' else error.code,error.state) from None
        except Exception:raise OwnerContextError('invalid_request') from None
    def prepare(self,request_id,expected_revision,scope,envelope):return self._call('prepare',request_id,expected_revision,scope,envelope)
    def commit(self,ticket):return self._call('post',ticket,False)
    def retry_unknown(self,ticket):return self._call('post',ticket,True)
    def verify_unknown(self,ticket):return self._call('verify',ticket)
    def pending(self):return self._call('pending')
    def close(self):return self._call('close')
