"""Portable owner facts authoring; trusted host review, no DOM impersonation."""
import inspect
import math
import threading
import time
import uuid
from concurrent.futures import Future, TimeoutError
from types import MappingProxyType

from . import sealed_candidate as s
from .contact_integrity import _origin
from .conversation_proposals import _selection, _record
from .owner_context import OwnerWorkflowContextClient, OwnerContextError
from .workflow_context import seal_workflow_context, workflow_context_aad

_ADMISSION=threading.BoundedSemaphore(4)


class ContextAuthoringError(Exception):
    def __init__(self,code='refused'):
        self.code=code
        super().__init__('Owner facts authoring: '+code)


def _call(fn,*args):
    value=fn(*args)
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):value.close()
        raise ContextAuthoringError('synchronous_callback_required')
    return value


def _freeze(value):
    return MappingProxyType({k:_freeze(v) for k,v in value.items()}) if type(value) is dict else value


class OwnerContextAuthoring:
    """One reviewed initial facts save, with explicit bounded reconciliation.

    read_draft_state returns epoch/revision/custodyLive. Its host lease is not
    nonexportable private-key custody: sealing uses an authorized public point.
    Hosts must invalidate on setup/session/draft/custody lifecycle changes.
    A normal synchronous review return authorizes commit; raise to decline.
    """
    def __init__(self,origin,binding,context_id,expires_ms,*,read_current,current_session,
                 read_draft_state,consume_review,enabled=False,timeout_ms=10000,observation_ms=10000):
        try:
            self._origin=_origin(origin);self._binding=_selection(binding,'refresh');self._context=s.capture(context_id,16)
            s.require(any(self._context) and type(expires_ms) is int and 0<expires_ms<=s.MAX,'context selection')
            s.require(type(enabled) is bool and all(callable(f) for f in (read_current,current_session,read_draft_state,consume_review)),'host callbacks')
            s.require(all(type(n) is int and 1<=n<=10000 for n in (timeout_ms,observation_ms)),'bounded lifetime')
        except Exception:raise ContextAuthoringError('invalid_options') from None
        self._expires=expires_ms;self._read,self._session,self._draft_read,self._review=read_current,current_session,read_draft_state,consume_review
        self._timeout,self._observation=timeout_ms/1000,observation_ms/1000
        self._guard=threading.RLock();self._busy=threading.Lock();self._closed=False;self._phase='editing'
        self._callbacks=0;self._settlement=threading.Condition(self._guard)
        self._deadline=math.inf;self._timer=None;self._now=0;self._client=None;self._ticket=None
        self._pending=None;self._saved=None;self._credentials=None;self._epoch=self._revision=None
        self._posts=self._checks=0;self._request=self._digest=self._text=None;self._scope=None
        if not enabled:self.close()

    def __repr__(self):return 'OwnerContextAuthoring(<draft and owner session redacted>)'

    def state(self):
        with self._guard:return _freeze(dict(phase=self._phase,pending=dict(self._pending) if self._pending else None))

    def saved_source(self):
        with self._guard:
            if self._closed:return None
            if time.monotonic()>=self._deadline:self.close();return None
            if self._phase!='saved' or self._saved is None:return None
            return _freeze(dict(accountId=self._saved['accountId'],receipt=dict(self._saved['receipt'])))

    def close(self):
        with self._guard:
            self._closed=True;self._phase='closed';self._saved=None;self._text=None;self._credentials=None;self._ticket=None
            if self._timer:self._timer.cancel();self._timer=None
            client=self._client
        if client is not None:
            pending=OwnerWorkflowContextClient.pending(client)
            with self._guard:self._pending=pending or self._pending
            OwnerWorkflowContextClient.close(client)

    def invalidate(self):self.close()

    def _host(self,fn,*args):
        # Backend transport workers can outlive their foreground prepare call.
        # Keep this author's admission until every supplied callback settles.
        with self._settlement:self._live();self._callbacks+=1
        try:return _call(fn,*args)
        finally:
            with self._settlement:self._callbacks-=1;self._settlement.notify_all()

    def _live(self):
        if self._closed:raise ContextAuthoringError('closed')
        if time.monotonic()>=self._deadline:self.close();raise ContextAuthoringError('expired')

    def _cap(self,deadline):
        with self._guard:
            self._live();s.require(deadline<=self._deadline,'deadline extension');self._deadline=deadline
            if self._timer:self._timer.cancel()
            self._timer=threading.Timer(max(0,deadline-time.monotonic()),self.close);self._timer.daemon=True;self._timer.start()
            self._live()

    def _draft(self):
        try:
            self._live();value=_record(self._host(self._draft_read),('epoch','revision','custodyLive'));self._live()
            s.require(type(value['epoch']) is int and type(value['revision']) is int and
                      (value['epoch'],value['revision'])==(self._epoch,self._revision) and value['custodyLive'] is True,'host draft changed')
        except Exception:self.close();raise ContextAuthoringError('closed') from None

    def _current(self):
        try:
            self._draft();started=time.monotonic()
            c=_record(self._host(self._read),('binding','manifest','nowMs','ownerSessionLive','consentLive'))
            binding=_selection(c['binding'],'refresh');now=s.integer(c['nowMs']);manifest=c['manifest']
            self._live()
            s.require(binding==self._binding and c['ownerSessionLive'] is True and c['consentLive'] is True and now>0 and now>=self._now,'owner current')
            original=s._bound(s._manifests,manifest);s.require(original.profile==2,'context profile')
            m=s._parse_manifest(original.raw,original.trust,now);b=self._binding
            s.require(m.trust.account==b['account'] and 0<self._expires-now<=30*86400000,'context authority')
            phone=next((k for k in m.keys if k.role==1 and k.id==b['phoneReader'] and k.active(now) and (k.device,k.line)==(b['device'],b['line'])),None)
            reader=next((k for k in m.keys if k.role==2 and k.id==b['archiveReader'] and k.active(now) and k.scope&8),None)
            signer=next((k for k in m.keys if k.role==4 and k.active(now) and k.scope==2 and (k.device,k.line)==(b['device'],b['line'])),None)
            s.require(phone is not None and reader is not None and signer is not None,'context current roles')
            signed=min(m.expires,phone.end,reader.end,signer.end,self._expires)
            self._cap(min(self._deadline,started+self._observation,started+(signed-now)/1000));self._now=now;self._draft()
            valid=math.floor((self._deadline-time.monotonic())*1000);s.require(valid>=1,'context freshness')
            return dict(binding=dict(b),manifest=manifest,nowMs=now,ownerSessionLive=True,consentLive=True,phase='active',validForMs=valid)
        except Exception:self.close();raise ContextAuthoringError('owner_changed') from None

    def _session_current(self):
        try:
            self._live();value=_record(self._host(self._session),('origin','cookie','csrf'));self._live()
            s.require(value['origin']==self._origin and (self._credentials is None or value==self._credentials),'owner session changed')
            self._credentials=dict(value)
            return dict(value)
        except Exception:self.close();raise ContextAuthoringError('owner_changed') from None

    def _review_write(self,review):
        self._draft()
        s.require(review['requestId']==self._request and review['contextId']==str(uuid.UUID(bytes=self._context)) and
                  review['expectedRevision']==0 and review['revision']==1 and review['envelopeDigest']==self._digest and
                  workflow_context_aad(dict(review['scope']))==workflow_context_aad(self._scope),'review identity')
        with self._guard:self._live();self._phase='review'
        self._host(self._review,_freeze(dict(review=dict(review,scope=dict(review['scope'])),text=self._text,
              accountId=str(uuid.UUID(bytes=self._binding['account'])),lineId=str(uuid.UUID(bytes=self._binding['line'])),
              peer=self._binding['peer'],expiresMs=self._expires,epoch=self._epoch,draftRevision=self._revision)))
        self._draft()
        with self._guard:self._live();self._phase='saving'

    def _retain(self,result):
        r=dict(result)
        s.require(set(r)=={'requestId','contextId','revision','envelopeDigest','state','requestAcknowledged'} and
                  r['requestId']==self._request and r['contextId']==str(uuid.UUID(bytes=self._context)) and r['revision']==1 and
                  r['envelopeDigest']==self._digest and r['state']=='verified_current_snapshot' and r['requestAcknowledged'] is True,'acknowledged source')
        with self._guard:
            self._live();self._saved=dict(accountId=str(uuid.UUID(bytes=self._binding['account'])),receipt=r)
            self._pending=None;self._ticket=None;self._text=None;self._phase='saved'
            if self._timer:self._timer.cancel();self._timer=None

    def _outcome(self,error):
        with self._guard:
            self._saved=None;self._text=None
            if self._client:self._pending=OwnerWorkflowContextClient.pending(self._client) or self._pending
            expired=isinstance(error,(OwnerContextError,ContextAuthoringError)) and error.code in ('expired','closed','owner_changed')
            if expired or time.monotonic()>=self._deadline:self.close()
            if self._closed:self._phase='closed'
            elif self._pending:self._phase='unknown'
            else:self.close();self._phase='refused'

    def _operation(self,fn):
        if not self._busy.acquire(False):
            self._outcome(ContextAuthoringError('busy'));return self.state()
        if not _ADMISSION.acquire(False):
            self._busy.release();self._outcome(ContextAuthoringError('capacity'));return self.state()
        future=Future();settled=False;returned=False
        def worker():
            nonlocal settled
            try:fn();self._live();future.set_result(None)
            except BaseException as error:self._outcome(error);future.set_result(None)
            finally:
                with self._settlement:
                    while self._callbacks:self._settlement.wait()
                _ADMISSION.release()
                with self._guard:
                    settled=True
                    if returned:self._busy.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except BaseException:_ADMISSION.release();self._busy.release();self.close();raise ContextAuthoringError() from None
        try:
            while True:
                try:future.result(timeout=.02);break
                except TimeoutError:
                    if self._closed or time.monotonic()>=self._deadline:self.close();break
            return self.state()
        finally:
            with self._guard:
                returned=True
                if settled:self._busy.release()

    def author(self,text,*,epoch,draft_revision):
        with self._guard:
            if self._closed or self._phase!='editing':return self.state()
            self._phase='preparing';self._deadline=time.monotonic()+self._timeout
        def run():
            self._live();self._cap(self._deadline)
            s.require(type(epoch) is int and epoch>0 and type(draft_revision) is int and draft_revision>0 and type(text) is str and 1<=len(text)<=32768,'draft')
            encoded=text.encode('utf-16-le','surrogatepass');s.require(1<=len(encoded)//2<=32768,'draft size')
            content=bytearray(encoded.decode('utf-16-le','replace').encode('utf-8'))
            self._epoch,self._revision,self._text=epoch,draft_revision,text
            try:
                s.require(len(content)<=32768,'draft bytes')
                current=self._current();m=s._bound(s._manifests,current['manifest']);b=self._binding
                self._scope=dict(kind=1,accountId=b['account'],deviceId=b['device'],lineId=b['line'],intervalId=b['interval'],contextId=self._context,
                    bindingGeneration=b['generation'],revision=1,expiresMs=self._expires,trustGeneration=m.trust.generation,manifestVersion=m.trust.version,
                    peerDigest=s.sha(b['peer'].encode('ascii')),readerId=b['archiveReader'],manifestDigest=m.trust.digest)
                envelope=seal_workflow_context(current['manifest'],self._scope,current['nowMs'],content)
            finally:content[:]=bytes(len(content))
            self._draft();self._digest=s.sha(envelope).hex();self._request=str(uuid.uuid4())
            client=OwnerWorkflowContextClient(self._origin,b,self._context,1,enabled=True,read_current=self._current,current_session=self._session_current,
                consume_write_review=self._review_write,timeout_ms=max(1,math.floor((self._deadline-time.monotonic())*1000)))
            with self._guard:
                if self._closed:client.close();raise ContextAuthoringError('closed')
                self._client=client
            self._ticket=client.prepare(self._request,0,self._scope,envelope);self._draft()
            self._posts+=1;result=client.commit(self._ticket);self._draft();self._retain(result)
        return self._operation(run)

    def _reconcile(self,retry):
        with self._guard:
            if self._closed or self._phase!='unknown' or self._client is None or self._ticket is None:return self.state()
            if (self._posts if retry else self._checks)>=3:return self.state()
            self._phase='saving'
        def run():
            self._draft()
            if retry:self._posts+=1;result=self._client.retry_unknown(self._ticket)
            else:self._checks+=1;result=self._client.verify_unknown(self._ticket)
            self._draft()
            if result['requestAcknowledged'] is not True:
                with self._guard:self._live();self._phase='unknown'
                return
            self._retain(result)
        return self._operation(run)

    def retry_unknown(self):return self._reconcile(True)
    def verify_unknown(self):return self._reconcile(False)
