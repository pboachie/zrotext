"""Opaque owner template save intents; no browser, plaintext or send authority."""
import http.client
import re
import threading
import time
import uuid
from concurrent.futures import Future,TimeoutError
from types import MappingProxyType
from . import encrypted_template as t
from . import sealed_candidate as s
from .template_store import template_save_request,template_save_receipt
from .owner_template import OwnerTemplateReader,OwnerTemplateError,_ADMISSION,_scope,_CONTENT


class OwnerTemplateClient(OwnerTemplateReader):
    """Explicit prepare/commit/retry/reconcile; no automatic retry or reset.

    consume_ciphertext_review receives a read-only captured review. Successful
    return represents the trusted host consuming that exact review, not relay
    approval. Tickets are local opaque object identities bound to this client.
    """
    def __init__(self,*args,consume_ciphertext_review,**kwargs):
        if not callable(consume_ciphertext_review):raise OwnerTemplateError('invalid_request')
        self._guard=threading.RLock();self._saved=None;self._pending=None;self._timer=None
        self._review=consume_ciphertext_review
        super().__init__(*args,**kwargs)

    def __repr__(self):return 'OwnerTemplateClient(<owner session redacted>)'

    def close(self):
        with self._guard:
            if self._timer:self._timer.cancel();self._timer=None
            self._saved=None
            super().close()

    def pending(self):
        with self._guard:return dict(self._pending) if self._pending is not None else None

    def _state(self):return 'unknown' if self._pending is not None else 'refused'

    def _live(self,deadline):
        try:super()._live(deadline)
        except OwnerTemplateError as error:raise OwnerTemplateError(error.code,self._state()) from None

    def _credentials(self,deadline):
        result=super()._credentials(deadline)
        with self._guard:
            if self._saved is not None and result!=self._saved['credentials']:
                self._closed_code='owner_changed';self.close();raise OwnerTemplateError('owner_changed',self._state())
        return result

    def _shorten(self,record,deadline):
        with self._guard:
            self._live(deadline)
            if self._saved is not record or deadline>record['deadline']:raise OwnerTemplateError('invalid_request',self._state())
            record['deadline']=deadline;self._deadline=deadline
            if self._timer:self._timer.cancel()
            def expire():
                with self._guard:
                    if self._saved is record and time.monotonic()>=record['deadline']:
                        self._closed_code='deadline';self.close()
            self._timer=threading.Timer(max(0,deadline-time.monotonic()),expire);self._timer.daemon=True;self._timer.start()

    def _authorize(self,scope,deadline,credentials):
        try:deadline=super()._authorize(scope,deadline,credentials)
        except OwnerTemplateError as error:raise OwnerTemplateError(error.code,self._state()) from None
        with self._guard:
            if self._saved is not None:self._shorten(self._saved,deadline)
        return deadline

    def _identity(self,r):
        return dict(requestId=r['request_id'],templateId=str(uuid.UUID(bytes=r['scope']['templateId'])),revision=r['request'].revision,encryptedDigest=r['request'].encrypted_digest)

    def _forget(self,r):
        with self._guard:
            if self._saved is r:
                if self._timer:self._timer.cancel();self._timer=None
                self._saved=None
            self._pending=None

    def _ticket(self,ticket):
        with self._guard:
            if self._closed.is_set():raise OwnerTemplateError('closed',self._state())
            r=self._saved;self._live(r['deadline'] if r else 0)
            if r is None or r['ticket'] is not ticket:raise OwnerTemplateError('invalid_request')
            return r

    def _operation(self,run,*,finish=None,deadline=None):
        if not self._busy.acquire(blocking=False):raise OwnerTemplateError('busy')
        if not _ADMISSION.acquire(blocking=False):self._busy.release();raise OwnerTemplateError('capacity',self._state())
        deadline=deadline if deadline is not None else time.monotonic()+self._timeout
        self._deadline=deadline;future=Future();settled=False;returned=False
        def worker():
            nonlocal settled
            try:
                self._live(deadline);result=run(deadline);self._live(min(deadline,self._deadline));future.set_result(result)
            except Exception as error:future.set_exception(error if isinstance(error,OwnerTemplateError) else OwnerTemplateError('read_refused',self._state()))
            finally:
                _ADMISSION.release()
                with self._guard:
                    settled=True
                    if returned:self._busy.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except Exception:_ADMISSION.release();self._busy.release();raise OwnerTemplateError('read_refused',self._state()) from None
        try:
            while True:
                self._live(min(deadline,self._deadline))
                try:result=future.result(timeout=.02)
                except TimeoutError:continue
                with self._guard:
                    self._live(min(deadline,self._deadline))
                    if finish:finish(result)
                    return result
        finally:
            with self._guard:
                returned=True
                if settled:self._busy.release()

    def prepare_save(self,request_id,expected_revision,scope,envelope):
        with self._guard:
            if self._saved is not None or self._pending is not None:raise OwnerTemplateError('pending_write')
            if self._closed.is_set():raise OwnerTemplateError('closed',self._state())
        # Snapshot before any callback or background work can mutate caller input.
        try:
            captured=s.capture(envelope,308,33075);parsed=_scope(captured)
            s.require(t.encrypted_template_aad(scope)==captured[:222],'template scope')
            request=template_save_request(parsed,request_id,expected_revision,captured)
        except Exception:raise OwnerTemplateError('invalid_request') from None
        def run(deadline):
            r=None
            try:
                credentials=self._credentials(deadline)
                r=dict(ticket=object(),request_id=request_id,scope=parsed,request=request,credentials=credentials,deadline=deadline,attempts=0,verifies=0,unknown=False)
                with self._guard:
                    self._live(deadline)
                    if self._saved is not None or self._pending is not None:raise OwnerTemplateError('pending_write')
                    self._saved=r
                deadline=self._authorize(parsed,deadline,credentials);s.point(captured[222:287]);self._live(deadline)
                review=MappingProxyType(dict(requestId=request_id,expectedRevision=request.revision-1,scope=MappingProxyType(dict(parsed)),encryptedDigest=request.encrypted_digest))
                s.require(self._review(review) is None,'synchronous consumed review');self._live(deadline);self._authorize(parsed,deadline,credentials)
                return r['ticket']
            except Exception as error:
                if r:self._forget(r)
                if isinstance(error,OwnerTemplateError):raise
                raise OwnerTemplateError('invalid_request') from None
        return self._operation(run)

    def _post(self,ticket,retry):
        if self._busy.locked():raise OwnerTemplateError('busy')
        initial=self._ticket(ticket)
        def run(deadline):
            r=self._ticket(ticket);was_unknown=r['unknown'];attempted=False
            if (retry and not was_unknown) or (not retry and r['attempts']!=0):raise OwnerTemplateError('invalid_request')
            if r['attempts']>=3:raise OwnerTemplateError('attempts_exhausted','unknown' if was_unknown else 'refused')
            try:
                deadline=self._authorize(r['scope'],r['deadline'],r['credentials'])
                with self._guard:
                    self._live(deadline);r['attempts']+=1;r['unknown']=True;attempted=True;self._pending=self._identity(r)
                self._live(deadline);s.require(self._credentials(deadline)==r['credentials'],'owner session')
                connection=http.client.HTTPSConnection(self._host,self._port,timeout=max(.001,deadline-time.monotonic()));self._connection=connection;response=None
                try:
                    connection.connect();self._live(deadline)
                    headers={'Accept':'application/json','x-zrotext-csrf':r['credentials']['csrf'],'Cookie':r['credentials']['cookie'],'Cache-Control':'no-store',**r['request'].headers}
                    connection.request('POST',r['request'].path,body=r['request'].body,headers=headers)
                    response=connection.getresponse();self._live(deadline)
                    if response.status in (401,403):self.close()
                    if response.status!=200 or re.fullmatch(r'application/json(?:\s*;\s*charset=utf-8)?',response.getheader('Content-Type') or '',re.I) is None:
                        raise OwnerTemplateError('response_unknown','unknown')
                    raw=response.read(257);self._live(deadline)
                    if len(raw)>256 or response.length not in (None,0):raise OwnerTemplateError('response_unknown','unknown')
                    template_save_receipt(r['request'],raw)
                    if raw.decode('utf-8-sig')!='{"revision":'+str(r['request'].revision)+'}':raise OwnerTemplateError('response_unknown','unknown')
                finally:
                    if response is not None:response.close()
                    connection.close();self._connection=None
                self._authorize(r['scope'],deadline,r['credentials'])
                with self._guard:
                    self._live(self._deadline)
                    if r['scope']['revision']==self._head and self._head_digest is not None and r['request'].encrypted_digest!=self._head_digest:raise OwnerTemplateError('response_unknown','unknown')
                return dict(self._identity(r),state='acknowledged_saved_revision')
            except Exception as error:
                if attempted or was_unknown:raise OwnerTemplateError('response_unknown','unknown') from None
                if isinstance(error,OwnerTemplateError):raise
                raise OwnerTemplateError('save_refused') from None
        def finish(value):
            r=self._saved
            if r is None:raise OwnerTemplateError('response_unknown','unknown')
            if r['scope']['revision']>=self._head:self._head,self._head_digest=r['scope']['revision'],r['request'].encrypted_digest
            self._forget(r)
        deadline=initial['deadline']
        try:return self._operation(run,finish=finish,deadline=deadline)
        except OwnerTemplateError as error:
            if error.state=='unknown' and error.code not in ('busy','attempts_exhausted'):raise OwnerTemplateError('response_unknown','unknown') from None
            raise

    def commit(self,ticket):return self._post(ticket,False)
    def retry_unknown(self,ticket):return self._post(ticket,True)

    def _latest(self,r,verify):
        if verify:
            if not r['unknown']:raise OwnerTemplateError('invalid_request')
            if r['verifies']>=3:raise OwnerTemplateError('attempts_exhausted','unknown')
            r['verifies']+=1
        try:
            result=super()._read(r['deadline'] if r else self._deadline)
            result['matchesPending']=r is not None and result['envelope']==r['request'].body
            return result
        except Exception as error:
            if verify:raise OwnerTemplateError('response_unknown','unknown') from None
            if isinstance(error,OwnerTemplateError):raise OwnerTemplateError(error.code,self._state() if error.state=='refused' else error.state) from None
            raise OwnerTemplateError('read_refused',self._state()) from None

    def read_latest(self):
        if self._busy.locked():raise OwnerTemplateError('busy')
        if self._closed.is_set():raise OwnerTemplateError('closed',self._state())
        def run(deadline):
            # Selection belongs to the admitted operation, never the gap before
            # acquiring busy. A concurrently completed write is no longer pending.
            with self._guard:
                r=self._saved
                if r is not None:self._deadline=min(deadline,r['deadline'])
            return self._latest(r,r is not None and r['unknown'])
        return self._operation(run)

    def verify_unknown(self,ticket):
        if self._busy.locked():raise OwnerTemplateError('busy')
        deadline=self._ticket(ticket)['deadline']
        return self._operation(lambda _:self._latest(self._ticket(ticket),True),deadline=deadline)
