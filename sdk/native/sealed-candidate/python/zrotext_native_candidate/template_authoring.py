"""DOM-free exclusive draft review; prepares ciphertext but never commits it."""
import json
import re
import threading
import time
from concurrent.futures import Future,TimeoutError
from types import MappingProxyType
from . import encrypted_template as t
from . import sealed_candidate as s
from .owner_template import OwnerTemplateReader,OwnerTemplateError,_record
from .owner_template_save import OwnerTemplateClient

_ADMISSION=threading.BoundedSemaphore(4)

def _freeze(value):
    return MappingProxyType({k:_freeze(v) for k,v in value.items()}) if type(value) is dict else value


class TemplateAuthoringError(Exception):
    def __init__(self,code):super().__init__('Template authoring '+code);self.code=code


class OwnerTemplateAuthoring:
    """One immutable reviewed draft and a dedicated owner persistence client.

    custodyLive is an independently maintained host lease fact, not a private-key
    capability. Host input/navigation/session/custody changes must invalidate().
    Callbacks are synchronous. Only exact True consumes plaintext draft review.
    """
    def __init__(self,origin,binding,template_id,*,read_current,current_session,consume_ciphertext_review,read_draft_state,consume_draft_review,enabled=False,timeout_ms=10000):
        if not callable(read_draft_state) or not callable(consume_draft_review):raise TemplateAuthoringError('invalid_draft')
        self._guard=threading.RLock();self._busy=threading.Lock();self._closed=False;self._expired=False;self._used=False;self._failure=None;self._timer=None;self._deadline=0
        self._draft_state,self._review=read_draft_state,consume_draft_review;self._sample=None;self._timeout=timeout_ms/1000 if type(timeout_ms) is int else 0
        def sampled():
            value=_record(read_current(),('binding','manifest','nowMs','ownerSessionLive','consentLive','phase','validForMs'));self._sample=dict(value);return value
        try:
            self.__client=OwnerTemplateClient(origin,binding,template_id,read_current=read_current,current_session=current_session,consume_ciphertext_review=consume_ciphertext_review,enabled=enabled,timeout_ms=timeout_ms)
            self._authority=OwnerTemplateReader(origin,binding,template_id,read_current=sampled,current_session=current_session,enabled=enabled,timeout_ms=timeout_ms)
        except Exception:raise TemplateAuthoringError('invalid_draft') from None
        if not enabled:self.close()

    @property
    def client(self):return self.__client
    def __repr__(self):return 'OwnerTemplateAuthoring(<draft and owner session redacted>)'

    def close(self):
        with self._guard:
            self._closed=True
            if self._timer:self._timer.cancel();self._timer=None
            OwnerTemplateClient.close(self.__client);OwnerTemplateReader.close(self._authority)

    def invalidate(self):self.close()

    def _live(self):
        if self._closed:raise TemplateAuthoringError('deadline' if self._expired else self._failure or 'closed')
        if time.monotonic()>=self._deadline:self._expired=True;self.close();raise TemplateAuthoringError('deadline')

    def _arm(self):
        with self._guard:
            self._live()
            if self._timer:self._timer.cancel()
            def expire():
                with self._guard:
                    if not self._closed and time.monotonic()>=self._deadline:self._expired=True;self.close()
            self._timer=threading.Timer(max(0,self._deadline-time.monotonic()),expire);self._timer.daemon=True;self._timer.start()

    def _draft(self,epoch,revision):
        try:value=_record(self._draft_state(),('epoch','revision','custodyLive'))
        except Exception:raise TemplateAuthoringError('draft_changed') from None
        self._live()
        if type(value['epoch']) is not int or type(value['revision']) is not int or value['epoch']!=epoch or value['revision']!=revision or value['custodyLive'] is not True:raise TemplateAuthoringError('draft_changed')

    def _current(self,scope,epoch,revision,session):
        self._live();self._draft(epoch,revision)
        try:
            self._deadline=self._authority._authorize(scope,self._deadline,session)
            current=self._sample;self._live();self._arm();self._draft(epoch,revision)
            if self._authority._credentials(self._deadline)!=session:raise TemplateAuthoringError('owner_changed')
            return current['manifest'],current['nowMs']
        except TemplateAuthoringError:raise
        except Exception:raise TemplateAuthoringError('owner_changed') from None

    def prepare(self,request_id,expected_revision,scope,template,values,*,epoch,draft_revision):
        if not self._busy.acquire(blocking=False):raise TemplateAuthoringError('busy')
        if not _ADMISSION.acquire(blocking=False):self._busy.release();raise TemplateAuthoringError('busy')
        with self._guard:
            if self._used or OwnerTemplateClient.pending(self.__client):_ADMISSION.release();self._busy.release();raise TemplateAuthoringError('pending_draft')
            self._deadline=time.monotonic()+self._timeout
        try:
            self._live()
            if type(epoch) is not int or epoch<1 or type(draft_revision) is not int or draft_revision<1:raise TemplateAuthoringError('invalid_draft')
            if type(request_id) is not str or re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',request_id) is None:raise TemplateAuthoringError('invalid_draft')
            if type(expected_revision) not in (int,float) or not 0<=expected_revision<128 or int(expected_revision)!=expected_revision:raise TemplateAuthoringError('invalid_draft')
            aad=t.encrypted_template_aad(scope)
            if s.num(aad,94)!=expected_revision+1:raise TemplateAuthoringError('invalid_draft')
            captured={k:s.capture(v,len(v)) if type(v) in (bytes,bytearray) else v for k,v in scope.items()}
            canonical=t.canonical_template_bytes(template,values)
            if len(canonical)>32768:raise TemplateAuthoringError('invalid_draft')
            content=json.loads(canonical);content={k:content[k] for k in ('template','values')}
        except Exception as error:
            _ADMISSION.release();self._busy.release();self.close()
            raise error if isinstance(error,TemplateAuthoringError) else TemplateAuthoringError('invalid_draft') from None
        future=Future();settled=False;returned=False
        def worker():
            nonlocal settled
            try:
                self._live();self._arm()
                preview=t.preview_encrypted_template(content);session=self._authority._credentials(self._deadline)
                self._current(captured,epoch,draft_revision,session)
                review=MappingProxyType(dict(requestId=request_id,expectedRevision=int(expected_revision),scope=MappingProxyType(dict(captured)),template=content['template'],values=MappingProxyType(dict(content['values'])),epoch=epoch,draftRevision=draft_revision,preview=_freeze(preview)))
                if self._review(review) is not True:raise TemplateAuthoringError('review_declined')
                self._live();manifest,now=self._current(captured,epoch,draft_revision,session)
                envelope=t.seal_encrypted_template(manifest,captured,now,content);self._live();self._current(captured,epoch,draft_revision,session)
                ticket=OwnerTemplateClient.prepare_save(self.__client,request_id,expected_revision,captured,envelope)
                self._live();self._current(captured,epoch,draft_revision,session)
                with self._guard:self._live();self._used=True
                future.set_result(ticket)
            except Exception as error:
                self._failure=error.code if isinstance(error,TemplateAuthoringError) else 'refused';self.close();future.set_exception(TemplateAuthoringError(self._failure))
            finally:
                _ADMISSION.release()
                with self._guard:
                    settled=True
                    if returned:self._busy.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except Exception:_ADMISSION.release();self._busy.release();self.close();raise TemplateAuthoringError('refused') from None
        try:
            while True:
                self._live()
                try:ticket=future.result(timeout=.02)
                except TimeoutError:continue
                self._live();return ticket
        finally:
            with self._guard:
                returned=True
                if settled:self._busy.release()
