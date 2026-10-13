"""Explicit current template opening with a dedicated owner-client lifetime."""
import threading
import time
from concurrent.futures import Future,TimeoutError
from types import MappingProxyType
from . import encrypted_template as t
from . import sealed_candidate as s
from .owner_template import OwnerTemplateReader,_record
from .owner_template_save import OwnerTemplateClient

_ADMISSION=threading.BoundedSemaphore(4)

def _freeze(value):
    return MappingProxyType({k:_freeze(v) for k,v in value.items()}) if type(value) is dict else value

class TemplateOpeningError(Exception):
    def __init__(self,code):super().__init__('Template opening '+code);self.code=code

class OwnerTemplateOpening:
    """Owns client close, never custody destruction; host changes must invalidate.

    Default opening requires a genuine qualified native protected recipient.
    Explicit require_protected=False admits only the existing software candidate.
    Neither setting establishes browser activation or owner login authority.
    """
    def __init__(self,origin,binding,template_id,*,client,read_current,current_session,enabled=False,timeout_ms=10000):
        if type(client) is not OwnerTemplateClient:raise TemplateOpeningError('refused')
        self._client=client;self._closed=threading.Event();self._busy=threading.Lock();self._guard=threading.RLock();self._failure=None;self._sample=None
        def sampled():
            value=_record(read_current(),('binding','manifest','nowMs','ownerSessionLive','consentLive','phase','validForMs'));self._sample=dict(value);return value
        try:
            if not callable(read_current):raise ValueError()
            self._authority=OwnerTemplateReader(origin,binding,template_id,read_current=sampled,current_session=current_session,enabled=enabled,timeout_ms=timeout_ms)
            s.require(client._origin==self._authority._origin and client._binding==self._authority._binding and client._template==self._authority._template,'opening client binding')
            self._timeout=timeout_ms/1000
        except Exception:
            OwnerTemplateClient.close(client)
            raise TemplateOpeningError('refused') from None
        if not enabled:self.close()
    def __repr__(self):return 'OwnerTemplateOpening(<owner session and custody redacted>)'
    def close(self):
        self._closed.set();OwnerTemplateClient.close(self._client);OwnerTemplateReader.close(self._authority)
    def invalidate(self):self.close()
    def _live(self,deadline):
        if self._closed.is_set():raise TemplateOpeningError(self._failure or 'closed')
        if time.monotonic()>=deadline:self._failure='deadline';self.close();raise TemplateOpeningError('deadline')
    def _current(self,scope,deadline,session):
        self._live(deadline);deadline=self._authority._authorize(scope,deadline,session);current=self._sample
        self._live(deadline);return current['manifest'],current['nowMs'],deadline
    def _custody(self,custody,protected,expected=None):
        s.require(type(protected) is bool,'opening protection')
        if protected or type(custody) is not s.SoftwareRecipient:s.require_protected_custody(custody)
        public=s.capture(custody.public_point(),65);s.point(public)
        s.require(expected is None or public==expected,'opening custody changed');return public
    def open_latest(self,custody,*,require_protected=True):
        if not self._busy.acquire(blocking=False):raise TemplateOpeningError('busy')
        if not _ADMISSION.acquire(blocking=False):self._busy.release();raise TemplateOpeningError('busy')
        deadline=time.monotonic()+self._timeout
        future=Future();settled=False;returned=False
        def worker():
            nonlocal deadline,settled
            envelope=None
            try:
                self._live(deadline);public=self._custody(custody,require_protected)
                session=self._authority._credentials(deadline);_,_,deadline=self._current(None,deadline,session)
                snapshot=OwnerTemplateClient.read_latest(self._client);self._live(deadline)
                scope=dict(snapshot['scope']);t.encrypted_template_aad(scope);envelope=bytearray(s.capture(snapshot['envelope'],308,33075))
                manifest,now,deadline=self._current(scope,deadline,session)
                content=t.open_encrypted_template(manifest,scope,now,custody,envelope,require_protected=require_protected)
                self._live(deadline);self._custody(custody,require_protected,public);_,_,deadline=self._current(scope,deadline,session)
                preview=t.preview_encrypted_template(content);_,_,deadline=self._current(scope,deadline,session)
                self._custody(custody,require_protected,public);self._live(deadline)
                result=MappingProxyType(dict(state='opened_current_preview',requestAcknowledged=False,matchesPending=snapshot['matchesPending'],revision=scope['revision'],encryptedDigest=snapshot['encryptedDigest'],preview=_freeze(preview)))
                future.set_result(result)
            except Exception as error:
                self._failure=error.code if isinstance(error,TemplateOpeningError) else 'refused';self.close();future.set_exception(TemplateOpeningError(self._failure))
            finally:
                if envelope is not None:envelope[:]=bytes(len(envelope))
                _ADMISSION.release()
                with self._guard:
                    settled=True
                    if returned:self._busy.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except Exception:_ADMISSION.release();self._busy.release();self.close();raise TemplateOpeningError('refused') from None
        try:
            while True:
                self._live(deadline)
                try:result=future.result(timeout=.02)
                except TimeoutError:continue
                self._live(deadline);return result
        finally:
            with self._guard:
                returned=True
                if settled:self._busy.release()
