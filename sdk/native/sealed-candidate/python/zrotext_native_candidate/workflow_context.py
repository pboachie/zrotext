"""ZTWC01 candidate content crypto; no interval permission or runtime grant."""
from concurrent.futures import Future, TimeoutError
from functools import wraps
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import sealed_candidate as s
from .compose03 import _wrap

_IDS=('accountId','deviceId','lineId','intervalId','contextId')
_NUMBERS=('bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion')
_DIGESTS=('peerDigest','readerId','manifestDigest')
_DOMAIN=b'ZT/workflow-context/hpke/v1\0'
_admission=threading.BoundedSemaphore(4)


class WorkflowContextError(ValueError):
    def __init__(self):super().__init__('workflow context: invalid ciphertext or current scope')


class WorkflowContextCancellation:
    """One-way local cancellation; it cannot preempt a native provider call."""
    def __init__(self):self._event=threading.Event()
    def cancel(self):self._event.set()
    def is_cancelled(self):return self._event.is_set()


def _closed(function):
    @wraps(function)
    def run(*args,**kwargs):
        try:return function(*args,**kwargs)
        except Exception:raise WorkflowContextError() from None
    return run


@_closed
def workflow_context_aad(scope):
    s.require(type(scope) is dict and set(scope)==set(_IDS+_NUMBERS+_DIGESTS+('kind',)),'context scope')
    kind=scope['kind'];s.require(type(kind) is int and kind in (1,2,3),'context kind')
    parts=[b'ZTWC\x01'+bytes([kind])]
    for key in _IDS:
        value=s.capture(scope[key],16);s.require(any(value),'context zero identity');parts.append(value)
    for key in _NUMBERS:
        value=s.integer(scope[key]);s.require(value>0 and (key!='revision' or value<=128),'context integer');parts.append(value.to_bytes(8,'big'))
    for key in _DIGESTS:
        value=s.capture(scope[key],32);s.require(any(value),'context zero digest');parts.append(value)
    return b''.join(parts)


def _authorize(manifest,aad,now,role):
    now=s.integer(now);expiry=s.num(aad,102)
    s.require(0<now<expiry and expiry-now<=30*86400000,'context expiry')
    m=s._bound(s._manifests,manifest);s.require(m.profile==2,'context profile')
    m=s._parse_manifest(m.raw,m.trust,now)
    s.require((m.trust.account,m.trust.generation,m.trust.version,m.trust.digest)==
              (aad[6:22],s.num(aad,110),s.num(aad,118),aad[190:222]),'context manifest binding')
    reader=next((k for k in m.keys if k.role==role and k.id==aad[158:190]),None)
    signer=next((k for k in m.keys if k.role==4 and k.active(now) and k.device==aad[22:38] and k.line==aad[38:54]),None)
    s.require(reader is not None and reader.active(now) and reader.scope&8 and signer is not None and signer.scope==2,'context reader/line authority')
    return reader.point


def _operation(cancel,initial,run):
    held=bytearray(initial)
    try:
        s.require(cancel is None or type(cancel) is WorkflowContextCancellation,'context cancellation')
        s.require(cancel is None or not cancel.is_cancelled(),'context cancelled')
        s.require(_admission.acquire(blocking=False),'context capacity')
    except BaseException:
        held[:]=bytes(len(held));raise
    deadline=time.monotonic()+10;stopped=threading.Event();future=Future()
    def live():
        s.require(not stopped.is_set() and (cancel is None or not cancel.is_cancelled()) and time.monotonic()<deadline,'context lifecycle')
    def worker():
        try:
            live();result=run(held,live);live();future.set_result(result)
        except BaseException as error:future.set_exception(error)
        finally:held[:]=bytes(len(held));_admission.release()
    try:threading.Thread(target=worker,daemon=True).start()
    except BaseException:
        held[:]=bytes(len(held));_admission.release();raise
    while True:
        try:
            live();result=future.result(timeout=min(0.02,max(0.001,deadline-time.monotonic())));live();return result
        except TimeoutError:continue
        except BaseException:stopped.set();raise


def _seal(manifest,scope,now,plaintext,role,cancel):
    aad=workflow_context_aad(scope);public=_authorize(manifest,aad,now,role)
    content=s.capture(plaintext,1,32768)
    def run(held,live):
        live();wrapped=_wrap(public,held,_DOMAIN+aad,aad);live()
        return aad+wrapped[:65]+(len(wrapped)-65).to_bytes(4,'big')+wrapped[65:]
    return _operation(cancel,content,run)


def _open(manifest,scope,now,custody,envelope,role,protected,cancel):
    s.require(type(protected) is bool,'context custody policy')
    if protected or type(custody) is not s.SoftwareRecipient:s.require_protected_custody(custody)
    envelope=s.capture(envelope,308,33075);aad=workflow_context_aad(scope)
    s.require(envelope[:222]==aad and s.num(envelope,287,4)==len(envelope)-291,'context envelope')
    public=_authorize(manifest,aad,now,role);ephemeral=envelope[222:287];s.point(ephemeral)
    def run(held,live):
        live();actual=custody.public_point();live();s.require(actual==public,'context custody binding')
        buffers=[]
        def retain(value):result=bytearray(value);buffers.append(result);return result
        try:
            kem,suite=b'KEM\x00\x10',b'HPKE\x00\x10\x00\x01\x00\x01'
            live();dh=retain(custody.exchange(ephemeral));live()
            eae=retain(s._extract(kem,b'',b'eae_prk',dh))
            shared=retain(s._expand(kem,eae,b'shared_secret',ephemeral+public,32))
            context=b'\0'+s._extract(suite,b'',b'psk_id_hash',b'')+s._extract(suite,b'',b'info_hash',_DOMAIN+aad)
            secret=retain(s._extract(suite,shared,b'secret',b''));key=retain(s._expand(suite,secret,b'key',context,16))
            nonce=s._expand(suite,secret,b'base_nonce',context,12);plain=retain(bytes(len(held)-16))
            live();s.require(AESGCM(key).decrypt_into(nonce,held,aad,plain)==len(plain),'context authentication');live()
            return bytes(plain)
        finally:
            for value in buffers:value[:]=bytes(len(value))
    return _operation(cancel,envelope[291:],run)


@_closed
def seal_workflow_context(manifest,scope,now_ms,plaintext,*,cancel=None):
    return _seal(manifest,scope,now_ms,plaintext,2,cancel)


@_closed
def seal_integration_workflow_context(manifest,scope,now_ms,plaintext,*,cancel=None):
    return _seal(manifest,scope,now_ms,plaintext,3,cancel)


@_closed
def open_workflow_context(manifest,scope,now_ms,custody,envelope,*,require_protected=True,cancel=None):
    return _open(manifest,scope,now_ms,custody,envelope,2,require_protected,cancel)


@_closed
def open_integration_workflow_context(manifest,scope,now_ms,custody,envelope,*,require_protected=True,cancel=None):
    return _open(manifest,scope,now_ms,custody,envelope,3,require_protected,cancel)
