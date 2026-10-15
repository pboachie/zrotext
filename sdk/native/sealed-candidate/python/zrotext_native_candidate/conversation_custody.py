"""Scope-bound native conversation lifecycle; no DOM, HTTP or generic signing."""
import base64
import inspect
import math
import threading
import time
import uuid
import weakref
from concurrent.futures import Future, TimeoutError
from types import MappingProxyType

from . import sealed_candidate as s
from .checkpoint_store import CheckpointStore
from .conversation_proposals import _selection, _record
from .conversation_signer import ConversationSignerSetup02
from .enrollment_ceremony import ConversationEnrollment

_ADMISSION = threading.BoundedSemaphore(4)
_SCOPE = ('account','session','interval','device','line','generation','peer','reader','manifest')


class _ReviewTicket:
    __slots__=('__weakref__',)


class ConversationCustodyError(Exception):
    def __init__(self, code='refused', state='refused'):
        self.code, self.state = code, state
        super().__init__('Conversation custody: '+code)


def _freeze(value):
    return MappingProxyType({k:_freeze(v) for k,v in value.items()}) if type(value) is dict else value


def _scope_input(value):
    s.require(type(value) in (dict,MappingProxyType),'scope record')
    result=_record(dict(value),_SCOPE)
    s.require(all(type(v) is str and len(v)<=128 for v in result.values()),'scope fields')
    return result


def _call(fn, *args):
    value=fn(*args)
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):value.close()
        raise ConversationCustodyError('synchronous_callback_required')
    return value


class ConversationCustody02:
    """One explicit setup, then serialized authority/review/sign/open operations.

    Root and archive custodians are borrowed and never deleted by this object.
    The freshly created role-5 signer is owned and requires durable exact-alias
    receipts. Current/install callbacks are trusted application authority, not
    server grants. Optional CheckpointStore provides verified retained history.
    """
    def __init__(self, binding, *, archive_custody, root_signer, read_current,
                 consume_setup_decision, consume_owner_decision, install_verified,
                 consume_confirmation, record_pending_alias, record_deleted_alias,
                 history_store=None, read_selection=None, require_protected=True):
        try:
            self._binding=_selection(binding,'refresh')
            s.require(type(require_protected) is bool,'custody policy')
            s.require(all(callable(f) for f in (read_current,consume_setup_decision,consume_owner_decision,
                install_verified,consume_confirmation,record_pending_alias,record_deleted_alias)),'callbacks')
            s.require(history_store is None or type(history_store) is CheckpointStore,'checkpoint type')
            s.require(read_selection is None or callable(read_selection),'selection callback')
        except Exception:raise ConversationCustodyError('invalid_options') from None
        self._archive,self._root_signer=archive_custody,root_signer
        self._read,self._setup_decision,self._owner_decision=read_current,consume_setup_decision,consume_owner_decision
        self._install,self._confirm=install_verified,consume_confirmation
        self._pending_receipt,self._deleted_receipt=record_pending_alias,record_deleted_alias
        self._store,self._selection=history_store,read_selection
        self._protected=require_protected;self._guard=threading.RLock();self._condition=threading.Condition(self._guard)
        self._closed=self._busy=self._started=self._ready=self._installed=self._install_started=False
        self._callbacks=0;self._signer=self._enrollment=None;self._last=None;self._archive_point=None
        self._reviews=weakref.WeakKeyDictionary();self._history={};self._observed_expiry=math.inf;self._expiry=math.inf;self._timer=None;self._op=None

    def __repr__(self):return 'ConversationCustody02(<scope and custody redacted>)'

    def _error(self,code='refused'):
        return ConversationCustodyError(code,'unknown' if self._install_started and not self._installed else 'refused')

    def _live(self):
        if self._closed or time.monotonic()>=self._expiry:raise self._error('closed')
        if self._op is not None and (self._op['cancel'].is_set() or time.monotonic()>=self._op['deadline']):raise self._error('timeout')

    def _host(self,fn,*args,cleanup=False):
        with self._condition:
            if not cleanup:self._live()
            self._callbacks+=1
        try:return _call(fn,*args)
        finally:
            with self._condition:self._callbacks-=1;self._condition.notify_all()

    def _archive_current(self,point):
        s.require(self._archive is not None,'archive unavailable')
        if self._protected:s.require_protected_custody(self._archive)
        elif type(self._archive) is not s.SoftwareRecipient:s.require_protected_custody(self._archive)
        s.require(self._archive.public_point()==point,'archive point binding')
        self._live()

    def _current(self):
        self._live();started=time.monotonic()
        value=_record(self._host(self._read),('binding','manifest','nowMs','ownerSessionLive','consentLive'))
        binding=_selection(value['binding'],'refresh');now=s.integer(value['nowMs']);token=value['manifest']
        s.require(binding==self._binding and value['ownerSessionLive'] is True and value['consentLive'] is True and now>0,'current scope')
        original=s._bound(s._manifests,token);s.require(original.profile==2,'profile02 current')
        m=s._parse_manifest(original.raw,original.trust,now);t=m.trust
        s.require(t.account==binding['account'],'current account')
        if self._last is not None:
            old_now,old=self._last
            s.require(now>=old_now and (t.generation,t.root)==(old.generation,old.root) and
                t.version>=old.version and (t.version!=old.version or t.digest==old.digest),'current regression')
        if self._store is not None:
            _,stored=self._store.snapshot(now)
            s.require(stored is not None and s.manifest_identity(stored)==s.manifest_identity(token),'persisted current changed')
        reader=next((k for k in m.keys if k.role==2 and k.id==binding['archiveReader']),None)
        s.require(reader is not None and reader.active(now) and reader.scope&8,'current archive revoked')
        if self._archive_point is not None:s.require(reader.point==self._archive_point,'archive substitution')
        self._archive_current(reader.point)
        end=min(m.expires,reader.end)
        if self._ready:
            signer=next((k for k in m.keys if k.role==5 and k.id==self._signer.key_id),None)
            s.require(signer is not None and signer.active(now) and signer.point==self._signer.public_point and signer.scope==1 and signer.line==binding['line'],'current signer revoked')
            end=min(end,signer.end)
        self._observed_expiry=started+(end-now)/1000
        self._op['deadline']=min(self._op['deadline'],self._observed_expiry)
        self._live();self._last=now,t;self._archive_point=reader.point
        if t.digest not in self._history:s.require(len(self._history)<64,'history capacity');self._history[t.digest]=token
        return dict(binding=dict(binding),manifest=token,nowMs=now,ownerSessionLive=True,consentLive=True)

    def _scope(self,current):
        b=self._binding
        value={k:str(uuid.UUID(bytes=b[k])) for k in ('account','session','interval','device','line')}
        value.update(generation=str(b['generation']),peer=b['peer'],reader=base64.b64encode(b['archiveReader']).decode(),
            manifest=base64.b64encode(s.manifest_identity(current['manifest'])['digest']).decode())
        return value

    def _selected(self,scope):
        current=self._current();s.require(scope==self._scope(current),'selected scope changed');return current

    def _remaining(self):
        self._live();return max(.001,min(10,self._op['deadline']-time.monotonic(),self._expiry-time.monotonic()))

    def _run(self,fn,timeout,cancel):
        s.require(type(timeout) in (int,float) and 0<timeout<=60 and (cancel is None or type(cancel) is threading.Event),'bounded operation')
        with self._guard:
            if self._busy:raise self._error('busy')
            self._live()
            if not _ADMISSION.acquire(False):raise self._error('capacity')
            self._busy=True;self._op=dict(deadline=time.monotonic()+timeout,cancel=cancel or threading.Event())
        future=Future();foreground=threading.Event()
        def worker():
            try:
                self._live();value=fn();self._live();future.set_result(value)
            except BaseException:
                self.close();future.set_exception(self._error())
            finally:
                # A child can time out while its provider/callback is still live.
                # Do not publish spare capacity until those actual workers settle.
                while True:
                    with self._condition:
                        children=(self._signer is not None and self._signer._busy) or (self._enrollment is not None and self._enrollment._busy.locked())
                        if not self._callbacks and not children:break
                        self._condition.wait(.02)
                foreground.wait()
                if self._closed and self._signer is not None:
                    try:self._signer.cleanup(timeout=5)
                    except Exception:pass
                    while self._signer._busy:time.sleep(.02)
                with self._guard:
                    if self._closed:self._archive=None;self._history.clear();self._reviews.clear()
                    self._op=None;self._busy=False
                _ADMISSION.release()
        try:
            thread=threading.Thread(target=worker,daemon=True);thread.start()
        except BaseException:
            with self._guard:self._busy=False;self._op=None
            _ADMISSION.release();raise
        try:
            while True:
                self._live()
                try:value=future.result(timeout=.01)
                except TimeoutError:continue
                self._live();return value
        except BaseException:self.close();raise
        finally:
            foreground.set();thread.join(.02)

    def setup(self,*,timeout=10,cancel=None):
        with self._guard:
            if self._started:raise self._error('setup_consumed')
            self._started=True
        def run():
            self._signer=ConversationSignerSetup02(self._binding,lambda b:self._host(self._setup_decision,b),self._current,
                record_pending_alias=lambda a:self._host(self._pending_receipt,a),
                record_deleted_alias=lambda a:self._host(self._deleted_receipt,a,cleanup=True),require_hardware=self._protected)
            self._signer.setup(timeout=self._remaining(),cancel=self._op['cancel'])
            self._live()
            def install(*args):
                self._live();self._install_started=True;return self._host(self._install,*args)
            self._enrollment=ConversationEnrollment(self._binding,self._signer.public_point,signer=self._root_signer,
                read_current=self._current,consume_owner_decision=lambda r:self._host(self._owner_decision,r),install_verified=install,
                require_protected=self._protected,timeout_ms=max(1,int(self._remaining()*1000)))
            accepted=self._enrollment.enroll();current=self._current()
            s.require(s.manifest_identity(current['manifest'])==s.manifest_identity(accepted),'enrollment not authoritatively installed')
            m=s._bound(s._manifests,current['manifest']);key=next((k for k in m.keys if k.role==5 and k.id==self._signer.key_id),None)
            s.require(key is not None and 0<key.end-current['nowMs']<=1800000,'enrollment lifetime')
            self._ready=True;self._current();self._installed=True
            self._expiry=self._observed_expiry
            # Preserve the initial signed session window, anchored before its
            # current callback. Per-operation timeouts cannot renew this window.
            self._timer=threading.Timer(max(0,self._expiry-time.monotonic()),self.close);self._timer.daemon=True;self._timer.start()
            return self
        return self._run(run,timeout,cancel)

    def authority(self,*,timeout=10,cancel=None):
        def run():
            s.require(self._ready,'setup required');current=self._current()
            key=next(k for k in s._bound(s._manifests,current['manifest']).keys if k.role==5 and k.id==self._signer.key_id)
            valid=min(60000,key.end-current['nowMs'],math.floor((self._expiry-time.monotonic())*1000))
            s.require(valid>0,'authority expired');return _freeze(dict(phase='active',scope=self._scope(current),validForMs=valid))
        return self._run(run,timeout,cancel)

    def prepare(self,scope,body,*,timeout=10,cancel=None):
        scope=_scope_input(scope)
        def run():
            s.require(self._ready and len(self._reviews)<1024,'setup or review capacity');self._selected(scope)
            review=self._signer.prepare_review(body,timeout=self._remaining(),cancel=self._op['cancel']);self._selected(scope)
            ticket=_ReviewTicket();self._reviews[ticket]=review;return ticket
        return self._run(run,timeout,cancel)

    def sign_reviewed(self,ticket,scope,body,*,timeout=10,cancel=None):
        scope=_scope_input(scope)
        def run():
            review=self._reviews.pop(ticket,None);s.require(review is not None and review['body']==body,'review consumed or changed')
            self._selected(scope)
            signature=self._signer.sign_reviewed(review['proof'],review['envelope'],body,lambda p,b:self._host(self._confirm,p,b),timeout=self._remaining(),cancel=self._op['cancel'])
            self._selected(scope)
            return _freeze(dict(envelope=base64.b64encode(review['envelope']).decode(),confirmation=base64.b64encode(review['proof']).decode(),signature=base64.b64encode(signature).decode()))
        return self._run(run,timeout,cancel)

    def open_sealed(self,envelope,scope,*,timeout=10,cancel=None):
        raw=s.capture(envelope,1,34082);scope=_scope_input(scope)
        def run():
            s.require(self._ready,'setup required');current=self._selected(scope);parsed=s.parse_envelope(raw)
            historical=self._history.get(parsed.digest)
            if historical is None and self._store is not None:
                historical=self._store.history(parsed.digest,parsed.observed);self._selected(scope)
            s.require(historical is not None and s.manifest_identity(historical)['digest']==parsed.digest,'accepted historical provenance unavailable')
            selection=self._host(self._selection,raw) if len(parsed.wraps)>1 and self._selection is not None else None
            s.require(len(parsed.wraps)==1 or selection is not None,'phone-approved selection unavailable')
            self._selected(scope);b=self._binding
            text=s.open_archive_candidate02(raw,historical,current['manifest'],self._archive,account=b['account'],device=b['device'],line=b['line'],peer=b['peer'],reader_id=b['archiveReader'],now_ms=current['nowMs'],selection=selection,interval=b['interval'])
            self._selected(scope);return text
        return self._run(run,timeout,cancel)

    @property
    def cleanup_pending(self):return self._signer is not None and self._signer.cleanup_pending

    @property
    def cleanup_state(self):return self._signer.cleanup_state if self._signer is not None else 'complete'

    def close(self):
        with self._guard:
            self._closed=True;self._reviews.clear()
            if self._timer:self._timer.cancel();self._timer=None
            if self._enrollment is not None:self._enrollment.close()
            signer=self._signer
            busy=self._busy
        if signer is not None:
            try:signer.close(timeout=.1)
            except Exception:pass
        if not busy:
            with self._guard:self._archive=None;self._history.clear()

    def cleanup(self,*,timeout=5):
        self.close()
        return self._signer.cleanup(timeout=timeout) if self._signer is not None else True
