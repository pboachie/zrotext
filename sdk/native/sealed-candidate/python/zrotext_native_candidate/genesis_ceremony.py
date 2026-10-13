"""One-shot existing-root genesis review/sign/install/readback bridge."""
from concurrent.futures import Future,TimeoutError
import inspect
import threading
import time
from types import MappingProxyType
from . import sealed_candidate as s
from . import conversation_proposals as p
from .cng_custody import _qualified
from .cng_signing import HardwareSigner
from .compose03 import SoftwareSigner

_DOMAIN='ZTSE/manifest/v2'
_ADMISSION=threading.BoundedSemaphore(4)

def _freeze(value):return MappingProxyType({k:_freeze(v) for k,v in value.items()}) if type(value) is dict else value

def _genesis_digest(raw,root):
    raw=s.capture(raw,747);issued,until=s.num(raw,37),s.num(raw,45)
    s.require(raw[:5]==b'ZTMA\x02' and any(raw[5:21]) and s.num(raw,21)==1 and s.num(raw,29)==1 and raw[53:85]==bytes(32) and raw[85:150]==root and raw[150]==4,'genesis signing header')
    s.require(0<issued<until and until-issued<=86400000,'genesis signing lifetime')
    points=[];device=line=None
    for n,(role,scope) in enumerate(((1,4),(2,12),(4,2),(6,0))):
        record=raw[151+n*149:151+(n+1)*149];point=record[33:98];s.point(point)
        s.require(record[0]==role and record[1:33]==s.key_id(role,point) and point not in points and s.num(record,130,2)==scope and s.num(record,132)==issued and s.num(record,140)==until and record[148]==1,'genesis signing record')
        points.append(point)
        if role==1:device,line=record[98:114],record[114:130];s.require(any(device) and any(line),'genesis signing subject')
        elif role==4:s.require(record[98:114]==device and record[114:130]==line,'genesis phone subject')
        else:s.require(record[98:130]==bytes(32),'genesis unbound role')
        if role==6:s.require(point==root,'genesis root role')
    return raw,s.sha(s.label(_DOMAIN)+len(raw).to_bytes(4,'big')+raw)

class GenesisRootSigner(HardwareSigner):
    """Dedicated locally qualified protected genesis authority, not generic signing."""
    _prefix='zrotext-candidate-genesis-root-p256-'
    def sign(self,*args,**kwargs):raise s.SealedError('generic genesis signing unavailable')
    def _sign_genesis(self,unsigned):
        _custody(self,True);raw,digest=_genesis_digest(unsigned,self.public_point());signature=self._sign_digest(digest)
        s.verify_signature(self.public_point(),signature,_DOMAIN,raw);return signature

class SoftwareGenesisRootSigner(SoftwareSigner):
    """Explicit software fixture capability; never nonexportable custody."""
    def sign(self,*args,**kwargs):raise s.SealedError('generic genesis signing unavailable')
    def _sign_genesis(self,unsigned):
        raw,_=_genesis_digest(unsigned,self.public_point());signature=super().sign(_DOMAIN,raw)
        s.verify_signature(self.public_point(),signature,_DOMAIN,raw);return signature

def _custody(signer,protected,root=None):
    s.require(type(protected) is bool,'genesis protection')
    if protected or type(signer) is not SoftwareGenesisRootSigner:
        s.require(type(signer) is GenesisRootSigner and signer in _qualified and not signer._closed,'qualified genesis root')
    public=s.capture(signer.public_point(),65);s.point(public);s.require(root is None or public==root,'genesis root binding');return public

def _sync(callback,*args):
    value=callback(*args)
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):value.close()
        raise s.SealedError('synchronous genesis callback required')
    return value

class GenesisCeremonyError(Exception):
    def __init__(self,code,state='refused'):super().__init__('Genesis ceremony '+code);self.code=code;self.state=state

class ConversationGenesis:
    """Caller install adapter must own atomic v0 and live owner/device/key/line CAS.

    Normal synchronous decision callback completion consumes explicit approval;
    throw to decline. A successful install callback alone is not installed state.
    """
    def __init__(self,input,*,signer,read_current,consume_owner_decision,install,require_protected=True,timeout_ms=10000):
        try:
            value=p._record(input,('selection','rootPin','comparedRootFingerprint','origin','phoneReaderPoint','archiveReaderPoint','phoneSignerPoint','nowMs','expiresMs'))
            value['selection']=p._selection(value['selection'],'genesis')
            for key,size in (('rootPin',94),('comparedRootFingerprint',32),('phoneReaderPoint',65),('archiveReaderPoint',65),('phoneSignerPoint',65)):value[key]=s.capture(value[key],size)
            s.require(type(timeout_ms) is int and 1<=timeout_ms<=10000 and type(require_protected) is bool and all(callable(fn) for fn in (read_current,consume_owner_decision,install)),'genesis configuration')
            self._input=value;self._signer=signer;self._read=read_current;self._decision=consume_owner_decision;self._install=install;self._protected=require_protected;self._timeout=timeout_ms/1000
        except Exception:raise GenesisCeremonyError('invalid_request') from None
        self._closed=threading.Event();self._guard=threading.RLock();self._busy=threading.Lock();self._used=False;self._install_started=False;self._completed=False;self._failure=None;self._last=0;self._expiry_deadline=float('inf')
    def __repr__(self):return 'ConversationGenesis(<root, review and installation redacted>)'
    def close(self):
        with self._guard:self._closed.set()
    def _state(self):return 'unknown' if self._install_started and not self._completed else 'refused'
    def _live(self,deadline):
        if self._closed.is_set():raise GenesisCeremonyError(self._failure or 'closed',self._state())
        if time.monotonic()>=min(deadline,self._expiry_deadline):self._failure='deadline';self.close();raise GenesisCeremonyError('deadline',self._state())
    def _current(self,version,deadline):
        self._live(deadline);sample_started=time.monotonic();value=p._record(_sync(self._read),('selection','rootPin','nowMs','version','manifest','ownerSessionLive','authorityLive','deviceKeyLive','lineBindingLive'))
        value['selection']=p._selection(value['selection'],'genesis');value['rootPin']=s.capture(value['rootPin'],94)
        value['manifest']=None if value['manifest'] is None else s.capture(value['manifest'],364,9751)
        self._live(deadline);now=p._number(value['nowMs']);i=self._input
        s.require(all(value[k] is True for k in ('ownerSessionLive','authorityLive','deviceKeyLive','lineBindingLive')) and type(value['version']) is int and value['version']==version and now>=i['nowMs'] and now>=self._last and now<i['expiresMs'] and value['rootPin']==i['rootPin'] and value['selection']==i['selection'] and (version!=0 or value['manifest'] is None),'genesis authority changed')
        self._expiry_deadline=min(self._expiry_deadline,sample_started+(i['expiresMs']-now)/1000);self._last=now;self._live(deadline);return value
    def provision(self):
        if not self._busy.acquire(blocking=False):raise GenesisCeremonyError('busy',self._state())
        if not _ADMISSION.acquire(blocking=False):self._busy.release();raise GenesisCeremonyError('busy',self._state())
        with self._guard:
            if self._used:_ADMISSION.release();self._busy.release();raise GenesisCeremonyError('consumed',self._state())
            self._used=True
        deadline=time.monotonic()+self._timeout;future=Future();settled=False;returned=False
        def worker():
            nonlocal settled
            try:
                self._live(deadline);i=self._input;pin=s.enroll_root02(i['rootPin'],i['comparedRootFingerprint']);root=s._bound(s._trusts,pin).root;_custody(self._signer,self._protected,root)
                self._current(0,deadline)
                review=p.encode_conversation_genesis_proposal02(i['selection'],i['rootPin'],i['comparedRootFingerprint'],i['origin'],i['phoneReaderPoint'],i['archiveReaderPoint'],i['phoneSignerPoint'],i['nowMs'],i['expiresMs'])
                _sync(self._decision,review);self._current(0,deadline);_custody(self._signer,self._protected,root);self._live(deadline)
                signature=self._signer._sign_genesis(review['unsigned']);_custody(self._signer,self._protected,root)
                before=self._current(0,deadline);raw=review['unsigned']+s.capture(signature,64);verified=s.verify_manifest02(raw,pin,before['nowMs'])
                installing=self._current(0,deadline);_custody(self._signer,self._protected,root)
                with self._guard:self._live(deadline);self._install_started=True
                _sync(self._install,raw,_freeze(installing));after=self._current(1,deadline)
                s.require(after['manifest'] is not None,'genesis installed missing');accepted=s.verify_manifest02(after['manifest'],pin,after['nowMs'])
                s.require(s._bound(s._manifests,accepted).trust.digest==s._bound(s._manifests,verified).trust.digest,'genesis installed fork')
                _custody(self._signer,self._protected,root);self._live(deadline);future.set_result(accepted)
            except Exception as error:
                self._failure=error.code if isinstance(error,GenesisCeremonyError) else 'refused';self.close();future.set_exception(GenesisCeremonyError(self._failure,self._state()))
            finally:
                _ADMISSION.release()
                with self._guard:
                    settled=True
                    if returned:self._busy.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except Exception:_ADMISSION.release();self._busy.release();self.close();raise GenesisCeremonyError('refused',self._state()) from None
        try:
            while True:
                self._live(deadline)
                try:result=future.result(timeout=.02)
                except TimeoutError:continue
                with self._guard:self._live(deadline);self._completed=True;return result
        finally:
            with self._guard:
                returned=True
                if settled:self._busy.release()
