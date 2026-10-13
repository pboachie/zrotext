"""One-shot role-5 enrollment; accepted successor never unlocks a signer."""
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

def _freeze(v):return MappingProxyType({k:_freeze(x) for k,x in v.items()}) if type(v) is dict else v
def _binding(v):return p._selection(v,'refresh')
def _manifest(handle,now):
    value=s._bound(s._manifests,handle);s.require(value.profile==2,'enrollment profile')
    return s._parse_manifest(value.raw,value.before,p._number(now))
def _readers(m,b,now):
    for role,name in ((1,'phoneReader'),(2,'archiveReader')):
        key=next((k for k in m.keys if k.role==role and k.id==b[name]),None)
        s.require(key is not None and key.active(now) and key.scope&4 and (role==2 or (key.device==b['device'] and key.line==b['line'])),'enrollment reader authority')
def _review(predecessor,binding,public,now):
    b=_binding(binding);point=s.capture(public,65);s.point(point);m=_manifest(predecessor,now);identity=m.trust;ident=s.key_id(5,point)
    s.require(identity.account==b['account'] and identity.version<s.MAX,'enrollment identity');_readers(m,b,now)
    until=min(m.expires,now+1800000)
    s.require(now<until and len(m.keys)<64 and all(k.id!=ident and k.point!=point for k in m.keys),'enrollment key unavailable')
    records=[m.raw[151+n*149:151+(n+1)*149] for n in range(len(m.keys))]
    records.append(b'\x05'+ident+point+bytes(16)+b['line']+b'\0\x01'+now.to_bytes(8,'big')+until.to_bytes(8,'big')+b'\x01');records.sort(key=lambda record:record[:33])
    header=bytearray(m.raw[:151]);header[29:37]=(identity.version+1).to_bytes(8,'big');header[37:45]=now.to_bytes(8,'big');header[53:85]=identity.digest;header[150]=len(records)
    return dict(binding=b,publicPoint=point,keyId=ident,predecessorDigest=identity.digest,successorVersion=identity.version+1,untilMs=until,unsigned=bytes(header)+b''.join(records)),m
def _transcript(review,predecessor,now):
    r=dict(review);unsigned=s.capture(r['unsigned'],151,9687)
    expected,m=_review(predecessor,dict(r['binding']),r['publicPoint'],s.num(unsigned,37))
    s.require(r==expected and s.num(unsigned,37)<=now<r['untilMs'],'exact enrollment transcript');_readers(_manifest(predecessor,now),r['binding'],now)
    return unsigned,m.trust.root
def _custody(signer,protected,root=None):
    s.require(type(protected) is bool,'enrollment protection')
    if protected or type(signer) is not SoftwareEnrollmentRootSigner:s.require(type(signer) is EnrollmentRootSigner and signer in _qualified and not signer._closed,'qualified enrollment root')
    public=s.capture(signer.public_point(),65);s.point(public);s.require(root is None or root==public,'enrollment root binding');return public

class EnrollmentRootSigner(HardwareSigner):
    """Dedicated existing-root capability for an exact reviewed role-5 addition."""
    _prefix='zrotext-candidate-enrollment-root-p256-'
    def sign(self,*args,**kwargs):raise s.SealedError('generic enrollment signing unavailable')
    def _sign_enrollment(self,review,predecessor,now):
        unsigned,root=_transcript(review,predecessor,now);_custody(self,True,root)
        signature=self._sign_digest(s.sha(s.label(_DOMAIN)+len(unsigned).to_bytes(4,'big')+unsigned));s.verify_signature(root,signature,_DOMAIN,unsigned);return signature

class SoftwareEnrollmentRootSigner(SoftwareSigner):
    """Explicit software experiment, never nonexportable custody."""
    def sign(self,*args,**kwargs):raise s.SealedError('generic enrollment signing unavailable')
    def _sign_enrollment(self,review,predecessor,now):
        unsigned,root=_transcript(review,predecessor,now);_custody(self,False,root)
        signature=super().sign(_DOMAIN,unsigned);s.verify_signature(root,signature,_DOMAIN,unsigned);return signature

def _sync(fn,*args):
    result=fn(*args)
    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):result.close()
        raise s.SealedError('synchronous enrollment callback required')
    return result

def _canonical(signature):
    raw=s.capture(signature,64);r=int.from_bytes(raw[:32],'big');value=int.from_bytes(raw[32:],'big')
    s.require(0<r<s.ORDER and 0<value<s.ORDER,'enrollment signature scalars')
    return raw[:32]+min(value,s.ORDER-value).to_bytes(32,'big')

class EnrollmentError(Exception):
    def __init__(self,code,state='refused'):super().__init__('Enrollment '+code);self.code=code;self.state=state

def enrollment_installation(accepted,high_water):
    """Immutable signed evidence from a genuine matching profile02 handle pair.

    This exports already verified evidence; it proves no review, consent or CAS.
    """
    try:
        manifest=s._bound(s._manifests,accepted);trust=s._bound(s._trusts,high_water)
        s.require(manifest.profile==2 and manifest.trust==trust,'enrollment installation pair')
        return _freeze(dict(manifest=manifest.raw,identity=s.manifest_identity(accepted)))
    except Exception:raise EnrollmentError('invalid_installation') from None

class ConversationEnrollment:
    """Host installation must CAS predecessor/high-water and live session/consent.

    Result is a verified successor only. No readback, unlocking or send authority
    is implied by the maintained installation callback contract.
    """
    def __init__(self,binding,public_point,*,signer,read_current,consume_owner_decision,install_verified,require_protected=True,timeout_ms=10000):
        try:
            self._binding=_binding(binding);self._point=s.capture(public_point,65);s.point(self._point)
            s.require(type(require_protected) is bool and type(timeout_ms) is int and 1<=timeout_ms<=10000 and all(callable(fn) for fn in (read_current,consume_owner_decision,install_verified)),'enrollment configuration')
        except Exception:raise EnrollmentError('invalid_request') from None
        self._signer=signer;self._read=read_current;self._decision=consume_owner_decision;self._install=install_verified;self._protected=require_protected;self._timeout=timeout_ms/1000
        self._closed=threading.Event();self._guard=threading.RLock();self._busy=threading.Lock();self._used=False;self._install_started=False;self._complete=False;self._last=0;self._expiry=float('inf')
    def __repr__(self):return 'ConversationEnrollment(<authority and review redacted>)'
    def close(self):
        with self._guard:self._closed.set()
    def _state(self):return 'unknown' if self._install_started and not self._complete else 'refused'
    def _live(self,deadline):
        if time.monotonic()>=min(deadline,self._expiry):self.close();raise EnrollmentError('deadline',self._state())
        if self._closed.is_set():raise EnrollmentError('closed',self._state())
    def _current(self,deadline,base=None,until=None):
        self._live(deadline);started=time.monotonic();v=p._record(_sync(self._read),('binding','manifest','nowMs','ownerSessionLive','consentLive'));v['binding']=_binding(v['binding']);now=p._number(v['nowMs'])
        s.require(v['ownerSessionLive'] is True and v['consentLive'] is True and v['binding']==self._binding and now>=self._last,'enrollment current authority')
        m=_manifest(v['manifest'],now);_readers(m,self._binding,now)
        if base is not None:s.require((m.trust.account,m.trust.generation,m.trust.root,m.trust.version,m.trust.digest)==(base.trust.account,base.trust.generation,base.trust.root,base.trust.version,base.trust.digest),'enrollment predecessor changed')
        limit=until if until is not None else min(m.expires,now+1800000)
        s.require(now<limit,'enrollment expired');self._expiry=min(self._expiry,started+(limit-now)/1000);self._last=now;self._live(deadline);return v,m
    def enroll(self):
        if not self._busy.acquire(blocking=False):raise EnrollmentError('busy',self._state())
        if not _ADMISSION.acquire(blocking=False):self._busy.release();raise EnrollmentError('busy',self._state())
        with self._guard:
            if self._used:_ADMISSION.release();self._busy.release();raise EnrollmentError('consumed',self._state())
            self._used=True
        deadline=time.monotonic()+self._timeout;future=Future();settled=False;returned=False
        def worker():
            nonlocal settled
            try:
                self._live(deadline);_custody(self._signer,self._protected)
                first,base=self._current(deadline);review,base=_review(first['manifest'],self._binding,self._point,first['nowMs']);root=base.trust.root;_custody(self._signer,self._protected,root)
                _sync(self._decision,_freeze(review));current,_=self._current(deadline,base,review['untilMs']);_custody(self._signer,self._protected,root);self._live(deadline)
                signature=_canonical(self._signer._sign_enrollment(_freeze(review),first['manifest'],current['nowMs']));_custody(self._signer,self._protected,root)
                final,_=self._current(deadline,base,review['untilMs']);trust=s._accept(s._trusts,base.trust);accepted=s.verify_manifest02(review['unsigned']+s.capture(signature,64),trust,final['nowMs'])
                latest,_=self._current(deadline,base,review['untilMs']);m=_manifest(accepted,latest['nowMs']);_readers(m,self._binding,latest['nowMs'])
                key=next((k for k in m.keys if k.role==5 and k.id==review['keyId']),None);s.require(key is not None and key.active(latest['nowMs']) and key.scope==1 and key.line==self._binding['line'],'accepted enrollment signer')
                proposed=s.advance_trust02(trust,accepted);_custody(self._signer,self._protected,root)
                with self._guard:self._live(deadline);self._install_started=True
                _sync(self._install,review['predecessorDigest'],accepted,proposed,_freeze(dict(self._binding)))
                _custody(self._signer,self._protected,root);self._live(deadline);future.set_result(accepted)
            except Exception as error:
                self.close();future.set_exception(EnrollmentError(error.code if isinstance(error,EnrollmentError) else 'refused',self._state()))
            finally:
                _ADMISSION.release()
                with self._guard:
                    settled=True
                    if returned:self._busy.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except Exception:_ADMISSION.release();self._busy.release();self.close();raise EnrollmentError('refused',self._state()) from None
        try:
            while True:
                self._live(deadline)
                try:result=future.result(timeout=.02)
                except TimeoutError:continue
                with self._guard:self._live(deadline);self._complete=True;return result
        finally:
            with self._guard:
                returned=True
                if settled:self._busy.release()
