"""Historical commitments over opaque ciphertext; no current permission."""
from concurrent.futures import Future, TimeoutError
from dataclasses import dataclass
from functools import wraps
import threading
import time

from . import contact_integrity as c
from . import sealed_candidate as s
from .cng_custody import _qualified
from .cng_signing import HardwareSigner
from .compose03 import SoftwareSigner

FIELD_DOMAIN='ZT/contact-field/commitment/v1'
MUTATION_DOMAIN='ZT/contact-field/mutation/v1'
_admission=threading.BoundedSemaphore(4)


class ContactProducerError(ValueError):
    def __init__(self):super().__init__('Contact producer refused')


class ContactCancellation:
    """One-way application cancellation; no reset or caller-supplied callbacks."""
    def __init__(self):self._event=threading.Event()
    def cancel(self):self._event.set()
    def is_cancelled(self):return self._event.is_set()


def _closed(function):
    @wraps(function)
    def run(*args,**kwargs):
        try:return function(*args,**kwargs)
        except Exception:raise ContactProducerError() from None
    return run


def _transcript(domain,unsigned):
    s.require(type(domain) is str and domain in (FIELD_DOMAIN,MUTATION_DOMAIN),'contact signing domain')
    unsigned=s.capture(unsigned,304,2379)
    # Strict unsigned framing is checked using a syntactically valid placeholder.
    # No verification token is created here; producer authority is checked below.
    placeholder=(1).to_bytes(32,'big')*2
    if domain==FIELD_DOMAIN:c.parse_contact_field01(unsigned+placeholder)
    else:c.parse_contact_mutation01(unsigned+placeholder)
    return unsigned,s.sha(s.label(domain)+len(unsigned).to_bytes(4,'big')+unsigned)


class OwnerRootSigner(HardwareSigner):
    """Separate locally qualified TPM root capability for contact domains only."""
    _prefix='zrotext-candidate-contact-root-p256-'

    def sign(self,domain,unsigned):
        _hardware(self);unsigned,digest=_transcript(domain,unsigned)
        signature=self._sign_digest(digest)
        s.verify_signature(self.public_point(),signature,domain,unsigned)
        return signature


class SoftwareOwnerRootSigner(SoftwareSigner):
    """Explicit experimental fixture capability, never protected custody."""
    def sign(self,domain,unsigned):
        unsigned,_=_transcript(domain,unsigned)
        signature=super().sign(domain,unsigned)
        s.verify_signature(self.public_point(),signature,domain,unsigned)
        return signature


def _hardware(signer):
    s.require(type(signer) is OwnerRootSigner and signer in _qualified and not signer._closed,'qualified contact root signer')


@dataclass(frozen=True)
class HistoricalProduction:
    signed_bytes: bytes
    verified: object
    kind: str='produced_historical_integrity'


def _scope(statement,expected,signer,require_hardware,legacy=False):
    st=s._bound(c._statements,statement)
    names=('accountId','origin','rootFingerprint','contactId','routingDigest')+(('legacyGeneration',) if legacy else ())
    expected=c._object(expected,names)
    for k,width in (('accountId',16),('rootFingerprint',32),('contactId',16),('routingDigest',32)):expected[k]=c._bytes(expected[k],width)
    c._origin(expected['origin'])
    if legacy:c._integer(expected['legacyGeneration'],True)
    s.require(type(require_hardware) is bool,'contact custody policy')
    if require_hardware or type(signer) is not SoftwareOwnerRootSigner:_hardware(signer)
    s.require(st['trustGeneration']==1 and all(st[k]==expected[k] for k in ('accountId','origin','rootFingerprint')),'contact expected scope')
    return st,expected


def _sign(signer,statement,domain,held,live):
    live();public=s.capture(signer.public_point(),65);live();s.point(public)
    s.require(public==statement['rootPoint'],'contact expected root signer')
    signature=signer.sign(domain,held);live()
    return bytes(held)+s.capture(signature,64)


def _operation(cancel,unsigned,run):
    s.require(cancel is None or type(cancel) is ContactCancellation,'native cancellation capability')
    s.require(cancel is None or not cancel.is_cancelled(),'contact cancelled')
    s.require(_admission.acquire(blocking=False),'contact producer capacity')
    deadline=time.monotonic()+10;stopped=threading.Event();future=Future()
    held=bytearray(unsigned)
    def live():
        s.require(not stopped.is_set() and (cancel is None or not cancel.is_cancelled()) and time.monotonic()<deadline,'contact producer lifecycle')
    def worker():
        try:
            live();result=run(held,live);live();future.set_result(result)
        except BaseException as error:future.set_exception(error)
        finally:
            held[:]=bytes(len(held));_admission.release()
    try:threading.Thread(target=worker,daemon=True).start()
    except BaseException:
        held[:]=bytes(len(held));_admission.release();raise
    while True:
        try:
            live();result=future.result(timeout=min(0.02,max(0.001,deadline-time.monotonic())));live();return result
        except TimeoutError:continue
        except BaseException:
            stopped.set();raise


@_closed
def produce_contact_field01(*,signer,statement,expected,field,cancel=None,require_hardware=True):
    st,e=_scope(statement,expected,signer,require_hardware)
    f=c._object(field,('kind','sealRevision','requestId','encapsulation','ciphertext'))
    v=dict(f,accountId=e['accountId'],contactId=e['contactId'],trustGeneration=1,manifestVersion=st['manifestVersion'],
        readerGeneration=st['readerGeneration'],readerId=st['readerId'],manifestDigest=st['manifestDigest'],statementDigest=st['digest'],
        routingDigest=e['routingDigest'],rootWriterId=st['rootWriterId'])
    unsigned=c.encode_contact_field01(v);s.point(unsigned[246:311])
    def run(held,live):
        raw=_sign(signer,st,FIELD_DOMAIN,held,live)
        verified=c.verify_contact_field01(raw,statement,contact=e['contactId'],routing_digest=e['routingDigest']);live()
        return HistoricalProduction(raw,verified)
    return _operation(cancel,unsigned,run)


@_closed
def produce_contact_transition01(*,signer,statement,expected,mutation,previous,previous_statement,replacement_fields,cancel=None,require_hardware=True):
    st,e=_scope(statement,expected,signer,require_hardware,True)
    n=c._mutation(mutation);unsigned=c.encode_contact_mutation01(n)
    c._scope(n,st,e['contactId'],e['routingDigest']);s.require(n['legacyGeneration']==e['legacyGeneration'],'contact legacy expectation')
    if previous is None:s.require(previous_statement is None,'contact previous statement')
    else:
        ps=s._bound(c._statements,previous_statement)
        s.require(s._bound(c._transitions,previous)[1]==ps and all(ps[k]==e[k] for k in ('accountId','origin','rootFingerprint')),'contact previous statement binding')
    s.require(type(replacement_fields) in (list,tuple) and len(replacement_fields)<=2,'contact replacement list')
    replacements=tuple(replacement_fields)
    c._transition_values(previous,n,st,replacements)  # Validate before any signing effect.
    def run(held,live):
        raw=_sign(signer,st,MUTATION_DOMAIN,held,live)
        verified=c.verify_contact_mutation01(raw,statement,contact=e['contactId'],routing_digest=e['routingDigest'],legacy_generation=e['legacyGeneration'])
        result=c.verify_contact_transition01(previous,verified,replacements);live()
        return HistoricalProduction(raw,result)
    return _operation(cancel,unsigned,run)
