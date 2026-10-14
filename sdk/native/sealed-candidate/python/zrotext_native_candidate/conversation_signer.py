"""Session-owned role-5 review/confirmation; no enrollment, HTTP or generic signing.

Trusted host callbacks supply actual consent and authenticated monotonic UTC.
Windows keys are fresh named PCP keys with mandatory durable cleanup receipts.
Python/provider copies cannot be guaranteed erased. Software mode is explicit.
"""
import inspect
import os
import threading
import time
from types import MappingProxyType

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import sealed_candidate as s
from . import compose02
from .cng_custody import _qualified
from .cng_signing import HardwareSigner
from .conversation_proposals import _selection, _record, _number

_ADMISSION = threading.BoundedSemaphore(4)
_CONFIRM = 'zrotext/conversation/confirm-send/v1'


class ConversationSignerError(Exception):
    def __init__(self, code='refused'):
        self.code = code
        super().__init__('Conversation signer: ' + code)


class ConversationRole5Signer(HardwareSigner):
    """Dedicated custody namespace; public arbitrary transcript signing refused."""
    _prefix = 'zrotext-conversation-sign-p256-'

    def sign(self, *args, **kwargs):
        raise ConversationSignerError('generic_signing_unavailable')


def _body(text):
    s.require(type(text) is str and 0 < len(text) <= 32768, 'body')
    # Match JavaScript well-formed UTF-16 including explicit surrogate pairs.
    value = text.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'strict').encode('utf-8')
    s.require(0 < len(value) <= 32768 and b'\0' not in value and not value.startswith(b'\xef\xbb\xbf'), 'body')
    return value


def _callback(fn, *args):
    value = fn(*args)
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value): value.close()
        raise ConversationSignerError('synchronous_callback_required')
    return value


def _u64(n): return n.to_bytes(8, 'big')


class ConversationSignerSetup02:
    """One-shot setup, followed by serialized review and confirmation operations.

    Call setup before reading public_point/key_id. Normal setup/confirmation
    callback completion consumes approval; its return value is not a decision.
    close suppresses output immediately; unresolved work retains admission and
    performs exact owned-key cleanup on settlement. cleanup retries a failed
    deletion/receipt. A successful deletion receipt is the cleanup completion.
    """
    def __init__(self, binding, consume_setup_decision, read_current, *,
                 record_pending_alias, record_deleted_alias, require_hardware=True):
        try:
            self._binding = _selection(binding, 'refresh')
            s.require(all(callable(v) for v in (consume_setup_decision, read_current, record_pending_alias, record_deleted_alias)), 'callbacks')
            s.require(type(require_hardware) is bool, 'custody policy')
        except Exception: raise ConversationSignerError() from None
        self._decision, self._read = consume_setup_decision, read_current
        self._pending_receipt, self._deleted_receipt = record_pending_alias, record_deleted_alias
        self._hardware = require_hardware
        self._guard = threading.RLock()
        self._closed = self._busy = self._started = self._ready = False
        self._key = self._public = self._id = self._alias = None
        self._deleted = False
        self._cleanup_error = None
        self._last = None
        self._used = set()

    @property
    def public_point(self):
        with self._guard:
            if not self._ready or self._closed: raise ConversationSignerError('unavailable')
            return self._public

    @property
    def key_id(self):
        with self._guard:
            if not self._ready or self._closed: raise ConversationSignerError('unavailable')
            return self._id

    @property
    def cleanup_pending(self):
        with self._guard: return self._key is not None or self._alias is not None

    @property
    def cleanup_state(self):
        """Creation uncertainty requires exact-alias operator recovery, not retry.

        A create failure may have performed internal deletion before returning
        no handle. This client cannot certify that outcome. Keep the durable
        pending receipt; cleanup never guesses or enumerates/deletes by prefix.
        """
        with self._guard:
            if self._key is not None: return 'key_cleanup_pending'
            if self._alias is not None:
                return 'deletion_receipt_pending' if self._deleted else 'creation_outcome_unknown'
            return 'complete'

    def _check(self, op):
        if self._closed or op['cancel'].is_set() or time.monotonic() >= op['deadline']:
            raise ConversationSignerError('closed_or_expired')

    def _custody(self):
        key = self._key
        if self._hardware:
            s.require(type(key) is ConversationRole5Signer and key in _qualified and not key._closed, 'protected role5 custody')
            s.require(key.public_point() == self._public, 'protected point binding')
        else:
            s.require(isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1), 'software role5 custody')
        return key

    def _cleanup(self):
        if self._key is not None:
            if self._hardware and not self._deleted:
                self._key.delete()
                self._deleted = True
            self._key = None
        if self._alias is not None and self._deleted:
            _callback(self._deleted_receipt, self._alias)
            self._alias = None
        self._cleanup_error = None

    def _run(self, fn, timeout, cancel, *, cleanup=False):
        s.require(type(timeout) in (int, float) and 0 < timeout <= 60, 'bounded timeout')
        s.require(cancel is None or type(cancel) is threading.Event, 'cancellation event')
        op = dict(deadline=time.monotonic()+timeout, cancel=cancel or threading.Event())
        with self._guard:
            if self._busy or (self._closed and not cleanup): raise ConversationSignerError('unavailable')
            if not _ADMISSION.acquire(False): raise ConversationSignerError('capacity')
            self._busy = True
        done, foreground = threading.Event(), threading.Event()
        result = {}
        def worker():
            cleanup_attempted = False
            try:
                if not cleanup: self._check(op)
                result['value'] = fn(op)
                if not cleanup: self._check(op)
            except BaseException:
                self._closed = True
                result['error'] = ConversationSignerError()
            finally:
                if self._closed:
                    cleanup_attempted = True
                    try: self._cleanup()
                    except BaseException:
                        self._cleanup_error = True
                        result['error'] = ConversationSignerError('cleanup_pending')
                done.set()
                # No new operation or worker slot until both worker and caller settle.
                foreground.wait()
                if self._closed and not cleanup_attempted:
                    try: self._cleanup()
                    except BaseException: self._cleanup_error = True
                with self._guard: self._busy = False
                _ADMISSION.release()
        try:
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
        except BaseException:
            with self._guard: self._busy = False
            _ADMISSION.release()
            raise
        try:
            while not done.wait(min(.01, max(0, op['deadline']-time.monotonic()))):
                if op['cancel'].is_set() or time.monotonic() >= op['deadline']:
                    self._closed = True
                    raise ConversationSignerError('cancelled_or_timeout')
            if 'error' in result: raise result['error']
            if not cleanup: self._check(op)
            return result.get('value')
        except BaseException:
            self._closed = True
            raise
        finally:
            foreground.set()
            # Successful settled work needs only a scheduling handoff. A blocked
            # cleanup never extends this bounded join or releases its admission.
            thread.join(.02)

    def close(self, *, timeout=5):
        with self._guard:
            self._closed = True
            if self._busy: return False
        self._run(lambda op: None, timeout, None, cleanup=True)
        return not self.cleanup_pending

    def cleanup(self, *, timeout=5): return self.close(timeout=timeout)

    def _current(self, op):
        self._check(op)
        started = time.monotonic()
        v = _record(_callback(self._read), ('binding','manifest','nowMs','ownerSessionLive','consentLive'))
        binding = _selection(v['binding'], 'refresh')
        now = _number(v['nowMs'])
        s.require(v['ownerSessionLive'] is True and v['consentLive'] is True and binding == self._binding, 'current authority')
        prior = s._bound(s._manifests, v['manifest'])
        s.require(prior.profile == 2, 'manifest profile')
        m = s._parse_manifest(prior.raw, prior.trust, now)
        t = m.trust
        s.require(t.account == binding['account'], 'current account')
        if self._last is not None:
            last, old = self._last
            s.require(now >= last and (t.generation,t.root)==(old.generation,old.root) and t.version >= old.version and (t.version != old.version or t.digest == old.digest), 'current regression')
        self._last = now, t
        op['deadline'] = min(op['deadline'], started+(m.expires-now)/1000)
        self._check(op)
        return m, now, started

    def setup(self, *, timeout=10, cancel=None):
        with self._guard:
            if self._started: raise ConversationSignerError('setup_consumed')
            self._started = True
        def run(op):
            _callback(self._decision, MappingProxyType(dict(self._binding)))
            self._current(op)
            if self._hardware:
                def receipt(alias):
                    _callback(self._pending_receipt, alias)
                    self._alias = alias
                    self._check(op)
                self._key = ConversationRole5Signer.create(receipt)
                self._public = self._key.public_point()
            else:
                from cryptography.hazmat.primitives import serialization
                self._key = ec.generate_private_key(ec.SECP256R1())
                self._public = self._key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            self._id = s.key_id(5, self._public)
            self._current(op)
            self._custody()
            self._ready = True
            return self
        return self._run(run, timeout, cancel)

    def _authorize(self, current, op, expiry=None):
        m, now, started = current
        b = self._binding
        signer = next((k for k in m.keys if k.role == 5 and k.id == self._id), None)
        s.require(signer is not None and signer.active(now) and signer.scope == 1 and signer.line == b['line'] and signer.point == self._public, 'role5 authority')
        deadline, recipients = min(m.expires,signer.end), []
        for role, name in ((1,'phoneReader'),(2,'archiveReader')):
            key = next((k for k in m.keys if k.role == role and k.id == b[name]), None)
            s.require(key is not None and key.active(now) and key.scope & 4 and (role != 1 or (key.device,key.line)==(b['device'],b['line'])), 'reader authority')
            recipients.append((role,key.id,key.point)); deadline = min(deadline,key.end)
        if expiry is not None:
            s.require(now < expiry and expiry-now <= 30000, 'confirmation expiry')
            deadline = min(deadline,expiry)
        op['deadline'] = min(op['deadline'], started+(deadline-now)/1000)
        self._custody(); self._check(op)
        return recipients

    def _signature(self, domain, raw, op):
        self._check(op)
        key = self._custody()
        digest = s.sha(s.label(domain)+len(raw).to_bytes(4,'big')+raw)
        if self._hardware: signature = key._sign_digest(digest)
        else:
            r, v = utils.decode_dss_signature(key.sign(digest,ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
            signature = r.to_bytes(32,'big')+min(v,s.ORDER-v).to_bytes(32,'big')
        s.verify_signature(self._public,signature,domain,raw)
        self._custody(); self._check(op)
        return signature

    def prepare_review(self, text, *, timeout=10, cancel=None):
        def run(op):
            s.require(self._ready, 'setup required')
            body = _body(text)
            current = self._current(op); m, now, _ = current
            expiry = now+30000; s.require(expiry <= s.MAX, 'expiry overflow')
            recipients = self._authorize(current,op,expiry)
            message = bytearray(os.urandom(16)); message[6]=(message[6]&15)|64; message[8]=(message[8]&63)|128; message=bytes(message)
            b,t = self._binding,m.trust
            protected = b['account']+message+b['device']+b['line']+_u64(t.version)+t.digest+self._id+_u64(now)+_u64(expiry)+bytes([1,len(b['peer'])])+b['peer'].encode('ascii')
            prefix = b'ZTSE\x02\x01\0\0'+len(protected).to_bytes(2,'big')+protected
            owner = self
            class ExactEnvelope:
                def sign(self, domain, unsigned):
                    s.require(domain == 'ZTSE/sign/v2' and unsigned.startswith(prefix), 'exact envelope transcript')
                    return owner._signature(domain,unsigned,op)
            envelope = compose02._compose((prefix,body,recipients,ExactEnvelope(),self._public)).envelope
            def fresh():
                latest = self._current(op)
                s.require((latest[0].trust.generation,latest[0].trust.version,latest[0].trust.digest)==(t.generation,t.version,t.digest), 'review authority changed')
                s.require(latest[1] < expiry, 'review expired')
            fresh()
            proof = b'ZTCS\x01'+b''.join(b[k] for k in ('account','device','line','interval','session'))+message+_u64(b['generation'])+_u64(t.generation)+_u64(t.version)+_u64(expiry)+bytes([len(b['peer'])])+b['peer'].encode('ascii')+self._id+b['archiveReader']+t.digest+s.sha(envelope)+s.sha(body)
            fresh(); self._custody(); self._check(op)
            return MappingProxyType(dict(proof=proof,envelope=envelope,body=text,messageId=message))
        return self._run(run,timeout,cancel)

    def sign_reviewed(self, proof, envelope, text, consume_confirmation, *, timeout=10, cancel=None):
        # Snapshot mutable caller bytes before asynchronous admission.
        proof,envelope = (bytes(v) if type(v) in (bytes,bytearray) and lo <= len(v) <= hi else None
                          for v,lo,hi in ((proof,297,310),(envelope,426,34213)))
        def run(op):
            s.require(self._ready and callable(consume_confirmation), 'confirmation setup')
            s.capture(proof,297,310); s.capture(envelope,426,34213)
            body,b = _body(text),self._binding
            s.require(proof[:5]==b'ZTCS\x01' and proof[5:85]==b''.join(b[k] for k in ('account','device','line','interval','session')) and any(proof[85:101]), 'confirmation scope')
            generation,trust,version,expiry=(s.num(proof,n) for n in (101,109,117,125)); length=proof[133]
            s.require(generation==b['generation'] and all(0<v<=s.MAX for v in (trust,version,expiry)) and 3<=length<=16 and len(proof)==294+length and proof[134:134+length]==b['peer'].encode('ascii'), 'confirmation selection')
            at=134+length
            s.require(proof[at:at+32]==self._id and proof[at+32:at+64]==b['archiveReader'] and proof[at+96:at+128]==s.sha(envelope) and proof[at+128:]==s.sha(body), 'confirmation content')
            digest=s.sha(proof)
            s.require(digest not in self._used and len(self._used)<1024, 'confirmation consumed')
            self._used.add(digest)
            _callback(consume_confirmation,digest,s.sha(body))
            def authorize():
                current=self._current(op); t=current[0].trust
                s.require((t.generation,t.version,t.digest)==(trust,version,proof[at+64:at+96]), 'confirmation manifest')
                self._authorize(current,op,expiry)
            authorize()
            signature=self._signature(_CONFIRM,proof,op)
            authorize()
            return signature
        return self._run(run,timeout,cancel)
