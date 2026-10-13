"""Candidate journal-to-HTTPS integration with a trusted application authority adapter.

The adapter must independently obtain current permission. Its return value is
not a server signature or a replacement for production grant verification.
"""
from dataclasses import dataclass
import http.client
import json
import queue
import re
import socket
import threading
import time
import urllib.parse
import uuid

from . import sealed_candidate as s
from .compose02 import SEALED_CONTENT_TYPE
from .compose03 import Composition
from .outbound02_journal import OutboundJournal02
from .outbound_journal import OutboundJournal

_WORKERS = threading.BoundedSemaphore(16)
_SUBMIT = {'invalid_request':400,'unauthorized':401,'forbidden':403,'idempotency_conflict':409,
           'unsupported_media_type':415,'rate_limited':429,'queue_full':429,'quota_exceeded':429,
           'billing_pending':503,'unavailable':503}
_LIFECYCLE = {'invalid_request':400,'unauthorized':401,'forbidden':403,'not_found':404,
              'cancellation_conflict':409,'rate_limited':429,'unavailable':503}
_STATES = {'accepted','queued','claimed','submitting','submitted','delivered','delivery_unknown',
           'unknown','failed','cancelled','expired'}


class SealedHttpError(Exception):
    """Redacted classification; unknown never establishes nonacceptance."""
    def __init__(self,code,*,state='refused',attempts=0,status=0,digest=None):
        super().__init__(code)
        self.code,self.state,self.attempts,self.status,self.digest=code,state,attempts,status,digest


@dataclass(frozen=True)
class PreparedSubmission:
    """Exact persisted ciphertext; retain the original journal and caller intent."""
    envelope: bytes
    unsigned_digest: bytes
    message_id: str
    device_id: str
    expires_ms: int
    revision: int | None


def _prepared(composition,revision=None):
    raw=s.capture(composition.envelope,557,34213)
    parsed=s.parse_envelope(raw)
    s.require(parsed.kind==1 and any(parsed.message),'outbound submission required')
    digest=s.capture(composition.unsigned_digest,32)
    s.require(s.sha(raw[:-64])==digest,'submission digest mismatch')
    return PreparedSubmission(raw,digest,str(uuid.UUID(bytes=raw[26:42])),
                              str(uuid.UUID(bytes=raw[42:58])),parsed.expires,revision)


def _integer(value,minimum=0):
    return type(value) is int and minimum<=value<=s.MAX


class SealedHttpClient:
    """No redirects/proxies/cookies. Application authority is mandatory per stage.

    authorizer(request) must return exactly the request mapping plus expires_ms.
    It receives action, message_id, device_id, unsigned_digest (hex), and now_ms.
    It must independently check permission rather than echo untrusted input.
    The supplied clock is trusted application time, never server body time.
    """
    def __init__(self,origin,credential,authorizer,*,timeout_ms=15000,max_attempts=1,
                 max_delay_ms=30000,clock=None):
        try:
            if (type(origin) is not str or type(credential) is not str or
                re.fullmatch(r'[\x21-\x7e]+',credential) is None or not callable(authorizer) or
                not _integer(timeout_ms,1) or timeout_ms>120000 or
                not _integer(max_attempts,1) or max_attempts>3 or
                not _integer(max_delay_ms) or max_delay_ms>30000):raise ValueError()
            url=urllib.parse.urlsplit(origin)
            if (url.scheme!='https' or not url.hostname or url.username is not None or url.password is not None or
                url.path not in ('','/') or url.query or url.fragment or '\\' in origin or
                any(ord(c)<33 for c in origin)):raise ValueError()
            self._host,self._port=url.hostname.encode('idna').decode(),url.port
            self.__credential=credential
            self._authorize=authorizer;self._timeout=timeout_ms/1000
            self._attempts=max_attempts;self._delay=max_delay_ms/1000
            self._clock=clock or (lambda:time.time_ns()//1000000)
            if not callable(self._clock):raise ValueError()
        except (ValueError,TypeError,UnicodeError):
            raise SealedHttpError('invalid_configuration') from None

    def __repr__(self):return 'SealedHttpClient(<credential redacted>)'

    def _authority(self,action,prepared,*,effect=False,attempts=0):
        try:
            now=self._clock()
            if not _integer(now,1):raise ValueError()
            request=dict(action=action,message_id=prepared.message_id,device_id=prepared.device_id,
                         unsigned_digest=prepared.unsigned_digest.hex(),now_ms=now)
            decision=self._authorize(dict(request))
            after=self._clock()
            if (type(decision) is not dict or set(decision)!=set(request)|{'expires_ms'} or
                any(decision[k]!=v for k,v in request.items()) or not _integer(decision['expires_ms'],1) or
                not _integer(after,1) or after<now or after>=decision['expires_ms'] or
                (action in ('compose','submit') and after>=prepared.expires_ms)):raise ValueError()
            deadline=min(decision['expires_ms'],prepared.expires_ms) if action in ('compose','submit') else decision['expires_ms']
            return after,deadline
        except Exception:
            raise SealedHttpError('authority_unavailable',state='unknown' if effect else 'refused',
                                  attempts=attempts,digest=prepared.unsigned_digest) from None

    def prepare02(self,journal,**inputs):
        if type(journal) is not OutboundJournal02:raise SealedHttpError('invalid_request')
        inputs=self._before_compose(inputs)
        revision,result=journal.compose_or_replay(**inputs)
        prepared=_prepared(result,revision)
        self._authority('compose',prepared)
        return prepared

    def prepare03(self,journal,**inputs):
        if type(journal) is not OutboundJournal:raise SealedHttpError('invalid_request')
        inputs=self._before_compose(inputs)
        prepared=_prepared(journal.compose_or_replay(**inputs))
        self._authority('compose',prepared)
        return prepared

    def _before_compose(self,inputs):
        # No ciphertext exists yet. The adapter still binds identity and expiry;
        # the post-commit check binds the resulting exact unsigned digest.
        manifest=s._bound(s._manifests,inputs['manifest'])
        message=s.capture(inputs['message_id'],16)
        if manifest.profile==2:device=s.capture(inputs['device_id'],16)
        else:device=s.capture(inputs['current_authority']['deviceId'],16)
        provisional=PreparedSubmission(b'',b'',str(uuid.UUID(bytes=message)),str(uuid.UUID(bytes=device)),inputs['expires_ms'],None)
        self._authority('compose',provisional)
        return dict(inputs,now_ms=self._clock())

    def _exchange(self,method,path,body,authority_until,*,content_type=SEALED_CONTENT_TYPE,extra_headers=None,max_response=16384):
        if not _WORKERS.acquire(blocking=False):return 'timeout'
        cancelled=threading.Event();result=queue.Queue(maxsize=1);connections=[]
        def worker():
            response_seen=False;connection=None
            try:
                connection=http.client.HTTPSConnection(self._host,self._port,timeout=self._timeout)
                connections.append(connection)
                if cancelled.is_set():raise TimeoutError()
                connection.connect()
                if cancelled.is_set():raise TimeoutError()
                now=self._clock()
                if not _integer(now,1) or not authority_until[0]<=now<authority_until[1]:
                    result.put('authority_unavailable');return
                headers={'Authorization':'Bearer '+self.__credential,'Accept':'application/json'}
                if body is not None:headers['Content-Type']=content_type
                if extra_headers:headers.update(extra_headers)
                connection.request(method,path,body=body,headers=headers)
                response=connection.getresponse();response_seen=True
                raw=response.read(max_response+1)
                if len(raw)>max_response or response.length not in (None,0) or cancelled.is_set():raise ValueError()
                result.put((response.status,response.getheader('Retry-After',''),raw,response.getheader('Content-Type','')))
            except Exception as error:
                result.put('timeout' if isinstance(error,(TimeoutError,socket.timeout)) else
                           'unexpected_response' if response_seen else 'network')
            finally:
                if connection is not None:connection.close()
                _WORKERS.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except Exception:
            _WORKERS.release();return 'network'
        try:return result.get(timeout=self._timeout)
        except queue.Empty:
            cancelled.set();active=connections[0].sock if connections else None
            if active is not None:
                try:active.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                active.close()
            return 'timeout'

    def _request(self,action,prepared):
        if type(prepared) is not PreparedSubmission:raise SealedHttpError('invalid_request')
        validated=_prepared(Composition(prepared.envelope,prepared.unsigned_digest,b''))
        if (validated.message_id,validated.device_id,validated.expires_ms)!=(prepared.message_id,prepared.device_id,prepared.expires_ms):
            raise SealedHttpError('invalid_request')
        prepared=validated
        submit=action=='submit';effect=action in ('submit','cancel')
        path='/v1/sealed/messages'+('' if submit else '/'+prepared.message_id+('/cancel' if action=='cancel' else ''))
        uncertain=False
        for attempt in range(1,(self._attempts if submit else 1)+1):
            authority_until=self._authority(action,prepared,effect=uncertain,attempts=attempt-1)
            result=self._exchange('POST' if effect else 'GET',path,prepared.envelope if submit else None,authority_until)
            status=0;retry_after=''
            if type(result) is str:code=result
            else:
                status,retry_after,raw,_=result
                try:
                    row=json.loads(raw.decode('utf-8'),parse_constant=lambda _:None)
                    if status==(202 if submit else 200):
                        value=self._accepted(row,prepared) if submit else self._metadata(row,prepared,action)
                        self._authority(action,prepared,effect=effect,attempts=attempt)
                        return value
                    taxonomy=_SUBMIT if submit else _LIFECYCLE
                    if type(row) is not dict or set(row)!={'code'} or type(row['code']) is not str or taxonomy.get(row['code'])!=status:raise ValueError()
                    code=row['code']
                except SealedHttpError:raise
                except (ValueError,TypeError,UnicodeError):code='unexpected_response'
            uncertain=uncertain or (effect and code in ('network','timeout','unexpected_response','unavailable'))
            retry=submit and code in ('network','rate_limited','billing_pending','unavailable')
            if retry and attempt<self._attempts:
                delay=int(retry_after.strip()) if re.fullmatch(r'\d{1,10}',retry_after.strip()) else attempt
                time.sleep(min(delay,self._delay));continue
            raise SealedHttpError(code,state='unknown' if uncertain or code in ('network','timeout','unexpected_response','unavailable') else 'refused',
                                  status=status,attempts=attempt,digest=prepared.unsigned_digest)

    @staticmethod
    def _accepted(row,prepared):
        if (type(row) is not dict or set(row)!={'message_id','created'} or
            row['message_id']!=prepared.message_id or type(row['created']) is not bool):raise ValueError()
        return dict(row)

    @staticmethod
    def _metadata(row,prepared,action):
        keys={'message_id','device_id','state','state_version','created_at_ms','updated_at_ms','expires_at_ms'}
        if (type(row) is not dict or set(row)!=keys or row['message_id']!=prepared.message_id or
            row['device_id']!=prepared.device_id or type(row['state']) is not str or row['state'] not in _STATES or
            (action=='cancel' and row['state']!='cancelled') or
            any(not _integer(row[k],1 if k=='state_version' else 0) for k in keys-{'message_id','device_id','state'})):raise ValueError()
        return dict(row)

    def submit(self,prepared):return self._request('submit',prepared)
    def status(self,prepared):return self._request('status',prepared)
    def cancel(self,prepared):return self._request('cancel',prepared)
    def reconcile(self,prepared):
        """Query status after uncertainty; never recomposes, resubmits or cancels."""
        return self._request('reconcile',prepared)
