"""Reviewed owner opening create/status; no allocation or browser authority."""
import http.client
import inspect
import json
import re
import socket
import threading
import time
import urllib.parse
import uuid
from concurrent.futures import Future,TimeoutError
from types import MappingProxyType
from . import sealed_candidate as s
from .contact_integrity import _origin
from .conversation_proposals import _selection

_ADMISSION=threading.BoundedSemaphore(8)
_REFUSALS=(400,401,403,404,409,413,429)


class OpeningCapacityError(Exception):
    def __init__(self,code='invalid'):
        self.code=code
        super().__init__('Owner opening unavailable: '+code)


def _fail(code='invalid'):raise OpeningCapacityError(code)


def _record(value,fields):
    if type(value) not in (dict,MappingProxyType) or set(value)!=set(fields):_fail()
    return dict(value)


def _freeze(value):
    return MappingProxyType({k:_freeze(v) for k,v in value.items()}) if type(value) is dict else value


def _id(value):
    if type(value) is not str or re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value) is None or not any(c!='0' for c in value.replace('-','')):_fail()
    return value


def _positive(value):
    if type(value) is not int or not 1<=value<=s.MAX:_fail()
    return value


def _number(value,maximum):
    if type(value) not in (int,float) or not 1<=value<=maximum or int(value)!=value:_fail()
    return int(value)


def _decimal(value,zero=False):
    if type(value) is not str or len(value)>19 or re.fullmatch(r'0|[1-9][0-9]*' if zero else r'[1-9][0-9]*',value) is None:_fail()
    result=int(value)
    if result>s.MAX:_fail()
    return result


def _source(value,account,context):
    result=_record(value,('accountId','receipt'));r=_record(result['receipt'],('requestId','contextId','revision','envelopeDigest','state','requestAcknowledged'))
    if (_id(result['accountId'])!=account or _id(r['contextId'])!=context or type(r['revision']) not in (int,float) or r['revision']!=1 or
        r['state']!='verified_current_snapshot' or r['requestAcknowledged'] is not True):_fail('source')
    _id(r['requestId']);digest=r['envelopeDigest']
    if type(digest) is not str or re.fullmatch(r'[0-9a-f]{64}',digest) is None or digest=='0'*64:_fail('source')
    return dict(accountId=account,receipt=dict(r,revision=1))


def _json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result or len(result)>=16 or key=='__proto__':_fail('response')
            result[key]=value
        return result
    def number(_):_fail('response')
    def depth(value,n=0):
        if n>6 or type(value) not in (dict,str,bool,type(None)):_fail('response')
        if type(value) is dict:
            for child in value.values():depth(child,n+1)
    try:
        result=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=pairs,parse_int=number,parse_float=number,parse_constant=number)
        depth(result);return result
    except Exception:_fail('response')


def _receipt(value,opening):
    r=_record(value,('opening','offer','allocation_id','allocation_version','phase','pending','confirmed'))
    o=_record(r['opening'],('opening_id','definition_version','state_version'))
    if _id(o['opening_id'])!=opening or any(r[k] is not None for k in ('offer','allocation_id','allocation_version')) or r['phase'] not in ('open','closed','cancelled'):_fail('response')
    pending,confirmed=_decimal(r['pending'],True),_decimal(r['confirmed'],True)
    if pending+confirmed>100:_fail('response')
    return dict(opening=dict(opening_id=opening,definition_version=_decimal(o['definition_version']),state_version=_decimal(o['state_version'])),
                offer=None,allocation_id=None,allocation_version=None,phase=r['phase'],pending=pending,confirmed=confirmed)


class OwnerOpeningCapacityClient:
    """Explicit create/retry/status under a caller-owned owner session.

    Current authority and the exact acknowledged source are compared during
    preparation. Later operations consume that original capped window and
    recheck the unchanged session; status is metadata, never acknowledgment.
    Host callbacks are synchronous and must not reenter this client.
    """
    def __init__(self,origin,binding,context_id,source_expires_ms,*,read_saved_source,read_current,current_session,
                 consume_create_review,enabled=False,total_timeout_ms=10000,attempt_timeout_ms=10000,
                 observation_timeout_ms=10000,max_attempts=1):
        try:
            self._origin=_origin(origin);self._binding=_selection(binding,'refresh');context=s.capture(context_id,16)
            if not any(context) or type(enabled) is not bool or not all(callable(f) for f in (read_saved_source,read_current,current_session,consume_create_review)):_fail()
            self._expires=_positive(source_expires_ms);total=_number(total_timeout_ms,60000)
            self._attempt=_number(attempt_timeout_ms,10000)/1000;self._observation=_number(observation_timeout_ms,10000)/1000;self._maximum=_number(max_attempts,3)
            url=urllib.parse.urlsplit(self._origin);self._host,self._port=url.hostname,url.port
        except Exception:_fail('invalid')
        self._source,self._current,self._session,self._review=read_saved_source,read_current,current_session,consume_create_review
        self._account=str(uuid.UUID(bytes=self._binding['account']));self._context=str(uuid.UUID(bytes=context))
        self._guard=threading.RLock();self._busy=False;self._closed=False;self._retired=False;self._attempts=0
        self._prepared=self._pending=self._connection=None;self._cancel=None
        self._root=self._digest=None;self._generation=self._version=self._now=0
        self._deadline=time.monotonic()+total/1000;self._operation_deadline=self._deadline;self._timer=None
        if enabled:self._arm()
        else:self.close()

    def __repr__(self):return 'OwnerOpeningCapacityClient(<owner session redacted>)'

    def _arm(self):
        if self._timer:self._timer.cancel()
        self._timer=threading.Timer(max(0,self._deadline-time.monotonic()),self.close);self._timer.daemon=True;self._timer.start()

    def _live(self,work=True):
        if self._closed:_fail('closed')
        if time.monotonic()>=self._deadline:self.close();_fail('closed')
        if work and self._cancel is not None and (self._cancel.is_set() or time.monotonic()>=self._operation_deadline):_fail('timeout')

    def _cap(self,value):
        with self._guard:
            if value<self._deadline:self._deadline=value;self._arm()
            self._live()

    def _call(self,fn,*args):
        self._live();result=fn(*args);self._live()
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):result.close()
            _fail('unavailable')
        return result

    def _credentials(self):
        try:
            value=_record(self._call(self._session),('origin','cookie','csrf'))
            if (value['origin']!=self._origin or type(value['cookie']) is not str or not 1<=len(value['cookie'])<=4096 or
                re.fullmatch(r'[\x20-\x7e]+',value['cookie']) is None or '=' not in value['cookie'] or type(value['csrf']) is not str or
                not 1<=len(value['csrf'])<=256 or re.fullmatch(r'[\x21-\x7e]+',value['csrf']) is None):_fail()
            return value
        except OpeningCapacityError as error:
            if error.code in ('closed','timeout'):raise
            _fail('csrf')
        except Exception:_fail('csrf')

    def _observe(self):
        started=time.monotonic();self._operation_deadline=min(self._deadline,started+self._observation)
        try:
            c=_record(self._call(self._current),('binding','manifest','nowMs','ownerSessionLive','consentLive'));now=_positive(c['nowMs'])
            if c['ownerSessionLive'] is not True or c['consentLive'] is not True or _selection(c['binding'],'refresh')!=self._binding or now<self._now:_fail()
            original=s._bound(s._manifests,c['manifest']);s.require(original.profile==2,'opening profile')
            m=s._parse_manifest(original.raw,original.trust,now);t=m.trust;b=self._binding
            if (t.account!=b['account'] or (self._root is not None and (t.root!=self._root or t.generation!=self._generation)) or
                t.version<self._version or (t.version==self._version and self._digest is not None and t.digest!=self._digest)):_fail()
            phone=next((k for k in m.keys if k.role==1 and k.active(now) and k.id==b['phoneReader'] and (k.device,k.line)==(b['device'],b['line'])),None)
            reader=next((k for k in m.keys if k.role==2 and k.active(now) and k.id==b['archiveReader'] and k.scope&8),None)
            signer=next((k for k in m.keys if k.role==4 and k.active(now) and k.scope==2 and (k.device,k.line)==(b['device'],b['line'])),None)
            if phone is None or reader is None or signer is None:_fail()
            ceiling=min(m.expires,phone.end,reader.end,signer.end,self._expires)
            if ceiling<=now:_fail()
            self._cap(min(self._operation_deadline,started+min(60000,ceiling-now)/1000))
            self._root,self._generation,self._version,self._digest,self._now=t.root,t.generation,t.version,t.digest,now
            return now,ceiling,started
        except OpeningCapacityError:raise
        except Exception:_fail('current')

    def _abort_connection(self):
        connection=self._connection
        if connection is not None and connection.sock is not None:
            try:connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            connection.close()

    def _run(self,fn,deadline=None,admit=None):
        with self._guard:
            self._live(False)
            if self._busy:_fail('busy')
            if not _ADMISSION.acquire(False):_fail('capacity')
            try:
                if admit is not None:admit()
            except BaseException:_ADMISSION.release();raise
            self._busy=True;cancel=threading.Event();self._cancel=cancel
            self._operation_deadline=min(self._deadline,deadline if deadline is not None else self._deadline)
        future=Future();settled=returned=False
        def worker():
            nonlocal settled
            try:self._live();value=fn();self._live();future.set_result(value)
            except BaseException as error:future.set_exception(error if isinstance(error,OpeningCapacityError) else OpeningCapacityError('unavailable'))
            finally:
                _ADMISSION.release()
                with self._guard:
                    settled=True
                    if returned:self._busy=False;self._cancel=None
        try:threading.Thread(target=worker,daemon=True).start()
        except BaseException:
            _ADMISSION.release()
            with self._guard:self._busy=False;self._cancel=None
            _fail('unavailable')
        try:
            while True:
                self._live()
                try:value=future.result(timeout=.01);self._live();return value
                except TimeoutError:continue
        except BaseException:
            cancel.set();self._abort_connection();raise
        finally:
            with self._guard:
                returned=True
                if settled:self._busy=False;self._cancel=None

    def prepare_create(self,request_id,opening_id,capacity,decision_deadline_ms):
        request_id,opening_id=_id(request_id),_id(opening_id);capacity=_number(capacity,100);decision=_positive(decision_deadline_ms)
        admitted=False;error_code='source'
        def admit():
            nonlocal admitted
            if self._busy or self._retired or self._prepared is not None:_fail('busy')
            admitted=True
        def run():
            nonlocal error_code
            captured=_source(self._call(self._source),self._account,self._context);credentials=self._credentials()
            error_code='prepare'
            now,ceiling,started=self._observe()
            if not now<decision<=ceiling:_fail('expiry')
            self._cap(started+min(60000,decision-now)/1000)
            self._call(self._review,_freeze(dict(accountId=self._account,requestId=request_id,openingId=opening_id,capacity=capacity,
                       source=captured,decisionDeadlineMs=decision,remainingMs=max(0,int((self._deadline-time.monotonic())*1000)))))
            now,ceiling,_=self._observe()
            if not now<decision<=ceiling or self._credentials()!=credentials or _source(self._call(self._source),self._account,self._context)!=captured:_fail('changed')
            body=json.dumps(dict(request_id=request_id,opening_id=opening_id,capacity=capacity,
                description=dict(context_id=captured['receipt']['contextId'],revision=1,digest=captured['receipt']['envelopeDigest']),decision_deadline_ms=str(decision)),separators=(',',':'))
            if len(body.encode())>8192:_fail()
            ticket=object();record=dict(ticket=ticket,identity=dict(accountId=self._account,requestId=request_id,openingId=opening_id),body=body,credentials=credentials,sent=False,unknown=False)
            with self._guard:
                self._live()
                if self._retired or self._prepared is not None:_fail('busy')
                self._prepared=record
            return ticket
        try:return self._run(run,admit=admit)
        except Exception:
            if not admitted:raise
            with self._guard:self._retired=True
            _fail(error_code)

    def _request(self,path,body,credentials):
        with self._guard:
            self._live()
            if self._attempts>=self._maximum:_fail('attempts')
            self._attempts+=1
        connection=http.client.HTTPSConnection(self._host,self._port,timeout=max(.001,min(self._deadline,self._operation_deadline)-time.monotonic()))
        try:
            with self._guard:self._connection=connection;self._live()
            connection.connect();self._live()
            connection.request('POST',path,body.encode(),headers={'Content-Type':'application/json','Accept':'application/json',
                'x-zrotext-opening-account':self._account,'x-zrotext-csrf':credentials['csrf'],'Cookie':credentials['cookie'],'Cache-Control':'no-store'})
            response=connection.getresponse();self._live()
            if response.status!=200:return response.status,None
            if (response.getheader('Content-Type') or '').split(';')[0].strip().lower()!='application/json':_fail('response')
            raw=response.read(8193);self._live()
            if not 1<=len(raw)<=8192 or response.length not in (None,0):_fail('response')
            return 200,_json(raw)
        except OpeningCapacityError as error:
            # Maintained transport wait classifies rejected body/media/JSON work
            # as unavailable; closed DTO validation occurs after that boundary.
            if error.code=='response':_fail('unavailable')
            raise
        finally:
            connection.close()
            with self._guard:
                if self._connection is connection:self._connection=None

    def _unknown(self,r,code):
        with self._guard:r['unknown']=True;self._pending=dict(r['identity']);return _freeze(dict(state='unknown',pending=dict(self._pending),code=code))

    def _dispatch(self,ticket,replay):
        with self._guard:
            r=self._prepared
            if r is None or r['ticket'] is not ticket or replay!=r['sent'] or (replay and not r['unknown']):
                return _freeze(dict(state='unknown',pending=dict(self._pending),code='ticket') if self._pending else dict(state='refused',code='ticket'))
        def run():
            if self._attempts>=self._maximum:_fail('attempts')
            if self._credentials()!=r['credentials']:_fail('csrf')
            with self._guard:self._live();r['sent']=True
            status,value=self._request('/v1/owner/workflow/openings',r['body'],r['credentials']);self._live()
            if status!=200:
                if not r['unknown'] and status in _REFUSALS:
                    with self._guard:self._prepared=None;self._retired=True
                    return _freeze(dict(state='refused',code='server'))
                return self._unknown(r,'server')
            value=_record(value,('account_id','request_id','outcome'));outcome=_record(value['outcome'],('receipt','applied','recorded'))
            if _id(value['account_id'])!=r['identity']['accountId'] or _id(value['request_id'])!=r['identity']['requestId'] or outcome['recorded'] is not True or type(outcome['applied']) is not bool:_fail('response')
            decoded=_receipt(outcome['receipt'],r['identity']['openingId'])
            if self._credentials()!=r['credentials']:_fail('closed')
            with self._guard:
                self._live()
                if self._prepared is not r:_fail('closed')
                self._prepared=self._pending=None;self._retired=True
                return _freeze(dict(state='acknowledged',**r['identity'],receipt=decoded,applied=outcome['applied']))
        try:return self._run(run,time.monotonic()+self._attempt)
        except OpeningCapacityError as error:
            return self._unknown(r,error.code) if r['sent'] or r['unknown'] else _freeze(dict(state='refused',code='unavailable'))

    def create(self,ticket):return self._dispatch(ticket,False)
    def retry(self,ticket):return self._dispatch(ticket,True)

    def status(self,opening_id):
        opening=_id(opening_id)
        with self._guard:
            self._live(False)
            if self._pending and self._pending['openingId']!=opening:_fail('selection')
        def run():
            credentials=self._credentials();status,value=self._request('/v1/owner/workflow/openings/'+opening+'/status','{}',credentials)
            if self._credentials()!=credentials or status!=200:_fail('status')
            value=_record(value,('account_id','receipt'))
            if _id(value['account_id'])!=self._account:_fail('response')
            result=_receipt(value['receipt'],opening)
            return _freeze(dict(state='metadata_snapshot',accountId=self._account,openingId=opening,receipt=result))
        return self._run(run,time.monotonic()+self._attempt)

    def state(self):
        with self._guard:return _freeze(dict(closed=self._closed,busy=self._busy,pending=dict(self._pending) if self._pending else None))

    def close(self):
        with self._guard:
            if self._closed:return
            self._closed=True;r=self._prepared
            if r is not None:
                if r['sent']:r['unknown']=True;self._pending=dict(r['identity'])
                r['body']='';r['credentials']=None
            self._prepared=None
            if self._timer:self._timer.cancel();self._timer=None
            if self._cancel:self._cancel.set()
            self._source=self._current=self._session=self._review=lambda *args:None
        self._abort_connection()
