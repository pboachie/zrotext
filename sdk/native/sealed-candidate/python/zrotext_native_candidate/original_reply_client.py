"""Dedicated original-event HTTPS grant client; no automatic retries or SMS send."""
import base64
import copy
from functools import wraps
import json
import re
import threading
import uuid
from . import sealed_candidate as s
from .original_reply_reader import capture_scope,open_original_reply02
from .reply_selection import verify_archive_reply_selection02
from .sealed_http import SealedHttpClient

_PROOF={'account_id','interval_id','device_id','line_id','connector_id','read_grant_id','reader_id','root_generation',
        'authority_revision','expires_at_ms','observed_at_ms','current_manifest_version','current_manifest_digest','manifest_chain'}
_IDENTITIES={'account_id':'account','device_id':'device','line_id':'line','interval_id':'interval','connector_id':'connector','read_grant_id':'read_grant'}


class OriginalReplyError(Exception):
    def __init__(self,unknown=False):
        super().__init__('Original reply unavailable');self.state='unknown' if unknown else 'unavailable'


def _object(value,fields):
    s.require(type(value) is dict and set(value)==set(fields),'original response fields');return value


def _positive(value):
    s.require(type(value) is int and 0<value<=2**53-1,'original integer');return value


def _uuid(value):
    s.require(type(value) is str and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value) is not None,'original UUID')
    raw=uuid.UUID(value).bytes;s.require(any(raw),'zero original UUID');return raw


def _text(value):return str(uuid.UUID(bytes=value))


def _hex(value):
    s.require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value) is not None,'original digest');return bytes.fromhex(value)


def _base64(value,limit):
    s.require(type(value) is str and len(value)<=((limit+2)//3)*4,'original base64 bounds')
    raw=base64.b64decode(value,validate=True)
    s.require(0<len(raw)<=limit and base64.b64encode(raw).decode()==value,'original canonical base64');return raw


def _credential(value,prefix):
    s.require(type(value) is str and re.fullmatch(prefix+r'[A-Za-z0-9_-]{43}',value) is not None,'original credential')
    raw=base64.urlsafe_b64decode(value[len(prefix):]+'=')
    s.require(len(raw)==32 and base64.urlsafe_b64encode(raw).decode().rstrip('=')==value[len(prefix):],'original credential encoding')
    return value


def _serialized(function):
    @wraps(function)
    def run(self,*args,**kwargs):
        if not self._busy.acquire(blocking=False):raise OriginalReplyError()
        self._effect_attempted=False
        try:return function(self,*args,**kwargs)
        except Exception:raise OriginalReplyError(self._effect_attempted) from None
        finally:self._busy.release()
    return run


class OriginalReplyClient:
    """Use an independently selected scope/custody and accepted local history.

    ztr credentials read originals; a separately configured ztw callback is used
    only for proposal consumption. Grant response fields are authenticated by
    this configured TLS service, never taken from an event or webhook alone.
    Accepted highwater is in-memory; caller-owned durable history remains needed.
    """
    def __init__(self,origin,credential,*,scope,custody,accepted_history,clock,
                 output_credential=None,timeout_ms=5000,require_protected=True):
        try:
            self._scope=capture_scope(scope);self._custody=custody;self._clock=clock
            self._protected=require_protected;self._output=output_credential
            s.require(callable(clock) and type(require_protected) is bool and (output_credential is None or callable(output_credential)),'original configuration')
            if require_protected or type(custody) is not s.SoftwareRecipient:s.require_protected_custody(custody)
            s.require(type(timeout_ms) is int and 1<=timeout_ms<=10000,'original timeout')
            self._transport=SealedHttpClient(origin,_credential(credential,'ztr_'),lambda _:None,clock=clock,timeout_ms=timeout_ms)
            s.require(type(accepted_history) in (list,tuple) and 1<=len(accepted_history)<=64,'original history capacity')
            self._history={};previous=0
            for token in accepted_history:
                manifest=s._bound(s._manifests,token)
                s.require(manifest.profile==2 and manifest.trust.account==self._scope['account'] and manifest.trust.version>previous,'original accepted history')
                s._parse_manifest(manifest.raw,manifest.trust,manifest.issued)
                previous=manifest.trust.version;self._history[previous]=token
            self._latest=accepted_history[-1];self._last=_positive(clock())
            m=s._bound(s._manifests,self._latest);s._parse_manifest(m.raw,m.trust,self._last)
            self._busy=threading.Lock();self._effect_attempted=False
        except Exception:raise OriginalReplyError() from None

    def __repr__(self):return 'OriginalReplyClient(<credentials redacted>)'

    def _request(self,method,*,event=None,baseline=None,additional=None,output=None):
        baseline=baseline or self._latest;version=s._bound(s._manifests,baseline).trust.version
        _positive(version)
        body=dict(v=1,method=method,accepted_manifest_version=version)
        if event is not None:body['event_id']=_text(event)
        if additional:body.update(additional)
        encoded=json.dumps(body,separators=(',',':'),allow_nan=False).encode('utf-8')
        s.require(len(encoded)<=4096,'original request bounds')
        now=_positive(self._clock());s.require(now>=self._last,'original clock rollback')
        if method=='consume':self._effect_attempted=True
        response=self._transport._exchange('POST','/v1/reply-events',encoded,(now,s.MAX),content_type='application/json',
                    extra_headers={'Cache-Control':'no-store',**({'x-zrotext-output-authorization':'Bearer '+output} if output else {})},max_response=524288)
        s.require(type(response) is tuple,'original transport unavailable')
        status,_,raw,content_type=response
        s.require(200<=status<300 and content_type.split(';')[0].strip()=='application/json','original HTTP response')
        result=_object(json.loads(raw.decode('utf-8',errors='strict')),{'kind','result'})
        s.require(result['kind']==method,'original response method');return result['result']

    def _proof(self,value,baseline=None):
        p=_object(value,_PROOF);now=_positive(self._clock())
        observed,expires=_positive(p['observed_at_ms']),_positive(p['expires_at_ms'])
        s.require(now>=self._last and observed-30000<=now<=observed+30000 and now<expires,'original proof freshness')
        for field,name in _IDENTITIES.items():s.require(_uuid(p[field])==self._scope[name],'original proof scope')
        s.require(_hex(p['reader_id'])==self._scope['reader'] and _positive(p['authority_revision'])==1,'original proof authority')
        chain=p['manifest_chain'];s.require(type(chain) is list and 1<=len(chain)<=32,'original manifest chain bounds')
        initial=s._bound(s._manifests,baseline or self._latest);previous=initial;staged={}
        for index,item in enumerate(chain):
            item=_object(item,{'version','accepted_at_ms','manifest_b64'});version=_positive(item['version']);at=_positive(item['accepted_at_ms'])
            s.require(at<=now+30000 and version==(initial.trust.version if index==0 else previous.trust.version+1),'original manifest chain order')
            parsed=s._parse_manifest(_base64(item['manifest_b64'],9751),previous.trust,at)
            s.require(parsed.profile==2 and parsed.trust.version==version,'original manifest chain identity')
            if index==0:s.require(parsed.trust.digest==initial.trust.digest,'original baseline digest')
            if version in self._history:s.require(s._bound(s._manifests,self._history[version]).trust.digest==parsed.trust.digest,'original cached fork')
            staged[version]=parsed;previous=parsed
        fresh=_positive(self._clock());high=s._bound(s._manifests,self._latest)
        s.require(fresh>=max(now,self._last) and observed-30000<=fresh<=observed+30000 and fresh<expires,'original final proof freshness')
        s._parse_manifest(previous.raw,previous.trust,fresh)
        identity=previous.trust
        s.require(identity.version==_positive(p['current_manifest_version']) and identity.digest==_hex(p['current_manifest_digest']) and
                  identity.generation==_positive(p['root_generation'])==initial.trust.generation and identity.root==initial.trust.root and
                  identity.version>=high.trust.version and (identity.version!=high.trust.version or identity.digest==high.trust.digest) and
                  len(set(self._history)|set(staged))<=64,'original current highwater')
        # No external call between final fence and publication. Earlier staged
        # entries stay independently verified; current comparison uses fresh time.
        for version,manifest in staged.items():self._history[version]=s._accept(s._manifests,manifest)
        self._latest=s._accept(s._manifests,s._parse_manifest(previous.raw,previous.trust,fresh))
        self._history[identity.version]=self._latest;self._last=fresh
        return dict(scope=dict(self._scope),revision='1',expires_ms=expires,now_ms=fresh,manifest=self._latest)

    def _current(self):return self._proof(self._request('current'))

    @_serialized
    def current(self):return self._current()

    @staticmethod
    def _cursor(value):
        row=_object(value,{'accepted_at_ms','event_id'});_positive(row['accepted_at_ms']);_uuid(row['event_id']);return dict(row)

    @_serialized
    def page(self,cursor=None,limit=20):
        s.require(type(limit) is int and 1<=limit<=32,'original page limit')
        cursor=None if cursor is None else self._cursor(cursor)
        row=_object(self._request('page',additional=dict(cursor=cursor,limit=limit)),{'events','next','proof'})
        self._proof(row['proof']);s.require(type(row['events']) is list and len(row['events'])<=limit,'original page size')
        seen=set();events=[]
        for value in row['events']:
            e=_object(value,{'event_id','accepted_at_ms','observed_at_ms','historical_manifest_version','activation_manifest_version','disposition','active_request_ids'})
            _uuid(e['event_id']);s.require(e['event_id'] not in seen,'original duplicate event');seen.add(e['event_id'])
            for field in ('accepted_at_ms','observed_at_ms','historical_manifest_version','activation_manifest_version'):_positive(e[field])
            s.require(type(e['disposition']) is str and e['disposition'] in ('unassociated','owner_review','request_available'),'original event disposition')
            requests=e['active_request_ids'];s.require(type(requests) is list and len(requests)<=8,'original request count')
            for ident in requests:_uuid(ident)
            s.require(len(set(requests))==len(requests),'original duplicate request');events.append(copy.deepcopy(e))
        return dict(events=events,next=None if row['next'] is None else self._cursor(row['next']))

    def _consumption(self,value):
        row=_object(value,{'event_id','consumption_id','disposition','active_request_id','action'})
        _uuid(row['event_id']);_uuid(row['consumption_id'])
        if row['active_request_id'] is not None:_uuid(row['active_request_id'])
        if row['action'] is not None:
            key=_object(row['action'],{'account_id','action_id','revision','binding_digest'})
            s.require(_uuid(key['account_id'])==self._scope['account'],'original action account');_uuid(key['action_id'])
            s.require(_positive(key['revision'])<=128,'original action revision');_hex(key['binding_digest'])
        s.require((row['disposition']=='proposal' and row['action'] is not None and row['active_request_id'] is not None) or
                  (row['disposition']=='owner_review' and row['action'] is None),'original consumption disposition')
        return copy.deepcopy(row)

    @_serialized
    def consume(self,request):
        params=copy.deepcopy(_object(request,{'request_id','event_id','active_request_id','descriptor'}))
        _uuid(params['request_id']);_uuid(params['event_id'])
        if params['active_request_id'] is not None:_uuid(params['active_request_id'])
        digest=None;output=None
        if params['descriptor'] is not None:
            from zrotext_workflow import validation
            s.require(validation.matches(validation.TOOLS['workflow.action.propose']['inputSchema'],
                         dict(request_id=params['request_id'],descriptor=params['descriptor'])),'original proposal schema')
            params=validation.wire_numbers(params);descriptor=params['descriptor']
            s.require(descriptor['account_id']==_text(self._scope['account']) and descriptor['line_id']==_text(self._scope['line']) and params['active_request_id'] is not None,'original proposal scope')
            digest=validation.action_digest(descriptor)
            s.require(self._output is not None,'original output credential unavailable')
            output=_credential(self._output(),'ztw_')
        result=self._consumption(self._request('consume',additional=dict(params=params),output=output))
        s.require(result['event_id']==params['event_id'] and result['consumption_id']==params['request_id'] and
                  result['active_request_id']==params['active_request_id'],'original consumption binding')
        action=result['action']
        if action is not None:s.require(params['descriptor'] is not None and action['action_id']==params['descriptor']['action_id'] and
                                        action['revision']==params['descriptor']['revision'] and action['binding_digest']==digest,'original proposal digest')
        return result

    @_serialized
    def status(self,consumption_id):
        _uuid(consumption_id);result=self._consumption(self._request('status',additional=dict(consumption_id=consumption_id)))
        s.require(result['consumption_id']==consumption_id,'original consumption identity');return result

    @_serialized
    def read_verified(self,event,accepted_manifest_version=None):
        event=s.capture(event,16);s.require(any(event),'original event')
        latest=s._bound(s._manifests,self._latest).trust.version
        version=accepted_manifest_version if accepted_manifest_version is not None else next((v for v in self._history if latest-v<32),None)
        s.require(type(version) is int and version in self._history and 0<=latest-version<32,'original read baseline')
        baseline=self._history[version]
        row=_object(self._request('read',event=event,baseline=baseline),{'event_id','accepted_at_ms','envelope_b64','historical_manifest_version',
                    'statement_b64','approval_signature_b64','installation_signature_b64','activation_manifest_version','proof'})
        s.require(_uuid(row['event_id'])==event,'original read event')
        proof=self._proof(row['proof'],baseline)
        historical=self._history[_positive(row['historical_manifest_version'])];activation=self._history[_positive(row['activation_manifest_version'])]
        manifest=s._bound(s._manifests,activation);archive=next(k.id for k in manifest.keys if k.role==2 and k.state==1)
        scope=self._scope
        selection=verify_archive_reply_selection02(_base64(row['statement_b64'],1536),_base64(row['approval_signature_b64'],64),
                    _base64(row['installation_signature_b64'],64),activation,_positive(row['accepted_at_ms']),account=scope['account'],
                    device=scope['device'],line=scope['line'],interval=scope['interval'],peer=scope['peer'],archive_reader=archive)
        envelope=_base64(row['envelope_b64'],34082);authorities=[proof]
        def current():
            if len(authorities)==1:authorities.append(proof);return proof
            authority=self._current();authorities.append(authority);return authority
        plaintext=open_original_reply02(envelope,scope=scope,event=event,historical=historical,selection=selection,custody=self._custody,
                                         read_current=current,require_protected=self._protected)
        return dict(plaintext=plaintext,event_id=_text(event),event_envelope_digest=s.sha(envelope).hex(),accepted_manifest_version=version,authority=authorities[-1])

    def read(self,event,accepted_manifest_version=None):return self.read_verified(event,accepted_manifest_version)['plaintext']
