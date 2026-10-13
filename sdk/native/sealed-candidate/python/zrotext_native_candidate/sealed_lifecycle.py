"""Standalone metadata observations; no ciphertext, grants or replay authority."""
import http.client
import json
import math
import queue
import re
import socket
import threading
import urllib.parse

SEALED_MESSAGE_STATES=('accepted','queued','claimed','submitting','submitted','delivered',
    'delivery_unknown','unknown','failed','cancelled','expired')
_UUID=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_CODES={'invalid_request':400,'unauthorized':401,'forbidden':403,'not_found':404,
    'cancellation_conflict':409,'rate_limited':429,'unavailable':503}
_WORKERS=threading.BoundedSemaphore(16)
_MAX_SAFE=(1<<53)-1


class SealedLifecycleError(Exception):
    """Unknown observations never establish nonacceptance of a cancellation."""
    def __init__(self,code,*,status=0,state='refused',attempts=0):
        super().__init__('Sealed lifecycle request failed: '+code)
        self.code,self.status,self.state,self.attempts=code,status,state,attempts


def _integer(value,minimum=0):
    return type(value) in (int,float) and minimum<=value<=_MAX_SAFE and math.isfinite(value) and int(value)==value


def _identity(value):
    if type(value) is not str or _UUID.fullmatch(value) is None:raise ValueError()
    return value


def _metadata(row):
    fields={'message_id','device_id','state','state_version','created_at_ms','updated_at_ms','expires_at_ms'}
    if type(row) is not dict or set(row)!=fields:raise ValueError()
    _identity(row['message_id']);_identity(row['device_id'])
    if type(row['state']) is not str or row['state'] not in SEALED_MESSAGE_STATES:raise ValueError()
    result=dict(row)
    for field in fields-{'message_id','device_id','state'}:
        if not _integer(row[field],1 if field=='state_version' else 0):raise ValueError()
        result[field]=int(row[field])
    return result


class SealedLifecycleClient:
    """Exactly one request, system TLS trust, no redirects/proxies/cookies.

    Caller credentials are metadata API authority only. No PreparedSubmission is
    created and no status observation permits re-submitting a sealed envelope.
    timeout_ms is a bounded native total deadline, between 1 and 120000.
    """
    def __init__(self,origin,credential,*,timeout_ms=15000):
        try:
            if (type(origin) is not str or type(credential) is not str or
                re.fullmatch(r'[\x21-\x7e]+',credential) is None or
                not _integer(timeout_ms,1) or timeout_ms>120000):raise ValueError()
            url=urllib.parse.urlsplit(origin)
            if (url.scheme!='https' or not url.hostname or url.username is not None or url.password is not None or
                url.path not in ('','/') or url.query or url.fragment or '\\' in origin or
                any(ord(c)<33 for c in origin)):raise ValueError()
            self._host,self._port=url.hostname.encode('idna').decode(),url.port
            self.__credential=credential;self._timeout=timeout_ms/1000
        except (ValueError,TypeError,UnicodeError):raise SealedLifecycleError('invalid_configuration') from None

    def __repr__(self):return 'SealedLifecycleClient(<credential redacted>)'

    def _exchange(self,method,path):
        if not _WORKERS.acquire(blocking=False):raise SealedLifecycleError('capacity')
        cancelled=threading.Event();results=queue.Queue(maxsize=1);connections=[]
        def worker():
            connection=None;response_seen=False
            try:
                connection=http.client.HTTPSConnection(self._host,self._port,timeout=self._timeout);connections.append(connection)
                if cancelled.is_set():raise TimeoutError()
                connection.connect()
                if cancelled.is_set():raise TimeoutError()
                connection.request(method,path,headers={'Authorization':'Bearer '+self.__credential,'Accept':'application/json'})
                response=connection.getresponse();response_seen=True;raw=response.read(16385)
                if len(raw)>16384 or response.length not in (None,0) or cancelled.is_set():raise ValueError()
                results.put((response.status,raw))
            except Exception as error:
                results.put('timeout' if isinstance(error,(TimeoutError,socket.timeout)) else
                            'unexpected_response' if response_seen else 'network')
            finally:
                if connection is not None:connection.close()
                _WORKERS.release()
        try:threading.Thread(target=worker,daemon=True).start()
        except Exception:
            _WORKERS.release();raise SealedLifecycleError('transport_unavailable') from None
        try:return results.get(timeout=self._timeout)
        except queue.Empty:
            cancelled.set();active=connections[0].sock if connections else None
            if active is not None:
                try:active.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                active.close()
            return 'timeout'

    def _request(self,method,path,validate):
        result=self._exchange(method,path)
        if type(result) is str:raise SealedLifecycleError(result,state='unknown',attempts=1)
        status,raw=result
        try:
            def nonfinite(_):raise ValueError()
            # Match TextDecoder's default stripping of exactly one leading BOM.
            row=json.loads(raw.decode('utf-8-sig',errors='strict'),parse_constant=nonfinite)
            if status==200:return validate(row)
            if type(row) is not dict or set(row)!={'code'} or type(row['code']) is not str or _CODES.get(row['code'])!=status:raise ValueError()
        except (ValueError,TypeError,UnicodeError,OverflowError,RecursionError):
            raise SealedLifecycleError('unexpected_response',status=status,state='unknown',attempts=1) from None
        raise SealedLifecycleError(row['code'],status=status,state='unknown' if row['code']=='unavailable' else 'refused',attempts=1)

    def _message(self,message_id,cancel):
        try:message_id=_identity(message_id)
        except ValueError:raise SealedLifecycleError('invalid_request') from None
        def validate(row):
            result=_metadata(row)
            if result['message_id']!=message_id or cancel and result['state']!='cancelled':raise ValueError()
            return result
        return self._request('POST' if cancel else 'GET','/v1/sealed/messages/'+message_id+('/cancel' if cancel else ''),validate)

    def status(self,message_id):return self._message(message_id,False)
    def cancel(self,message_id):return self._message(message_id,True)
    def list(self,cursor=None):
        try:query='' if cursor is None else '?cursor='+_identity(cursor)
        except ValueError:raise SealedLifecycleError('invalid_request') from None
        def validate(row):
            if type(row) is not dict or set(row)!={'messages','next_cursor'} or type(row['messages']) is not list or len(row['messages'])>20:raise ValueError()
            next_cursor=row['next_cursor']
            if next_cursor is not None:_identity(next_cursor)
            messages=[_metadata(value) for value in row['messages']]
            if next_cursor is not None and (len(messages)!=20 or messages[-1]['message_id']!=next_cursor):raise ValueError()
            return dict(messages=messages,next_cursor=next_cursor)
        return self._request('GET','/v1/sealed/messages'+query,validate)
