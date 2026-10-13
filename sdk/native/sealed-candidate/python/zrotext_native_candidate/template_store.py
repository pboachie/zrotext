"""Pure bounded template persistence messages; no owner or sending authority."""
from dataclasses import dataclass
from functools import wraps
import json
import re
from types import MappingProxyType
from typing import Mapping
from . import encrypted_template as t
from . import sealed_candidate as s


class TemplateStoreError(ValueError):
    def __init__(self):super().__init__('Invalid template persistence contract')


@dataclass(frozen=True)
class TemplateSaveRequest:
    """Captured persistence intent, not an authenticated or verified capability."""
    path: str
    headers: Mapping[str,str]
    body: bytes
    revision: int
    encrypted_digest: str


def _closed(function):
    @wraps(function)
    def run(*args,**kwargs):
        try:return function(*args,**kwargs)
        except Exception:raise TemplateStoreError() from None
    return run


@_closed
def template_save_request(scope,request_id,expected_revision,envelope):
    s.require(type(request_id) is str and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',request_id) is not None
              and request_id!='00000000-0000-0000-0000-000000000000','template request identity')
    s.require(type(expected_revision) in (int,float) and 0<=expected_revision<=127 and int(expected_revision)==expected_revision,'template CAS')
    expected_revision=int(expected_revision);aad=t.encrypted_template_aad(scope)
    s.require(s.num(aad,94)==expected_revision+1,'template next revision')
    body=s.capture(envelope,308,33075)
    s.require(body[:222]==aad and s.num(body,287,4)==len(body)-291,'template envelope framing')
    headers=MappingProxyType({'content-type':'application/vnd.zrotext.workflow-template.v1',
        'idempotency-key':request_id,'x-zrotext-template-revision':str(expected_revision)})
    return TemplateSaveRequest('/v1/owner/workflow/templates',headers,body,expected_revision+1,t.encrypted_template_digest(body).hex())


@_closed
def template_save_receipt(request,body):
    s.require(type(request) is TemplateSaveRequest,'template save request')
    # A request is structural metadata, not a private trust token. No remote
    # authentication or cryptographic validity is inferred from this comparison.
    s.require(type(request.revision) is int and 1<=request.revision<=128,'template receipt revision')
    raw=s.capture(body,0,256)
    def nonfinite(_):raise ValueError()
    value=json.loads(raw.decode('utf-8-sig',errors='strict'),parse_constant=nonfinite)
    s.require(type(value) is dict and set(value)=={'revision'} and type(value['revision']) in (int,float)
              and value['revision']==request.revision,'template receipt')
    return {'revision':request.revision}
