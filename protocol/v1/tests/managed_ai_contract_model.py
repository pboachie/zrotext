# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic managed-reader checkpoints, never a runtime authorization service."""
from copy import deepcopy


class Denied(ValueError):
    pass


def validate(task, grant, content, now):
    for field in ('account_id', 'grant_id', 'grant_version', 'revocation_generation',
                  'reader_id', 'key_generation', 'provider_id', 'purpose_id',
                  'routine_generation'):
        if task[field] != grant[field]:
            raise Denied('binding')
    if grant['revoked'] or grant['account_deleted']:
        raise Denied('revoked')
    if now >= min(task['expires_at'], grant['expires_at']):
        raise Denied('expired')
    if task['line_id'] not in grant['line_ids']:
        raise Denied('line')
    if task['conversation_id'] not in grant['conversation_ids']:
        raise Denied('conversation')
    if not task['objects']:
        raise Denied('empty selection')
    seen = set()
    for selected in task['objects']:
        identity = selected['object_id']
        if identity in seen or identity not in grant['object_ids']:
            raise Denied('selection')
        seen.add(identity)
        actual = content.get(identity)
        if actual is None or actual['deleted']:
            raise Denied('deleted')
        for field in ('account_id', 'line_id', 'conversation_id'):
            if actual[field] != task[field]:
                raise Denied('content binding')
        if selected['version'] != actual['version'] or selected['digest'] != actual['digest']:
            raise Denied('content version')
        if (actual['wrap_reader_id'] != task['reader_id']
                or actual['wrap_key_generation'] != task['key_generation']
                or actual['wrap_task_id'] != task['task_id']
                or actual['wrap_grant_id'] != task['grant_id']
                or actual['wrap_grant_version'] != task['grant_version']
                or actual['wrap_purpose_id'] != task['purpose_id']):
            raise Denied('wrap binding')


class Task:
    def __init__(self, task):
        self.task = deepcopy(task)
        self.state = 'queued'
        self.version = 1
        self.reserved_units = 0
        self.call_id = None
        self.output = None

    def begin_call(self, grant, content, budget, now, expected):
        if expected != self.version or self.state != 'queued':
            raise Denied('state')
        validate(self.task, grant, content, now)
        units = self.task['maximum_units']
        if (any(type(budget.get(k)) is not int or budget[k] < 0
                for k in ('hard_ceiling', 'remaining_units', 'remaining_tasks'))
                or budget.get('available') is not True
                or type(units) is not int or not 1 <= units <= budget['hard_ceiling']
                or not budget['available'] or budget['remaining_units'] < units
                or budget['remaining_tasks'] < 1):
            raise Denied('budget')
        budget['remaining_units'] -= units
        budget['remaining_tasks'] -= 1
        self.reserved_units = units
        self.call_id = self.task['task_id'] + '-call'
        self.state = 'provider_inflight'
        self.version += 1

    def accept_output(self, grant, content, now, response):
        if self.state != 'provider_inflight':
            raise Denied('state')
        try:
            validate(self.task, grant, content, now)
            for field in ('task_id', 'reader_id', 'provider_id'):
                if response[field] != self.task[field]:
                    raise Denied('response binding')
            if response['call_id'] != self.call_id:
                raise Denied('call binding')
        except Denied:
            self.state = 'discarded'
            self.version += 1
            return 'discarded'
        digest = response.get('encrypted_draft_digest')
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            self.state = 'discarded'
            self.version += 1
            return 'discarded'
        self.output = digest
        self.state = 'draft_ready'
        self.version += 1
        return 'draft_ready'

    def begin_send(self, grant, content, now, expected, approval_digest,
                   send_authorized, suppression_clear, send_budget_available):
        if self.state != 'draft_ready' or expected != self.version:
            raise Denied('state')
        validate(self.task, grant, content, now)
        if (approval_digest != self.output or not send_authorized
                or not suppression_clear or not send_budget_available):
            raise Denied('send authority')
        self.state = 'dispatching'
        self.version += 1



def deletion_report(local_deleted, provider_status):
    """Acknowledge local erasure separately; past access is never recalled."""
    if type(local_deleted) is not bool or provider_status not in {
            'attempted', 'acknowledged', 'unsupported', 'failed', 'unknown'}:
        raise Denied('deletion status')
    return dict(local_deleted=local_deleted, provider_status=provider_status,
                prior_access_recalled=False)
