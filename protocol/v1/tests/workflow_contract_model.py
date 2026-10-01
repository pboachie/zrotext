# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic exact-action conformance oracle. Not a production service."""
import hashlib
import json

FIELDS = {
    'account_id', 'action_id', 'revision', 'line_id', 'recipient_id',
    'purpose_id', 'content_ref', 'content_digest', 'content_version',
    'not_before', 'expires_at', 'timezone', 'window_id', 'routine_id',
    'authority_generation', 'commitment',
}
INTEGERS = {'revision', 'content_version', 'authority_generation', 'not_before', 'expires_at'}
EDITABLE = {'proposed', 'approved', 'invalidated'}


def binding(action):
    if set(action) != FIELDS:
        raise ValueError('fields')
    for name, value in action.items():
        if name in INTEGERS:
            minimum = 0 if name in {'not_before', 'expires_at'} else 1
            if type(value) is not int or value < minimum:
                raise ValueError('integer')
        elif not isinstance(value, str) or not 1 <= len(value) <= 128 or not value.isascii():
            raise ValueError('string')
    digest = action['content_digest']
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('digest')
    if action['commitment'] not in {'informational', 'sensitive'}:
        raise ValueError('commitment')
    if action['not_before'] >= action['expires_at']:
        raise ValueError('timing')
    raw = json.dumps(action, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


class Conflict(ValueError):
    pass


class Record:
    def __init__(self, action):
        self.action = dict(action)
        self.digest = binding(action)
        self.state = 'proposed'
        self.version = 1
        self.approved_digest = None
        self.decisions = {}
        self.updates = {}

    def _authorize(self, account, authorized, confirmed):
        if account != self.action['account_id'] or not authorized or not confirmed:
            raise Conflict('authority')

    @staticmethod
    def _replay(fences, identity, request):
        if identity in fences:
            previous, result = fences[identity]
            if previous != request:
                raise Conflict('identity conflict')
            return result
        return None

    def decide(self, identity, account, revision, digest, operation, expected,
               now, authorized=True, confirmed=True):
        self._authorize(account, authorized, confirmed)
        request = (account, revision, digest, operation, expected)
        replay = self._replay(self.decisions, identity, request)
        if replay is not None:
            return replay
        if (expected != self.version or revision != self.action['revision']
                or digest != self.digest or now >= self.action['expires_at']):
            raise Conflict('stale decision')
        if operation == 'approve' and self.state in {'proposed', 'invalidated'}:
            self.state = 'approved'
            self.approved_digest = digest
        elif operation == 'cancel' and self.state in EDITABLE:
            self.state = 'cancelled'
            self.approved_digest = None
        else:
            raise Conflict('transition')
        self.version += 1
        result = (self.state, self.version)
        self.decisions[identity] = (request, result)
        return result

    def edit(self, identity, action, expected, account, now, authorized=True, confirmed=True):
        self._authorize(account, authorized, confirmed)
        digest = binding(action)
        request = (digest, expected)
        replay = self._replay(self.updates, identity, request)
        if replay is not None:
            return replay
        if (expected != self.version or self.state not in EDITABLE
                or now >= self.action['expires_at']
                or action['account_id'] != self.action['account_id']
                or action['action_id'] != self.action['action_id']
                or action['revision'] != self.action['revision'] + 1
                or all(action[k] == self.action[k] for k in FIELDS - {'revision'})):
            raise Conflict('edit')
        self.action = dict(action)
        self.digest = digest
        self.approved_digest = None
        self.state = 'invalidated'
        self.version += 1
        result = (self.state, self.version)
        self.updates[identity] = (request, result)
        return result

    def expire(self, now):
        if self.state in EDITABLE and now >= self.action['expires_at']:
            self.state = 'expired'
            self.approved_digest = None
            self.version += 1

    def dispatch(self, expected, now, authorized=True):
        if (expected != self.version or self.state != 'approved' or not authorized
                or self.approved_digest != self.digest
                or not self.action['not_before'] <= now < self.action['expires_at']):
            raise Conflict('dispatch')
        self.state = 'dispatching'
        self.version += 1

    def outcome(self, state):
        if ((self.state == 'dispatching' and state in {'unknown', 'succeeded', 'failed'})
                or (self.state == 'unknown' and state in {'succeeded', 'failed'})):
            self.state = state
            self.version += 1
        else:
            raise Conflict('outcome')
