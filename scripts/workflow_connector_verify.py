# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only verification of the exact reviewed, OS-custody MCP launcher."""
from __future__ import annotations
import asyncio
import importlib.metadata
import json
import logging
import os
import platform
import re
import time
import uuid
from workflow_paths import ParentGuard

SDK_VERSION = '2.3.0'
DEADLINE_SECONDS = 30
KNOWN_CODES = {'unauthorized', 'forbidden', 'not_found', 'conflict', 'rate_limited',
               'unsupported', 'response_unknown', 'unavailable', 'invalid_request', 'invalid_configuration'}


class VerificationRefused(Exception):
    def __init__(self, code='invalid_response', state='refused'):
        self.code, self.state = code, state
        super().__init__('connector_verification_refused')


def failure(error):
    # SDK task groups may wrap the tool refusal while unwinding transports.
    # Preserve a single known leaf; mixed failures remain honestly unknown.
    if isinstance(error, BaseExceptionGroup):
        if len(error.exceptions) == 1:
            return failure(error.exceptions[0])
        return VerificationRefused('connection_unknown', 'unknown')
    if isinstance(error, VerificationRefused):
        return error
    if isinstance(error, TimeoutError):
        return VerificationRefused('deadline_exceeded', 'unknown')
    if isinstance(error, (KeyboardInterrupt, asyncio.CancelledError)):
        return VerificationRefused('interrupted', 'unknown')
    return VerificationRefused('connection_unknown', 'unknown')


def body(result):
    value = result.structured_content
    if not isinstance(value, dict) or len(json.dumps(value).encode()) > 262144:
        raise VerificationRefused()
    if result.is_error or value.get('available') is False:
        code = value.get('code')
        state = value.get('state')
        raise VerificationRefused(code if code in KNOWN_CODES else 'invalid_response',
                                  state if state in ('refused', 'unknown') else 'unknown')
    return value


def custody_environment():
    # Official stdio's default desktop environment omits these session-bus
    # hints. Only the Python OS-custody launcher needs them; its existing Node
    # environment filter still excludes both, all credentials and TLS overrides.
    values = {key: os.environ[key] for key in ('DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR')
              if os.name == 'posix' and key in os.environ}
    if any(len(value) > 2048 or any(ord(char) < 32 for char in value) for value in values.values()):
        raise VerificationRefused('runtime_refused')
    return values


async def check_session(client, context):
    if (client.protocol_version not in ('2025-11-25', '2025-06-18') or client.server_info is None
            or client.server_info.name != 'zrotext-scoped-tools'
            or client.server_info.version != '0.0.0-experimental'):
        raise VerificationRefused('unsupported_protocol')
    listed = await client.list_tools()
    names = [tool.name for tool in listed.tools]
    if (len(names) > 64 or len(set(names)) != len(names)
            or not {'zrotext_readiness', 'workflow.context.metadata'} <= set(names)):
        raise VerificationRefused()
    ready = body(await client.call_tool('zrotext_readiness', {}))
    # These are observed permissions, never authority for a subsequent call.
    # The broker independently validates the complete readiness wire schema.
    if (ready.get('available') is not True or ready.get('scope', {}).get('context_id') != context
            or not isinstance(ready.get('methods'), list)
            or {item['method'] for item in ready['methods'] if item.get('permission_granted') is True}
            != {'workflow.context.metadata', 'workflow.action.status'}):
        raise VerificationRefused('scope_mismatch')
    metadata = body(await client.call_tool('workflow.context.metadata', {'request_id': str(uuid.uuid4()), 'context_id': context}))
    expected = {'context_id', 'source_content_digest', 'revision', 'kind', 'expires_at_ms',
                'binding_generation', 'trust_generation', 'manifest_version'}
    value = metadata.get('result')
    if (set(metadata) != {'kind', 'result'} or metadata['kind'] != 'context_metadata'
            or not isinstance(value, dict) or set(value) != expected or value['context_id'] != context
            or not isinstance(value['source_content_digest'], str)
            or not re.fullmatch('[0-9a-f]{64}', value['source_content_digest'])
            or any(type(value[key]) is not int or not 1 <= value[key] <= 9007199254740991
                   for key in expected - {'context_id', 'source_content_digest', 'kind'})
            or type(value['kind']) is not int or not 0 <= value['kind'] <= 255):
        raise VerificationRefused()
    # Deliberately return no identifiers, digests, context metadata or service text.
    return {'protocolVersion': client.protocol_version, 'authenticatedMetadata': 'observed'}


async def exchange(launch, context, remaining=DEADLINE_SECONDS):
    from mcp import Client, StdioServerParameters
    from mcp.client.stdio import stdio_client
    # The official transport bounds shutdown and attempts process-tree cleanup.
    # Windows Job Object creation/assignment remains SDK best-effort behavior.
    with open(os.devnull, 'w') as errors:
        transport = stdio_client(StdioServerParameters(command=launch['command'], args=launch['args'],
                                 cwd=os.getcwd(), env=custody_environment()), errlog=errors)
        with __import__('anyio').fail_after(remaining):
            async with Client(transport, mode='legacy', cache=None, read_timeout_seconds=10) as client:
                return await check_session(client, context)


def verify(path, client, broker, expected, origin, selected):
    import guided_workflow_setup as setup
    deadline = time.monotonic() + DEADLINE_SECONDS
    setup.scope(selected)
    guard = ParentGuard(path)
    raw, config = setup.preflight(path, client, broker, expected, origin, selected)
    existing = config.get('mcpServers', {}).get(setup.ENTRY)
    if existing is None:
        raise setup.local.SetupError('installed_entry_required')
    args = setup.entry_arguments(existing)
    fingerprint = setup.local.digest(json.dumps(setup.scope(selected), sort_keys=True).encode())
    proposal, current, _ = setup.plan(path, client, broker, expected, origin, args[9], args[11],
                                     scope_digest=fingerprint)
    if proposal['action'] != 'unchanged' or current != raw:
        raise setup.local.SetupError('configuration_changed')
    public = {'operation': 'verify', 'automaticRetry': False, 'sendAvailable': False,
              'pairingCreated': False, 'clientAppCompatibility': 'unverified',
              'originalContent': 'unverified', 'carrierDelivery': 'unverified'}
    try:
        if importlib.metadata.version('mcp') != SDK_VERSION:
            raise VerificationRefused('client_sdk_required')
        _, node_version = setup.local.node_runtime()
        if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', node_version):
            raise VerificationRefused('runtime_refused')
        guard.check()
        if setup.local.read_config(path)[0] != raw:
            raise VerificationRefused('configuration_changed')
        # SDK logging can include raw validation input. This CLI emits only its
        # allowlisted report; restore the previous logging policy afterwards.
        previous = logging.root.manager.disable
        try:
            logging.disable(logging.CRITICAL)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            result = asyncio.run(exchange(proposal['launch'], selected['context_id'], remaining))
        finally:
            logging.disable(previous)
        guard.check()
        if setup.local.read_config(path)[0] != raw:
            raise VerificationRefused('configuration_changed')
        return dict(public, status='verified', state='observed', **result,
                    runtime={'python': platform.python_version(), 'node': node_version, 'mcp': SDK_VERSION})
    except importlib.metadata.PackageNotFoundError:
        error = VerificationRefused('client_sdk_required')
    except VerificationRefused as refused:
        error = refused
    except (KeyboardInterrupt, asyncio.CancelledError):
        error = VerificationRefused('interrupted', 'unknown')
    except TimeoutError:
        error = VerificationRefused('deadline_exceeded', 'unknown')
    except BaseExceptionGroup as group:
        error = failure(group)
    except Exception:
        # Never surface SDK validation errors, server text, subprocess output,
        # executable paths, vault references or configuration fragments.
        error = VerificationRefused('connection_unknown', 'unknown')
    return dict(public, status='unverified', code=error.code, state=error.state)
