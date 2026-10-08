# Provider proposal history

The dormant owner-decision consumer retains a complete validated
`workflow-action-02` descriptor as proposal history. The router remains
unmounted. This change supplies proposal, read, cancellation and internal edit
behavior; it supplies no provider approval, content access or SEND authority.
The unchanged [descriptor conformance contract](provider-action-descriptor-proposal.md)
defines the closed02 grammar. Its historical consumer-migration table describes
the conformance module's earlier baseline; this document describes the separate
proposal-history consumer.

## Original proposal and whole binding

The only provider proposal envelope is exactly
`{"descriptor":<complete02>,"request_id":<canonical UUID>}`. Retain the original
UTF-8 bytes. The complete body is at most 8192 bytes and the canonical descriptor
at most 4096 bytes. Raw02 intake uses the explicit `Content-Type: application/json`
media profile (case-insensitive, without parameters). Other header values retain
the unchanged01 `ApiJson` path and its reject-before-body behavior; they do not
enter the new provider parser. The protected `ProposedDescriptor::parse_owner_proposal_wire`
validates closed fields, reader variants, UUIDs, integer and string bounds,
strict timing order and equality of the entire original body to canonical
encoding. Do not normalize through a generic JSON value before validation.
Duplicate or escaped-alias keys, extra/missing fields, fractional or exponent
integers, padding, noncanonical ordering and trailing values refuse. Request ID
is a nonnil lowercase canonical UUID.

The binding is SHA-256 of **all** canonical02 bytes: action, profile, route,
reader and disclosure. Canonical encoding recursively sorts ASCII object keys,
uses compact separators and ordinary decimal integers. An `ActionKey` contains
the nested action's account ID, action ID and revision, plus the lowercase
64-character whole-descriptor digest. Request ID does not enter that digest.
The consumer retains the complete bytes in immutable version history; nested
action metadata cannot be converted to a01 descriptor or used as the binding.
Read/export must preserve the whole descriptor and whole key under the existing
owner/context fences. Storage does not accept a caller-selected projection.

`ActionState` retains its existing closed shape:

```json
{"key":{"account_id":"00000000-0000-0000-0000-000000000001","action_id":"00000000-0000-0000-0000-00000000000a","revision":1,"binding_digest":"0a5b3363d9d9ff8ea8dcb0a1b1eebe137a895abf0821e6b6e3635946136e4ade"},"record_version":1,"phase":"proposed"}
```

Provider history uses `proposed`, `invalidated` and `cancelled` phases. The key
revision is bounded by128; record version is a positive signed64-bit integer.
The response gains no descriptor, acceptance flag, route or authority field.

## Internal edit and replay

There is **no02 HTTP edit envelope, handler or endpoint**. The internal service
accepts the exact previous whole `ActionKey`, positive expected record version,
nonnil request UUID and complete next validated02 descriptor. It requires the
maintained authenticated Owner and current context; descriptor identifiers are
metadata, never substitute authentication. Both initial and final fresh checks
apply before the single durable commit. Cancel/read/register use the maintained
owner and context fences as well.

An edit preserves account ID, action ID, profile, `content_ref` and `routine_id`.
Revision advances by checked addition of exactly1, remains at most128, and at
least one other canonical field changes. The expected version and previous
whole key must match the current record; cancelled history cannot be edited.
A new immutable version retains complete new bytes and digest, invalidates any
earlier approval, and increments the record version without overflow. Route,
reader and disclosure changes participate just as action changes do. There is
no inherited approval for a changed provider route or reader.

Provider replay is separated from the unchanged01 replay domain. Its internal
request digest is SHA-256 over the bytes `ZT/provider-proposal-history/v1`, a
zero byte, operation as signed16-bit big-endian, and compact JSON serialization
of `[owner_user_uuid, request_uuid, input]`. Operations are1 register,2 cancel
and3 edit. Register input is the complete canonical descriptor as a byte array;
cancel input is `[whole_key, expected_record_version, "cancel"]`; edit input is
`[previous_whole_key, expected_record_version, complete_next_byte_array]`.
`ActionKey` serializes in declaration order: account ID, action ID, revision,
binding digest. This private serialization is separate from canonical descriptor
sorting and defines no request wire. The same request with identical bound
arguments replays its recorded result; changed actor, previous key, CAS value,
operation or complete next bytes conflicts instead of making a second mutation.
Replay requires current authority fences and never grants authority itself.

## Effect boundary

Provider Approve, `LockedAction`, message binding, dispatch, scheduling, send
and liability refuse as unavailable **before mutation or effect**. Whole
metadata and history do not establish accepted configuration, eligibility,
reader trust, grant, actual local read, explicit review, exposure admission or
writer authority. Synthetic reader/route/disclosure values cannot satisfy those
producers. Legacy phone facades refuse02 and retain01 bytes, digest and replay
behavior. No SQL schema, SQL effect helper, active mount, SDK producer or provider
transport is introduced here.

## Synthetic conformance document

The [new schema](vectors/provider-proposal-history.schema.json) describes the
[vector document](vectors/provider-proposal-history-01.json), **not production
request wire**. Its descriptor reference resolves to the unchanged02 schema.
The discovered [Python controls](tests/test_provider_proposal_history.py) resolve
that resource locally and use only stdlib and the existing `jsonschema` package.

The vectors contain literal independently computed canonical descriptors,
original proposal bodies, byte lengths, whole keys and digests for both reader
forms, plus route/reader/disclosure/action edits and each mutable binding field.
Internal edit refusal cases cover stale whole keys, CAS, profile and lineage
changes, skipped/overflowing revision and revision-only changes. Replay controls
retain literal expected digests and one short literal serialization. Complete
byte-array inputs are independently reconstructed from the named literal
specimens, avoiding repeated arrays while binding actor, request, operation
and all inputs. Raw controls
exercise caps before parsing, closed objects, duplicate/alias keys, canonical
order, numeric spelling, string suffixes, integer limits and malformed UTF-8.

These are independent protocol/source conformance controls, with synthetic
metadata and a pure edit relation. They do not execute HTTP, SQL, authentication,
context fences, runtime rollback or provider effect refusal. Consumer Rust and
PostgreSQL controls must verify those behaviors separately; vector metadata is
never an authority fixture or proof of live delivery.
