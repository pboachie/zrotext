# Owner managed-grant HTTP foundation

`MANAGED_AI_GRANTS_ENABLED` defaults to `false`. Configured account routes are
required to mount this boundary. With the flag off, these routes are absent.
The flag only mounts metadata endpoints; it does not install the six-table SQL
proposal, admit a service reader or policy issuer, select a model/provider/region,
authorize spending, or activate a content reader or provider transport.

Production create and replace remain unavailable: the adapter uses
`ManagedGrants::default()`, whose issuance gate rejects before password
verification, factor consumption, policy/source evaluation, or grant writes.
A configured MFA cipher or manually installed proposal does not enable issuance.
There is currently no admitted production-created grant chain. The complete
positive owner consent/grant/task journey still requires the existing reader,
issuer, durable schema, task, policy and transport integration owners.

## Authentication and request boundary

All four endpoints use POST and the maintained live owner session cookie,
exact configured Origin, and session-bound CSRF cookie/header. Observer sessions
cannot mutate grants; maintained owner-role refusal is 401, while wrong Origin
or CSRF binding is 403. `OwnerMutation` executes before the bounded JSON body
extractor. Its authentication connection is released before body reading; its
named per-account slot remains held until the operation finishes or is canceled.
The existing process-local cap is four body-carrying requests per account.
Authorization headers and any query string are refused. Neither caller-supplied
account IDs nor bearer credentials substitute for the authenticated principal.

The raw JSON limit is 16,384 bytes. Bodies require JSON content type and valid
UTF-8; unknown, duplicate, missing and mistyped DTO fields are rejected. The
operation deadline is ten seconds, including authentication, body reading and
the core transaction. Timeout is a 503 response and cancellation drops the
pending operation. A timeout during commit can have an indeterminate outcome;
it is not a guarantee that a commit could never have completed.

Routed responses carry `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`, including extractor, size, method, deadline
and core refusals. These endpoints do not set session cookies. Path grant IDs
must be nonzero lowercase canonical hyphenated UUIDs. Path validation in the
handler follows successful authentication and bounded body extraction.

## Typed request bodies and named responses

The collection is `/v1/owner/managed-ai/grants`.

| Endpoint | Exact top-level fields | Successful response |
|---|---|---|
| Collection | `password`, `factor`, `request` | 201: `grant_id`, `current_version` (production issuance unavailable) |
| `/{id}/replace` | `expected_version`, `password`, `factor`, `request` | 200: `grant_id`, `current_version` (production issuance unavailable) |
| `/{id}/narrow` | `expected_version`, `request` | 200: `grant_id`, committed `current_version` |
| `/{id}/revoke` | none: empty object or existing empty-array compatibility | 204, empty body |

The table gives the named-object representation. The unchanged serde struct
decoder also accepts exact positional arrays in declaration order: create is
`[password, factor, request]`; replace is
`[expected_version, password, factor, request]`; narrow is
`[expected_version, request]`; revoke is `[]`. Missing/extra elements and wrong
types refuse. Nested `GrantRequest`, `PolicyIdentity` and `Selection` have the
same ordered-array compatibility, with the fields listed below in order.
Unknown or duplicate names refuse in named objects. This is existing serde
compatibility, not a new parser or an authentication bypass. Successful
`GrantVersion` and static JSON error responses serialize as named objects.

`expected_version` is a JSON integer in 1..127, permitting an append through
version 128. Revocation does not need an expected version and remains valid at
128. Passwords contain 12..1024 decoded UTF-8 bytes; factors contain 1..256.
Escaping can expand valid decoded strings past the raw body cap. Parsed owned
secret strings use best-effort zeroization and expose no clone/debug/serialization
convenience. Original HTTP/serde buffers, allocator copies, TLS/kernel buffers
and caller-held strings are outside that limited guarantee.

`request` is the existing closed `managed_ai::GrantRequest`: `policy`, `contact`,
`purpose`, `instruction_digest`, `expires_ms`, `max_calls`, `max_input_bytes`,
`max_cost_microunits`, and `selections`. `policy` has exactly `id`, `version`,
`digest`, `reader`, and `reader_generation`. Each selection has exactly `kind`,
`id`, `version`, and `digest`; the sole kind is `workflow_context_v1`. Digests
use the existing 32-byte JSON arrays, not a new encoding. Purposes remain
`transactional`, `operational`, or `marketing`. Their maintained unit-enum
decoder accepts either the string or the corresponding single-name null object,
such as `{"operational":null}`; the source kind also accepts
`{"workflow_context_v1":null}`. Nested UUID serde accepts case-insensitive hex
in simple, hyphenated, braced or lowercase-prefix `urn:uuid:` string formats,
including nil at the parsing layer. Canonical nonnil path spelling is a separate
handler check; core validation separately rejects nil identities.

Core validation requires nonzero identities/digests, positive policy versions,
reader generations and expiry, nonnegative caps, at most 32 canonically sorted
selections, nonduplicate source IDs, and source versions 1..128. Public policy
identity metadata is not trusted issuer proof. The HTTP adapter adds no permit,
task type, policy freshness assertion, content, instructions, reader key or
source plaintext to this representation.

## Protocol artifacts and independent wire controls

The [HTTP schema](vectors/managed-grant-owner-http.schema.json) models the actual
named and positional typed request shapes, nested enum/UUID compatibility, and
closed named successful/error envelopes. The [synthetic literal vectors](vectors/managed-grant-owner-http-01.json)
pair raw JSON with independently retained expected fields and source-derived
status examples. An issuance response example describes a shape only; it does
not claim production create/replace success. A 204 response has no JSON body.
The preserved Axum byte-reader rejection, including 413, need not be JSON and
is not assigned a fabricated `code` envelope by this schema.

Standard JSON Schema measures string characters, not decoded UTF-8 bytes.
Its secret limits are necessary character bounds only. Supplemental raw-wire
controls enforce the source's decoded-byte limits and raw 16,384-byte cap;
valid decoded strings may exceed the raw cap when escaped. The schema cannot
detect raw duplicate names after ordinary JSON parsing, attest lexical integer
tokens (mathematical `1.0` can satisfy schema integer), reject unpaired Unicode
as a Rust string parser would, or prove authentication and transaction facts.
The maintained numeric decoder refuses float/exponent tokens for typed integers,
including `-0`, which the pinned parser represents as a float.

`test_managed_grant_owner_http.py` independently checks these raw-wire limits,
literal vectors, nested shapes and a separate source-derived core validation
profile. Wire-schema acceptance is not core validation: nil/zero identities,
negative caps, source version 129, unsorted/duplicate selections or more than32
selections can parse before the core refuses them. Core-shape acceptance proves
no policy freshness, consent, narrowing against a stored prior version, owner
recheck, commit or successful issuance. Python controls run through the explicit
quality selector using the existing schema environment. They do not import or
invoke the Rust parser, authenticated route or database.

## Durable reduction and revocation

Reduction delegates to the existing account-scoped, owner-fenced transaction.
It preserves policy, contact, purpose and instruction digest, permits only a
subset of exact prior selections and nonincreasing expiry/caps, appends one
immutable version/event, and rechecks the same owner/session before commit.
Expired reader/policy/source authority does not prevent reduction. Empty
selections and zero caps are valid reductions. No password, MFA cipher, root,
fresh source, or provider policy is added as a prerequisite for narrow/revoke.

Revocation locks the same account/grant, records one irreversible revocation
generation/event, and rechecks the owner before committing. Repetition is
idempotent. A revoked grant cannot be narrowed. Stale versions conflict;
foreign-account IDs are not found in the authenticated account. An absent
proposal yields unavailable; a partial installation fails closed with observable
storage failure. No request installs or repairs schema.

The existing contact-consent transaction withdraws even expired grants.
Renewing contact consent does not revive their revoked generation. Existing
owner export pages six metadata sets with 21-row fetch/20-row return, and owner
erasure removes children before parents in its existing atomic deletion plan.
The new adapter changes none of those lifecycle implementations or retention.

## Error and validation limits

Observable invalid input maps to 400, authentication to the maintained 400/401/
403/409/429/500/503 statuses, conflict to 409, scope refusal to 403, missing scoped
grant to 404, and unavailable/database/archive storage errors to 503. JSON and
core errors do not echo secrets or database diagnostics. The maintained private
auth mapper is represented locally through its public response variants.
The existing dormant issuer's `lock_current` path already collapses some deep
storage errors to a scope refusal; this adapter cannot recover that lost
provenance and does not claim to repair it.

Source controls exercise closed/raw-wire parsing and mount/header/deadline
boundaries. Opt-in PostgreSQL controls use maintained registration, password-bound
email verification, login and session authentication, then explicitly synthetic
SQL grant/reader/policy/source metadata. They cover dormant issuance, expired
empty/zero reduction, version 128, idempotent revoke, stale/widened identity,
concurrent versions, account isolation, owner expiry around locks/writes,
rollback, body slots, absent/partial schema, withdrawal, export and erasure.
Synthetic SQL scheduling hooks isolate refusal/rollback fences. These fixtures
are not genuine reader, cryptographic root, phone, provider or custody proof.
Source controls require compilation and execution before any runtime result is
claimed; genuine end-to-end acceptance remains a separate gate.
