# Unverified OpenRouter request body codec

`managed_ai::openrouter_body` is a synchronous, network-free JSON serializer of
caller-supplied data. It is not connected to a production caller, grant issuance,
task execution or provider transport. Managed grant issuance remains unavailable
by default. This module supplies no authenticated task, request identity, policy
approval, release permit, replay guard, region selection or custody evidence.

## Supplied inputs and closed output

`UnverifiedOpenRouterProfile` borrows the exact model string, requested provider
slug and completion-token ceiling. Both strings must be 1 through 128 ASCII bytes
using letters, digits, slash, dot, underscore or hyphen. Slash-separated segments
must be nonempty. These checks are lexical framing only; a string passing them is
not an approved, available, pinned or safe model/provider. No default model,
provider, fallback model or processing endpoint is chosen.

The encoder separately borrows instructions and selected text as byte slices.
Each must be nonempty strict UTF-8; their checked combined raw byte length must
be at most 8192. The token ceiling must be 1 through 65536. These are technical
codec ceilings, not grant entitlements, approved budgets or pricing assumptions.
A future consumer must enforce stricter authenticated policy/grant bounds.
The encoder does not select, fetch, concatenate or authenticate either buffer.
System/user role labels do not establish instruction provenance.

The body contains exactly five root fields in this order:

| Field | Emitted value |
| --- | --- |
| `model` | Exact supplied model string |
| `messages` | Exactly two objects: system/instructions, then user/selected text; each has only `role` and `content` |
| `max_completion_tokens` | Supplied bounded integer |
| `stream` | `false` |
| `provider` | Exactly `only`, `allow_fallbacks`, `require_parameters`, `data_collection`, `zdr` |

The provider object requests one exact supplied slug in `only`,
`allow_fallbacks: false`, `require_parameters: true`, `data_collection: "deny"`
and `zdr: true`. These are requested restrictions. Their serialization proves no
external processor compliance, retention, actual route selection, processing
region or local consent/policy approval. There is no JSON region field.
Tools, plugins, model fallback arrays, streaming, debug/echo/cache/session/user
metadata, identifying grant/task/account/phone fields and extension maps are
outside this closed subset. No credential, bearer header, HTTP request, response
parser, retry or fallback machinery is created.

The primary [chat completion reference](https://openrouter.ai/docs/api/api-reference/chat/create-a-chat-completion)
documents these request fields; `max_completion_tokens` replaces deprecated
`max_tokens`. The [provider routing guide](https://openrouter.ai/docs/guides/routing/provider-selection)
documents requested routing/privacy controls and separate regional endpoints.
The operator must choose approved model/provider settings and an actually
entitled endpoint/region independently; this codec does not verify availability
or make that decision.

## Buffer ownership and limits

Borrowed typed serialization writes directly into a private bounded writer.
It reserves 65536 bytes before copying plaintext and never grows that allocation
while writing. Every write uses checked length arithmetic and refuses a result
above 65536 bytes. There is no intermediate owned plaintext `String`, generic
JSON value, unchecked output vector or arbitrary caller writer.

`UnverifiedOpenRouterBody` owns a `Zeroizing<Vec<u8>>` and provides immutable
borrowed byte access. It has no Debug, Clone, serialization or ownership-extracting
convenience API. Returned bytes are data, not a release permit. Static errors do
not echo input/profile values or serde details. A serialization error returns no
partial body; the local buffer's zeroizing guard remains responsible for cleanup.

Zeroization is best effort and local to this allocation. Borrowed caller buffers,
caller-created copies, allocator/OS state, process crashes and remote processors
are outside its guarantee. The synchronous serializer creates no clock-bound
secret window or custody authority. Preallocation avoids codec-created
reallocation copies; it does not establish heap-wide erasure.

A conservative static bound is six escaped bytes per raw input byte, at most
256 profile bytes and less than 512 fixed/integer bytes: at most 49920 bytes.
The independent writer cap remains necessary if fields change. This arithmetic
does not itself establish an executed serializer result.

## Structural fixtures and independent controls

The [response-independent body schema](vectors/openrouter-request-body.schema.json)
and [synthetic body vector](vectors/openrouter-request-body-01.json) describe this
output subset. The schema closes every object, fixes roles/order/counts and
routing/privacy requests, and bounds lexical slugs and token values. Standard
JSON Schema counts text characters; it cannot enforce the encoder's combined
UTF-8 byte cap or authenticate supplied data. Schema-valid examples can exceed
that byte cap and must still be refused by the Rust encoder.

Pure Rust controls independently cover literal bytes/shape, escaped control and
multibyte text, JSON-like text staying data, isolated supplied-value changes,
malformed UTF-8, empty input, lexical/profile/token boundaries, combined raw-byte
limits, checked length overflow, worst escaping, writer exact-cap/no-growth/no
partial-write refusal and static errors. A synthetic live-allocation clear
control inspects initialized bytes only; it does not inspect freed memory or
prove Drop/crash/OS cleanup. Python schema controls independently mutate closed
fields, roles/order/counts, privacy requests, profile/token shapes and scalar
types. Their fixture model/provider identifiers are synthetic, not availability
claims. Hosted quality explicitly selects `test_openrouter_request_body.py`
using its existing schema environment.

These controls describe source coverage. Test declarations, schema validity and
technical ceilings do not establish provider, policy, budget or pilot acceptance.

## Required later integration

The [managed AI grant contract](managed-ai-grant-contract.md), dormant grant
foundation and signed reader-policy/evidence contracts retain their own
semantics. Grant/policy metadata and historical cryptographic identity do not
supply an implemented managed provider-request identity, model/region allowlist
or current installed custody. This module introduces no competing task/permit
type, commitment digest, policy lookup or cryptographic domain.

Before any provider caller can use these bytes, the maintained immutable task
contract must bind the real grant, current reader/policy/provider identities,
selected sources and instructions, exact chosen model/routing controls, entitled
endpoint and release bounds. Current account/content/consent/expiry facts and
shared exposure reservations require their actual atomic checkpoint and stable
once-only provider-call identity. Explicit unverified profile data cannot supply
those facts. No locally invented digest, synthetic call ID or separate quota
ledger is an authority substitute.

Actual operator choices remain required for model/provider, processing route and
region, retention/subprocessors/deletion, disclosure/minimization, prices and
hard budgets. Later transport needs separate review of exact task/output
correlation, retained reservations on unknown acceptance, bounded deadlines,
cancellation and late-output discard, no automatic retry/provider switch,
sealed owner output, canary absence and export/erasure. This serializer neither
implements nor admits those operations.
