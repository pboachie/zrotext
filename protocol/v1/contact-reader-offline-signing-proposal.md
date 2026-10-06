<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Offline contact reader signing candidate

This is an explicit, non-default Windows `unlock` build candidate. It signs one
historical, owner-reviewed account-contact statement using an existing protected
root backup. It does not install a reader, issue current permission, establish
accepted manifest history, or send a request. The matched issuer aggregate,
authenticated proposal producer, browser controller, genesis/restore admission,
contact ciphertext storage and custody remain separate unavailable prerequisites.

The real command is `contact-reader-sign`, with these fixed, ordered arguments:
`--account --origin --bundle --proposal --output --reader --reader-point --until`.
Account is a nonnil canonical lowercase UUID. Bundle, reader ID and reader SEC1
point are lowercase hexadecimal of 16, 32 and 65 bytes respectively. Origin is
the independently intended canonical HTTPS origin, 9..512 printable ASCII bytes.
Until is a positive canonical decimal string no greater than signed int64 maximum.
Input and output are distinct absolute ASCII drive paths, at most 260 bytes,
without device names, dot/empty components, streams or ambiguous trailing bytes.
These public arguments contain no secret or clock override.

## Closed copied public input

The CLI reads one regular, non-reparse final leaf once, with a 32 KiB raw UTF-8
cap and an oversize byte. Ancestor junction traversal remains an ordinary Windows
path limitation; this is not a hostile same-user filesystem containment claim.
The wrapper has exactly `create` and `pending`. Their retained raw JSON object
tokens are capped at 8192 bytes and 20 KiB before direct typed deserialization.
Outer whitespace counts toward the wrapper cap. Unknown, missing, duplicate
fields (including escaped duplicate aliases), nulls and wrong types refuse.
This is not an authenticated response-encoding compatibility claim.

`create` has `create_request`, `expected_revision`, `prior`, `selected_reader_id`,
`compared_root_fingerprint`, `requested_until_ms`. `prior` is `{phase:"empty"}`
or has phase `active`/`withdrawn` plus `authorization`, `generation`, `digest`.

`pending` has `kind:"pending"`, `create_input_digest`, `create_request`,
`authorization`, `generation`, `creation_expected_revision`, `allocated_revision`,
`unsigned_digest`, `unsigned`, `issued_ms`, `expires_ms`, `until_ms`,
`created_by_user`, `created_session`, `creation_source`, `current`.
`current` has `phase`, `mutation_revision`, `allocation_generation`, `observed_ms`;
active/withdrawn additionally have `authorization`, `generation`, `statement_digest`.

`creation_source` has `kind:"historical_creation_source"`, `account_id`,
`root_pin_b64`, `root_fingerprint_b64`, `trust_generation`, `manifest_version`,
`manifest_digest_b64`, `manifest_b64`, `observed_ms`, `manifest_issued_ms`,
`manifest_expires_ms`, `signed_until_ms`, `reader`, `root_writer`.
Each record has `key_id_b64`, `public_point_b64`, `from_ms`, `until_ms`.
Numbers are canonical decimal strings within signed int64; only original revision,
allocation and record start permit zero. UUIDs are nonnil canonical lowercase.
Binary JSON fields are canonical padded base64. The 94-byte generation-one pin
and complete signed manifest (364..9751 bytes, 1..64 records) are copied public
evidence. `observed_ms` is the frozen original creation comparison time, never a
lookup refresh or a current-authority brand.

The original CREATE commitment is SHA-256 of this internal binary transcript:
version byte `01`; derived account16; origin length u16BE and origin bytes;
create-request16; original expected-revision u64BE; prior phase byte
`00`/`01`/`02`; prior authorization16/generation u64BE/digest32 (all zero when
empty); selected-reader32; compared-root-fingerprint32; requested-until u64BE.
Its size is 172 plus origin length. Reconciling user/session are excluded;
original pending actor fields remain contextual display facts. They do not become
extra signed statement fields. CREATE revision must leave two increments of
headroom; allocated revision is original plus one. Current copied prior must
match exactly and its allocator cannot lag the pending generation.

## Exact signature and local validation

Unsigned statement bytes have existing `ZTKA` version byte `01`, capability `03`:
authorization16, account16, origin u16BE+bytes, root-generation u64BE,
manifest-version u64BE, reader-generation u64BE, root-fingerprint32,
manifest-semantic-digest32, reader-ID32, reader-point65, issued/until u64BE.
Size is 241 plus origin length (250..753); signed size is 314..817.
The unchanged signature transcript is the 35-byte domain
`ZT/contact-reader/authorization/v1` including its trailing NUL, unsigned length
u32BE, and those exact unsigned bytes. Signature is raw low-S P256 `r||s`64.
Received high-S signatures are refused rather than normalized into acceptance.

The new private historical manifest validator checks the full signed framing,
root signature, independent pin/fingerprint, semantic digest, every record's
curve/key ID/role/scope/subject/state/order and unique point, and exact root and
archive cardinality. Selected role2/scope12 reader and role6/scope0 root must be
active at original comparison and statement issuance. All interval bounds apply;
no unselected malformed record is ignored. The returned private review state owns
its copied statement and display facts and is consumed once by signing. It is not
a `VerifiedManifest`, accepted-chain factory, high-water or current permission.

## Recovery, publication and ambiguity

One eligible console acquisition consumes the independently compared full kit
fingerprint. Then a fresh review acquisition displays the complete copied facts
in printable ASCII/CRLF chunks of at most 512 bytes and consumes
`APPROVE-READER` or `DECLINE`. Decline does no recovery or publication.
A separate acquisition consumes the no-echo recovery token. A new eligible output
session is acquired before backup opening and remains the SAME session through
recovery, root-point comparison, consuming signature, file write/sync and receipt.
The existing encrypted bundle is read only; root and recovery values are dropped
before publication. No durable unlock, secret JSON/argument/environment or signing
callback is introduced.

Actual wall-clock nonregression, pending expiry, statement/source bounds and a
10-second monotonic post-token success window are checked at operation boundaries
and each receipt chunk. This does not interrupt or bound synchronous crypto or OS
`write_all`/`sync_all`. A fresh check after publication gates the success receipt.
Late/error output may leave partial OR complete valid public bytes. Never
automatically overwrite, delete, resign, retry or reset the original operation.
Output uses create-new semantics. Its receipt says **Signed locally; server
completion has not been acknowledged**. Future authenticated completion must
retain the original operation and exact whole signed bytes, enforce genuine
current owner/root/source/factor checks after its last write, and obtain commit
acknowledgement. The offline command supplies none of that authority.

## Shared closed-input key sets

`contact-reader-signing-input-shape.json` lists the exact JSON key sets of
`create`, `prior`, `pending`, `creation_source`, the two role records and
`current` (per phase). The issuer's real `PendingView`/`Prior` serialization is
tested against it in Rust, and `test_contact_reader_signing_input_shape.py`
checks the command's serde struct and variant fields against it, so a key added
or renamed on one side fails CI instead of surfacing as a `deny_unknown_fields`
refusal at signing time. This checks key names and order only. It does not run
the Windows parser on server-produced bytes, validate values, or establish
signature, history or current-authority acceptance.
