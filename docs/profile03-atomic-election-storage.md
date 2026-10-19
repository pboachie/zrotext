<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Atomic first Profile03 election storage

Migration110 provides a narrow structural transaction for the initial,
single-line, same-root02-to03 selection. It does not verify signatures,
authenticate an owner or device, consume MFA, enable routes, or enable sending.
The production adapter must perform those independent checks against actual
held records before calling any mutator, and recheck currentness after waits.

`payload_profile_election_reserve` retains one complete original E500 core,
successor03, original signed02 checkpoint, original109 activation mapping and
actual owner/device lease selection. The actual line issuance highwater burns
the next generation in the same transaction. A retained opening retry returns
its original reservation without extending time, changing IDs or consuming
another slot. At most16 reservations are retained per account. Different
opening bytes, an unexpired competing reservation, unknown history, multiple
active SEALED lines, and unclosed effects refuse. Unsupported history is never
deleted or relabeled to qualify.

`payload_profile_election_device_proof` retains the exact original raw64 proof
once, after independent authenticated device and signature checks. A different
proof conflicts. Any retained device signature permanently fences legacy02
sealed effect fallback, including after expiry or an interrupted response.
Ordinary SMS remains distinct and retains its existing invariants.

An explicit fresh higher reservation can close expired unaccepted predecessors
under the unchanged02 root/binding and actual exclusive account fence. Closure
time equals the new core's issued time, with old expiry at or before that time
and actual primary time at or after it. The old core/proof stays immutable.
The same-account deferred link requires a strictly higher generation and the
exact same old binding, line, device, root and original02. Linked ancestors
remain available through multiple lost responses. A closed attempt can never
accept, even following clock regression; observing status does not close or
allocate anything.

`payload_profile_election_accept` retains the exact core/device/owner bundle,
creates a distinct03 binding with03-domain proof digests, revokes the old02
binding, installs the same-root successor manifest, removes prior readiness,
and advances the actual retained account anchor from0 to1. Insert-only deferred
completion requires all those changes, the original installed physical proof,
current owner/device/keys, and the primary/factor deadline to agree at commit.
Incomplete reservation, partial acceptance, revoked selection or time expiry
rolls back the whole transaction. An accepted historical retry returns its
original receipt and supplies no new current permission.

The original physical v2 pending/installation ACK, nonce-cleared state,
observation and109 receipt remain unchanged. No old v2 generation or proof is
rewritten as a new03 activation. Reconnection and later physical refresh are
separate obligations; this initial storage does not invent a fresh observation.

All original107 writer classes retain their actual account extraction,
immutable parent mirrors, nullable legacy handling, stable user/member tuple
participation and typed global fences. Positive epochs require actual retained
accepted provenance plus an explicit relation/operation policy. Ordinary
metadata, login/sign-out, device reconnect and monotone revocation stay
available. Legacy sealed/conversation/workflow/effect writers without a typed03
path refuse. An accepted row is never a general permission or epoch-advance API.
Account-erasure cascades retain the original minimal anchor tombstone policy;
historical owner/session UUIDs have no new live-session restriction.

The runtime receives SELECT and the three narrow functions only. Row/column
writes, internal scope/epoch/completion helpers and baseline mutation remain
denied, including after stock role reprovisioning. The Rust schema validator
and independent stock verifier pin function bodies and complete declarations
before readiness calls. The complete reviewed table/constraint/trigger/rule/
inheritance/RLS/function graph must still match. Unknown, absent, disabled,
partial and polluted installations refuse. Manifest constraints preserve02
bounds and admit only the explicitly framed03 extension; they use explicit
comparisons so logical restore needs no added normalization exception.

The finite writer inventory records every relation and operation policy.
Structural SQL controls and source tests do not establish genuine application
authentication, cryptographic verification, device acceptance, deployment or
release readiness. Those remain separate qualification steps.
