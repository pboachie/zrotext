# Experimental managed protected profile02 composition

Java `Compose02.fresh`, Csharp `Compose02.Fresh` and Ruby `Compose02.fresh` create
fresh native profile02 candidates with the locally qualified Windows PCP signer.
Each composer owns the input identity/recipient snapshots, revalidates the verified
profile02 manifest at comparison time, authorizes the exact signer and recipients,
and then draws native randomness. Body AES-256-GCM, RFC9180 P-256/HKDF-SHA256/
AES-128-GCM wrapping with empty profile02 AAD, and native low-S signature use the
profile02 domain and length framing. Each result is independently parsed and its
signature verified before return. All recipient keys come from the verified
manifest; caller-provided public points cannot override them.

The maintained profile02 candidate grammar deliberately permits zero message IDs
and observed/expiry values such as 0/1 even when comparison time is later. It
checks signer/recipient authorization at comparison time. These candidate bytes
are not current permission, transport authorization, retry authorization or an
SMS effect. Do not substitute profile03 elected authority or silently apply its
pending [observed-time policy decision](https://github.com/pboachie/zrotext/issues/1226). The compiler/native method refuses
the other signature profile, and offers no software signing fallback.

Run the shared acceptance harness with an exact clean producer checkout:

```text
python sdk/native/crypto-envelope/composition02-run.py --language java --producer PRODUCER_DIRECTORY --controls CONTROLS_DIRECTORY
python sdk/native/crypto-envelope/composition02-run.py --language csharp --producer PRODUCER_DIRECTORY --controls CONTROLS_DIRECTORY
python sdk/native/crypto-envelope/composition02-run.py --language ruby --producer PRODUCER_DIRECTORY --controls CONTROLS_DIRECTORY
```

The producer/consumer pin is `a13ea1e3d6f6db594485c19b36c43fe642e67c7a` from the
maintained Python interoperability work. Its TypeScript build is independent of
these native implementations. The harness injects only the new native public
point, verifies and decrypts both recipients for fresh/random and zero-candidate
cases, and exercises malformed identity/text/time/recipient/authority and wrong
signature-domain refusals. Native aliases have a fsynced pending receipt before
creation and are deleted only by the owning instance. A failed cleanup retains
its receipt outside the temporary build directory. The Java adapter reuses pinned
JNA5.17.0; Csharp uses platform P/Invoke, Ruby uses standard Fiddle/OpenSSL.

A precreation unavailable provider reports `UNQUALIFIED`; that result proves only
compilation/refusal, not hardware acceptance. Any failure after creation fails the
run. Qualification is local, not remote attestation. Owned mutable plaintext and
CEK buffers are cleared where possible; immutable strings and runtime/provider
copies have no guaranteed erasure. Fresh composition has no durable retry state.

The separate `composeOrReplay` / `ComposeOrReplay` / `compose_or_replay` API
persists the exact ciphertext before exposure. Its mandatory current-manifest
callback returns a verified profile02 descendant and comparison time. Every entry,
replay, precommit and postcommit check revalidates the current signature/window,
retained active signing and recipient keys, points and scope. The original intent
and manifest prefix remain unchanged across a retained-key successor. Revocation,
missing current evidence, another root/generation, changed content or recipients,
and decreasing clocks refuse. The journal requires `0 < observed <= now < expires`;
this is stricter than fresh candidate construction. A callback is an application
trust boundary, not proof of live service permission.

The original independently compared generation1 enrollment binds the journal,
including new candidates after an explicitly approved root transition. An old-root
request cannot replay under a new current root. The bounded ZTJ2 format holds at
most256 records/10 MB, exclusive ownership, checksummed clock/records and fsync
before return. Restore checks exact signature, prefix and wrap identities. Torn
writes fail closed rather than automatically recovering a complete prefix;
checksums do not resist hostile filesystem rollback. Do not replace or reset a
journal after an uncertain result. Supply the same original intent and fresh
current evidence to reconcile committed bytes.

The additional clean controls checkout is pinned to
`1b7732ec36bf705f78e69a2cea95b792f04dc772`. Tests cover separate-process protected
signer reopen and exact replay, signed retained/revoked successors, concurrent
retry, clock regression, corruption, postcommit authority loss, and independently
opened rotated-root composition. Durable profile03 election selection uses the separate
[election journal](election-journal.md). Clean native package consumers remain
a separate gate. No live transport is exercised.
