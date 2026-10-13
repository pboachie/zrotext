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
python sdk/native/crypto-envelope/composition02-run.py --language java --producer PRODUCER_DIRECTORY
python sdk/native/crypto-envelope/composition02-run.py --language csharp --producer PRODUCER_DIRECTORY
python sdk/native/crypto-envelope/composition02-run.py --language ruby --producer PRODUCER_DIRECTORY
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
copies have no guaranteed erasure. Fresh composition has no durable retry state;
retain returned bytes for external reconciliation and never generate a replacement
after an uncertain outcome. Profile02 exact-replay integration, root transitions,
durable manifest/election selection, and clean native package consumers remain
separate gates. No live transport is exercised.
