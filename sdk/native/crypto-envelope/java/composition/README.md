# Experimental Java protected profile03 composition

The Java composer uses a locally qualified 64-bit Windows PCP ECDSA P-256 signer,
the existing pinned JNA bridge, native JCA AES-GCM and RFC9180 P-256 wraps. The
signer checks hardware capability, public encoding, export policy zero, private
export denial and a verified native signature. It normalizes low S and signs
exact profile03 domain/length-framed bytes. There is no private export or software
fallback. Local qualification is not remote attestation or a transport grant.

`fresh` validates elected/current authority and the complete intent before
randomness and rechecks authority before returning. `composeOrReplay` binds an
independently enrolled root and canonical intent to an application-owned private
journal. It locks the file, validates checksummed records and signatures, and
forces exact ciphertext to disk before exposure. A matching retry revalidates
authority and returns stored bytes. Conflicting intent, partial records and
corruption refuse. Capacity is 256 records and 10 MB. Retain the journal after
uncertain outcomes; never reset it to force retries. Recovery requires independent
application reconciliation. It is not antirollback storage, a defense against
hostile filesystem administrators or a carrier-effect ledger.

The managed candidate preserves the stricter reader requirement that observed
time is at or after manifest/key issuance. Existing TypeScript/Python outbound
authorization uses trusted current time without that same lower bound. This is
an explicit unresolved parity question, not a settled universal protocol rule.
The shared policy and signed-vector decision is tracked in [#1226](https://github.com/pboachie/zrotext/issues/1226).

```text
python sdk/native/crypto-envelope/java/composition/run.py --producer PRODUCER_CHECKOUT
```

The runner checks the maintained producer revision and JNA digest, compiles with
Java17 warnings as errors, and uses a read-only precreation probe. Unavailable
capability is `UNQUALIFIED`; later failures fail. A fresh synthetic native signer
point is passed to the independent producer. The maintained TypeScript consumer
verifies low-S signatures and opens both recipients for fresh and journaled
native ciphertext. Tests also exercise separate-process reopen, concurrent
callers, lost-response retry, conflicts, truncation and postcommit revocation.
Only the owned signer is deleted; failed cleanup receipts survive temporary
build removal. Owned plaintext/key arrays are cleared where possible, without
claiming erasure of immutable strings or provider/runtime copies.

Profile02 composition, Ruby composition, root transitions and clean native
package consumers remain separate gates. No live transport or SMS is exercised.
