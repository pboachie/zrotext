# Experimental Windows protected recipient

`ProtectedRecipient` opens the candidate profile02 and elected profile03 readers
using a Windows Microsoft Platform Crypto Provider P-256 key. Qualification checks
the provider hardware bit, exact public blob and curve, export policy zero,
private export refusal, and a real ECDH exchange against an independent peer.
Failure refuses the operation; there is no software fallback. This is local
provider qualification, not remote attestation or a complete product release gate.

Create requires an application callback that durably records and flushes the
fresh alias before native creation. The application owns that pending receipt
and preserves it until deletion succeeds. `Dispose` closes handles without
deleting persistent keys. Only the instance that created a fresh key can call
`DeleteCreated`; reopening requires an independently trusted public point and
does not grant deletion. Application recovery of an interrupted creation must
verify its own receipt and key ownership before removal.

Protected entry points use the existing verified manifest/election and current
authority interfaces. The private scalar never enters managed code. ECDH output,
derived keys, and plaintext necessarily do; this does not promise complete memory
erasure or protection from a compromised process. Public points can be exported.

Run the test with a directory containing the pinned maintained TypeScript
`produce-fixture.mjs` and `produce-election03.mjs` producers, and a new pending
receipt path outside the public checkout:

```text
dotnet run --project sdk/native/crypto-envelope/csharp/custody/CustodyTest.csproj -- PRODUCER_DIRECTORY PENDING_RECEIPT
```

The harness first performs a read-only capability probe. Missing capability
reports `UNQUALIFIED` before creation. Any subsequent failure fails the test.
It creates one synthetic key, asks the independent producer to encrypt to its
public point, opens profile02 inbound/outbound and profile03, checks authority
refusal and public binding, then deletes only its owned key. A failed cleanup
preserves the receipt. Hosted CI without PCP capability proves compilation and
refusal only. Java and Ruby protected-provider qualification remains separate.
