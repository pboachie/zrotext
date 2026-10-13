# Native Python sealed candidate

Experimental cryptographic companion for [native parity #1128](https://github.com/pboachie/zrotext/issues/1128).
This module is separate from stable Python package exports and generated HTTP
clients. It does not establish live permission, durable currentness, delivery,
device custody or release readiness.

Implemented and executed with PyCA `cryptography==50.0.2`:

- Exact profile-02 root pin comparison, manifest syntax, key IDs, role/scope
  rules, low-S P-256 signatures, semantic digest, predecessor/high-water checks
  and dual-signed root transitions. Verifier tokens keep immutable byte snapshots.
- Profile-03 generation-one, zero-anchor manifest upgrade from original signed
  profile-02 evidence and subsequent profile-03 successors. Unsupported genesis
  and generation transitions refuse. Historical predecessor evidence cannot be
  replaced with caller-created metadata.
- Bounded profile-02/03 inbound/outbound envelope syntax, origin signature,
  manifest/line/device/recipient binding and exact byte identity. Public
  verification returns no execution capability or accepted election.
- Full profile-02 archive-only inbound opening: historical signer authority at
  observation time, current reader authority, same root and accepted predecessor
  lineage, RFC 9180 base-mode P-256/HKDF-SHA256/AES128GCM unwrap with the profile's
  exact info and empty wrap AAD, then AES256GCM authentication and strict body text.
  Integration wraps refuse until an independently accepted selection is implemented.

The HPKE implementation uses native PyCA ECDH, HKDF and AEAD primitives with the
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) labeled schedule. TypeScript
`@hpke/core` independently produces the full encrypted fixture. Tests consume
existing signed genesis, rotation and profile-03 vectors rather than accepting
shape-only stand-ins. Profile-03 public vectors contain no recipient private
scalar and therefore establish public verification, not profile-03 decryption.

## Custody and authority boundary

`RecipientCustody` documents the public-point/ECDH provider contract.
`SoftwareRecipient` is the only implemented provider and holds an exportable
PyCA software key. `open_archive_candidate02` names this experimental path
explicitly. It cannot qualify protected storage. `require_protected_custody`
always refuses, including objects that claim a protected capability flag.

No TPM, OS vault, Android Keystore, secure enclave, atomic persistent adapter,
rollback-resistant high-water, receipt store or sender replay journal is supplied.
`advance_trust02` only proposes a new process-local immutable high-water token;
an integration must atomically compare and persist the original predecessor
before accepting effects. Python process-local tokens are not a sandbox against
code already executing in the same interpreter. The trusted caller supplies the
independently compared root, routing scope, current manifest and trusted time.

Owned mutable working DH/KDF/key/plaintext buffers are wiped in `finally` blocks.
PyCA, Python immutable intermediate objects and returned text may retain copies;
this is not an erasure guarantee. Authentication failure precedes text decoding,
and text refusal does not retain a plaintext-carrying decode exception.

## Remaining work before full native parity

| Surface | Current boundary / required follow-on |
|---|---|
| Native outbound composition | Not implemented; needs fresh CSPRNG material, authorized signer custody, exact replay persistence and independent TS consumption |
| Profile-03 body opening | Public origin/manifest verification only; needs accepted election, independently authenticated current account/device/line/audience permission and exact nonempty wrap AAD |
| Protected custody | Unsupported; concrete native provider plus nonexportability, atomic persistence, concurrent CAS, restart and rollback tests required |
| Integration reader selection | Unsupported; needs exact phone-approved selection and interval binding, never an archive alias |
| Live authority and delivery | SDK/server/grant/journal/receiver integration and controlled device acceptance remain under #1054/#1004 |
| Publication / replacement | Neither stable package removal nor registry publication is authorized by these tests |

Run from the repository root after building the maintained TypeScript SDK:

```sh
cd sdk/typescript
npm ci --ignore-scripts --no-audit --no-fund
npm run build
cd ../..
python -m pip install -r sdk/native/sealed-candidate/python/requirements.txt
python -m unittest discover -s sdk/native/sealed-candidate/python -p 'test_*.py'
```

Use an isolated Python environment. Tests invoke the synthetic TypeScript producer
with Node, without an HTTP server, provider account, device, or SMS action.
