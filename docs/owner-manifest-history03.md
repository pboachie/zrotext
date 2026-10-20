# Owner browser accepted manifest history

The additive TypeScript `accepted-manifest-history03` module verifies a complete
same-root profile03 manifest history. It leaves the first-election current
transport and parser unchanged. The owner conversation page now provides a
separate explicit recovery controller for accepted history. Its HTTP history
routes still require separate server library composition before deployment.

`startAcceptedManifestHistory03` requires a genuine historical election proof,
a genuine first03 manifest token at its original acceptance checkpoint, the
original ten evidence fields, and the independently configured HTTPS origin.
The proof accessor returns owned historical metadata, never current authority.
The caller must independently verify the original compared root, registration,
activation and actual retained acceptance provenance. A parsed record cannot
replace either private proof token.

For a fresh browser without an original local journal, the client's explicit
`original(lineId)` reads the additive `/manifests/original` route before any
history token exists. It returns only closed historical candidates and their
actual retained binding UUID. That UUID is absent from signed E500 bytes but
needed for the base prefix. The response does not create a proof token. The
controller must verify the independently compared root and original evidence
before constructing the genuine first-election inputs. A physical/current
permission is neither required for this public history read nor inferred from it.

`continueAcceptedManifestHistory03` captures one closed page before asynchronous
crypto. It verifies contiguous original root signatures, the role05 possession
signature and full stated owner/election/origin scope, original proof windows,
the exact enrollment/renewal/replacement record policy, and each prefix
commitment. Pagination fixes the exact signed tip, digest, acceptance and full
prefix. Later pages cannot silently move it. Incomplete pages cannot produce a
current result. Original evidence remains byte-exact; no later manifest replaces
the first03 evidence field. More than32 historical renewals are supported;
each explicit call still accepts at most8 entries and64KiB raw entry material.

`OwnerManifestHistoryClient03` reads one page per explicit `next` call from the
fixed same-origin owner history endpoint. It uses cookie credentials, the
unchanged selected CSRF value, no redirects or cache, a192KiB response bound,
strict decoded-duplicate JSON handling and one finite deadline across fetch,
streaming, parsing and crypto. Abort, changed sign-in, changed tip, failure or
unknown response never causes an automatic retry or mutation. It stores no
password, factor or private key.

Only a complete history can use `current` against the distinct additive current
endpoint. That response must match the actual configured owner/session,
original evidence, selected binding and full verified manifest/prefix. Current
server selection and physical-source metadata remain trusted adapter inputs,
not client cryptographic proof of hardware or a new effect permit. Fresh trusted
time is checked synchronously after the final cryptographic wait, immediately
before release, and the last successful local clock is retained across reads.
A historical signature or matching
public digest never creates current owner, factor, device or content permission.

The separate `original-manifest-history03` verifier reconstructs historical
registration, activation, E500 and first03 proofs from the actual fixed original
read and independently compared root, phone point and original02 checkpoint.
It checks the original signed manifests at their retained acceptance times,
including after their windows have elapsed. Received acceptance times and the
binding UUID remain authenticated service record claims, not signed attestations.

The mounted recovery page checks the actual owner session before each explicit
bounded page read. A fresh same-original-user sign-in can reconstruct history
without an old local opening, replacement key, factor or repeated approval.
An actual IndexedDB transaction commits and reads back the exact original
identity, binding, version, digest and ancestry before releasing a current
selection or historical proposal input. Compare-and-set refuses an unseen
other-tab update; history must pass through the previously committed checkpoint,
including when that checkpoint falls inside a later page. A request success
without transaction completion is not durable. An uncertain storage outcome
can be reconciled by reopening. There is no lifetime manifest-history quota.

These crypto tokens and the separate current tuple are inputs to later message
review. Subsequent composition still must withdraw old interval lifetimes before
new-tip publication, compare the actual phone selection, obtain explicit content
consent, and compose authenticated admission/fetch. No old message, interval or
attempt is translated to a later signer or selection. No browser runtime,
physical device, carrier delivery, deployment or release is qualified by these
source tests.
