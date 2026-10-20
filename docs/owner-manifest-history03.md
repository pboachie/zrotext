# Owner browser accepted manifest history

The additive TypeScript `accepted-manifest-history03` module verifies a complete
same-root profile03 manifest history. It leaves the first-election current
transport and parser unchanged. This is an unmounted source dependency; the
shipping owner controller does not yet use it.

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

The returned crypto token and current tuple are inputs to later message review.
The shipping controller still must persist and read back a separate monotonic
local highwater, withdraw old interval lifetimes before new-tip publication,
compare the actual phone selection, obtain explicit content consent, and compose
the actual authenticated admission/fetch path. No old message, interval or
attempt is translated to a later signer or selection. No browser runtime,
physical device, carrier delivery, deployment or release is qualified by these
source tests.
