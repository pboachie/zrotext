# Historical contact field candidates

Rust and Go verify generation-one profile02 contact reader statements and
produce or verify field commitments over **already encrypted** bytes. The APIs
return owned signature provenance. They do not encrypt/decrypt contact fields,
establish current permission, submit requests, or persist history. Mutation and
transition production use the separate typed APIs described in
[historical contact mutations](contact-mutation.md).

Statement verification requires an actual native `Manifest`, plus independently
supplied account, canonical origin and compared root fingerprint. It rechecks
the exact accepted manifest at the statement's declared issue time, including
archive role2/scope12 and root role6/scope0 activity and end times. The issue time
must be at least the manifest issue time. This matches the maintained historical
contact API; it is intentionally distinct from a locally sampled live grant.
Only private copies lose their comparison floor for this historical recheck.
The original accepted token and live/durable comparison state are unchanged.

Go exposes `VerifyContactStatement02`, `VerifyContactField01`,
`ProduceSoftwareContactField01` and `ProduceProtectedContactField01`.
Rust exposes the corresponding `contact::verify_statement02`, `verify_field01`,
`produce_software_field01` and `produce_protected_field01` functions.
The software methods explicitly accept exportable scalar material. Rust's
owned scalar buffer and signing key are cleared on drop; Go clears its owned
scalar byte copy, without promising erasure of provider/internal arithmetic
allocations. Neither software entrypoint claims protected custody.

The protected methods require the concrete Windows `ContactRootSigner`.
Creation records the private pending alias receipt before creating the exact
key. Provider/hardware, export policy, private-export refusal and actual native
signature qualification are cumulative. Its dedicated alias namespace and
private signer prevent importing it as the envelope signer capability. No
arbitrary digest/domain, root enrollment, reader-statement or manifest signing
method is exported. Tests provision synthetic enrollment through private
test-only access, separately from the production API. Applications must supply
their independently enrolled root authority through their own provisioning.
The caller owns handle close and exact newly-created-key deletion. Close never
deletes a persistent key, and opening an existing key never grants deletion.

Field and mutation operations share at most four outstanding workers and have a fixed
ten-second limit; Go contexts and Rust `Cancellation` can stop exposure earlier.
Cancellation or timeout never releases capacity or clears a key buffer still
owned by an executing worker. There is no automatic retry. A returned commitment
is historical integrity only, with no automatic review/persistence/submission.

## Origin compatibility and dependencies

Canonical ASCII HTTPS origins use pinned WHATWG parsers, rather than generic
URI splitting: Rust `url=2.5.8` and `idna=1.1.0` (already in the HTTP dependency
graph), and Go `whatwg-url v0.7.0` plus its pinned `x/net/idna` implementation.
The Go parser is Apache-2.0; Rust URL/IDNA and Go x/net retain their published
dependency licenses. No parser source or private dynamic library is injected.

The maintained SDK/Python contract uses decoded ACE label validation from
[UTS46 processing and validity criteria](https://www.unicode.org/reports/tr46/tr46-35.html).
Both wrappers reject empty/all-ASCII decoded ACE labels and decoded labels
starting `xn--`. These are general label rules, not hostname exceptions.
This preserves the pinned maintained contract where some newer URL parsers
differ. The shared runner compares 215 origin cases with the actual maintained
SDK, including ASCII punctuation, canonical ports/addresses and ACE cases.
This is bounded differential evidence, not a claim covering every Unicode
version or every future URL standard.

## Repeatable qualification

Use a clean checkout of producer commit
`ccf28fe445ba959aa01d99fed6bd9ee3188b749c`, then run `npm ci --ignore-scripts`
and `npm run build` in its `sdk/typescript` directory. Build `go/cmd/contact`
with Go1.26.9 or Rust's `contact` example with Rust1.97.1, then run:

```sh
python sdk/native/hpke-candidate/test-contact-field.py --producer PATH_TO_PINNED_CHECKOUT --binary PATH_TO_NATIVE_PROBE
```

The test-only runner also accepts a trusted `--command-file` JSON argv array.
It checks genuine issue-time cases, full signed-byte mutations, high-S
equivalent signatures, independent scope, wrong keys and cancellation, then
has the maintained SDK independently verify three native-produced fields.
Unit tests exercise cancelled/outstanding capacity and the real ten-second
deadline. Software CI runs on Linux and Windows.

For actual Windows protected tests, set `ZROTEXT_CONTACT_FIXTURE_ROOT` to that
clean pinned checkout. In `go`, run `go test -run TestContactProtectedHardware
-count=1 -v`. In `rust`, run `cargo test --locked contact_hardware_fields --
--ignored --nocapture`. These tests create a fresh temporary private receipt,
sign three synthetic fields, independently verify them in the maintained SDK,
refuse closed providers and envelope alias reuse, delete only their owned key,
and check that the deleted key cannot reopen. The receipt is marked deleted
and retained outside the public repository. Normal hosted software runs do not
qualify protected hardware. Installed-package qualification and publication
remain separate gates.
