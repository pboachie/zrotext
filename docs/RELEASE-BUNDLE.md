# One source tag, one release bundle

An annotated `vMAJOR.MINOR.PATCH[-rc.N]` tag selects one reviewed commit on
`main`. The tag names source, not a mutable container tag. The Android release
APK embeds the full source commit and carries `versionCode`/`versionName`; the
server image embeds the commit, tag, web static digest, device-stream schema
digest and final migration number. `GET /about/version` reports the server's
nonsecret build metadata. The owner pages link to that endpoint.

The web UI is embedded in the server binary, so its artifact is the deterministic
digest of the five shipped HTML, JavaScript and CSS files. There is no separate
web image in this repository. The server image uses an immutable digest
reference; its human-readable run tag is only a locator.

The bundle manifest is assembled **after** the signed Android APK and server
image are independently built and verified. The image digest cannot be part of
the earlier source tag because it does not exist until after the tagged build.
The manifest binds the tag and full commit to the signed APK SHA-256, Android
version and certificate digest, server image digest, web static digest, device
stream v1 schema digest, migration range and explicit deployment environment.
It records the SHA-256 of both input receipts. Sealed content is recorded as
disabled until its separate approval gates close.

Before creating a bundle, verify the signed APK with
`android/tools/release_candidate.py verify` and verify the published image
digest, provenance and SBOM with `scripts/verify_release_image.py`. Supply their
exact `candidate.json` and `image-receipt.json` outputs. The bundle tool checks
receipt shape and cross-source consistency; it does not replace those artifact
verifiers or attest that the supplied receipts are authentic.

The bundle tool reads only these fixed files in the operator's private home
directory: `~/.zrotext/release-bundle/candidate.json` and
`~/.zrotext/release-bundle/image-receipt.json`. Create that directory with
owner-only permissions (mode `0700` on POSIX), and copy the exact reviewed
receipts there. On Windows, use the equivalent directory under the operator's
home profile with its private ACL. The tool refuses linked or oversized
receipts and writes `release-bundle.json` in the same directory.

From a clean checkout at the annotated tag, with `origin/main` fetched and
the receipts in that private directory:

```sh
python3 scripts/release_bundle.py create \
  --tag v0.1.6-rc.1 --commit "$(git rev-parse HEAD)" \
  --environment staging

python3 scripts/release_bundle.py verify \
  --tag v0.1.6-rc.1 --commit "$(git rev-parse HEAD)" \
  --environment staging
```

`create` refuses to overwrite an existing manifest. `verify` regenerates its
exact canonical JSON from the clean tagged checkout and supplied receipts.
Archive the reviewed manifest and both receipts in private custody before
preparing a different release bundle. On PowerShell, pass `(git rev-parse HEAD)`
as the commit argument and use `python` if `python3` is unavailable.
Keep signing keys, passwords and private approval records outside the source
repository. A bundle is release evidence, not permission to deploy: the
approved signing identity, hosted attestations, phone acceptance and production
change approval remain separate gates.
