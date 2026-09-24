# Releases and version tags

ZROtext uses Semantic Versioning for published source releases: `vMAJOR.MINOR.PATCH`. Before a stable release, use `vMAJOR.MINOR.PATCH-rc.N` for release candidates, such as `v0.1.0-rc.1`. Increment `N` for each candidate. The `v` prefix and lowercase `rc` are required. Do not move, reuse, or delete a published tag.

The version describes the source release and its documented API and device-protocol compatibility. A Git tag alone does not imply a hosted deployment or an Android app release.

For a release, merge the candidate through a pull request, wait for required checks, then create an annotated tag on the chosen `main` commit. Publish a GitHub Release with the same name and include changes, upgrade steps, compatibility notes, known limitations, and links to any artifacts actually built from that commit. Attach checksums for downloadable binaries. Keep release notes free of customer data, credentials, and private infrastructure details.

```sh
git fetch origin main --tags
git switch main
git pull --ff-only origin main
git tag -a v0.1.0-rc.1 -m "ZROtext v0.1.0-rc.1"
git push origin v0.1.0-rc.1
```

Only the repository maintainer can publish release tags. GitHub rules protect tags from deletion and movement. The release-tag workflow checks the exact version format, requires an annotated tag, and verifies that it points to a `main` commit. Publish a GitHub Release only after that check passes.

Publishing a GitHub Release starts the server-image workflow for that exact tag. It rechecks the annotated tag and `main` ancestry, then builds `deploy/compose/Dockerfile` for `linux/amd64` and publishes to `ghcr.io/pboachie/zrotext`. Each workflow attempt gets a distinct `TAG-runID-attempt` registry tag; the uploaded `image-receipt.json` records the source tag, commit and **immutable image digest**. Promote or deploy only the `ghcr.io/pboachie/zrotext@sha256:...` reference from a reviewed receipt, never a mutable registry tag. The workflow also publishes provenance and SBOM attestations; it does not deploy the image.

Before writing the receipt, the workflow pulls that exact digest and boots its
migrator and API in a disposable Compose project. It checks source labels,
container image IDs, migrations, health, readiness, disabled dispatch and a
seeded logical restore with two synthetic tenants and persisted delivery and
usage state. A failed rehearsal leaves no promotion receipt. The registry
may retain the uniquely tagged image after a failure; do not promote it.

Before linking an image from the GitHub Release, review the workflow result and
download its `image-receipt.json`. From a checkout with fetched release tags,
authenticated `gh` access to the attestation and GHCR, and local Docker, run:

```sh
git fetch origin main --tags
python3 scripts/verify_release_image.py --tag v0.1.0-rc.1 \
  < /trusted/review/image-receipt.json
```

Select the tag independently of the receipt. This verifies the receipt's
derived fields, annotated tag and `main` ancestry, GitHub's attestation for
the exact image digest with the release workflow and source ref/SHA pinned,
then pulls that digest and checks its source labels. A receipt or mutable
registry tag alone is insufficient. Confirm the package is publicly readable
without registry credentials before offering it to self-hosters. A successful
image verification does not establish Android, phone, database-restore, or
hosted-deployment readiness.

## Android candidate custody

The manual `android-release-candidate.yml` workflow builds and uploads only an
unsigned APK and its source/identity receipt. Artifacts from this public
repository can be downloaded by readers, so do not put an Android signing key
or a signed APK into its Actions artifacts. The local
`android/tools/release_candidate.py sign` command verifies an unsigned build
against the exact clean source commit, signs it using a keystore and passwords
held outside the source checkout, and writes a signed APK plus checksum and
certificate receipt outside the repository. Run it only in an approved private
signing environment after reviewing the unsigned build. A signed candidate is
not a published app release; approve the exact APK digest and distribution
channel separately before sharing it.

After the unsigned and signed directories have been transferred to a trusted
review machine, verify them without loading the signing key. Obtain the source
commit from the reviewed annotated tag and the signing certificate SHA-256 from
an independently approved custody record, not from `candidate.json`:

Place the two directories at the tool's fixed external artifact root:
`<system temporary directory>/zrotext-android-release/unsigned` and
`<system temporary directory>/zrotext-android-release/candidate`. The tool
rejects symlinked or oversized artifact files.

```sh
python3 android/tools/release_candidate.py verify \
  --source-commit <full-tag-commit-sha> \
  --certificate-sha256 <approved-64-character-hex-fingerprint>
```

The verifier checks both receipts and checksums, the embedded source commit,
package and SDK identity, every uncompressed APK ZIP entry, ZIP alignment,
the v2 and v3 signatures with `apksigner`, and the approved certificate
fingerprint. Install Android SDK build tools (`aapt`, `zipalign`, and
`apksigner`) before running it. The unsigned APK, signed APK, and receipts must
remain outside the source checkout. This check does not authorize publication
or replace a physical-device acceptance test.
