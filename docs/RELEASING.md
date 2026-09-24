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

The image embeds the tag, full commit, web static digest, device-stream schema
digest and final migration number. Its `/about/version` endpoint reports those
nonsecret build values. After independently verifying the signed Android APK
and server image, bind their receipts to one tag and environment with the
[release bundle procedure](RELEASE-BUNDLE.md). This metadata does not authorize
deployment.

Before writing the receipt, the workflow pulls that exact digest and boots its
migrator and API in a disposable Compose project. It checks source labels,
container image IDs, migrations, health, readiness, disabled dispatch and a
seeded logical restore with two synthetic tenants and persisted delivery and
usage state. It also retrieves the BuildKit SPDX SBOM from the published digest,
requires a nonempty package inventory, and signs that exact SBOM as a GitHub
attestation for the same digest. A failed rehearsal or missing SBOM leaves no
promotion receipt. The registry may retain the uniquely tagged image after a
failure; do not promote it.

Before linking an image from the GitHub Release, review the workflow result and
download its `image-receipt.json`. From a checkout with fetched release tags,
authenticated `gh` access to the attestation and GHCR, and local Docker, run:

```sh
git fetch origin main --tags
python3 scripts/verify_release_image.py --tag v0.1.0-rc.1 \
  < /trusted/review/image-receipt.json
```

Select the tag independently of the receipt. This verifies the receipt's
derived fields, annotated tag and `main` ancestry, GitHub's provenance
attestation for the exact image digest with the release workflow and source
ref/SHA pinned, and a separately verified SPDX SBOM attestation whose content
matches the BuildKit SBOM retrieved from that same published digest. It then
pulls that digest and checks its source labels. This requires Docker Buildx,
the GitHub CLI, and registry access to the image and its attestations. A
receipt or mutable registry tag alone is insufficient. Confirm the package is
publicly readable without registry credentials before offering it to
self-hosters. A successful image verification does not establish Android,
phone, database-restore, or hosted-deployment readiness. BuildKit's default
SBOM inventories the final server image, not build-stage dependencies.

## Android candidate custody

The manual `android-release-candidate.yml` workflow builds and uploads only an
unsigned APK, its CycloneDX release-runtime SBOM, and a receipt containing both
SHA-256 digests. The pinned CycloneDX Gradle task resolves only
`releaseRuntimeClasspath`; test, KSP, and other build-only dependencies remain
in the Gradle lockfile and dependency graph, outside this shipped-app
inventory. GitHub attests the SBOM as a predicate of the exact unsigned APK and
verifies the receipt, APK identity, SBOM inventory, and signed attestation against
the checked-out source commit before uploading the files. Artifacts from this public
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
review machine, verify them without loading the signing key. Select the source
tag independently from the reviewed GitHub Release, fetch it and `main`, and
obtain the signing certificate SHA-256 from an independently approved custody
record. Before inspecting candidate artifacts, prepare a release approval
manifest outside the checkout and artifact root with the selected tag,
certificate fingerprint, and approved Android `versionCode` and `versionName`.
Obtain those values from the reviewed release decision and certificate custody
record, never from `candidate.json`, `unsigned.json`, or the APK. For one
release bundle, the Android `versionName` must share the tag's
`MAJOR.MINOR.PATCH` core; a suffix may describe the app build. Approve the
exact tag and app version pair for this distribution. A manifest prepared from
candidate artifacts provides no
independent check. For example, the separately approved file has this shape:

```json
{
  "source_tag": "v0.1.0-rc.1",
  "certificate_sha256": "<approved-64-character-hex-fingerprint>",
  "version_code": 1,
  "version_name": "<approved-app-version>"
}
```

The local artifact root is
`~/.local/state/zrotext/android-release` on Linux and macOS, and
`%USERPROFILE%\AppData\Local\ZROtext\android-release` on Windows. Its `unsigned` and
`candidate` subdirectories hold the transferred artifacts. The private signing
keystore is separately at `~/.local/state/zrotext/android-signing/keystore.p12`
and `%USERPROFILE%\AppData\Local\ZROtext\android-signing\keystore.p12`, respectively. Keep the
keystore outside the artifact root so it cannot be included in a transfer.
The signing alias is `zrotext-release`; supply its two passwords through
`ZROTEXT_ANDROID_KEYSTORE_PASSWORD` and `ZROTEXT_ANDROID_KEY_PASSWORD` in the
private signing environment. Do not put passwords on the command line or in a
repository file.

The paths are fixed under the current user's home directory. The tool creates the artifact root and new output directories with
owner-only access. Before reading transferred artifacts or a signing key, it
rejects a symlink, a foreign owner, or a group/world-accessible artifact root,
`unsigned` or `candidate` directory, keystore directory, or keystore file on
POSIX. The keystore file should have mode `0600` and its directory `0700`.
On Windows the tool restricts newly created artifact directories to the current
user and checks owner and allow rules on existing directories and the key;
prepare the key directory and file with current-user-only ACLs. It never fixes
an insecure existing key automatically. It also rejects symlinked or oversized
artifact files, caps central-directory metadata before opening APK ZIPs, and
caps uncompressed entries before reading them.

```sh
git fetch origin main --tags
python3 android/tools/release_candidate.py verify \
  --source-tag v0.1.0-rc.1 \
  --certificate-sha256 <approved-64-character-hex-fingerprint> \
  --approval-stdin < /trusted/review/release-approval.json
```

The verifier reads the bounded approval record from standard input. Keep the
approved file outside the checkout and artifact root; select and redirect it
on the review machine. On PowerShell, use `Get-Content -Raw -Encoding utf8`
to pipe the file into the same verifier command.

The verifier requires an annotated version tag whose object matches the
published `origin` tag, a fresh fetched `origin/main`, and tag commit ancestry
on that branch. It then checks both receipts and checksums against that tag's
source commit, approved app version, package and SDK identity, the hashed release-runtime SBOM,
GitHub's verified CycloneDX attestation for the exact unsigned APK digest and
source commit, every uncompressed APK ZIP entry, ZIP alignment, the v3
signature (supported by the app's API 28 minimum) with `apksigner`, and the
approved certificate fingerprint. Matching APK contents links the attested
unsigned artifact to the privately signed candidate. Install the GitHub CLI
with attestation access and Android SDK
build tools (`aapt`, `zipalign`, and
`apksigner`) before running it. The unsigned APK, signed APK, and receipts must
remain outside the source checkout. This check does not authorize publication
or replace a physical-device acceptance test.
