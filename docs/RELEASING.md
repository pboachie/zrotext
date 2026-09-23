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

Before linking an image from the GitHub Release, review the workflow result and receipt, verify the image attestation against this repository and the release-image workflow, and confirm the package is publicly readable if it is offered to self-hosters. For example, after authenticating to GHCR, run `gh attestation verify oci://ghcr.io/pboachie/zrotext@sha256:<digest> -R pboachie/zrotext --signer-workflow pboachie/zrotext/.github/workflows/release-image.yml`. Compare the attested source ref and SHA with the annotated tag and receipt. A successful image build does not establish Android, phone, database-restore, or hosted-deployment readiness.

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
