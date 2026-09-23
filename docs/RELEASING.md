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
