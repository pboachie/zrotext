# Public alpha npm publication

The public package contract is `zrotext`, AGPL-3.0-only, ESM, Node.js 24 or
newer, with no runtime dependencies or lifecycle scripts. Its root exports the
synthetic-alpha client and webhook verifier already implemented in
`sdk/typescript`. It does not expose the sealed-content draft or a general
message-send API. See [the package README](../sdk/npm/README.md).

The checked-in `0.0.0-development` version is a private development sentinel,
not a release candidate. No stable version is selected here. The publishing
workflow is disabled unless the repository variable `NPM_PUBLICATION_ENABLED`
equals `true`. Merging this preparation does not grant npm access or publish.

## Owner setup, performed separately

1. Select an approved, unused `X.Y.Z-rc.N` version consistent with the repository
   release plan. Prepare a reviewed PR updating `sdk/npm/package.json`, both
   public lockfile version fields, `private: false`, a matching changelog heading
   and the README's installation/status wording. Keep the existing draft SDK's
   version and dependencies separate. Tags must be annotated `vX.Y.Z-rc.N` and
   point to the reviewed merge commit on main. Wait for its checks to finish.
2. The npm account `elysra` must verify its email, enable 2FA, and establish
   ownership of `zrotext`. A registry 404 establishes neither ownership nor name
   reservation. Trusted publishing requires an existing package: it cannot
   create a brand-new name. Bootstrap therefore needs a separately approved
   owner-authenticated release of the real reviewed artifact, followed by
   trusted-publisher configuration. This workflow intentionally refuses a
   missing package. Never publish the development sentinel. No reusable token
   belongs in GitHub secrets or this repository.
3. Create the GitHub environment `npm-publication` before activation. Its sole
   required reviewer must be `pboachie` (GitHub user ID `9089767`). Permit only
   tags matching `v*-rc.*`, using a **tag**, not branch, policy. Turn off
   administrator bypass. Keep **prevent self-review off** because the owner
   initiates releases and is the sole reviewer. Other protection rules may add
   restrictions; they must not provide an alternate approval path.
4. In npm, configure trusted publishing for owner `pboachie`, repository
   `zrotext`, workflow filename `npm-publish.yml`, and environment
   `npm-publication`. Select direct publishing only if that is the owner's
   approved operating mode. The workflow uses GitHub-hosted Ubuntu runners,
   Node.js `24.13.0` and npm `11.21.0`. It needs no `NPM_TOKEN` or
   `NODE_AUTH_TOKEN`. OIDC publishing requires npm at least `11.5.1` and Node
   at least `22.14.0`; the pinned client also supports OIDC publication with a
   new distribution tag.
5. Inspect package ownership, trusted-publisher and environment settings, then
   explicitly enable `NPM_PUBLICATION_ENABLED`. This document and PR do not
   perform any of those account or repository setting changes.

[npm staged publishing](https://docs.npmjs.com/staged-publishing/) offers another
bootstrap route with an owner-approved stage and npm's special public bootstrap
version. It is an alternative requiring a separate owner decision, not a step in
this workflow. A stage-only trusted publisher will not execute this workflow's
direct `npm publish`; adopting staging requires a separate pipeline change.

## Triggers and checks

`npm-package.yml` runs on relevant pull requests and every push to main. It
tests guard mutations, installs and audits the locked SDK build graph, builds
and tests the selected alpha surface, packs a real tarball, verifies its file
boundary and installs that exact artifact in a disposable offline consumer.
The consumer checks root imports, declarations, alpha uncertainty behavior,
webhook verification and refusal of sealed/internal deep imports.

`npm-publish.yml` starts on a published GitHub release, or a fresh manual dispatch
on its exact tag. Preflight accepts only published GitHub **prereleases** with
annotated `vX.Y.Z-rc.N` tags. Stable releases and branch dispatches fail. The
source must be a main merge commit with successful `rust`, `android`, `quality`,
`owner-browser` and `npm-package` checks at that exact commit. Its merged PR
head must also have a successful `dependency-review` check. Missing, queued,
failed or skipped evidence stops preparation.

Preparation checks the exact manifest/lock/tag/changelog identity, npm ownership
by `elysra`, unused and increasing preview versions, the existing `next` channel,
and the already configured approval environment. It then installs the locked
SDK, audits for high/critical dependency issues, runs its full tests and compiles
only three selected source modules with declarations. It packs and dry-runs the
actual tarball with scripts disabled. Dry-run does not authenticate or reserve
a version; provenance is disabled only for that dry-run, before OIDC permission.

The artifact contains exactly ten files: six JavaScript/declaration outputs,
`package.json`, `README.md`, the full unchanged `LICENSE` and `CHANGELOG.md`.
The verifier rejects links, unsafe paths, duplicate/extra/missing entries,
oversized data, changed metadata/license/docs, unexpected module imports and
privacy/credential markers. No tests, source maps, internal sources, `.npmrc`,
dependencies or lifecycle scripts enter the tarball. Size limits bound inspection.

A receipt binds the source commit, tag, version, run ID/attempt, environment ID,
public manifest/lock/build-lock hashes, file list and tarball SHA256/SHA512.
Tarball, content inspection, receipt, pack preview and audit results remain in a
run-specific Actions artifact for 30 days. Approval and publication download
that same artifact and verify the prepare job's receipt hash.

## Notification and approval

The notification job reuses the existing maintainer release-checklist marker
and assigned GitHub issue, or creates one assigned to `pboachie`. It mentions
the verified GitHub login with the source commit, artifact digest and Actions
run link. It deduplicates the exact run/artifact notification. No email or Slack
destination is assumed. Notification failure stops publication. A comment or
checkbox is not approval, and successful GitHub delivery cannot guarantee the
user reads a notification.

The publish job waits for the `npm-publication` environment. Once admitted it
rechecks source, registry state, exact package bytes, receipt, environment and
the run's actual deployment-review history. Approval must match both
`pboachie` and the verified numeric user ID. An administrator bypass without
that approval fails the runtime guard. GitHub's environment read API does not
expose the administrator-bypass setting, so the owner must inspect it during
setup; actual review-history validation provides an additional guard.

Only this protected job requests `id-token: write`. It publishes the approved
tarball with `--ignore-scripts --access public --tag next --provenance` and no
registry token. Public repository/package provenance is supported by npm trusted
publishing. Post-publication checks compare the registry's SHA512 integrity,
`next` tag and attestation presence with the receipt. This is not independent
cryptographic verification of the attestation's source claims. Consumers can
inspect npm provenance and use `npm audit signatures` for verification.

## Recovery and limits

Publication runs serialize and never cancel an in-progress publish. Each run
must have attempt `1`: rerunning old jobs cannot reuse historical approval.
Recover a pre-publication failure with a **new** manual dispatch on the exact
annotated release tag and a fresh environment approval. If a version already
exists, stop and compare registry provenance/integrity with the retained receipt;
do not automatically retry publication or claim a network timeout means failure.

An npm version is immutable and an unpublished version cannot be reused.
Post-publication verification failure cannot roll back the registry write.
Prefer a reviewed fix-forward version; owner-authorized deprecation or `next`
tag reassignment may reduce exposure, but cannot remove installed copies.
Unpublishing has npm policy/time/dependency limits. Stable `latest` promotion,
automatic dist-tag rollback and staged publication are outside this preview
workflow. Expired Actions artifacts require retained public receipts or renewed
review, not an assumed byte match. The pipeline does not enable a hosted service,
alter account permissions, or enable messaging.

## Primary references

- [Creating public unscoped packages](https://docs.npmjs.com/creating-and-publishing-unscoped-public-packages/)
- [Creating public scoped packages](https://docs.npmjs.com/creating-and-publishing-scoped-public-packages/)
- [npm trusted publishers and OIDC requirements](https://docs.npmjs.com/trusted-publishers/)
- [npm provenance](https://docs.npmjs.com/generating-provenance-statements/)
- [GitHub environments and required reviewers](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [GitHub workflow review history](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run)
- [npm unpublish policy](https://docs.npmjs.com/policies/unpublish/)
