# Changelog

All notable changes to the ZROtext server are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The
server version is the `version` field of `crates/server/Cargo.toml`, and each
release is the `v<version>` tag of that commit. The release lane publishes the
section for the released version as the GitHub release notes, so a version bump
cannot be released without a non-empty section here. The Android app, the
TypeScript SDK and the npm packages keep their own independent versions.

## [Unreleased]

### Changed

- Nothing yet.

## [1.0.3] - 2026-10-29

### Fixed

- A PostgreSQL 18.6 dump and second restore can regroup three schema 119
  CHECK expressions, leaving the stored writer graph inconsistent with the
  graph the stock runtime-role verifier rebuilds, so readiness fails after a
  restore. A narrowly scoped migrator replay path now reconstructs exactly
  those three constraints transactionally and verifies the stored graph is
  restored; migrations 108, 109 and 119, the stored graph hash and the stock
  role scripts are unchanged, and any other graph drift is still refused.

### Notes

- This final `1.0.3` collects the `1.0.3-rc` candidate series; the fix above
  shipped as `1.0.3-rc.4`. No server behavior changed after `1.0.3-rc.4` —
  main ahead of that tag only carries the automatic release lane itself.

## [1.0.3-rc.3] - 2026-10-28

### Added

- Numbered database migrations through `119`, extending database fencing and
  current-state checks for reviewed conversation operations.
- Narrow compatibility for a known restored schema 107 function configuration
  while retaining the migration 108 guard.
- Improved metadata graph construction while preserving canonical graph bytes,
  catalog seals and runtime-role verification.

### Security

- Existing authorization, approval expiry and dispatch gates are preserved. A
  version change does not enable messaging or live billing.

### Upgrade notes

- Existing installations need the maintained migration and runtime-role
  provisioning procedures, with separately qualified backup and restore
  evidence. An older application binary is not a database downgrade procedure.
