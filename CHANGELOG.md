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
