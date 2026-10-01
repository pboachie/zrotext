// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate root possession and encrypted backup codecs, shared without a server dependency.
//!
//! These codecs do not provide enrollment authority, custody, file or terminal I/O,
//! networking, recovery-kit lifecycle, rotation, reset or recovery policy.

/// Existing-archive-only encrypted codec, default-off with offline custody.
#[cfg(feature = "unlock")]
pub mod archive_backup;
/// Typed offline conversation refresh; compiled only in the explicit unlock build.
#[cfg(feature = "unlock")]
pub mod conversation_refresh;
pub mod recovery_kit;
pub mod root_backup;
/// Offline unlock signing, compiled only when the `unlock` feature is
/// enabled. The server never enables it; only the owner CLI's own
/// default-off `unlock` feature does.
#[cfg(feature = "unlock")]
pub mod root_unlock;
pub mod sealed_root_enrollment;
