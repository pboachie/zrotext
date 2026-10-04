// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate root possession and encrypted backup codecs, shared without a server dependency.
//!
//! These codecs do not provide enrollment authority, custody, file or terminal I/O,
//! networking, recovery-kit lifecycle, rotation, reset or recovery policy.

/// Closed account-only first manifest signing after independent identity review.
#[cfg(feature = "unlock")]
pub mod account_genesis;
/// Existing-archive-only encrypted codec, default-off with offline custody.
#[cfg(feature = "unlock")]
pub mod archive_backup;
/// Explicit archive creation snapshot; the caller supplies separate material.
#[cfg(feature = "unlock")]
pub use archive_backup::creation as archive_init;
/// Typed offline conversation refresh; compiled only in the explicit unlock build.
#[cfg(feature = "unlock")]
pub mod conversation_refresh;
#[cfg(feature = "unlock")]
pub use conversation_refresh::activation as conversation_activation;
/// Typed first manifest signing with independently compared public points.
#[cfg(feature = "unlock")]
pub mod conversation_genesis;
/// Cryptographic stage-root evidence only; signing is offline unlock-only.
pub mod preaccount_root_evidence;
/// One historical contact statement signature with a genuinely recovered root.
#[cfg(feature = "unlock")]
pub mod contact_reader_signing;
pub mod recovery_kit;
pub mod root_backup;
/// Offline unlock signing, compiled only when the `unlock` feature is
/// enabled. The server never enables it; only the owner CLI's own
/// default-off `unlock` feature does.
#[cfg(feature = "unlock")]
pub mod root_unlock;
pub mod sealed_root_enrollment;

/// Dedicated line approval-key codec/verification; secret signing is unlock-only.
pub mod line_key_registration;
