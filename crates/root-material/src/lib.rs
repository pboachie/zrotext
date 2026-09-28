// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate root possession and encrypted backup codecs, shared without a server dependency.
//!
//! These codecs do not provide enrollment authority, custody, file or terminal I/O,
//! networking, recovery-kit lifecycle, rotation, reset or archive recovery.

pub mod recovery_kit;
pub mod root_backup;
pub mod root_unlock;
pub mod sealed_root_enrollment;
