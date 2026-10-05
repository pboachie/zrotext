// SPDX-License-Identifier: AGPL-3.0-only
//! Recoverable Android-local owner custody. Server enrollment authority is unchanged.
//!
//! Root material stays transient in native memory. The encrypted owner bundle and
//! separate recovery token are not hardware-backed root custody. Device/content
//! keys retain their existing, separate hardware requirements.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod bridge;
pub mod custody;
pub mod signing;
pub mod typed;
