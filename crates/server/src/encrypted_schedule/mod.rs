// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant recipient-local encrypted scheduling. No runtime or sending gate.
pub mod policy;
pub mod state;
pub mod time;

#[cfg(test)]
mod schema_tests;
