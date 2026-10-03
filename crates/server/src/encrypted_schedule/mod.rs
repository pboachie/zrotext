// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant recipient-local encrypted scheduling. No runtime or sending gate.
pub(crate) mod permit;
pub mod policy;
pub use permit::Actor;
pub(crate) mod lifecycle;
pub mod state;
pub mod store;
pub mod time;
pub mod worker;

#[cfg(test)]
mod schema_tests;

#[cfg(test)]
mod store_tests;
