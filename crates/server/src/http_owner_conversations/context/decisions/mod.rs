// SPDX-License-Identifier: AGPL-3.0-only
//! Exact owner decisions over immutable workflow ciphertext. No mounted route.
pub mod descriptor;
pub mod fence;
pub mod http;
pub mod lifecycle;
pub mod model;
pub(crate) mod proposal;
pub mod reply;
pub mod responses;
pub mod store;
pub use descriptor::{ActionKey, Descriptor};
pub use fence::{LockedAction, lock_approved};
pub use responses::{Correlation, CorrelationResult, TakeoverResult, correlate_reply, takeover};
pub use store::{ActionState, bind_message, decide, edit, read, register};

#[cfg(test)]
pub(crate) mod tests;
