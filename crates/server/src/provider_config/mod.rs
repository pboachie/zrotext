// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-created declarations, always unavailable. No provider acceptance,
//! credentials, billing authority, sender, main-mounted router or usage writer.
pub mod http;
pub(crate) mod lifecycle;
mod model;
mod store;

use crate::http_owner_conversations::ConversationError;
pub use model::{Acknowledgment, Declaration, Details, Mutation, Withdrawal};
pub use store::{create, read, revise, withdraw};
type Result<T> = std::result::Result<T, ConversationError>;

#[cfg(test)]
mod tests;
