// SPDX-License-Identifier: AGPL-3.0-only
//! Separate review HTTP surface; ordinary application composition does not mount it.
mod cookies;
pub mod dto;
mod handlers;

/// Explicit library composition only. The ordinary executable never calls it;
/// construction does not assert real deployment/key/database containment.
pub fn unmounted_router(
    access: std::sync::Arc<crate::auth::review_access::storage::ReviewAccess>,
) -> axum::Router {
    crate::ingress::protect(handlers::router(access))
}
