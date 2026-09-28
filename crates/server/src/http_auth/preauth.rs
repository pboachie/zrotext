// SPDX-License-Identifier: AGPL-3.0-only
//! Header-only authentication that runs before a request body is read.
//!
//! Axum runs `FromRequestParts` extractors before the single body extractor,
//! so listing [`OwnerMutation`] ahead of `ApiJson`/`Bytes` means a request
//! without a live owner session is answered with 401/403 and releases its
//! ingress permit without waiting for its body. The pooled database client
//! used for the session lookup is dropped before the body is read, so an
//! authenticated client trickling a body cannot hold a database connection
//! either. [`AccountSlot`] then bounds how many of those authenticated requests
//! one account can have in flight at once.
use super::{AuthHttpError, require_member, require_owner, require_session_cookie};
use crate::auth::{SessionPrincipal, TokenHasher};
use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
};
use uuid::Uuid;

/// Authenticated body-carrying requests one account may have in flight in
/// this process. Owner UIs issue these one at a time; the cap stops one
/// signed-in account from pinning the shared owner/API admission pool.
pub const ACCOUNT_IN_FLIGHT: usize = 4;

static IN_FLIGHT: LazyLock<Mutex<HashMap<Uuid, usize>>> = LazyLock::new(Default::default);

/// One of an account's [`ACCOUNT_IN_FLIGHT`] request slots, released on drop.
#[must_use]
pub struct AccountSlot {
    account_id: Uuid,
}

impl AccountSlot {
    /// Takes a slot, or returns `None` when the account is at its cap.
    pub fn try_acquire(account_id: Uuid) -> Option<Self> {
        let mut map = IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = map.entry(account_id).or_insert(0);
        if *count >= ACCOUNT_IN_FLIGHT {
            return None;
        }
        *count += 1;
        Some(Self { account_id })
    }

    #[cfg(test)]
    pub(crate) fn in_flight(account_id: Uuid) -> usize {
        IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&account_id)
            .copied()
            .unwrap_or(0)
    }
}

impl Drop for AccountSlot {
    fn drop(&mut self) {
        let mut map = IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = map.get_mut(&self.account_id) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.account_id);
            }
        }
    }
}

/// What an owner-authenticated router needs to check a session.
pub trait OwnerAuthState: Send + Sync + 'static {
    fn database_url(&self) -> &str;
    fn session_hasher(&self) -> &TokenHasher;
    fn canonical_origin(&self) -> &str;
    /// The router's own response when the session store is unreachable.
    fn unavailable_response(&self) -> Response {
        AuthHttpError::Unavailable.into_response()
    }
}

/// An owner session authorized for a mutation (exact Origin plus CSRF cookie
/// and header), plus the account's in-flight slot. Bind the slot to a named
/// variable (not `_`) so it is held until the handler returns.
pub struct OwnerMutation(pub SessionPrincipal, pub AccountSlot);

impl<S: OwnerAuthState> FromRequestParts<Arc<S>> for OwnerMutation {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<S>) -> Result<Self, Response> {
        // Stateless first: no cookie means 401 without touching the pool.
        require_session_cookie(&parts.headers).map_err(IntoResponse::into_response)?;
        let principal = {
            let client = crate::runtime_db::connect(state.database_url())
                .await
                .map_err(|_| state.unavailable_response())?;
            require_owner(
                &client,
                state.session_hasher(),
                state.canonical_origin(),
                &parts.headers,
                true,
            )
            .await
            .map_err(IntoResponse::into_response)?
            // The client returns to the pool here, before any body byte is read.
        };
        let slot = AccountSlot::try_acquire(principal.tenant.account_id())
            .ok_or_else(|| AuthHttpError::TooManyRequests.into_response())?;
        Ok(Self(principal, slot))
    }
}

/// A live membership of any role (owner or observer) authorized for a
/// self-service mutation: password change and session revocation for the
/// caller's own account. Owner authority never routes through this
/// extractor; it keeps using [`OwnerMutation`].
pub struct MemberMutation(pub SessionPrincipal, pub AccountSlot);

impl<S: OwnerAuthState> FromRequestParts<Arc<S>> for MemberMutation {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<S>) -> Result<Self, Response> {
        require_session_cookie(&parts.headers).map_err(IntoResponse::into_response)?;
        let principal = {
            let client = crate::runtime_db::connect(state.database_url())
                .await
                .map_err(|_| state.unavailable_response())?;
            require_member(
                &client,
                state.session_hasher(),
                state.canonical_origin(),
                &parts.headers,
                true,
            )
            .await
            .map_err(IntoResponse::into_response)?
        };
        let slot = AccountSlot::try_acquire(principal.tenant.account_id())
            .ok_or_else(|| AuthHttpError::TooManyRequests.into_response())?;
        Ok(Self(principal, slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_slots_cap_each_account_and_release_on_drop() {
        let account = Uuid::new_v4();
        let other = Uuid::new_v4();
        let held: Vec<_> = (0..ACCOUNT_IN_FLIGHT)
            .map(|_| AccountSlot::try_acquire(account).expect("slot under the cap"))
            .collect();
        assert!(AccountSlot::try_acquire(account).is_none());
        // The cap is per account: another account is unaffected.
        let other_slot = AccountSlot::try_acquire(other).expect("independent account");
        assert_eq!(AccountSlot::in_flight(account), ACCOUNT_IN_FLIGHT);
        drop(held);
        assert_eq!(AccountSlot::in_flight(account), 0);
        let again = AccountSlot::try_acquire(account).expect("released slots are reusable");
        assert_eq!(AccountSlot::in_flight(account), 1);
        drop((again, other_slot));
        assert_eq!(AccountSlot::in_flight(other), 0);
    }
}
