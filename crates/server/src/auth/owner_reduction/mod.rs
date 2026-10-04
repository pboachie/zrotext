// SPDX-License-Identifier: AGPL-3.0-only
//! Held ordinary-owner checks for reducing contact issuance state. No root,
//! password or factor requirement; no authority survives the transaction.

use super::{AuthError, SESSION_IDLE_HOURS, SessionPrincipal};
use tokio_postgres::Transaction;

/// Only actual row acquisition creates this borrowed, nonserializable fence.
pub(crate) struct OwnerReductionFence<'tx, 'connection, 'principal> {
    tx: &'tx Transaction<'connection>,
    principal: &'principal SessionPrincipal,
    acquired_ms: i64,
}

impl<'tx, 'connection, 'principal> OwnerReductionFence<'tx, 'connection, 'principal> {
    pub(crate) async fn acquire(
        tx: &'tx Transaction<'connection>,
        principal: &'principal SessionPrincipal,
    ) -> Result<Self, AuthError> {
        let account = principal.tenant.account_id();
        // Separate queries specify the real acquisition order. NOWAIT limits
        // row contention; table/FK waits and other lock orders still exist.
        tx.query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE NOWAIT",
            &[&account],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
        tx.query_opt(
            "SELECT id FROM users WHERE id=$1 AND email_verified_at IS NOT NULL FOR SHARE NOWAIT",
            &[&principal.user_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
        tx.query_opt(
            "SELECT user_id FROM memberships WHERE account_id=$1 AND user_id=$2 AND role='owner' AND revoked_at IS NULL FOR SHARE NOWAIT",
            &[&account, &principal.user_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
        tx.query_opt(
            "SELECT id FROM sessions WHERE id=$1 AND account_id=$2 AND user_id=$3 FOR SHARE NOWAIT",
            &[&principal.session_id, &account, &principal.user_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
        let mut fence = Self {
            tx,
            principal,
            acquired_ms: 0,
        };
        fence.acquired_ms = fence.final_check(0).await?;
        Ok(fence)
    }

    /// Called after the last reducing write, while all SHARE locks remain held.
    /// This is neither an MFA check nor a wall-clock-free response lease.
    pub(crate) async fn final_check(&self, previous_ms: i64) -> Result<i64, AuthError> {
        let p = self.principal;
        let row = self.tx.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint, \
             EXISTS(SELECT 1 FROM accounts a JOIN memberships m ON m.account_id=a.id \
             JOIN users u ON u.id=m.user_id JOIN sessions s ON s.account_id=a.id AND s.user_id=u.id \
             WHERE a.id=$1 AND u.id=$2 AND s.id=$3 AND a.disabled_at IS NULL \
             AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL \
             AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
             AND COALESCE(s.last_used_at,s.created_at)>clock_timestamp()-make_interval(hours=>$4))",
            &[&p.tenant.account_id(), &p.user_id, &p.session_id, &SESSION_IDLE_HOURS],
        ).await?;
        let now: i64 = row.get(0);
        if now <= 0 || now < self.acquired_ms.max(previous_ms) || !row.get::<_, bool>(1) {
            return Err(AuthError::Unauthorized);
        }
        Ok(now)
    }
}

#[cfg(test)]
mod tests;
