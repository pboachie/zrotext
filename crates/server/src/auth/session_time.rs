// SPDX-License-Identifier: AGPL-3.0-only
//! Final live-principal fence and database clock sample for session responses.
use super::{AuthError, SESSION_IDLE_HOURS, SessionPrincipal};
use tokio_postgres::Client;

pub(crate) async fn sample(
    client: &Client,
    principal: &SessionPrincipal,
) -> Result<String, AuthError> {
    // Re-read after authentication's activity write. The clock and liveness
    // predicates share one final statement; process wall clocks and imported
    // proposal timestamps never become owner authority.
    let row = client
        .query_opt(
            "WITH tick AS MATERIALIZED (SELECT clock_timestamp() AS utc) \
             SELECT floor(extract(epoch FROM tick.utc)*1000)::bigint \
             FROM sessions s \
             JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) \
             JOIN users u ON u.id=s.user_id JOIN accounts a ON a.id=s.account_id \
             CROSS JOIN tick \
             WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 AND m.role=$4 \
               AND m.revoked_at IS NULL AND s.revoked_at IS NULL \
               AND s.expires_at>tick.utc \
               AND COALESCE(s.last_used_at,s.created_at)>tick.utc-($5::integer*interval '1 hour') \
               AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL \
               AND s.csrf_hash=$6",
            &[
                &principal.session_id,
                &principal.tenant.account_id(),
                &principal.user_id,
                &principal.role.as_str(),
                &SESSION_IDLE_HOURS,
                &&principal.csrf_hash[..],
            ],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    let utc: i64 = row.get(0);
    if utc <= 0 {
        return Err(AuthError::Unauthorized);
    }
    Ok(utc.to_string())
}

#[cfg(test)]
mod tests;
