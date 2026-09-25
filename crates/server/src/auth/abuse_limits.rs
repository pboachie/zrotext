// SPDX-License-Identifier: AGPL-3.0-only
//! Shared PostgreSQL request budgets for public auth and enrollment routes.
//! Counts are spent before password hashing or pairing proof work.
//!
//! Each route has an anonymous budget that any caller can spend with made-up
//! subjects. Exhausting it must not lock out real owners and phones, so a
//! refused request may still be admitted through `consume_or_verify` once a
//! cheap indexed probe proves its subject is live (a device, a pairing and its
//! one-use secret, a login challenge). Login instead accepts a login-client
//! token and charges that browser's own subject. Either way the request spends
//! a per-subject budget plus a separate, larger verified-route ceiling that
//! made-up subjects never reach. Email verification probes live one-use codes
//! the same way.

use super::TokenHasher;
use std::future::Future;
use tokio_postgres::Client;

/// Verified subjects share a route ceiling this many times the anonymous one.
/// It is a backstop against many real subjects, not the per-subject limit.
const VERIFIED_CEILING_FACTOR: i32 = 10;

#[derive(Clone, Copy, Debug)]
pub enum Limit {
    OutboundAccept,
    Registration,
    Login,
    Resend,
    Verify,
    PasswordResetRequest,
    PasswordResetConfirm,
    PasswordChange,
    SessionsRevokeOthers,
    PairClaim,
    PairProof,
    DeviceChallenge,
    DeviceAuthenticate,
    MfaChallenge,
    MfaManage,
    BillingSession,
    ApiKeyCreate,
}

impl Limit {
    fn policy(self) -> (&'static str, i32, i32, Option<(i32, i32)>) {
        // (scope, global attempts, global window seconds, subject policy)
        match self {
            Self::ApiKeyCreate => ("api_key_create", 600, 60, Some((20, 86_400))),
            Self::OutboundAccept => ("alpha_send", 600, 60, Some((60, 60))),
            Self::Registration => ("registration", 120, 3_600, Some((3, 86_400))),
            Self::Login => ("login", 240, 60, Some((12, 900))),
            Self::Resend => ("resend", 120, 60, Some((12, 900))),
            Self::Verify => ("verify", 120, 60, None),
            Self::PasswordResetRequest => ("password_reset_request", 120, 60, Some((3, 86_400))),
            Self::PasswordResetConfirm => ("password_reset_confirm", 120, 60, Some((8, 3_600))),
            Self::PasswordChange => ("password_change", 120, 60, Some((8, 900))),
            Self::SessionsRevokeOthers => ("sessions_revoke_others", 120, 60, Some((8, 900))),
            Self::PairClaim => ("pair_claim", 300, 60, Some((20, 60))),
            Self::PairProof => ("pair_proof", 300, 60, Some((20, 60))),
            Self::DeviceChallenge => ("device_challenge", 300, 60, Some((30, 60))),
            Self::DeviceAuthenticate => ("device_authenticate", 300, 60, Some((30, 60))),
            Self::MfaChallenge => ("mfa_challenge", 300, 60, Some((5, 300))),
            Self::MfaManage => ("mfa_manage", 120, 60, Some((8, 900))),
            Self::BillingSession => ("billing_session", 120, 60, Some((8, 60))),
        }
    }
}

/// Charge the subject and route together. A rejected route charge rolls back
/// the subject write so distinct rejected identifiers cannot grow the table.
/// `subject` must already be normalized by the caller; HMAC hides it from the
/// database.
pub async fn consume(
    client: &Client,
    hasher: &TokenHasher,
    limit: Limit,
    subject: Option<&str>,
) -> Result<bool, tokio_postgres::Error> {
    let (scope, global_max, global_seconds, _) = limit.policy();
    let global_hash = hasher.digest(b"abuse-global-v1", scope);
    charge(
        client,
        hasher,
        limit,
        subject,
        &global_hash,
        global_max,
        global_seconds,
    )
    .await
}

/// Admit a subject the caller has verified is real after the anonymous route
/// budget refused it. The per-subject budget is the same one `consume` spends;
/// only the route ceiling differs.
pub async fn consume_verified(
    client: &Client,
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
) -> Result<bool, tokio_postgres::Error> {
    let (scope, global_max, global_seconds, _) = limit.policy();
    let ceiling_hash = hasher.digest(b"abuse-verified-v1", scope);
    charge(
        client,
        hasher,
        limit,
        Some(subject),
        &ceiling_hash,
        global_max * VERIFIED_CEILING_FACTOR,
        global_seconds,
    )
    .await
}

/// Spend the anonymous budget first. Only when it refuses does `live` run;
/// a live subject is then charged through `consume_verified`. `live` must be a
/// cheap indexed lookup that performs no credential or signature work.
pub async fn consume_or_verify<E: From<tokio_postgres::Error>>(
    client: &Client,
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
    live: impl Future<Output = Result<bool, E>>,
) -> Result<bool, E> {
    if consume(client, hasher, limit, Some(subject)).await? {
        return Ok(true);
    }
    if !live.await? {
        return Ok(false);
    }
    Ok(consume_verified(client, hasher, limit, subject).await?)
}

async fn charge(
    client: &Client,
    hasher: &TokenHasher,
    limit: Limit,
    subject: Option<&str>,
    route_hash: &[u8; 32],
    route_max: i32,
    route_seconds: i32,
) -> Result<bool, tokio_postgres::Error> {
    let (scope, _, _, subject_policy) = limit.policy();
    let subject_hash = subject
        .zip(subject_policy)
        .map(|(subject, _)| hasher.digest(format!("abuse-subject-{scope}-v1").as_bytes(), subject));
    let (subject_max, subject_seconds) = subject_policy.unwrap_or((0, 0));
    let subject_bytes: Option<&[u8]> = subject_hash.as_ref().map(|hash| &hash[..]);
    let row = client
        .query_one(
            "SELECT auth_abuse_consume($1,$2,$3,$4,$5,$6,$7)",
            &[
                &scope,
                &&route_hash[..],
                &subject_bytes,
                &route_max,
                &route_seconds,
                &subject_max,
                &subject_seconds,
            ],
        )
        .await?;
    Ok(row.get(0))
}

/// Bounded cleanup; safe for concurrent workers due to SKIP LOCKED.
pub async fn prune(client: &Client) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            "WITH stale AS (
                SELECT scope,subject_hash FROM auth_abuse_counters
                WHERE updated_at < now() - CASE scope
                    WHEN 'registration' THEN interval '25 hours'
                    WHEN 'password_reset_request' THEN interval '25 hours'
                    WHEN 'password_reset_confirm' THEN interval '61 minutes'
                    WHEN 'api_key_create' THEN interval '25 hours'
                    WHEN 'inbound_daily' THEN interval '25 hours'
                    WHEN 'login' THEN interval '16 minutes'
                    WHEN 'resend' THEN interval '16 minutes'
                    WHEN 'mfa_manage' THEN interval '16 minutes'
                    WHEN 'password_change' THEN interval '16 minutes'
                    WHEN 'sessions_revoke_others' THEN interval '16 minutes'
                    WHEN 'mfa_challenge' THEN interval '6 minutes'
                    ELSE interval '2 minutes' END
                ORDER BY updated_at LIMIT 5000 FOR UPDATE SKIP LOCKED
             ) DELETE FROM auth_abuse_counters a USING stale s
             WHERE a.scope=s.scope AND a.subject_hash=s.subject_hash",
            &[],
        )
        .await
}

#[cfg(test)]
mod tests;
