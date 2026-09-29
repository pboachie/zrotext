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
//! a verified per-subject budget, distinct from the anonymous per-subject
//! counter that anyone naming a public identifier can exhaust, plus a
//! separate, larger verified-route ceiling that made-up subjects never reach.
//! Email verification probes live one-use codes the same way.
//!
//! Limits whose every spender is already authenticated (`subject_only`) charge
//! only the caller's own per-subject row and skip the shared route counter
//! entirely, so one tenant's traffic can neither rate-limit nor serialize
//! another's.

use super::TokenHasher;
use std::future::Future;
use tokio_postgres::{Client, GenericClient, Transaction};

/// Verified subjects share a route ceiling this many times the anonymous one.
/// It is a backstop against many real subjects, not the per-subject limit.
const VERIFIED_CEILING_FACTOR: i32 = 10;

/// Counter rows idle this much longer than their longest window are pruned.
/// The slack absorbs the gap between the prune query's `now()` and the
/// `clock_timestamp()` the charge function records.
const PRUNE_SLACK_SECONDS: i32 = 60;

/// Retention for scopes that no `Limit` or `OTHER_SCOPES` entry names, such
/// as the deployment smoke check's scope.
const DEFAULT_RETENTION_SECONDS: i32 = 120;

/// Scopes charged through `auth_abuse_consume` outside `Limit`, with their
/// longest window in seconds. `inbound_daily` and `inbound_consent_daily` are
/// charged by `inbound::consume_storage_budget` and
/// `inbound::consume_consent_budget` with fixed 24-hour windows.
const OTHER_SCOPES: &[(&str, i32)] =
    &[("inbound_daily", 86_400), ("inbound_consent_daily", 86_400)];

/// Declares `Limit` and `Limit::ALL` from one list so a new variant cannot be
/// left out of prune retention.
macro_rules! limits {
    ($($variant:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug)]
        pub enum Limit {
            $($variant),+
        }

        impl Limit {
            pub const ALL: &'static [Limit] = &[$(Self::$variant),+];
        }
    };
}

limits! {
    OutboundAccept,
    Registration,
    Login,
    Resend,
    Verify,
    PasswordResetRequest,
    PasswordResetVerifiedDaily,
    PasswordResetConfirm,
    PasswordChange,
    SessionsRevokeOthers,
    PairCreate,
    PairClaim,
    PairProof,
    DeviceChallenge,
    DeviceAuthenticate,
    MfaChallenge,
    MfaManage,
    MfaStepUp,
    BillingSession,
    ApiKeyCreate,
    SmsLineActivation,
}

impl Limit {
    /// Whether this limit's subject is a secret only its holder can name (a
    /// sign-in MFA challenge token or a password reset token). Nobody else
    /// can spend such a subject's anonymous counter, so a separate verified
    /// counter would protect nothing and would only double the attempts the
    /// holder gets, such as MFA code guesses per challenge. These limits keep
    /// one per-subject counter across both lanes; only the route ceiling
    /// differs.
    fn subject_is_secret(self) -> bool {
        matches!(self, Self::MfaChallenge | Self::PasswordResetConfirm)
    }

    /// Whether every spender of this limit is an authenticated caller whose
    /// per-subject counter is the intended bound. Such limits charge no shared
    /// route row: one hot counter would serialize the whole deployment on its
    /// row lock and cap all tenants together at the route maximum, so tenants
    /// could rate-limit each other. `OutboundAccept` is spent only by
    /// API-key-authenticated admission paths with a server-derived account
    /// subject; the per-account policy plus billing quotas and device caps
    /// remain the per-tenant bounds.
    fn subject_only(self) -> bool {
        matches!(self, Self::OutboundAccept)
    }

    /// The longest window, route or subject, that this limit's rows track.
    fn longest_window_seconds(self) -> i32 {
        let (_, _, global_seconds, subject) = self.policy();
        subject.map_or(global_seconds, |(_, subject_seconds)| {
            global_seconds.max(subject_seconds)
        })
    }

    fn policy(self) -> (&'static str, i32, i32, Option<(i32, i32)>) {
        // (scope, global attempts, global window seconds, subject policy)
        match self {
            Self::ApiKeyCreate => ("api_key_create", 600, 60, Some((20, 86_400))),
            // Subject-only: authenticated accepts charge just their account
            // row, so the route pair here stays available as the backstop an
            // anonymous lane would spend and sizes prune retention.
            Self::OutboundAccept => ("alpha_send", 600, 60, Some((60, 60))),
            Self::Registration => ("registration", 120, 3_600, Some((3, 86_400))),
            Self::Login => ("login", 240, 60, Some((12, 900))),
            Self::Resend => ("resend", 120, 60, Some((12, 900))),
            Self::Verify => ("verify", 120, 60, None),
            Self::PasswordResetRequest => ("password_reset_request", 120, 60, Some((3, 86_400))),
            // Daily cap on the verified reset lane for one owner address,
            // charged only through `consume_verified`.
            Self::PasswordResetVerifiedDaily => {
                ("password_reset_verified_daily", 120, 60, Some((12, 86_400)))
            }
            Self::PasswordResetConfirm => ("password_reset_confirm", 120, 60, Some((8, 3_600))),
            Self::PasswordChange => ("password_change", 120, 60, Some((8, 900))),
            Self::SessionsRevokeOthers => ("sessions_revoke_others", 120, 60, Some((8, 900))),
            Self::PairCreate => ("pair_create", 120, 60, Some((10, 900))),
            Self::PairClaim => ("pair_claim", 300, 60, Some((20, 60))),
            Self::PairProof => ("pair_proof", 300, 60, Some((20, 60))),
            Self::DeviceChallenge => ("device_challenge", 300, 60, Some((30, 60))),
            Self::DeviceAuthenticate => ("device_authenticate", 300, 60, Some((30, 60))),
            Self::MfaChallenge => ("mfa_challenge", 300, 60, Some((5, 300))),
            Self::MfaManage => ("mfa_manage", 120, 60, Some((8, 900))),
            // Spent through `record_failure` only; its route pair is unused.
            Self::MfaStepUp => ("mfa_step_up", 120, 60, Some((5, 900))),
            Self::BillingSession => ("billing_session", 120, 60, Some((8, 60))),
            Self::SmsLineActivation => ("sms_line_activation", 120, 60, Some((30, 900))),
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
    charge(client, hasher, limit, subject, Lane::Anonymous).await
}

/// Admit a subject the caller has verified is real after the anonymous lane
/// refused it. The subject counter and the route ceiling are both distinct
/// from the ones `consume` spends, so anonymous callers who name a live
/// device or pairing ID cannot use up the budget its real holder needs.
pub async fn consume_verified(
    client: &Client,
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
) -> Result<bool, tokio_postgres::Error> {
    charge(client, hasher, limit, Some(subject), Lane::Verified).await
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

/// Charge the existing owner-management policy inside an owned transaction.
/// The caller must lock and authenticate its owner before spending this budget.
pub(crate) async fn consume_owner_management(
    tx: &Transaction<'_>,
    hasher: &TokenHasher,
    subject: &str,
) -> Result<bool, tokio_postgres::Error> {
    charge(tx, hasher, Limit::MfaManage, Some(subject), Lane::Anonymous).await
}

/// Which counters a charge spends. The anonymous lane is open to anyone who
/// names a subject. The verified lane is reached only by a caller who has
/// shown the subject is live, so it keeps a per-subject counter of its own
/// and a route ceiling `VERIFIED_CEILING_FACTOR` times the anonymous one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lane {
    Anonymous,
    Verified,
}

/// The HMAC key of `subject`'s counter row in `lane`, or `None` for a limit
/// without a per-subject policy. Tests use it to seed counters.
pub(crate) fn subject_hash(
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
    lane: Lane,
) -> Option<[u8; 32]> {
    let (scope, _, _, subject_policy) = limit.policy();
    subject_policy?;
    let domain = match lane {
        Lane::Verified if !limit.subject_is_secret() => {
            format!("abuse-subject-{scope}-verified-v1")
        }
        Lane::Anonymous | Lane::Verified => format!("abuse-subject-{scope}-v1"),
    };
    Some(hasher.digest(domain.as_bytes(), subject))
}

/// Failures `subject` has spent in the current window of a failure-only
/// budget such as `Limit::MfaStepUp`. Such a budget is spent only by a
/// rejected factor, so the caller checks it before verifying and calls
/// `record_failure` after a rejection. Both must run in one transaction that
/// already holds a row lock serializing the subject.
pub(crate) async fn failures_in_window(
    client: &impl GenericClient,
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
) -> Result<i32, tokio_postgres::Error> {
    let (scope, _, seconds, hash) = failure_subject(hasher, limit, subject);
    let row = client
        .query_opt(
            "SELECT attempts FROM auth_abuse_counters WHERE scope=$1 AND subject_hash=$2
             AND window_started_at > clock_timestamp() - make_interval(secs => $3::int4)",
            &[&scope, &&hash[..], &seconds],
        )
        .await?;
    Ok(row.map_or(0, |row| row.get(0)))
}

/// Whether `subject` may try another factor under a failure-only budget.
pub(crate) async fn failure_budget_open(
    client: &impl GenericClient,
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
) -> Result<bool, tokio_postgres::Error> {
    let (_, maximum, _, _) = failure_subject(hasher, limit, subject);
    Ok(failures_in_window(client, hasher, limit, subject).await? < maximum)
}

/// Whether `subject` still has room in `limit`'s per-subject window in
/// `lane`, without charging anything. Callers use it where a refused path
/// must run the same number of statements as a charging one. A limit without
/// a per-subject policy has no room.
pub(crate) async fn subject_budget_open(
    client: &impl GenericClient,
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
    lane: Lane,
) -> Result<bool, tokio_postgres::Error> {
    let (scope, _, _, subject_policy) = limit.policy();
    let (maximum, seconds) = subject_policy.unwrap_or((0, 0));
    let hash = subject_hash(hasher, limit, subject, lane).unwrap_or_default();
    let row = client
        .query_opt(
            "SELECT attempts FROM auth_abuse_counters WHERE scope=$1 AND subject_hash=$2
             AND window_started_at > clock_timestamp() - make_interval(secs => $3::int4)",
            &[&scope, &&hash[..], &seconds],
        )
        .await?;
    Ok(row.map_or(0, |row| row.get::<_, i32>(0)) < maximum)
}

/// Record one rejected factor, opening a new window once the previous one has
/// lapsed. No route ceiling applies, so a busy route can never leave a
/// rejected factor unrecorded.
pub(crate) async fn record_failure(
    client: &impl GenericClient,
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
) -> Result<(), tokio_postgres::Error> {
    let (scope, _, seconds, hash) = failure_subject(hasher, limit, subject);
    client
        .execute(
            "INSERT INTO auth_abuse_counters(scope,subject_hash,window_started_at,attempts,updated_at)
             VALUES ($1,$2,clock_timestamp(),1,clock_timestamp())
             ON CONFLICT(scope,subject_hash) DO UPDATE SET
                window_started_at = CASE WHEN auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => $3::int4)
                    THEN clock_timestamp() ELSE auth_abuse_counters.window_started_at END,
                attempts = CASE WHEN auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => $3::int4)
                    THEN 1 ELSE auth_abuse_counters.attempts + 1 END,
                updated_at = clock_timestamp()",
            &[&scope, &&hash[..], &seconds],
        )
        .await?;
    Ok(())
}

/// Scope, per-subject maximum and window, and the subject digest `charge`
/// would store for this limit. A limit without a subject policy has no room.
fn failure_subject(
    hasher: &TokenHasher,
    limit: Limit,
    subject: &str,
) -> (&'static str, i32, i32, [u8; 32]) {
    let (scope, _, _, subject_policy) = limit.policy();
    let (maximum, seconds) = subject_policy.unwrap_or((0, 0));
    let hash = hasher.digest(format!("abuse-subject-{scope}-v1").as_bytes(), subject);
    (scope, maximum, seconds, hash)
}

async fn charge(
    client: &impl GenericClient,
    hasher: &TokenHasher,
    limit: Limit,
    subject: Option<&str>,
    lane: Lane,
) -> Result<bool, tokio_postgres::Error> {
    let (scope, global_max, global_seconds, subject_policy) = limit.policy();
    let (subject_max, subject_seconds) = subject_policy.unwrap_or((0, 0));
    let subject_hash = subject.and_then(|subject| subject_hash(hasher, limit, subject, lane));
    // A subject-only limit charges one row: its authenticated caller's own
    // counter, keyed exactly as the per-subject row above, with the per-subject
    // policy as the ceiling and no second shared row. The upsert semantics are
    // identical to the subject branch of auth_abuse_consume, so an account's
    // live window keeps counting across the change.
    let subject_only = limit.subject_only() && subject_hash.is_some();
    let route_key = if subject_only {
        subject_hash.unwrap()
    } else {
        match lane {
            Lane::Anonymous => hasher.digest(b"abuse-global-v1", scope),
            Lane::Verified => hasher.digest(b"abuse-verified-v1", scope),
        }
    };
    let (route_max, route_seconds) = if subject_only {
        (subject_max, subject_seconds)
    } else if lane == Lane::Verified {
        (global_max * VERIFIED_CEILING_FACTOR, global_seconds)
    } else {
        (global_max, global_seconds)
    };
    let route_bytes: &[u8] = &route_key[..];
    let subject_bytes: Option<&[u8]> = if subject_only {
        None
    } else {
        subject_hash.as_ref().map(|hash| &hash[..])
    };
    let row = client
        .query_one(
            "SELECT auth_abuse_consume($1,$2,$3,$4,$5,$6,$7)",
            &[
                &scope,
                &route_bytes,
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

/// Per-scope prune retention in seconds, derived from each scope's longest
/// window. A counter row's `updated_at` is never earlier than its
/// `window_started_at`, so a row idle past its longest window has no budget
/// left to enforce; deleting it cannot reset a live window.
fn prune_retention() -> Vec<(&'static str, i32)> {
    let mut retention: Vec<(&'static str, i32)> = Vec::new();
    let windows = Limit::ALL
        .iter()
        .map(|limit| (limit.policy().0, limit.longest_window_seconds()))
        .chain(OTHER_SCOPES.iter().copied());
    for (scope, window) in windows {
        let seconds = (window + PRUNE_SLACK_SECONDS).max(DEFAULT_RETENTION_SECONDS);
        match retention.iter_mut().find(|(known, _)| *known == scope) {
            Some((_, kept)) => *kept = (*kept).max(seconds),
            None => retention.push((scope, seconds)),
        }
    }
    retention
}

/// Bounded cleanup; safe for concurrent workers due to SKIP LOCKED.
pub async fn prune(client: &Client) -> Result<u64, tokio_postgres::Error> {
    let (scopes, seconds): (Vec<&str>, Vec<i32>) = prune_retention().into_iter().unzip();
    client
        .execute(
            "WITH retention(scope, seconds) AS (
                SELECT * FROM unnest($1::text[], $2::int4[])
             ), stale AS (
                SELECT a.scope,a.subject_hash FROM auth_abuse_counters a
                LEFT JOIN retention r ON r.scope=a.scope
                WHERE a.updated_at < now() - make_interval(secs => $3::int4)
                  AND a.updated_at < now() - make_interval(secs => coalesce(r.seconds, $3::int4))
                ORDER BY a.updated_at LIMIT 5000 FOR UPDATE OF a SKIP LOCKED
             ) DELETE FROM auth_abuse_counters a USING stale s
             WHERE a.scope=s.scope AND a.subject_hash=s.subject_hash",
            &[&scopes, &seconds, &DEFAULT_RETENTION_SECONDS],
        )
        .await
}

#[cfg(test)]
mod tests;
