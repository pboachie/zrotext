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
mod tests {
    use super::*;
    use crate::auth::normalize_email;
    use std::sync::Arc;
    use tokio_postgres::NoTls;
    use uuid::Uuid;

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn postgres_budget_is_shared_across_connections_and_hides_subjects() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("abuse_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (a, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let (b, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        a.batch_execute(include_str!(
            "../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"
        ))
        .await
        .unwrap();
        a.batch_execute(include_str!(
            "../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"
        ))
        .await
        .unwrap();
        let a = Arc::new(a);
        let b = Arc::new(b);
        let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let mut tasks = Vec::new();
        for index in 0..48 {
            let client = if index % 2 == 0 { a.clone() } else { b.clone() };
            let hasher = hasher.clone();
            tasks.push(tokio::spawn(async move {
                let subject = normalize_email(" Owner@Example.Test ").unwrap();
                consume(&client, &hasher, Limit::Login, Some(&subject))
                    .await
                    .unwrap()
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            accepted += usize::from(task.await.unwrap());
        }
        assert_eq!(accepted, 12);
        assert!(
            !consume(&b, &hasher, Limit::Login, Some("owner@example.test"))
                .await
                .unwrap()
        );
        assert!(
            consume(&b, &hasher, Limit::Login, Some("other@example.test"))
                .await
                .unwrap()
        );
        assert!(
            consume(&b, &hasher, Limit::Resend, Some("owner@example.test"))
                .await
                .unwrap()
        );
        let rows = a
            .query(
                "SELECT scope,subject_hash,attempts FROM auth_abuse_counters",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 5); // login global + two subjects; resend global + subject
        for row in &rows {
            assert_eq!(row.get::<_, Vec<u8>>(1).len(), 32);
        }
        let row = a
            .query_one(
                "SELECT attempts FROM auth_abuse_counters WHERE scope='login' AND subject_hash=$1",
                &[&&hasher.digest(b"abuse-subject-login-v1", "owner@example.test")[..]],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i32>(0), 12);
        let global = a
            .query_one(
                "SELECT attempts FROM auth_abuse_counters WHERE scope='login' AND subject_hash=$1",
                &[&&hasher.digest(b"abuse-global-v1", "login")[..]],
            )
            .await
            .unwrap();
        assert_eq!(global.get::<_, i32>(0), 13);
        a.execute(
            "UPDATE auth_abuse_counters SET window_started_at=now()-interval '16 minutes' WHERE scope='login' AND subject_hash=$1",
            &[&&hasher.digest(b"abuse-subject-login-v1", "owner@example.test")[..]],
        )
        .await
        .unwrap();
        assert!(
            consume(&b, &hasher, Limit::Login, Some("owner@example.test"))
                .await
                .unwrap()
        );
        a.execute(
            "UPDATE auth_abuse_counters SET updated_at=now()-interval '26 hours'",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(prune(&b).await.unwrap(), 5);
        assert!(
            consume(
                &a,
                &hasher,
                Limit::PasswordResetRequest,
                Some("owner@example.test")
            )
            .await
            .unwrap()
        );
        a.execute(
            "UPDATE auth_abuse_counters SET updated_at=now()-interval '3 minutes' WHERE scope='password_reset_request'",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(prune(&b).await.unwrap(), 0);
        for _ in 0..2 {
            assert!(
                consume(
                    &b,
                    &hasher,
                    Limit::PasswordResetRequest,
                    Some("owner@example.test")
                )
                .await
                .unwrap()
            );
        }
        assert!(
            !consume(
                &b,
                &hasher,
                Limit::PasswordResetRequest,
                Some("owner@example.test")
            )
            .await
            .unwrap()
        );
        a.execute(
            "UPDATE auth_abuse_counters SET updated_at=now()-interval '26 hours' WHERE scope='password_reset_request'",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(prune(&b).await.unwrap(), 2);
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn junk_subjects_cannot_spend_the_budget_of_verified_subjects() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("abuse_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            db.batch_execute(migration).await.unwrap();
        }
        let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
        let probes = AtomicUsize::new(0);
        let live = |answer: bool| {
            let probes = &probes;
            async move {
                probes.fetch_add(1, Ordering::SeqCst);
                Ok::<_, tokio_postgres::Error>(answer)
            }
        };
        // An open route never runs the liveness probe.
        assert!(
            consume_or_verify(&db, &hasher, Limit::DeviceChallenge, "phone", live(true))
                .await
                .unwrap()
        );
        assert_eq!(probes.load(Ordering::SeqCst), 0);
        // One anonymous caller spends the whole route with made-up device IDs.
        for index in 1..300 {
            assert!(
                consume_or_verify(
                    &db,
                    &hasher,
                    Limit::DeviceChallenge,
                    &format!("junk-{index}"),
                    live(false),
                )
                .await
                .unwrap()
            );
        }
        for index in 300..400 {
            assert!(
                !consume_or_verify(
                    &db,
                    &hasher,
                    Limit::DeviceChallenge,
                    &format!("junk-{index}"),
                    live(false),
                )
                .await
                .unwrap()
            );
        }
        // The real phone keeps its own per-device budget, and no more.
        for _ in 1..30 {
            assert!(
                consume_or_verify(&db, &hasher, Limit::DeviceChallenge, "phone", live(true))
                    .await
                    .unwrap()
            );
        }
        assert!(
            !consume_or_verify(&db, &hasher, Limit::DeviceChallenge, "phone", live(true))
                .await
                .unwrap()
        );
        // Other routes are unaffected.
        assert!(
            consume(&db, &hasher, Limit::DeviceAuthenticate, Some("phone"))
                .await
                .unwrap()
        );
        // Refused junk leaves no rows; only the two route rows, 300 admitted
        // junk subjects, the phone and the other route's two rows remain.
        let rows: i64 = db
            .query_one("SELECT count(*) FROM auth_abuse_counters", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(rows, 2 + 299 + 1 + 2);
        // The verified ceiling is a backstop across many real subjects.
        let ceiling = hasher.digest(b"abuse-verified-v1", "device_challenge");
        db.execute(
            "UPDATE auth_abuse_counters SET attempts=2999 WHERE scope='device_challenge' AND subject_hash=$1",
            &[&&ceiling[..]],
        )
        .await
        .unwrap();
        assert!(
            consume_or_verify(&db, &hasher, Limit::DeviceChallenge, "phone-2", live(true))
                .await
                .unwrap()
        );
        assert!(
            !consume_or_verify(&db, &hasher, Limit::DeviceChallenge, "phone-3", live(true))
                .await
                .unwrap()
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn exhausted_route_does_not_store_rejected_unique_subjects() {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("abuse_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (a, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let (b, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            a.batch_execute(migration).await.unwrap();
        }
        let a = Arc::new(a);
        let b = Arc::new(b);
        let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
        let global_hash = hasher.digest(b"abuse-global-v1", "pair_claim");
        a.execute(
            "INSERT INTO auth_abuse_counters(scope,subject_hash,window_started_at,attempts,updated_at)
             VALUES('pair_claim',$1,now(),299,now())",
            &[&&global_hash[..]],
        )
        .await
        .unwrap();
        let mut tasks = Vec::new();
        for index in 0..32 {
            let client = if index % 2 == 0 { a.clone() } else { b.clone() };
            let hasher = hasher.clone();
            tasks.push(tokio::spawn(async move {
                consume(
                    &client,
                    &hasher,
                    Limit::PairClaim,
                    Some(&format!("unique-{index}")),
                )
                .await
                .unwrap()
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            accepted += usize::from(task.await.unwrap());
        }
        assert_eq!(accepted, 1);
        for index in 32..96 {
            assert!(
                !consume(
                    &a,
                    &hasher,
                    Limit::PairClaim,
                    Some(&format!("unique-{index}")),
                )
                .await
                .unwrap()
            );
        }
        let row = a
            .query_one(
                "SELECT count(*), max(attempts) FROM auth_abuse_counters WHERE scope='pair_claim'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 2); // global and the one admitted subject
        assert_eq!(row.get::<_, i32>(1), 300);
        a.execute(
            "UPDATE auth_abuse_counters SET updated_at=now()-interval '3 minutes'",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(prune(&b).await.unwrap(), 2);
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
