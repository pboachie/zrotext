// SPDX-License-Identifier: AGPL-3.0-only
//! Shared PostgreSQL request budgets for public auth and enrollment routes.
//! Counts are spent before password hashing, verification lookup or pairing
//! proof work. The database is the authority across hubs and processes.

use super::TokenHasher;
use tokio_postgres::Client;

#[derive(Clone, Copy, Debug)]
pub enum Limit {
    Registration,
    Login,
    Resend,
    Verify,
    PairClaim,
    PairProof,
    DeviceChallenge,
    DeviceAuthenticate,
}

impl Limit {
    fn policy(self) -> (&'static str, i32, i32, Option<(i32, i32)>) {
        // (scope, global attempts, global window seconds, subject policy)
        match self {
            Self::Registration => ("registration", 120, 3_600, Some((3, 86_400))),
            Self::Login => ("login", 240, 60, Some((12, 900))),
            Self::Resend => ("resend", 120, 60, Some((12, 900))),
            Self::Verify => ("verify", 120, 60, None),
            Self::PairClaim => ("pair_claim", 300, 60, Some((20, 60))),
            Self::PairProof => ("pair_proof", 300, 60, Some((20, 60))),
            Self::DeviceChallenge => ("device_challenge", 300, 60, Some((30, 60))),
            Self::DeviceAuthenticate => ("device_authenticate", 300, 60, Some((30, 60))),
        }
    }
}

/// Each increment is an atomic UPSERT guarded by the row lock. A narrow
/// subject cap is checked first so repeated attacks on one identifier cannot
/// consume the shared route budget. `subject` must already be normalized by
/// the caller; HMAC hides it from the database.
pub async fn consume(
    client: &Client,
    hasher: &TokenHasher,
    limit: Limit,
    subject: Option<&str>,
) -> Result<bool, tokio_postgres::Error> {
    let (scope, global_max, global_seconds, subject_policy) = limit.policy();
    if let (Some(subject), Some((subject_max, subject_seconds))) = (subject, subject_policy) {
        let subject_hash = hasher.digest(format!("abuse-subject-{scope}-v1").as_bytes(), subject);
        if !increment(client, scope, &subject_hash, subject_max, subject_seconds).await? {
            return Ok(false);
        }
    }
    let global_hash = hasher.digest(b"abuse-global-v1", scope);
    increment(client, scope, &global_hash, global_max, global_seconds).await
}

async fn increment(
    client: &Client,
    scope: &str,
    hash: &[u8; 32],
    maximum: i32,
    window_seconds: i32,
) -> Result<bool, tokio_postgres::Error> {
    Ok(client
        .query_opt(
            "INSERT INTO auth_abuse_counters(scope,subject_hash,window_started_at,attempts,updated_at)
             VALUES($1,$2,clock_timestamp(),1,clock_timestamp())
             ON CONFLICT(scope,subject_hash) DO UPDATE SET
                 window_started_at=CASE WHEN auth_abuse_counters.window_started_at <= clock_timestamp()-make_interval(secs => $4::integer) THEN clock_timestamp() ELSE auth_abuse_counters.window_started_at END,
                 attempts=CASE WHEN auth_abuse_counters.window_started_at <= clock_timestamp()-make_interval(secs => $4::integer) THEN 1 ELSE auth_abuse_counters.attempts+1 END,
                 updated_at=clock_timestamp()
             WHERE auth_abuse_counters.window_started_at <= clock_timestamp()-make_interval(secs => $4::integer)
                OR auth_abuse_counters.attempts < $3
             RETURNING attempts",
            &[&scope, &&hash[..], &maximum, &window_seconds],
        )
        .await?
        .is_some())
}

/// Bounded cleanup; safe for concurrent workers due to SKIP LOCKED.
pub async fn prune(client: &Client) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            "WITH stale AS (
                SELECT scope,subject_hash FROM auth_abuse_counters
                WHERE updated_at < now()-interval '25 hours'
                ORDER BY updated_at LIMIT 500 FOR UPDATE SKIP LOCKED
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
    async fn postgres_budget_is_shared_across_connections_and_hides_subjects() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
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
        let a = Arc::new(a);
        let b = Arc::new(b);
        let hasher = Arc::new(TokenHasher::new(vec![91; 32]).unwrap());
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
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
