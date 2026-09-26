// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-initiated account erasure. This is the one-request, irreversible
//! counterpart of the owner data export: the signed-in owner re-proves the
//! current password, and one database transaction deletes every account-owned
//! row in foreign-key order, ending with the account itself. It is separate
//! from the scheduled retention worker, which prunes old content and history
//! on a timetable and is explicitly not an account-erasure API.
//!
//! Some rows are deliberately impossible to erase. Append-only consent and
//! audit tables (`owner_recipient_holds`, `owner_opt_out_review_decisions`,
//! `owner_opt_out_audit`, `sms_owner_key_audit`), line identity tombstones
//! (`phone_lines`, `device_line_bindings`), and their approval keys,
//! challenges and activation exchanges reject DELETE at the schema level, and
//! operator billing review actions outlive their account. Their foreign keys
//! reference the account row, so while any of them exist a complete erasure
//! is impossible: the request fails closed with the blocking tables listed
//! and nothing is deleted. Metering and billing rows are erased with
//! everything else; only request-budget counters (keyed hashes shared across
//! accounts) and billing events still referenced by another account's risk
//! records are kept, and each kept set is reported honestly in the response.

use crate::{
    auth::{
        AuthError, TokenHasher,
        abuse_limits::{self, Limit},
        account,
    },
    http_auth::require_owner,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(test)]
use tokio_postgres::NoTls;
use uuid::Uuid;

/// Schema-protected tables whose rows reference the account and cannot be
/// deleted by design. Any row here blocks the whole erasure.
const BLOCKED_TABLES: &[&str] = &[
    "phone_lines",
    "device_line_bindings",
    "line_owner_approval_keys",
    "line_activation_challenges",
    "sms_line_activation_exchanges",
    "sms_line_owner_approval_keys",
    "sms_owner_key_audit",
    "owner_recipient_holds",
    "owner_opt_out_review_decisions",
    "owner_opt_out_audit",
];

/// FK-safe deletion order: every table is emptied before the rows it
/// references. Each statement takes the account UUID as `$1`; composite
/// foreign keys make cross-account references impossible except where an
/// extra `OR device_id/message_id IN (...)` arm covers pre-account legacy
/// rows with a NULL account_id.
const DELETE_PLAN: &[(&str, &str)] = &[
    // Consent and inbound history over messages, attempts and devices.
    (
        "recipient_suppressions",
        "DELETE FROM recipient_suppressions WHERE account_id=$1",
    ),
    (
        "line_opt_out_events",
        "DELETE FROM line_opt_out_events WHERE account_id=$1",
    ),
    (
        "sealed_inbound_events",
        "DELETE FROM sealed_inbound_events WHERE account_id=$1",
    ),
    // Webhook history, children before their delivery and endpoint parents.
    (
        "webhook_attempts",
        "DELETE FROM webhook_attempts WHERE delivery_id IN (SELECT id FROM webhook_deliveries WHERE account_id=$1)",
    ),
    (
        "webhook_replay_requests",
        "DELETE FROM webhook_replay_requests WHERE delivery_id IN (SELECT id FROM webhook_deliveries WHERE account_id=$1)",
    ),
    (
        "webhook_deliveries",
        "DELETE FROM webhook_deliveries WHERE account_id=$1",
    ),
    (
        "webhook_dispatch_accounts",
        "DELETE FROM webhook_dispatch_accounts WHERE account_id=$1",
    ),
    (
        "inbound_events",
        "DELETE FROM inbound_events WHERE account_id=$1",
    ),
    (
        "webhook_endpoints",
        "DELETE FROM webhook_endpoints WHERE account_id=$1",
    ),
    // Metered usage before its messages and quota periods.
    (
        "usage_ledger",
        "DELETE FROM usage_ledger WHERE account_id=$1",
    ),
    // Delivery history before its messages, devices and attempts.
    (
        "message_events",
        "DELETE FROM message_events WHERE account_id=$1",
    ),
    (
        "dispatch_jobs",
        "DELETE FROM dispatch_jobs WHERE account_id=$1",
    ),
    (
        "dispatch_fences",
        "DELETE FROM dispatch_fences WHERE account_id=$1 \
         OR message_id IN (SELECT id FROM messages WHERE account_id=$1) \
         OR device_id IN (SELECT id FROM devices WHERE account_id=$1)",
    ),
    (
        "idempotency_keys",
        "DELETE FROM idempotency_keys WHERE account_id=$1",
    ),
    (
        "message_attempts",
        "DELETE FROM message_attempts WHERE account_id=$1",
    ),
    ("messages", "DELETE FROM messages WHERE account_id=$1"),
    // Enrollment before its device keys and devices.
    (
        "device_auth_challenges",
        "DELETE FROM device_auth_challenges WHERE account_id=$1",
    ),
    ("device_keys", "DELETE FROM device_keys WHERE account_id=$1"),
    (
        "pairing_requests",
        "DELETE FROM pairing_requests WHERE account_id=$1",
    ),
    // Owner API keys can bind a device, so they go before devices.
    ("api_keys", "DELETE FROM api_keys WHERE account_id=$1"),
    (
        "device_sessions",
        "DELETE FROM device_sessions WHERE account_id=$1 \
         OR device_id IN (SELECT id FROM devices WHERE account_id=$1)",
    ),
    (
        "usage_periods",
        "DELETE FROM usage_periods WHERE account_id=$1",
    ),
    (
        "usage_quota_policies",
        "DELETE FROM usage_quota_policies WHERE account_id=$1",
    ),
    ("devices", "DELETE FROM devices WHERE account_id=$1"),
    // Billing: children first, provider binding last. billing_events is
    // handled separately for cross-account risk references.
    (
        "billing_payment_holds",
        "DELETE FROM billing_payment_holds WHERE account_id=$1",
    ),
    (
        "billing_risk_events",
        "DELETE FROM billing_risk_events WHERE account_id=$1",
    ),
    (
        "billing_quota_audit",
        "DELETE FROM billing_quota_audit WHERE account_id=$1",
    ),
    (
        "billing_device_cap_audit",
        "DELETE FROM billing_device_cap_audit WHERE account_id=$1",
    ),
    (
        "billing_device_caps",
        "DELETE FROM billing_device_caps WHERE account_id=$1",
    ),
    (
        "billing_subscriptions",
        "DELETE FROM billing_subscriptions WHERE account_id=$1",
    ),
    (
        "billing_reconciliations",
        "DELETE FROM billing_reconciliations WHERE account_id=$1",
    ),
    (
        "billing_customers",
        "DELETE FROM billing_customers WHERE account_id=$1",
    ),
    // Account mail, second-factor and session state before the membership.
    (
        "verification_mail_outbox",
        "DELETE FROM verification_mail_outbox \
         WHERE verification_id IN (SELECT id FROM email_verifications WHERE account_id=$1)",
    ),
    (
        "email_verifications",
        "DELETE FROM email_verifications WHERE account_id=$1",
    ),
    (
        "password_reset_mail_outbox",
        "DELETE FROM password_reset_mail_outbox \
         WHERE reset_id IN (SELECT id FROM password_resets WHERE account_id=$1)",
    ),
    (
        "password_resets",
        "DELETE FROM password_resets WHERE account_id=$1",
    ),
    (
        "password_reset_notice_outbox",
        "DELETE FROM password_reset_notice_outbox WHERE account_id=$1",
    ),
    (
        "sms_owner_key_challenges",
        "DELETE FROM sms_owner_key_challenges WHERE account_id=$1",
    ),
    (
        "owner_mfa_login_challenges",
        "DELETE FROM owner_mfa_login_challenges WHERE account_id=$1",
    ),
    (
        "owner_mfa_recovery_codes",
        "DELETE FROM owner_mfa_recovery_codes WHERE account_id=$1",
    ),
    ("owner_mfa", "DELETE FROM owner_mfa WHERE account_id=$1"),
    ("sessions", "DELETE FROM sessions WHERE account_id=$1"),
    ("memberships", "DELETE FROM memberships WHERE account_id=$1"),
];

const ERASED_STATEMENT: &str = "One transaction deleted every account-owned row listed under deleted, in foreign-key order, and then the account itself. Rows under retained were kept only for the stated reason: either the schema forbids deleting them or another account still references them. This response is the only confirmation. The account and its sessions no longer exist, so later authenticated requests fail, and database backups, replicas and WAL archives keep their own separate lifecycle.";

const BLOCKED_STATEMENT: &str = "Nothing was deleted. The schema keeps the listed rows (append-only consent and audit records, line identity tombstones, or operator review decisions) and their foreign keys still reference the account, so a complete erasure is impossible while they exist. The transaction rolled back unchanged; contact the operator about those records.";

#[derive(Clone)]
pub struct OwnerErasureState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
}

pub fn router(state: OwnerErasureState) -> Router {
    Router::new()
        .route("/v1/owner/erasure", post(erase_account))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EraseBody {
    current_password: String,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
}

#[derive(Serialize)]
struct TableCount {
    table: &'static str,
    rows: u64,
}

#[derive(Serialize)]
struct RetainedSet {
    table: &'static str,
    rows: Option<u64>,
    reason: &'static str,
}

#[derive(Serialize)]
struct ErasureView {
    account_id: Uuid,
    deleted: Vec<TableCount>,
    retained: Vec<RetainedSet>,
    statement: &'static str,
}

#[derive(Serialize)]
struct BlockedView {
    code: &'static str,
    blocked: Vec<TableCount>,
    statement: &'static str,
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (status, Json(ErrorBody { code })).into_response()
}

fn auth_error(error: AuthError) -> Response {
    // Same shape the account routes return for these conditions.
    match error {
        AuthError::InvalidInput => error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        AuthError::InvalidCredentials | AuthError::Unauthorized | AuthError::MfaRequired { .. } => {
            error_response(StatusCode::UNAUTHORIZED, "unauthorized")
        }
        AuthError::EmailNotVerified | AuthError::Forbidden | AuthError::SmsOwnerKeyActive => {
            error_response(StatusCode::FORBIDDEN, "forbidden")
        }
        AuthError::RateLimited => error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        AuthError::Database(_) => error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        AuthError::Password => error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        AuthError::Crypto => error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

async fn count(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    account_id: Uuid,
) -> Result<u64, tokio_postgres::Error> {
    Ok(tx
        .query_one(sql, &[&account_id])
        .await?
        .get::<_, i64>(0)
        .max(0) as u64)
}

async fn erase_account(
    State(state): State<Arc<OwnerErasureState>>,
    headers: HeaderMap,
    Json(body): Json<EraseBody>,
) -> Response {
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    // Exactly the mutation chain the account routes enforce: session cookie,
    // exact configured Origin, and the double-submit CSRF pair.
    let principal = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    // A wrong password here must cost the same budget as the other
    // password-proven account mutations.
    let subject = principal.user_id.to_string();
    match abuse_limits::consume(
        &client,
        &state.auth_hasher,
        Limit::PasswordChange,
        Some(&subject),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
    // Re-verify the current password against the stored argon2 hash through
    // the same lookup the /sessions/revoke-others handler uses. A wrong
    // password fails closed with that route's status and body.
    match account::verify_current_password(&client, &principal, &body.current_password).await {
        Ok(()) => {}
        Err(AuthError::InvalidCredentials) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request");
        }
        Err(error) => return auth_error(error),
    }
    let account_id = principal.tenant.account_id();
    let tx = match client.transaction().await {
        Ok(tx) => tx,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    // Fail closed before touching anything: while any schema-protected row
    // references the account, the account row itself cannot be deleted and a
    // partial erasure must not be committed.
    let mut blocked = Vec::new();
    for table in BLOCKED_TABLES {
        let rows = match count(
            &tx,
            &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
            account_id,
        )
        .await
        {
            Ok(rows) => rows,
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        if rows > 0 {
            blocked.push(TableCount { table, rows });
        }
    }
    let live_challenges = match count(
        &tx,
        "SELECT count(*) FROM sms_owner_key_challenges \
         WHERE account_id=$1 AND expires_at>clock_timestamp()-interval '1 hour'",
        account_id,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    if live_challenges > 0 {
        blocked.push(TableCount {
            table: "sms_owner_key_challenges",
            rows: live_challenges,
        });
    }
    let reviewed_risk = match count(
        &tx,
        "SELECT count(*) FROM billing_risk_review_actions a \
         JOIN billing_risk_events r ON r.stripe_event_id=a.stripe_event_id \
         WHERE r.account_id=$1",
        account_id,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    if reviewed_risk > 0 {
        blocked.push(TableCount {
            table: "billing_risk_review_actions",
            rows: reviewed_risk,
        });
    }
    if !blocked.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(BlockedView {
                code: "erasure_blocked",
                blocked,
                statement: BLOCKED_STATEMENT,
            }),
        )
            .into_response();
    }
    // Everything below is one transaction: any failure rolls the whole
    // erasure back, never leaving a half-erased account.
    let mut deleted = Vec::new();
    for &(table, sql) in DELETE_PLAN {
        let rows = match tx.execute(sql, &[&account_id]).await {
            Ok(rows) => rows,
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        deleted.push(TableCount { table, rows });
    }
    // Provider receipt log: delete this account's events unless another
    // account's risk record still references them.
    let retained_billing_events = match count(
        &tx,
        "SELECT count(*) FROM billing_events b WHERE b.account_id=$1 \
         AND EXISTS (SELECT 1 FROM billing_risk_events r WHERE r.stripe_event_id=b.stripe_event_id)",
        account_id,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    let billing_events = match tx
        .execute(
            "DELETE FROM billing_events b WHERE b.account_id=$1 \
             AND NOT EXISTS (SELECT 1 FROM billing_risk_events r WHERE r.stripe_event_id=b.stripe_event_id)",
            &[&account_id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    deleted.push(TableCount {
        table: "billing_events",
        rows: billing_events,
    });
    // The membership cascade would carry these, but deleting explicitly
    // keeps every count honest and the order observable.
    let users = match tx
        .execute("DELETE FROM users WHERE id=$1", &[&principal.user_id])
        .await
    {
        Ok(rows) => rows,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    deleted.push(TableCount {
        table: "users",
        rows: users,
    });
    let accounts = match tx
        .execute("DELETE FROM accounts WHERE id=$1", &[&account_id])
        .await
    {
        Ok(rows) => rows,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    deleted.push(TableCount {
        table: "accounts",
        rows: accounts,
    });
    if tx.commit().await.is_err() {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    let mut retained = vec![RetainedSet {
        table: "auth_abuse_counters",
        rows: None,
        reason: "request-budget rows are pepper-keyed digests shared across accounts; \
                 they hold no identifiers and the worker prunes them",
    }];
    if retained_billing_events > 0 {
        retained.push(RetainedSet {
            table: "billing_events",
            rows: Some(retained_billing_events),
            reason: "still referenced by another account's billing_risk_events",
        });
    }
    Json(ErasureView {
        account_id,
        deleted,
        retained,
        statement: ERASED_STATEMENT,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{login, register, verify_email};
    use axum::body::{Body, to_bytes};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    const ORIGIN: &str = "https://test.example";

    /// Every migration the handler's tables need, in runner order. This is
    /// the auth lifecycle list reconciled with the delivery, usage, billing,
    /// webhook, consent and line tables the erasure touches. Migration 034 is
    /// a checksum gate for a CONCURRENTLY built index and never runs here.
    const MIGRATIONS: &[&str] = &[
        include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
        include_str!("../../../deploy/compose/migrations/019_line_activation_contract.sql"),
        include_str!("../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
        include_str!("../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../deploy/compose/migrations/032_line_opt_out_events.sql"),
        include_str!("../../../deploy/compose/migrations/033_sms_line_binding_scope.sql"),
        include_str!("../../../deploy/compose/migrations/035_sms_owner_key_ceremony.sql"),
        include_str!("../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../deploy/compose/migrations/037_sms_line_activation_exchange.sql"),
    ];

    /// A migrated schema plus its admin connection for teardown. Mirrors the
    /// sibling owner/auth PostgreSQL tests.
    async fn migrated_schema(
        label: &str,
    ) -> (
        tokio_postgres::Client,
        tokio_postgres::Client,
        String,
        String,
    ) {
        let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("owner_erasure_{label}_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in MIGRATIONS {
            db.batch_execute(migration).await.unwrap();
        }
        (admin, db, database_url, schema)
    }

    fn erasure_post(
        session: Option<&str>,
        csrf: Option<&str>,
        origin: Option<&str>,
        password: &str,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/owner/erasure")
            .header(axum::http::header::CONTENT_TYPE, "application/json");
        if let Some(token) = session {
            request = request.header(header::COOKIE, format!("__Host-zrotext_session={token}"));
        }
        if let Some(token) = csrf {
            request = request.header(header::COOKIE, format!("__Host-zrotext_csrf={token}"));
            request = request.header("x-zrotext-csrf", token);
        }
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        request
            .body(Body::from(
                json!({ "current_password": password }).to_string(),
            ))
            .unwrap()
    }

    async fn body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
    }

    fn deleted_count(report: &Value, table: &str) -> u64 {
        report["deleted"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["table"] == table)
            .unwrap_or_else(|| panic!("{table} missing from the deleted list"))["rows"]
            .as_u64()
            .unwrap()
    }

    fn blocked_count(report: &Value, table: &str) -> u64 {
        report["blocked"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["table"] == table)
            .unwrap_or_else(|| panic!("{table} missing from the blocked list"))["rows"]
            .as_u64()
            .unwrap()
    }

    async fn table_count(db: &tokio_postgres::Client, sql: &str) -> i64 {
        db.query_one(sql, &[]).await.unwrap().get(0)
    }

    /// Two accounts carrying delivery, enrollment, metering, webhook,
    /// billing and account-recovery fixtures. Returns both signups, both
    /// sessions and the hasher-backed router under test.
    async fn fixture(
        db: &mut tokio_postgres::Client,
        hasher: &Arc<TokenHasher>,
        database_url: &str,
    ) -> (
        crate::auth::Signup,
        crate::auth::SessionCredentials,
        crate::auth::Signup,
        crate::auth::SessionCredentials,
        Router,
    ) {
        let a = register(
            db,
            hasher,
            "erase-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let b = register(
            db,
            hasher,
            "erase-b@example.test",
            &crate::test_keys::password(2),
        )
        .await
        .unwrap();
        verify_email(db, hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(db, hasher, &b.verification_token)
            .await
            .unwrap();
        let session_a = login(
            db,
            hasher,
            "erase-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let session_b = login(
            db,
            hasher,
            "erase-b@example.test",
            &crate::test_keys::password(2),
        )
        .await
        .unwrap();
        let device_a = Uuid::new_v4();
        let device_b = Uuid::new_v4();
        db.execute("INSERT INTO sites(site_id) VALUES('erasure-site')", &[])
            .await
            .unwrap();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) \
             VALUES($1,$2,'Erasure probe'),($3,$4,'Isolation probe')",
            &[&device_a, &a.account_id, &device_b, &b.account_id],
        )
        .await
        .unwrap();
        let message_a0 = Uuid::new_v4();
        let message_a1 = Uuid::new_v4();
        for (id, state) in [(message_a0, "delivered"), (message_a1, "queued")] {
            db.execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,$7,now()+interval '1 hour')",
                &[&id, &a.account_id, &device_a, &vec![1_u8; 32],
                    &b"ERASE_A_BODY".to_vec(), &vec![2_u8; 32], &state],
            )
            .await
            .unwrap();
        }
        let message_b = Uuid::new_v4();
        db.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
             VALUES($1,$2,$3,'+15557654321',$4,'synthetic_alpha',$5,$6,'queued',now()+interval '1 hour')",
            &[&message_b, &b.account_id, &device_b, &vec![3_u8; 32],
                &b"KEEP_B_BODY".to_vec(), &vec![4_u8; 32]],
        )
        .await
        .unwrap();
        let attempt = Uuid::new_v4();
        db.execute(
            "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
             VALUES($1,$2,$3,$4,1,1,1,'submitted')",
            &[&attempt, &a.account_id, &message_a0, &device_a],
        )
        .await
        .unwrap();
        for (evidence, state) in [
            ("sent_callback_ok", "submitted"),
            ("delivery_callback_ok", "delivered"),
        ] {
            db.execute(
                "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,event_digest,observed_at,resulting_state,segment_index,segment_count) \
                 VALUES($1,$2,$3,$4,$5,$6,now(),$7,0,1)",
                &[&Uuid::new_v4(), &a.account_id, &message_a0, &attempt,
                    &evidence, &vec![5_u8; 32], &state],
            )
            .await
            .unwrap();
        }
        db.execute(
            "INSERT INTO dispatch_jobs(message_id,account_id,device_id) VALUES($1,$2,$3)",
            &[&message_a0, &a.account_id, &device_a],
        )
        .await
        .unwrap();
        // The second fence is a pre-accounting legacy row: a NULL account_id
        // escapes the composite foreign keys, so it needs its own attempt and
        // is matched by the message/device arms of the delete.
        let legacy_attempt = Uuid::new_v4();
        db.execute(
            "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
             VALUES($1,$2,$3,$4,1,1,1,'failed')",
            &[&legacy_attempt, &a.account_id, &message_a1, &device_a],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO dispatch_fences(message_id,account_id,device_id,attempt_id,generation,session_epoch,deployment_epoch,grant_expires_at,outcome) \
             VALUES($1,$2,$3,$4,1,1,1,now(),'failed'),($5,NULL,$3,$6,1,1,1,now(),'failed')",
            &[&message_a0, &a.account_id, &device_a, &attempt, &message_a1,
                &legacy_attempt],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO idempotency_keys(account_id,key,request_digest,message_id,expires_at) \
             VALUES($1,'erase-key',$2,$3,now()+interval '1 hour')",
            &[&a.account_id, &vec![6_u8; 32], &message_a0],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO device_sessions(device_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch,account_id) \
             VALUES($1,'erasure-site','erasure-instance',1,now()+interval '1 hour',1,NULL)",
            &[&device_a],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO pairing_requests(id,account_id,created_by_user_id,token_digest,display_name,expires_at) \
             VALUES($1,$2,$3,$4,'Erasure pairer',now()+interval '1 hour')",
            &[&Uuid::new_v4(), &a.account_id, &a.user_id, &vec![7_u8; 32]],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
             VALUES($1,$2,$3,$4)",
            &[&device_a, &a.account_id, &vec![8_u8; 65], &vec![9_u8; 32]],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO device_auth_challenges(id,account_id,device_id,nonce_digest,expires_at) \
             VALUES($1,$2,$3,$4,now()+interval '1 hour')",
            &[&Uuid::new_v4(), &a.account_id, &device_a, &vec![10_u8; 32]],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id) \
             VALUES($1,$2,$3,'erase-prefix',$4,ARRAY['messages:read'],$5)",
            &[&Uuid::new_v4(), &a.account_id, &a.user_id, &vec![11_u8; 32],
                &device_a],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units) \
             VALUES($1,'outbound_message',date_trunc('month',now())::date,(date_trunc('month',now())+interval '1 month')::date,10)",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO usage_quota_policies(account_id,metric,limit_units) \
             VALUES($1,'outbound_message',10)",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) \
             VALUES($1,$2,'outbound_message',date_trunc('month',now())::date,'reserve',1)",
            &[&a.account_id, &message_a0],
        )
        .await
        .unwrap();
        let endpoint = Uuid::new_v4();
        db.execute(
            "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version) \
             VALUES($1,$2,'https://example.test/hooks',$3,1)",
            &[&endpoint, &a.account_id, &vec![12_u8; 32]],
        )
        .await
        .unwrap();
        let inbound = Uuid::new_v4();
        db.execute(
            "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence,classification,observed_at,part_count,content_kind,event_digest,signature_der) \
             VALUES($1,$2,$3,$4,$5,1,'captured_local',now(),1,'metadata_only',$6,$7)",
            &[&inbound, &a.account_id, &device_a, &message_a0, &attempt,
                &vec![13_u8; 32], &vec![14_u8; 8]],
        )
        .await
        .unwrap();
        let delivery = Uuid::new_v4();
        db.execute(
            "INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,status) \
             VALUES($1,$2,$3,$4,'pending')",
            &[&delivery, &a.account_id, &endpoint, &inbound],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO webhook_attempts(id,delivery_id,attempt_number) VALUES($1,$2,1)",
            &[&Uuid::new_v4(), &delivery],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO webhook_replay_requests(account_id,request_id,delivery_id,generation) \
             VALUES($1,$2,$3,2)",
            &[&a.account_id, &Uuid::new_v4(), &delivery],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO recipient_suppressions(account_id,recipient_e164,active,source_event_id,source_attempt_id,source_observed_at,source) \
             VALUES($1,'+15559999999',true,$2,$3,now(),'sms_keyword')",
            &[&a.account_id, &inbound, &attempt],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_erasurefixture')",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_events(stripe_event_id,event_type,stripe_customer_id,account_id,body_sha256,disposition) \
             VALUES('evt_erasurefixture','invoice.paid','cus_erasurefixture',$1,$2,'queued')",
            &[&a.account_id, &vec![15_u8; 32]],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) \
             VALUES('evt_erasurefixture','ch_erasurefixture','refund',$1)",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_payment_holds(stripe_event_id,account_id,stripe_subscription_id,stripe_charge_id,reason) \
             VALUES('evt_erasurefixture',$1,'sub_erasurefixture','ch_erasurefixture','refund')",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) \
             VALUES('sub_erasurefixture',$1,'cus_erasurefixture')",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status) \
             VALUES('sub_erasurefixture',$1,'cus_erasurefixture','active')",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_quota_audit(account_id,stripe_subscription_id,reconciliation_generation,limit_units,reason) \
             VALUES($1,'sub_erasurefixture',1,10,'active')",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_device_caps(account_id,limit_devices) VALUES($1,2)",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO billing_device_cap_audit(account_id,stripe_subscription_id,reconciliation_generation,limit_devices,reason) \
             VALUES($1,'sub_erasurefixture',1,2,'active')",
            &[&a.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO password_resets(id,account_id,user_id,token_hash,expires_at) \
             VALUES($1,$2,$3,$4,now()+interval '1 hour')",
            &[&Uuid::new_v4(), &a.account_id, &a.user_id, &vec![16_u8; 32]],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO password_reset_notice_outbox(id,account_id,user_id) VALUES($1,$2,$3)",
            &[&Uuid::new_v4(), &a.account_id, &a.user_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,pending_expires_at,pending_session_id) \
             VALUES($1,$2,$3,$4,now()+interval '1 hour',$5)",
            &[&a.account_id, &a.user_id, &vec![17_u8; 12], &vec![18_u8; 36],
                &session_a.id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)",
            &[&a.account_id, &a.user_id, &vec![19_u8; 32]],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO owner_mfa_login_challenges(id,account_id,user_id,token_hash,expires_at) \
             VALUES($1,$2,$3,$4,now()+interval '1 hour')",
            &[&Uuid::new_v4(), &a.account_id, &a.user_id, &vec![20_u8; 32]],
        )
        .await
        .unwrap();
        // An expired challenge is deletable; the live-row guard must not trip.
        db.execute(
            "INSERT INTO sms_owner_key_challenges(id,account_id,user_id,session_id,signing_key_sec1,fingerprint,nonce_digest,created_at,expires_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,now()-interval '3 hours',now()-interval '2 hours')",
            &[&Uuid::new_v4(), &a.account_id, &a.user_id, &session_a.id,
                &vec![21_u8; 65], &vec![22_u8; 32], &vec![23_u8; 32]],
        )
        .await
        .unwrap();
        let app = router(OwnerErasureState {
            database_url: database_url.to_owned(),
            auth_hasher: hasher.clone(),
            canonical_origin: ORIGIN.to_owned(),
        });
        (a, session_a, b, session_b, app)
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn erasure_deletes_every_account_row_and_ends_the_session() {
        let (admin, mut db, database_url, schema) = migrated_schema("full").await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(23)).unwrap());
        let (a, session_a, b, _session_b, app) = fixture(&mut db, &hasher, &database_url).await;
        let response = app
            .clone()
            .oneshot(erasure_post(
                Some(&session_a.token),
                Some(&session_a.csrf_token),
                Some(ORIGIN),
                &crate::test_keys::password(1),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let report = body(response).await;
        assert_eq!(report["account_id"], a.account_id.to_string());
        for (table, rows) in [
            ("recipient_suppressions", 1),
            ("webhook_attempts", 1),
            ("webhook_replay_requests", 1),
            ("webhook_deliveries", 1),
            ("webhook_dispatch_accounts", 1),
            ("webhook_endpoints", 1),
            ("inbound_events", 1),
            ("usage_ledger", 1),
            ("usage_periods", 1),
            ("usage_quota_policies", 1),
            ("message_events", 2),
            ("dispatch_jobs", 1),
            ("dispatch_fences", 2),
            ("idempotency_keys", 1),
            ("message_attempts", 2),
            ("messages", 2),
            ("device_auth_challenges", 1),
            ("device_keys", 1),
            ("pairing_requests", 1),
            ("api_keys", 1),
            ("device_sessions", 1),
            ("devices", 1),
            ("billing_payment_holds", 1),
            ("billing_risk_events", 1),
            ("billing_quota_audit", 1),
            ("billing_device_cap_audit", 1),
            ("billing_device_caps", 1),
            ("billing_subscriptions", 1),
            ("billing_reconciliations", 1),
            ("billing_events", 1),
            ("billing_customers", 1),
            ("email_verifications", 1),
            ("verification_mail_outbox", 1),
            ("password_resets", 1),
            ("password_reset_notice_outbox", 1),
            ("sms_owner_key_challenges", 1),
            ("owner_mfa", 1),
            ("owner_mfa_recovery_codes", 1),
            ("owner_mfa_login_challenges", 1),
            ("sessions", 1),
            ("memberships", 1),
            ("users", 1),
            ("accounts", 1),
        ] {
            assert_eq!(
                deleted_count(&report, table),
                rows,
                "per-table count {table}"
            );
        }
        assert_eq!(deleted_count(&report, "line_opt_out_events"), 0);
        assert_eq!(deleted_count(&report, "sealed_inbound_events"), 0);
        assert!(
            report["retained"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["table"] == "auth_abuse_counters"),
            "the retained list names the shared budget counters"
        );
        // Direct queries: no row for the erased account survives anywhere.
        for table in [
            "messages",
            "message_events",
            "message_attempts",
            "dispatch_jobs",
            "dispatch_fences",
            "idempotency_keys",
            "devices",
            "device_sessions",
            "device_keys",
            "device_auth_challenges",
            "pairing_requests",
            "api_keys",
            "usage_ledger",
            "usage_periods",
            "usage_quota_policies",
            "webhook_endpoints",
            "webhook_deliveries",
            "webhook_replay_requests",
            "webhook_dispatch_accounts",
            "inbound_events",
            "recipient_suppressions",
            "billing_customers",
            "billing_events",
            "billing_risk_events",
            "billing_payment_holds",
            "billing_reconciliations",
            "billing_subscriptions",
            "billing_quota_audit",
            "billing_device_caps",
            "billing_device_cap_audit",
            "email_verifications",
            "password_resets",
            "password_reset_notice_outbox",
            "sms_owner_key_challenges",
            "owner_mfa",
            "owner_mfa_recovery_codes",
            "owner_mfa_login_challenges",
            "sessions",
            "memberships",
        ] {
            let sql = format!("SELECT count(*) FROM {table} WHERE account_id=$1");
            let left: i64 = db.query_one(&sql, &[&a.account_id]).await.unwrap().get(0);
            assert_eq!(left, 0, "{table} still holds erased-account rows");
        }
        // Outbox rows follow their verification codes, not an account column.
        let mail_left: i64 = db
            .query_one(
                "SELECT count(*) FROM verification_mail_outbox o \
                 JOIN email_verifications v ON v.id=o.verification_id \
                 WHERE v.account_id=$1",
                &[&a.account_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(mail_left, 0, "verification mail outbox still holds rows");
        // Webhook attempts follow their delivery rows, not an account column.
        let attempts_left: i64 = db
            .query_one(
                "SELECT count(*) FROM webhook_attempts a \
                 JOIN webhook_deliveries d ON d.id=a.delivery_id \
                 WHERE d.account_id=$1",
                &[&a.account_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(attempts_left, 0, "webhook attempts still hold rows");
        assert_eq!(
            table_count(
                &db,
                &format!("SELECT count(*) FROM accounts WHERE id='{}'", a.account_id)
            )
            .await,
            0,
            "the erased account row is gone"
        );
        let users_gone: i64 = db
            .query_one("SELECT count(*) FROM users WHERE id=$1", &[&a.user_id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(users_gone, 0);
        // The second account keeps every row: tenant isolation.
        let b_alive: i64 = db
            .query_one(
                "SELECT count(*) FROM accounts WHERE id=$1",
                &[&b.account_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(b_alive, 1);
        for sql in [
            "SELECT count(*) FROM devices WHERE account_id=$1",
            "SELECT count(*) FROM messages WHERE account_id=$1",
            "SELECT count(*) FROM sessions WHERE account_id=$1",
        ] {
            let rows: i64 = db.query_one(sql, &[&b.account_id]).await.unwrap().get(0);
            assert_eq!(rows, 1, "isolation probe row missing for account b");
        }
        let raw = serde_json::to_string(&report).unwrap();
        assert!(!raw.contains("ERASE_A_BODY"));
        assert!(!raw.contains("KEEP_B_BODY"));
        // The erased session no longer authenticates.
        let again = app
            .clone()
            .oneshot(erasure_post(
                Some(&session_a.token),
                Some(&session_a.csrf_token),
                Some(ORIGIN),
                &crate::test_keys::password(1),
            ))
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn wrong_current_password_is_rejected_and_deletes_nothing() {
        let (admin, mut db, database_url, schema) = migrated_schema("wrongpw").await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(24)).unwrap());
        let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url).await;
        let response = app
            .clone()
            .oneshot(erasure_post(
                Some(&session_a.token),
                Some(&session_a.csrf_token),
                Some(ORIGIN),
                &crate::test_keys::password(3),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let error = body(response).await;
        assert_eq!(error["code"], "invalid_request");
        for sql in [
            "SELECT count(*) FROM accounts WHERE id=$1",
            "SELECT count(*) FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.account_id=$1",
            "SELECT count(*) FROM messages WHERE account_id=$1",
            "SELECT count(*) FROM sessions WHERE account_id=$1",
            "SELECT count(*) FROM billing_customers WHERE account_id=$1",
        ] {
            let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
            assert_eq!(
                rows,
                if sql.contains("messages") { 2 } else { 1 },
                "a rejected erasure must not delete anything"
            );
        }
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn missing_csrf_or_wrong_origin_is_rejected_and_deletes_nothing() {
        let (admin, mut db, database_url, schema) = migrated_schema("csrf").await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(25)).unwrap());
        let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url).await;
        let missing_csrf = app
            .clone()
            .oneshot(erasure_post(
                Some(&session_a.token),
                None,
                Some(ORIGIN),
                &crate::test_keys::password(1),
            ))
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
        assert_eq!(body(missing_csrf).await["code"], "forbidden");
        let wrong_origin = app
            .clone()
            .oneshot(erasure_post(
                Some(&session_a.token),
                Some(&session_a.csrf_token),
                Some("https://evil.example"),
                &crate::test_keys::password(1),
            ))
            .await
            .unwrap();
        assert_eq!(wrong_origin.status(), StatusCode::FORBIDDEN);
        let anonymous = app
            .clone()
            .oneshot(erasure_post(
                None,
                Some(&session_a.csrf_token),
                Some(ORIGIN),
                &crate::test_keys::password(1),
            ))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        for sql in [
            "SELECT count(*) FROM accounts WHERE id=$1",
            "SELECT count(*) FROM messages WHERE account_id=$1",
        ] {
            let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
            assert_eq!(rows, if sql.contains("messages") { 2 } else { 1 });
        }
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn schema_protected_consent_rows_block_the_whole_erasure() {
        let (admin, mut db, database_url, schema) = migrated_schema("blocked").await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(26)).unwrap());
        let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url).await;
        db.execute(
            "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) \
             VALUES($1,$2,'+15559999999','email','opt_out',now()-interval '1 hour',$3)",
            &[&Uuid::new_v4(), &a.account_id, &a.user_id],
        )
        .await
        .unwrap();
        let response = app
            .clone()
            .oneshot(erasure_post(
                Some(&session_a.token),
                Some(&session_a.csrf_token),
                Some(ORIGIN),
                &crate::test_keys::password(1),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let blocked = body(response).await;
        assert_eq!(blocked["code"], "erasure_blocked");
        assert_eq!(blocked_count(&blocked, "owner_recipient_holds"), 1);
        // The rollback is complete: every fixture row is still present.
        for sql in [
            "SELECT count(*) FROM accounts WHERE id=$1",
            "SELECT count(*) FROM messages WHERE account_id=$1",
            "SELECT count(*) FROM sessions WHERE account_id=$1",
            "SELECT count(*) FROM billing_events WHERE account_id=$1",
        ] {
            let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
            assert_eq!(rows, if sql.contains("messages") { 2 } else { 1 });
        }
        let holds: i64 = db
            .query_one(
                "SELECT count(*) FROM owner_recipient_holds WHERE account_id=$1",
                &[&a.account_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(holds, 1);
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
