// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-initiated account erasure. This is the one-request, irreversible
//! counterpart of the owner data export: the signed-in owner re-proves the
//! current password (and a second factor when MFA is enabled), and one
//! database transaction deletes every account-owned row in foreign-key
//! order, ending with the account itself. It is separate from the scheduled
//! retention worker, which prunes old content and history on a timetable and
//! is explicitly not an account-erasure API. Self-hosting semantics and
//! limits are documented in "Account erasure" in `docs/SELF-HOSTING.md`.
//!
//! The password proof is taken before the transaction, but the transaction
//! re-fences authorization under locks immediately before the first delete
//! (see [`crate::auth::account::fence_owner_mutation`]): a password change,
//! session revocation or expiry, or account disable that happens after the
//! proof — including while the fence's own locks were being granted —
//! aborts the erasure with nothing deleted.
//!
//! Some rows are deliberately impossible to erase. Append-only consent and
//! audit tables (`owner_recipient_holds`, `owner_opt_out_review_decisions`,
//! `owner_opt_out_audit`, `sms_owner_key_audit`), line identity tombstones
//! (`phone_lines`, `device_line_bindings`), and their approval keys,
//! challenges and activation exchanges reject DELETE at the schema level;
//! the sealed trust history (`known_signing_point_reservations`,
//! `known_signing_role_claims`, `sealed_root_enrollments`,
//! `sealed_root_receipts`) is immutable the same way, and its rows appear
//! for every account that ever enrolled a device key or approval key; and
//! operator billing review actions outlive their account. Their foreign
//! keys reference the account row — and the cascade itself fires the
//! immutability triggers — so while any of them exist a complete erasure is
//! impossible: the request fails closed with the blocking tables listed
//! and nothing is deleted. The same applies when another account's
//! `billing_risk_events` row still references one of this account's
//! `billing_events`: the referenced event cannot be deleted while the
//! reference exists, so the whole erasure is blocked instead of partially
//! retained. Metering and billing rows are erased with everything else; only
//! request-budget counters (keyed hashes shared across accounts) are kept,
//! and that kept set is reported honestly in the response.
//!
//! Observer seats are account-owned people too. Erasing the account deletes
//! every observer user row of it (email, password hash, verification state),
//! live or removed, together with its invitations and removal records, using
//! the guard seat removal uses: only a user whose sole membership is an
//! observer seat of THIS account, never an owner and never a user with a
//! membership elsewhere. Before the auth fence the transaction locks the
//! account's observer memberships and invitation rows in the same order seat
//! removal and acceptance take them (membership, then invitation), so an
//! in-flight removal or acceptance finishes first and none can start on
//! those rows until the erasure ends; the fence's `FOR UPDATE` on the account
//! row then blocks any membership insert, so an acceptance cannot resurrect
//! an observer of an erased account (it fails once the account is gone). If a
//! foreign key refuses an observer user delete the erasure fails closed like
//! every other blocker: 409 `erasure_blocked` naming `observer_users`, and
//! nothing is deleted.

use crate::{
    auth::{
        AuthError, TokenHasher,
        abuse_limits::{self, Limit},
        account, mfa,
    },
    http_auth::preauth::{OwnerAuthState, OwnerMutation},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{StatusCode, header},
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
/// deleted by design — DELETE-rejecting triggers, which the account-row
/// cascade fires too. Any row here blocks the whole erasure.
const BLOCKED_TABLES: &[&str] = &[
    "phone_lines",
    "device_line_bindings",
    "line_owner_approval_keys",
    "line_activation_challenges",
    "sms_line_activation_exchanges",
    "sealed_line_activation_exchanges",
    "sms_line_owner_approval_keys",
    "sms_owner_key_audit",
    "owner_recipient_holds",
    "owner_opt_out_review_decisions",
    "owner_opt_out_audit",
    "known_signing_point_reservations",
    "known_signing_role_claims",
    "sealed_root_enrollments",
    "sealed_root_receipts",
];

/// FK-safe deletion order: every table is emptied before the rows it
/// references. Each statement takes the account UUID as `$1`; composite
/// foreign keys make cross-account references impossible except where an
/// extra `OR device_id/message_id IN (...)` arm covers pre-account legacy
/// rows with a NULL account_id. Tables that the schema cascades from the
/// account row are deleted explicitly anyway, so the reported per-table
/// counts stay honest.
pub(crate) const DELETE_PLAN: &[(&str, &str)] = &[
    (
        "exposure_reservation_scopes",
        "DELETE FROM exposure_reservation_scopes WHERE account_id=$1",
    ),
    (
        "exposure_reservations",
        "DELETE FROM exposure_reservations WHERE account_id=$1",
    ),
    (
        "exposure_scope_budgets",
        "DELETE FROM exposure_scope_budgets WHERE account_id=$1",
    ),
    (
        "exposure_route_policies",
        "DELETE FROM exposure_route_policies WHERE account_id=$1",
    ),
    (
        "workflow_schedule_audit",
        "DELETE FROM workflow_schedule_audit WHERE account_id=$1",
    ),
    (
        "workflow_schedule_occurrences",
        "DELETE FROM workflow_schedule_occurrences WHERE account_id=$1",
    ),
    (
        "workflow_schedule_series",
        "DELETE FROM workflow_schedule_series WHERE account_id=$1",
    ),
    (
        "workflow_schedule_policies",
        "DELETE FROM workflow_schedule_policies WHERE account_id=$1",
    ),
    (
        "workflow_integration_access",
        "DELETE FROM workflow_integration_access WHERE account_id=$1",
    ),
    (
        "workflow_connector_context_envelopes",
        "DELETE FROM workflow_connector_context_envelopes WHERE account_id=$1",
    ),
    (
        "workflow_integration_grants",
        "DELETE FROM workflow_integration_grants WHERE account_id=$1",
    ),
    (
        "workflow_message_links",
        "DELETE FROM workflow_message_links WHERE account_id=$1",
    ),
    (
        "workflow_reply_correlations",
        "DELETE FROM workflow_reply_correlations WHERE account_id=$1",
    ),
    (
        "workflow_action_mutations",
        "DELETE FROM workflow_action_mutations WHERE account_id=$1",
    ),
    (
        "workflow_action_versions",
        "DELETE FROM workflow_action_versions WHERE account_id=$1",
    ),
    (
        "workflow_actions",
        "DELETE FROM workflow_actions WHERE account_id=$1",
    ),
    (
        "workflow_routines",
        "DELETE FROM workflow_routines WHERE account_id=$1",
    ),
    (
        "workflow_context_fences",
        "DELETE FROM workflow_context_fences WHERE account_id=$1",
    ),
    (
        "workflow_context_audit",
        "DELETE FROM workflow_context_audit WHERE account_id=$1",
    ),
    (
        "workflow_exceptions",
        "DELETE FROM workflow_exceptions WHERE account_id=$1",
    ),
    (
        "workflow_context_versions",
        "DELETE FROM workflow_context_versions WHERE account_id=$1",
    ),
    (
        "workflow_contexts",
        "DELETE FROM workflow_contexts WHERE account_id=$1",
    ),
    (
        "conversation_execution_records",
        "DELETE FROM conversation_execution_records WHERE account_id=$1",
    ),
    (
        "conversation_confirmation_records",
        "DELETE FROM conversation_confirmation_records WHERE account_id=$1",
    ),
    // Contacts and their append-only consent history: erasable account
    // records (unlike the schema-protected opt-out planes), deleted before
    // the memberships their recorder foreign keys point at.
    (
        "contact_consent_records",
        "DELETE FROM contact_consent_records WHERE account_id=$1",
    ),
    ("contacts", "DELETE FROM contacts WHERE account_id=$1"),
    (
        "conversation_inbound_provenance",
        "DELETE FROM conversation_inbound_provenance WHERE account_id=$1",
    ),
    (
        "conversation_intervals",
        "DELETE FROM conversation_intervals WHERE account_id=$1",
    ),
    (
        "owner_conversation_consents",
        "DELETE FROM owner_conversation_consents WHERE account_id=$1",
    ),
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
        "agent_authority_actions",
        "DELETE FROM agent_authority_actions WHERE account_id=$1",
    ),
    (
        "agent_authority_approvals",
        "DELETE FROM agent_authority_approvals WHERE account_id=$1",
    ),
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
    (
        "agent_authority_grants",
        "DELETE FROM agent_authority_grants WHERE account_id=$1",
    ),
    // Enrollment before its device keys and devices.
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
    // Device-reported preconditions before the devices they describe.
    (
        "device_preconditions",
        "DELETE FROM device_preconditions WHERE account_id=$1",
    ),
    ("devices", "DELETE FROM devices WHERE account_id=$1"),
    // Sealed state. The immutable trust history (reservations, role claims,
    // root enrollments, public receipts) is a blocked table above; these
    // sealed rows are cascade-deletable and deleted explicitly so their
    // counts appear in the report.
    (
        "sealed_manifest_authorities",
        "DELETE FROM sealed_manifest_authorities WHERE account_id=$1",
    ),
    (
        "sealed_root_challenges",
        "DELETE FROM sealed_root_challenges WHERE account_id=$1",
    ),
    // Billing: children first, provider binding last. billing_events follows
    // billing_risk_events: the account's own risk rows are gone by then, and
    // any cross-account reference was blocked before the deletes began.
    (
        "billing_payment_holds",
        "DELETE FROM billing_payment_holds WHERE account_id=$1",
    ),
    (
        "billing_risk_events",
        "DELETE FROM billing_risk_events WHERE account_id=$1",
    ),
    (
        "billing_events",
        "DELETE FROM billing_events WHERE account_id=$1",
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
    // Invitations and removal records hold invitee addresses. Their user link
    // is `ON DELETE SET NULL` and the account link cascades, but they are
    // deleted explicitly so the report and the account-row delete stay honest.
    (
        "seat_invitations",
        "DELETE FROM seat_invitations WHERE account_id=$1",
    ),
    // Observer users of this account, by the seat-removal guard: the user is
    // an observer of THIS account and holds no membership of any other kind
    // or account. Owners never match. Deleting the user cascades the observer
    // membership, so the plan's memberships count below is owners only.
    (OBSERVER_USERS_TABLE, OBSERVER_USERS_SQL),
    ("memberships", "DELETE FROM memberships WHERE account_id=$1"),
];

/// Report label of the guarded observer user delete in [`DELETE_PLAN`].
const OBSERVER_USERS_TABLE: &str = "observer_users";
const OBSERVER_USERS_SQL: &str = "DELETE FROM users u WHERE \
     EXISTS (SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.account_id=$1 AND m.role='observer') \
     AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id=u.id \
                     AND NOT (m.account_id=$1 AND m.role='observer'))";

const ERASED_STATEMENT: &str = "One transaction deleted every account-owned row listed under deleted, in foreign-key order, including the observer users invited to the account and its invitation records, and then the account itself. Rows under retained were kept only for the stated reason: the request-budget rows are pepper-keyed digests shared across accounts, hold no identifiers, and the worker prunes them. This response is the only confirmation. The account and its sessions no longer exist, so later authenticated requests fail, and database backups, replicas and WAL archives keep their own separate lifecycle.";

const BLOCKED_STATEMENT: &str = "Nothing was deleted. The listed rows are append-only consent and audit records, line identity tombstones, immutable sealed trust history, operator review decisions, billing events still referenced by another account's risk records, or an observer user that a foreign key refuses to delete, and their foreign keys still reference the account, so a complete erasure is impossible while they exist. The transaction rolled back unchanged; contact the operator about those records.";

#[derive(Clone)]
pub struct OwnerErasureState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
    /// Second-factor cipher for the MFA step-up, exactly as the account
    /// routes hold it. `None` still accepts recovery codes.
    pub mfa_cipher: Option<Arc<mfa::MfaCipher>>,
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
    /// Second-factor code, required when the owner has MFA enabled. Same
    /// field name and semantics as the password-change and revoke-others
    /// request bodies.
    code: Option<String>,
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
        // Only the seat-invitation routes raise Conflict; erasure never does.
        AuthError::Conflict => error_response(StatusCode::CONFLICT, "conflict"),
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

impl OwnerAuthState for OwnerErasureState {
    fn database_url(&self) -> &str {
        &self.database_url
    }
    fn session_hasher(&self) -> &TokenHasher {
        &self.auth_hasher
    }
    fn canonical_origin(&self) -> &str {
        &self.canonical_origin
    }
    fn unavailable_response(&self) -> Response {
        error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    }
}

async fn erase_account(
    State(state): State<Arc<OwnerErasureState>>,
    OwnerMutation(principal, _slot): OwnerMutation,
    Json(body): Json<EraseBody>,
) -> Response {
    // The extractor above already enforced the mutation chain the account
    // routes use — session cookie, exact configured Origin, and the
    // double-submit CSRF pair — before this body was read, and holds one of
    // the account's in-flight slots until the handler returns.
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
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
    // the same lookup the /sessions/revoke-others handler uses, keeping the
    // verified hash for the in-transaction fence below. A wrong password
    // fails closed with that route's status and body.
    let verified_hash =
        match account::verify_current_password(&client, &principal, &body.current_password).await {
            Ok(hash) => hash,
            Err(AuthError::InvalidCredentials) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request");
            }
            Err(error) => return auth_error(error),
        };
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
        if *table == "sealed_line_activation_exchanges" {
            let installed = match tx
                .query_one(
                    "SELECT to_regclass('sealed_line_activation_exchanges') IS NOT NULL",
                    &[],
                )
                .await
            {
                Ok(r) => r.get::<_, bool>(0),
                Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            };
            if !installed {
                continue;
            }
        }
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
    // A billing event referenced by ANOTHER account's risk record cannot be
    // deleted while that reference exists, and `billing_risk_events` keeps
    // its foreign key to it, so `accounts` could never be deleted either.
    // Block the whole erasure up front instead of failing the foreign key
    // mid-transaction after the other deletes already ran.
    let shared_billing_events = match count(
        &tx,
        "SELECT count(*) FROM billing_events b WHERE b.account_id=$1 \
         AND EXISTS (SELECT 1 FROM billing_risk_events r \
                     WHERE r.stripe_event_id=b.stripe_event_id AND r.account_id<>$1)",
        account_id,
    )
    .await
    {
        Ok(rows) => rows,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    if shared_billing_events > 0 {
        blocked.push(TableCount {
            table: "billing_events",
            rows: shared_billing_events,
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
    // Quiesce observer seats before the fence, in the order seat removal and
    // acceptance take these rows (membership, then invitation), so no lock
    // cycle can form with them: an in-flight removal or acceptance finishes
    // first, and later ones queue behind this transaction on rows that no
    // longer exist once it commits. These reads can wait, so they belong
    // before the fence and never after it. Removed seats whose user row
    // survived (their membership is revoked, not deleted) are included.
    let observer_seats = match tx
        .query(
            "SELECT user_id FROM memberships \
             WHERE account_id=$1 AND role='observer' ORDER BY user_id FOR UPDATE",
            &[&account_id],
        )
        .await
    {
        Ok(rows) => rows.len() as u64,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    if tx
        .query(
            "SELECT id FROM seat_invitations WHERE account_id=$1 ORDER BY id FOR UPDATE",
            &[&account_id],
        )
        .await
        .is_err()
    {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    // Inspect proof storage before the final fence: schema preparation can wait.
    let confirmation_installed =
        match crate::http_owner_conversations::confirmation_records::installed(&tx).await {
            Ok(value) => value,
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
    if confirmation_installed
        && !crate::http_owner_conversations::confirmation_records::validate(&tx)
            .await
            .unwrap_or(false)
    {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    let execution_installed =
        match crate::http_owner_conversations::channel::execution::lifecycle::installed(&tx).await {
            Ok(value) => value,
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
    if execution_installed {
        if !crate::http_owner_conversations::channel::execution::lifecycle::validate(&tx)
            .await
            .unwrap_or(false)
        {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        // Serialize manifest-first producers before taking the canonical owner
        // locks. Missing authority is not approval and does not prevent erasure.
        if tx
            .query(
                "SELECT account_id FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
                &[&account_id],
            )
            .await
            .is_err()
        {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        // Main's owner mutation order is user/member before account. Acquire only
        // those rows first; password/MFA verification remains the final fence.
        match tx.query_opt("SELECT 1 FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$1 AND m.account_id=$2 AND m.role='owner' AND a.disabled_at IS NULL FOR UPDATE OF u,m", &[&principal.user_id,&account_id]).await {
            Ok(Some(_)) => {}
            Ok(None) => return auth_error(AuthError::Unauthorized),
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
        // The existing helper acquires billing-customer before account, including
        // the concurrent-new-binding recheck. SQL locks belong to the transaction.
        match zrotext_delivery_store::sealed::lock_account(&tx, account_id, false).await {
            Ok(_) => {}
            Err(zrotext_delivery_store::StoreError::Revoked) => {
                return auth_error(AuthError::Unauthorized);
            }
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
        // Manifest -> user/member -> billing/account -> execution record. All
        // waits precede the single complete password/MFA/current-session fence.
        if tx.query("SELECT message_id FROM conversation_execution_records WHERE account_id=$1 ORDER BY message_id FOR UPDATE",&[&account_id]).await.is_err() {
            return error_response(StatusCode::SERVICE_UNAVAILABLE,"unavailable");
        }
    }
    // FINAL AUTH FENCE. Ordering inside this transaction is deliberate:
    // every read that can wait on a row lock — all the blocked-table
    // preflight counts above — has already run, and this fence is the last
    // statement set before the first delete, with nothing that waits in
    // between. The fence locks the user, membership, and account rows plus
    // the session row, revalidates the password proof against the locked
    // hash, runs the MFA step-up, and finishes with one fresh-statement
    // recheck of revoked/expiry (against clock_timestamp())/disabled state,
    // so an invalidation committed while any of its locks were being
    // granted is observed here and aborts with nothing deleted.
    match account::fence_owner_mutation(
        &tx,
        state.mfa_cipher.as_deref(),
        &state.auth_hasher,
        &principal,
        &verified_hash,
        body.code.as_deref(),
    )
    .await
    {
        Ok(account::OwnerMutationFence::Cleared) => {}
        Ok(account::OwnerMutationFence::FactorRejected) => {
            // The wrong factor spent the shared failure budget; commit that
            // one recording before rejecting, exactly like revoke-others.
            if tx.commit().await.is_err() {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
            }
            return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        Err(error) => return auth_error(error),
    }
    // Everything below is one transaction: any failure rolls the whole
    // erasure back, never leaving a half-erased account.
    // The proof table is absent only before its allocated migration. No proof
    // can be accepted then. Once installed it participates in the guarded plan.
    if execution_installed {
        let still_live=tx.query_one("SELECT EXISTS(SELECT 1 FROM sessions s JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN accounts a ON a.id=s.account_id JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL)",&[&principal.session_id,&account_id,&principal.user_id]).await;
        match still_live {
            Ok(row) if row.get::<_, bool>(0) => {}
            Ok(_) => return auth_error(crate::auth::AuthError::Unauthorized),
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
        // This disable and every deletion commit together; any failure rolls
        // back both. All rows which could wait have now been fenced.
        if tx
            .execute(
                "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
                &[&account_id],
            )
            .await
            .is_err()
        {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
    }
    let integration_installed = match crate::workflow_runtime::lifecycle::installed(&tx).await {
        Ok(value) => value,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    let mut deleted = Vec::new();
    match crate::workflow_templates::lifecycle::erase(&tx, account_id).await {
        Ok(counts) => deleted.extend(
            counts
                .into_iter()
                .map(|(table, rows)| TableCount { table, rows }),
        ),
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }

    match crate::billing::invoice::lifecycle::erase(&tx, account_id).await {
        Ok(counts) => deleted.extend(
            counts
                .into_iter()
                .map(|(table, rows)| TableCount { table, rows }),
        ),
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
    for &(table, sql) in DELETE_PLAN {
        if table == "conversation_execution_records" && !execution_installed {
            continue;
        }
        if [
            "workflow_integration_access",
            "workflow_connector_context_envelopes",
            "workflow_integration_grants",
        ]
        .contains(&table)
            && !integration_installed
        {
            continue;
        }
        if table == "conversation_confirmation_records" && !confirmation_installed {
            continue;
        }
        let rows = match tx.execute(sql, &[&account_id]).await {
            Ok(rows) => rows,
            // A foreign key refusing an observer user delete is a blocker,
            // not a transient fault: fail closed and say what blocks it.
            Err(error)
                if table == OBSERVER_USERS_TABLE
                    && error
                        .code()
                        .is_some_and(|code| code.code().starts_with("23")) =>
            {
                return (
                    StatusCode::CONFLICT,
                    Json(BlockedView {
                        code: "erasure_blocked",
                        blocked: vec![TableCount {
                            table: OBSERVER_USERS_TABLE,
                            rows: observer_seats,
                        }],
                        statement: BLOCKED_STATEMENT,
                    }),
                )
                    .into_response();
            }
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        deleted.push(TableCount { table, rows });
    }
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
    // Cross-account billing references were blocked before any delete, so
    // the only retained set is the shared request-budget counters.
    let retained = vec![RetainedSet {
        table: "auth_abuse_counters",
        rows: None,
        reason: "request-budget rows are pepper-keyed digests shared across accounts; \
                 they hold no identifiers and the worker prunes them",
    }];
    Json(ErasureView {
        account_id,
        deleted,
        retained,
        statement: ERASED_STATEMENT,
    })
    .into_response()
}

#[cfg(test)]
mod tests;
