// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-recorded off-channel opt-out holds and review decisions.
//!
//! Every mutation needs the owner session, exact Origin and CSRF. It runs in
//! one transaction under the account lock that delivery admission takes, so a
//! committed hold is visible to every later admission. Requests carry bounded
//! codes only; a free-text field is rejected. Nothing here lifts a signed
//! suppression or a hold. Only a later signed START releases a hold.

use super::{OwnerReviewState, PAGE_SIZE};
use crate::http_auth::require_owner;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Allow small browser clock skew, but never a future withdrawal date.
const MAX_FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;
/// Owners record a withdrawal soon after it happens, not years later.
const MAX_REPORT_AGE_MS: i64 = 366 * 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Channel {
    Email,
    PhoneCall,
    WebForm,
    PostalMail,
    InPerson,
    Other,
}

impl Channel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::PhoneCall => "phone_call",
            Self::WebForm => "web_form",
            Self::PostalMail => "postal_mail",
            Self::InPerson => "in_person",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    OptOut,
    ConsentWithdrawn,
    Complaint,
    WrongNumber,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Self::OptOut => "opt_out",
            Self::ConsentWithdrawn => "consent_withdrawn",
            Self::Complaint => "complaint",
            Self::WrongNumber => "wrong_number",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Decision {
    ConfirmedOptOut,
    NotOptOut,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Self::ConfirmedOptOut => "confirmed_opt_out",
            Self::NotOptOut => "not_opt_out",
        }
    }

    fn audit_event(self) -> &'static str {
        match self {
            Self::ConfirmedOptOut => "review_confirmed",
            Self::NotOptOut => "review_dismissed",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HoldBody {
    recipient_e164: String,
    channel: Channel,
    reason: Reason,
    reported_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionBody {
    review_event_id: Uuid,
    decision: Decision,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HoldListQuery {
    /// A hold UUID keeps phone numbers out of request URLs and access logs.
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct CreatedHold {
    hold_id: Uuid,
    cancelled_messages: u64,
}

#[derive(Serialize)]
struct HoldView {
    hold_id: Uuid,
    recipient_e164: String,
    channel: String,
    reason: String,
    reported_at_ms: i64,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct HoldPage {
    holds: Vec<HoldView>,
    next_cursor: Option<Uuid>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
}

fn error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(ErrorBody { code })).into_response()
}

fn unavailable() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}

pub(super) fn valid_e164(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=16).contains(&bytes.len())
        && bytes[0] == b'+'
        && (b'1'..=b'9').contains(&bytes[1])
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

pub(super) fn valid_hold(body: &HoldBody, now_ms: i64) -> bool {
    valid_e164(&body.recipient_e164)
        && body.reported_at_ms <= now_ms.saturating_add(MAX_FUTURE_SKEW_MS)
        && body.reported_at_ms >= now_ms.saturating_sub(MAX_REPORT_AGE_MS)
}

fn now_ms() -> Option<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

/// Delivery admission and signed suppression writers take this lock first.
async fn lock_account(tx: &Transaction<'_>, account_id: Uuid) -> Result<bool, Response> {
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
        &[&account_id],
    )
    .await
    .map(|row| row.is_some())
    .map_err(|_| unavailable())
}

pub(super) async fn create_hold(
    State(state): State<Arc<OwnerReviewState>>,
    headers: HeaderMap,
    Json(body): Json<HoldBody>,
) -> Response {
    let Some(now) = now_ms() else {
        return unavailable();
    };
    if !valid_hold(&body, now) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let owner = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await
    {
        Ok(owner) => owner,
        Err(error) => return error.into_response(),
    };
    let account_id = owner.tenant.account_id();
    let Ok(tx) = client.transaction().await else {
        return unavailable();
    };
    match lock_account(&tx, account_id).await {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(response) => return response,
    }
    let reported_seconds = body.reported_at_ms as f64 / 1000.0;
    let hold_id = Uuid::new_v4();
    // One insert time clamps permitted clock skew, so reported_at never
    // exceeds created_at whichever expression PostgreSQL evaluates first.
    let inserted = tx
        .query_opt(
            "WITH t AS (SELECT clock_timestamp() AS at) \
             INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by,created_at) \
             SELECT $1,$2,$3,$4,$5,LEAST(to_timestamp($6),t.at),$7,t.at FROM t \
             ON CONFLICT (account_id,recipient_e164) WHERE released_at IS NULL DO NOTHING RETURNING id",
            &[&hold_id, &account_id, &body.recipient_e164, &body.channel.as_str(),
              &body.reason.as_str(), &reported_seconds, &owner.user_id],
        )
        .await;
    match inserted {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::CONFLICT, "hold_active"),
        Err(_) => return unavailable(),
    }
    let cancelled_messages = match zrotext_delivery_store::cancel_pending_recipient(
        &tx,
        account_id,
        &body.recipient_e164,
    )
    .await
    {
        Ok(count) => count,
        Err(_) => return unavailable(),
    };
    if tx
        .execute(
            "INSERT INTO owner_opt_out_audit(id,account_id,event,actor_user_id,actor_session_id,hold_id) \
             VALUES($1,$2,'hold_created',$3,$4,$5)",
            &[&Uuid::new_v4(), &account_id, &owner.user_id, &owner.session_id, &hold_id],
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return unavailable();
    }
    (
        StatusCode::CREATED,
        Json(CreatedHold {
            hold_id,
            cancelled_messages,
        }),
    )
        .into_response()
}

pub(super) async fn list_holds(
    State(state): State<Arc<OwnerReviewState>>,
    Query(query): Query<HoldListQuery>,
    headers: HeaderMap,
) -> Response {
    let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let owner = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await
    {
        Ok(owner) => owner,
        Err(error) => return error.into_response(),
    };
    let account_id = owner.tenant.account_id();
    let before: Option<(SystemTime, Uuid)> = if let Some(before) = query.before {
        match client
            .query_opt(
                "SELECT created_at,id FROM owner_recipient_holds \
                 WHERE account_id=$1 AND id=$2 AND released_at IS NULL",
                &[&account_id, &before],
            )
            .await
        {
            Ok(Some(row)) => Some((row.get(0), row.get(1))),
            Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
            Err(_) => return unavailable(),
        }
    } else {
        None
    };
    let before_at = before.map(|point| point.0);
    let before_id = before.map(|point| point.1);
    let rows = match client
        .query(
            "SELECT id,recipient_e164,channel,reason, \
             (extract(epoch FROM reported_at)*1000)::bigint, \
             (extract(epoch FROM created_at)*1000)::bigint \
             FROM owner_recipient_holds WHERE account_id=$1 AND released_at IS NULL \
             AND ($2::timestamptz IS NULL OR (created_at,id)<($2,$3::uuid)) \
             ORDER BY created_at DESC,id DESC LIMIT 21",
            &[&account_id, &before_at, &before_id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unavailable(),
    };
    let has_more = rows.len() > PAGE_SIZE;
    let holds: Vec<HoldView> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .map(|row| HoldView {
            hold_id: row.get(0),
            recipient_e164: row.get(1),
            channel: row.get(2),
            reason: row.get(3),
            reported_at_ms: row.get(4),
            created_at_ms: row.get(5),
        })
        .collect();
    let next_cursor = if has_more {
        holds.last().map(|hold| hold.hold_id)
    } else {
        None
    };
    Json(HoldPage { holds, next_cursor }).into_response()
}

pub(super) async fn decide_review(
    State(state): State<Arc<OwnerReviewState>>,
    headers: HeaderMap,
    Json(body): Json<DecisionBody>,
) -> Response {
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return unavailable();
    };
    let owner = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await
    {
        Ok(owner) => owner,
        Err(error) => return error.into_response(),
    };
    let account_id = owner.tenant.account_id();
    let Ok(tx) = client.transaction().await else {
        return unavailable();
    };
    match lock_account(&tx, account_id).await {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(response) => return response,
    }
    // Only an active, ambiguous review item can be decided. A signed STOP is
    // not in the queue and never reaches this insert.
    let recipient: String = match tx
        .query_opt(
            "SELECT recipient_e164 FROM recipient_suppressions \
             WHERE account_id=$1 AND active AND source IN ('sms_review','sms_unsolicited_review') \
             AND COALESCE(source_event_id,source_unsolicited_event_id)=$2",
            &[&account_id, &body.review_event_id],
        )
        .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return unavailable(),
    };
    let inserted = tx
        .query_opt(
            "INSERT INTO owner_opt_out_review_decisions(account_id,review_event_id,recipient_e164,decision,decided_by) \
             VALUES($1,$2,$3,$4,$5) ON CONFLICT (account_id,review_event_id) DO NOTHING RETURNING 1",
            &[&account_id, &body.review_event_id, &recipient, &body.decision.as_str(), &owner.user_id],
        )
        .await;
    match inserted {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::CONFLICT, "already_decided"),
        Err(_) => return unavailable(),
    }
    if tx
        .execute(
            "INSERT INTO owner_opt_out_audit(id,account_id,event,actor_user_id,actor_session_id,review_event_id) \
             VALUES($1,$2,$3,$4,$5,$6)",
            &[&Uuid::new_v4(), &account_id, &body.decision.audit_event(), &owner.user_id,
              &owner.session_id, &body.review_event_id],
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return unavailable();
    }
    StatusCode::CREATED.into_response()
}

#[cfg(test)]
mod tests;
