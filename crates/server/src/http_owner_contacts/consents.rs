// SPDX-License-Identifier: AGPL-3.0-only
//! Per-purpose consent records for one contact: append-only grant and
//! withdraw events with source, effective time and optional expiry.
//!
//! Consent is never created by import; only an owner session can record it
//! here. The current state of a purpose is the latest event for it: a
//! `withdraw` stands until a later grant, and a `grant` whose expiry has
//! passed reads as expired without any write. Recording a withdrawal needs
//! an existing grant for the same purpose; granting again needs the purpose
//! to be withdrawn, expired or never granted. Writers serialize on the
//! contact row so two owners cannot interleave events for one purpose.

use super::OwnerContactsState;
use crate::{
    api_json::ApiJson,
    auth::TokenHasher,
    http_auth::preauth::{OwnerAuthState, OwnerMutation},
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::SystemTime};
use tokio_postgres::Row;
use uuid::Uuid;

/// Allow small browser clock skew, but never a future effective time.
const MAX_FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;
/// Owners record consent soon after it happens, not years later.
const MAX_EFFECTIVE_AGE_MS: i64 = 366 * 24 * 60 * 60 * 1000;
/// The farthest expiry a grant may carry past its own effective time.
pub const MAX_EXPIRY_HORIZON_MS: i64 = 730 * 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Purpose {
    Transactional,
    Operational,
    Marketing,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Transactional => "transactional",
            Self::Operational => "operational",
            Self::Marketing => "marketing",
        }
    }

    /// Marketing consent must carry an expiry: it is the one purpose that
    /// can never be open-ended.
    fn requires_expiry(self) -> bool {
        self == Self::Marketing
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConsentAction {
    Grant,
    Withdraw,
}

impl ConsentAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Withdraw => "withdraw",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConsentSource {
    ManualEntry,
    OffChannelRecord,
}

impl ConsentSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ManualEntry => "manual_entry",
            Self::OffChannelRecord => "off_channel_record",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConsentBody {
    purpose: Purpose,
    action: ConsentAction,
    source: ConsentSource,
    effective_at_ms: i64,
    expires_at_ms: Option<i64>,
}

/// One stored consent event, newest first.
#[derive(Serialize)]
pub(crate) struct ConsentRecordView {
    pub record_id: Uuid,
    pub purpose: String,
    pub action: String,
    pub source: String,
    pub effective_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub recorded_at_ms: i64,
}

/// The evaluated state of one purpose: its newest event plus the status the
/// event implies at read time.
#[derive(Serialize)]
pub(crate) struct ConsentStateView {
    pub purpose: String,
    pub status: &'static str,
    #[serde(flatten)]
    pub latest: ConsentRecordView,
}

impl ConsentStateView {
    /// Builds the state one purpose is in given its newest event.
    fn from_latest(latest: &ConsentRecordView, now_ms: i64) -> Self {
        let status = if latest.action == "withdraw" {
            "withdrawn"
        } else {
            match latest.expires_at_ms {
                Some(expires_at_ms) if expires_at_ms <= now_ms => "expired",
                _ => "granted",
            }
        };
        Self {
            purpose: latest.purpose.clone(),
            status,
            latest: ConsentRecordView {
                record_id: latest.record_id,
                purpose: latest.purpose.clone(),
                action: latest.action.clone(),
                source: latest.source.clone(),
                effective_at_ms: latest.effective_at_ms,
                expires_at_ms: latest.expires_at_ms,
                recorded_at_ms: latest.recorded_at_ms,
            },
        }
    }
}

pub(super) fn valid_consent(body: &ConsentBody, now_ms: i64) -> bool {
    let bounded_effective = body.effective_at_ms <= now_ms.saturating_add(MAX_FUTURE_SKEW_MS)
        && body.effective_at_ms >= now_ms.saturating_sub(MAX_EFFECTIVE_AGE_MS);
    if !bounded_effective {
        return false;
    }
    match body.action {
        ConsentAction::Grant => {
            if body.purpose.requires_expiry() && body.expires_at_ms.is_none() {
                return false;
            }
            match body.expires_at_ms {
                // An expiry must sit strictly after the effective time and
                // within the bounded horizon.
                Some(expires_at_ms) => {
                    expires_at_ms > body.effective_at_ms
                        && expires_at_ms
                            <= body.effective_at_ms.saturating_add(MAX_EXPIRY_HORIZON_MS)
                }
                None => true,
            }
        }
        ConsentAction::Withdraw => body.expires_at_ms.is_none(),
    }
}

/// Reads one contact's consent history newest-first, account-scoped.
pub(crate) async fn consent_history(
    client: &tokio_postgres::Client,
    account_id: Uuid,
    contact_id: Uuid,
) -> Result<Vec<ConsentRecordView>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT id,purpose,action,source, \
             (extract(epoch FROM effective_at)*1000)::bigint, \
             (extract(epoch FROM expires_at)*1000)::bigint, \
             (extract(epoch FROM recorded_at)*1000)::bigint \
             FROM contact_consent_records \
             WHERE account_id=$1 AND contact_id=$2 \
             ORDER BY effective_at DESC,recorded_at DESC,id DESC",
            &[&account_id, &contact_id],
        )
        .await?;
    Ok(rows.iter().map(record_view).collect())
}

/// Collapses the history into the current state of each purpose, newest
/// event per purpose first, in history order.
pub(crate) fn consent_states(history: &[ConsentRecordView], now_ms: i64) -> Vec<ConsentStateView> {
    let mut seen = Vec::new();
    history
        .iter()
        .filter(|record| {
            if seen.contains(&record.purpose) {
                false
            } else {
                seen.push(record.purpose.clone());
                true
            }
        })
        .map(|latest| ConsentStateView::from_latest(latest, now_ms))
        .collect()
}

fn record_view(row: &Row) -> ConsentRecordView {
    ConsentRecordView {
        record_id: row.get(0),
        purpose: row.get(1),
        action: row.get(2),
        source: row.get(3),
        effective_at_ms: row.get(4),
        expires_at_ms: row.get(5),
        recorded_at_ms: row.get(6),
    }
}

pub(super) fn now_ms() -> Option<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

fn error(status: StatusCode, code: &'static str) -> Response {
    #[derive(Serialize)]
    struct ErrorBody {
        code: &'static str,
    }
    (status, Json(ErrorBody { code })).into_response()
}

impl OwnerAuthState for OwnerContactsState {
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
        error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    }
}

pub(super) async fn record_consent(
    State(state): State<Arc<OwnerContactsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(contact_id): Path<Uuid>,
    ApiJson(body): ApiJson<ConsentBody>,
) -> Response {
    let Some(now) = now_ms() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    if !valid_consent(&body, now) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(mut client) = crate::runtime_db::connect(&state.database_url).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    let account_id = owner.tenant.account_id();
    let Ok(tx) = client.transaction().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    if tx
        .batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    // The same account lock admission and the opt-out writers take.
    let locked = tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
            &[&account_id],
        )
        .await;
    match locked {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
    // Serialize concurrent consent writers on the contact row; the scoped
    // lookup doubles as the cross-account check.
    let contact = tx
        .query_opt(
            "SELECT id FROM contacts WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&account_id, &contact_id],
        )
        .await;
    match contact {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
    // The newest event for this purpose decides whether the requested
    // transition is coherent.
    let current = tx
        .query_opt(
            "SELECT action,expires_at,floor(extract(epoch FROM effective_at)*1000)::bigint FROM contact_consent_records \
             WHERE account_id=$1 AND contact_id=$2 AND purpose=$3 \
             ORDER BY effective_at DESC,recorded_at DESC,id DESC LIMIT 1",
            &[&account_id, &contact_id, &body.purpose.as_str()],
        )
        .await;
    let current = match current {
        Ok(row) => row,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    if current.as_ref().is_some_and(|row| {
        let latest_effective_ms: i64 = row.get(2);
        body.effective_at_ms < latest_effective_ms
    }) {
        return error(StatusCode::CONFLICT, "consent_conflict");
    }
    let coherent = match (&current, body.action) {
        (None, ConsentAction::Grant) => true,
        (None, ConsentAction::Withdraw) => false,
        (Some(row), ConsentAction::Grant) => {
            let action: String = row.get(0);
            if action == "withdraw" {
                true
            } else {
                let expires_at: Option<SystemTime> = row.get(1);
                // An active (unexpired or open-ended) grant cannot be
                // re-granted; let it expire or withdraw it first.
                expires_at.is_some_and(|at| at <= SystemTime::now())
            }
        }
        (Some(row), ConsentAction::Withdraw) => {
            let action: String = row.get(0);
            action == "grant"
        }
    };
    if !coherent {
        return error(StatusCode::CONFLICT, "consent_conflict");
    }
    let record_id = Uuid::new_v4();
    let effective_seconds = body.effective_at_ms as f64 / 1000.0;
    let expires_seconds = body.expires_at_ms.map(|ms| ms as f64 / 1000.0);
    let inserted = tx
        .query_opt(
            "INSERT INTO contact_consent_records \
             (id,account_id,contact_id,purpose,action,source,effective_at,expires_at,recorded_by) \
             SELECT $1,$2,$3,$4,$5,$6,LEAST(to_timestamp($7),clock_timestamp()), \
             CASE WHEN $8::double precision IS NULL THEN NULL \
                  ELSE to_timestamp($8) END,$9 \
             RETURNING id",
            &[
                &record_id,
                &account_id,
                &contact_id,
                &body.purpose.as_str(),
                &body.action.as_str(),
                &body.source.as_str(),
                &effective_seconds,
                &expires_seconds,
                &owner.user_id,
            ],
        )
        .await;
    match inserted {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
    if body.action == ConsentAction::Withdraw
        && crate::workflow_runtime::lifecycle::consent::withdraw(
            &tx,
            account_id,
            contact_id,
            body.purpose.as_str(),
        )
        .await
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    let history = match tx
        .query(
            "SELECT id,purpose,action,source, \
             (extract(epoch FROM effective_at)*1000)::bigint, \
             (extract(epoch FROM expires_at)*1000)::bigint, \
             (extract(epoch FROM recorded_at)*1000)::bigint \
             FROM contact_consent_records \
             WHERE account_id=$1 AND contact_id=$2 \
             ORDER BY effective_at DESC,recorded_at DESC,id DESC",
            &[&account_id, &contact_id],
        )
        .await
    {
        Ok(rows) => rows.iter().map(record_view).collect::<Vec<_>>(),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    if crate::auth::require_current_owner(&tx, &owner)
        .await
        .is_err()
    {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if tx.commit().await.is_err() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    let states = consent_states(&history, now);
    #[derive(Serialize)]
    struct RecordedView {
        record_id: Uuid,
        consents: Vec<ConsentStateView>,
    }
    Json(RecordedView {
        record_id,
        consents: states,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: i64 = 1_800_000_000_000;

    fn body(action: ConsentAction, purpose: Purpose, expiry: Option<i64>) -> ConsentBody {
        ConsentBody {
            purpose,
            action,
            source: ConsentSource::ManualEntry,
            effective_at_ms: NOW_MS - 60_000,
            expires_at_ms: expiry,
        }
    }

    #[test]
    fn marketing_grants_need_a_bounded_expiry() {
        assert!(!valid_consent(
            &body(ConsentAction::Grant, Purpose::Marketing, None),
            NOW_MS
        ));
        assert!(valid_consent(
            &body(
                ConsentAction::Grant,
                Purpose::Marketing,
                Some(NOW_MS + 3_600_000)
            ),
            NOW_MS
        ));
        // Past-the-effective-time expiries and ones beyond the horizon are
        // both invalid, for every purpose.
        assert!(!valid_consent(
            &body(
                ConsentAction::Grant,
                Purpose::Marketing,
                Some(NOW_MS - 120_000)
            ),
            NOW_MS
        ));
        assert!(!valid_consent(
            &body(
                ConsentAction::Grant,
                Purpose::Marketing,
                Some(NOW_MS - 60_000 + MAX_EXPIRY_HORIZON_MS + 1)
            ),
            NOW_MS
        ));
    }

    #[test]
    fn other_purposes_may_be_open_ended_but_bounded_when_set() {
        assert!(valid_consent(
            &body(ConsentAction::Grant, Purpose::Transactional, None),
            NOW_MS
        ));
        assert!(valid_consent(
            &body(
                ConsentAction::Grant,
                Purpose::Operational,
                Some(NOW_MS + 86_400_000)
            ),
            NOW_MS
        ));
        assert!(!valid_consent(
            &body(
                ConsentAction::Grant,
                Purpose::Transactional,
                Some(NOW_MS - 120_000)
            ),
            NOW_MS
        ));
    }

    #[test]
    fn withdrawals_never_carry_an_expiry_and_times_stay_bounded() {
        assert!(valid_consent(
            &body(ConsentAction::Withdraw, Purpose::Marketing, None),
            NOW_MS
        ));
        assert!(!valid_consent(
            &body(
                ConsentAction::Withdraw,
                Purpose::Marketing,
                Some(NOW_MS + 1)
            ),
            NOW_MS
        ));
        let future = ConsentBody {
            effective_at_ms: NOW_MS + MAX_FUTURE_SKEW_MS + 1,
            ..body(ConsentAction::Grant, Purpose::Transactional, None)
        };
        assert!(!valid_consent(&future, NOW_MS));
        let ancient = ConsentBody {
            effective_at_ms: NOW_MS - MAX_EFFECTIVE_AGE_MS - 1,
            ..body(ConsentAction::Withdraw, Purpose::Transactional, None)
        };
        assert!(!valid_consent(&ancient, NOW_MS));
    }

    #[test]
    fn consent_states_follow_the_newest_event_per_purpose() {
        let contact = Uuid::new_v4();
        let history = vec![
            ConsentRecordView {
                record_id: Uuid::new_v4(),
                purpose: "marketing".to_owned(),
                action: "withdraw".to_owned(),
                source: "manual_entry".to_owned(),
                effective_at_ms: NOW_MS - 1_000,
                expires_at_ms: None,
                recorded_at_ms: NOW_MS - 1_000,
            },
            ConsentRecordView {
                record_id: Uuid::new_v4(),
                purpose: "marketing".to_owned(),
                action: "grant".to_owned(),
                source: "manual_entry".to_owned(),
                effective_at_ms: NOW_MS - 10_000,
                expires_at_ms: Some(NOW_MS - 5_000),
                recorded_at_ms: NOW_MS - 10_000,
            },
            ConsentRecordView {
                record_id: contact,
                purpose: "transactional".to_owned(),
                action: "grant".to_owned(),
                source: "off_channel_record".to_owned(),
                effective_at_ms: NOW_MS - 50_000,
                expires_at_ms: None,
                recorded_at_ms: NOW_MS - 50_000,
            },
        ];
        let states = consent_states(&history, NOW_MS);
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].purpose, "marketing");
        assert_eq!(states[0].status, "withdrawn");
        assert_eq!(states[1].purpose, "transactional");
        assert_eq!(states[1].status, "granted");
        // The older marketing event alone would read expired.
        let only_old = consent_states(&history[1..], NOW_MS);
        assert_eq!(only_old[0].status, "expired");
    }
}
