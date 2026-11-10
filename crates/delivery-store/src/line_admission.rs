// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0004 submit path: resolve an owner-named line label to immutable line
//! identity at admission and apply the per-line not-ready policy. This module
//! reads observed line state inside the caller's admission transaction and
//! hands the pure [`decide_not_ready`] decision correctly assembled facts; it
//! grants no authority of its own. No SIM slot, subscription identifier,
//! ICCID, IMSI or phone number is read or produced here — labels address
//! lines, and lines are account-scoped identity.

use crate::StoreError;
use crate::line_policy::{
    FallbackFacts, LineFacts, NotReadyDecision, NotReadyMode, RequestFacts, decide_not_ready,
};
use tokio_postgres::Transaction;
use uuid::Uuid;

/// The routing result for an accepted submission: which immutable line
/// identity was recorded and which bound device actually sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineAdmission {
    pub line_id: Uuid,
    pub label: Option<String>,
    pub device_id: Uuid,
}

/// A refusal before acceptance: no message record, attempt or unknown outcome
/// is created. The code is stable API surface; the label is presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineRefusal {
    pub code: &'static str,
    pub label: Option<String>,
}

pub enum RouteOutcome {
    Admitted(LineAdmission),
    Refused(LineRefusal),
}

/// One line's authoritative row, locked FOR SHARE by the caller's loader.
struct LineRow {
    id: Uuid,
    label: Option<String>,
    line_active: bool,
    mode: NotReadyMode,
    fallback_line_id: Option<Uuid>,
    offline_threshold_seconds: i32,
    current_binding_generation: i64,
}

/// The observed state of one line: authoritative activation and binding plus
/// the phone's latest accepted readiness classification.
struct LineState {
    facts: LineFacts,
    bound_device: Option<Uuid>,
}

/// Resolves `label` in the account and applies the line's not-ready policy.
///
/// `device_id` is the device the request named; a line whose approved binding
/// currently belongs to a different device does not resolve, so a label can
/// never redirect a request onto another device. Suppression is account-wide
/// and has already refused by the time this runs inside admission, so both
/// suppression facts are false on entry. A device-bound API key
/// (`allowed_device`) constrains fallback: a fallback line bound to a device
/// the key may not drive is not eligible.
pub async fn route_line(
    tx: &Transaction<'_>,
    account_id: Uuid,
    device_id: Uuid,
    label: &str,
    fallback_forbidden: bool,
    allowed_device: Option<Uuid>,
) -> Result<RouteOutcome, StoreError> {
    let Some(target) = load_line_by_label(tx, account_id, label).await? else {
        return Err(StoreError::NotFound);
    };
    let threshold_ms = target.offline_threshold_seconds as u64 * 1000;
    let state = line_state(tx, account_id, &target, Some(device_id)).await?;
    if state.facts.not_ready(threshold_ms).is_none() {
        return Ok(RouteOutcome::Admitted(LineAdmission {
            line_id: target.id,
            label: target.label.clone(),
            device_id,
        }));
    }
    let fallback = match (target.mode, target.fallback_line_id) {
        (NotReadyMode::Fallback, Some(id)) => {
            let row = load_line_by_id(tx, account_id, id).await?;
            let state = line_state(tx, account_id, &row, None).await?;
            Some((row, state))
        }
        _ => None,
    };
    // A device-bound key may only be routed onto its own device, so a
    // fallback bound elsewhere is simply not eligible.
    let fallback_facts = fallback.as_ref().filter(|(_, state)| {
        allowed_device.is_none_or(|allowed| state.bound_device == Some(allowed))
    });
    let fallback_facts = fallback_facts.map(|(row, state)| FallbackFacts {
        line_id: row.id.into_bytes(),
        label: row.label.clone(),
        line_active: state.facts.line_active,
        binding_active: state.facts.binding_active,
        continuity_pending: state.facts.continuity_pending,
        card_changed: state.facts.card_changed,
        since_last_seen_ms: state.facts.since_last_seen_ms,
        offline_threshold_ms: row.offline_threshold_seconds as u64 * 1000,
        // Account-wide suppression already refused before routing;
        // per-line suppression does not exist in this model.
        recipient_suppressed: false,
    });
    let decision = decide_not_ready(
        target.mode,
        threshold_ms,
        &state.facts,
        fallback_facts.as_ref(),
        RequestFacts {
            target_recipient_suppressed: false,
            fallback_forbidden,
            // An outcome cannot be unknown before anything is attempted.
            outcome_is_unknown: false,
        },
    );
    Ok(match decision {
        NotReadyDecision::Refuse { code, label } => {
            RouteOutcome::Refused(LineRefusal { code, label })
        }
        NotReadyDecision::QueueOnLine { .. } => RouteOutcome::Admitted(LineAdmission {
            line_id: target.id,
            label: target.label.clone(),
            device_id,
        }),
        NotReadyDecision::SendFromFallback { .. } => {
            let (row, state) =
                fallback.expect("decide_not_ready picks fallback only when facts were supplied");
            let device = state
                .bound_device
                .expect("eligible fallback facts require an active binding");
            RouteOutcome::Admitted(LineAdmission {
                line_id: row.id,
                label: row.label.clone(),
                device_id: device,
            })
        }
    })
}

async fn load_line_by_label(
    tx: &Transaction<'_>,
    account_id: Uuid,
    label: &str,
) -> Result<Option<LineRow>, StoreError> {
    let row = tx
        .query_opt(
            "SELECT id,label,state,not_ready_mode,fallback_line_id, \
                    offline_not_ready_after_seconds,current_binding_generation \
             FROM phone_lines WHERE account_id=$1 AND label=$2 FOR SHARE",
            &[&account_id, &label],
        )
        .await?;
    match row {
        Some(row) => Ok(Some(line_row(row)?)),
        None => Ok(None),
    }
}

async fn load_line_by_id(
    tx: &Transaction<'_>,
    account_id: Uuid,
    line_id: Uuid,
) -> Result<LineRow, StoreError> {
    let row = tx
        .query_opt(
            "SELECT id,label,state,not_ready_mode,fallback_line_id, \
                    offline_not_ready_after_seconds,current_binding_generation \
             FROM phone_lines WHERE account_id=$1 AND id=$2 FOR SHARE",
            &[&account_id, &line_id],
        )
        .await?;
    // The same-account foreign key guarantees the row exists; a miss is a
    // torn read, not a routing fact.
    line_row(row.ok_or(StoreError::PolicyCorrupt)?)
}

fn line_row(row: tokio_postgres::Row) -> Result<LineRow, StoreError> {
    let state: String = row.get(2);
    let mode: String = row.get(3);
    Ok(LineRow {
        id: row.get(0),
        label: row.get(1),
        line_active: state == "active",
        mode: NotReadyMode::from_storage(&mode).ok_or(StoreError::PolicyCorrupt)?,
        fallback_line_id: row.get(4),
        offline_threshold_seconds: row.get(5),
        current_binding_generation: row.get(6),
    })
}

/// Builds [`LineFacts`] for a line. Activation and the binding come from the
/// authoritative tables; card and continuity come from the latest accepted
/// `line_readiness` observation, and only while it names the line's current
/// binding generation. A `ready` report is evidence only while it stays
/// within the offline threshold; every other reported kind is the phone's own
/// fail-closed classification, which hub clock arithmetic never overrides.
/// `required_device`, when set, demands the line's active binding belong to
/// that device: label resolution never redirects onto another device.
async fn line_state(
    tx: &Transaction<'_>,
    account_id: Uuid,
    line: &LineRow,
    required_device: Option<Uuid>,
) -> Result<LineState, StoreError> {
    let bound_device: Option<Uuid> = tx
        .query_opt(
            "SELECT device_id FROM device_line_bindings \
             WHERE account_id=$1 AND line_id=$2 AND generation=$3 AND state='active' FOR SHARE",
            &[&account_id, &line.id, &line.current_binding_generation],
        )
        .await?
        .map(|row| row.get(0));
    if let (Some(required), Some(bound)) = (required_device, bound_device)
        && required != bound
    {
        return Err(StoreError::NotFound);
    }
    let observation = tx
        .query_opt(
            "SELECT kind,since_observation_ms, \
                    (extract(epoch FROM hub_received_at)*1000)::bigint, binding_generation \
             FROM line_readiness_observations WHERE account_id=$1 AND line_id=$2 FOR SHARE",
            &[&account_id, &line.id],
        )
        .await?;
    let mut continuity_pending = false;
    let mut card_changed = false;
    let since_last_seen_ms = match observation {
        Some(row) if row.get::<_, i64>(3) == line.current_binding_generation => {
            let kind: String = row.get(0);
            match kind.as_str() {
                "ready" => {
                    let now_ms: i64 = tx
                        .query_one(
                            "SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint",
                            &[],
                        )
                        .await?
                        .get(0);
                    let received_ms: i64 = row.get(2);
                    let report_age = (now_ms - received_ms).max(0) as u64;
                    let evidence_age = row.get::<_, Option<i64>>(1).unwrap_or(0).max(0) as u64;
                    Some(report_age + evidence_age)
                }
                "continuity_pending" => {
                    continuity_pending = true;
                    Some(0)
                }
                "card_changed" => {
                    card_changed = true;
                    Some(0)
                }
                // The phone's own fail-closed classification, including
                // offline past threshold: missing or aged evidence reads as
                // offline whatever the hub's clocks say.
                _ => None,
            }
        }
        // No current-generation observation: fail closed as offline.
        _ => None,
    };
    Ok(LineState {
        facts: LineFacts {
            label: line.label.clone(),
            line_active: line.line_active,
            binding_active: bound_device.is_some(),
            continuity_pending,
            card_changed,
            since_last_seen_ms,
        },
        bound_device,
    })
}
