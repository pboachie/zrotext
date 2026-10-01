// SPDX-License-Identifier: AGPL-3.0-only
//! Authoritative usage projection for the scoped usage API (#631).
//!
//! Counter semantics, fixed for every consumer of this module:
//!
//! - `reserved_units` counts accepted messages that consumed quota. A
//!   reservation is placed when a message is admitted, before any dispatch.
//! - `refunded_units` counts quota released again. Refunds happen only for
//!   messages that never dispatched (cancellation, expiry, admission
//!   rollback), are recorded exactly once per message in `usage_ledger`
//!   (`(account_id, message_id, entry_kind)` primary key), and are aggregated
//!   into the period by the same recovery sweeps that own the ledger.
//! - `consumed_units()` is `reserved_units - refunded_units`: the quota
//!   actually held. It is a reservation counter. It is deliberately NOT a
//!   submitted or delivered counter - a message that submits and fails
//!   keeps its reservation, because the quota was spent admitting it.
//!   Submitted/delivered summaries are a different projection (#608) and
//!   must never be conflated with quota usage.
//! - `limit_units` is the projected quota-only plan limit for the period
//!   (`usage_plan_assignments` reprojected into `usage_quota_policies`).
//!   No price, currency or billing configuration is part of this projection.
//!
//! Categories: the only metered metric today is `outbound_message`
//! (account-level). The API contract reserves the category dimension
//! (`account` scope, metric names); per-device or per-route metering does
//! not exist and must not be implied by this module.
//!
//! Reads are tenant-scoped by `account_id`, bounded by [`USAGE_PAGE_MAX`],
//! and stable under replay: a read reflects committed period state only and
//! never mutates anything.

use tokio_postgres::{Client, error::SqlState};
use uuid::Uuid;

use crate::StoreError;

/// Upper bound on periods per page. Bounded queries are part of the #631
/// contract; callers cannot ask for more.
pub const USAGE_PAGE_MAX: i32 = 24;

/// One authoritative metering period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsagePeriodView {
    /// Metered category, `outbound_message` today.
    pub metric: String,
    /// Inclusive period start, `YYYY-MM-DD` (UTC calendar month).
    pub period_start: String,
    /// Exclusive period end, `YYYY-MM-DD` (start + one month).
    pub period_end: String,
    /// Quota-only plan limit projected for the period.
    pub limit_units: i64,
    /// Accepted messages that consumed quota in the period.
    pub reserved_units: i64,
    /// Exactly-once quota releases in the period.
    pub refunded_units: i64,
}

impl UsagePeriodView {
    /// Quota actually held: reservations minus exactly-once refunds.
    pub fn consumed_units(&self) -> i64 {
        self.reserved_units - self.refunded_units
    }
}

/// One bounded page of period history, newest period first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageHistoryPage {
    pub periods: Vec<UsagePeriodView>,
    /// Cursor for the next older page: the last row's `period_start`, or
    /// `None` when the history is exhausted. Absent history is an empty
    /// page with `next_before: None`, not an error and not a distinction
    /// the API may expose beyond emptiness.
    pub next_before: Option<String>,
}

/// Reads up to `limit` periods for one account, newest first, optionally
/// starting strictly below the `before` cursor (`YYYY-MM-DD`).
///
/// The cursor's shape is validated in Rust and its calendar validity by the
/// database cast, so malformed input is rejected as [`StoreError::InvalidInput`]
/// without a Rust date dependency. `limit` is clamped to `1..=USAGE_PAGE_MAX`.
pub async fn usage_history(
    client: &Client,
    account_id: Uuid,
    before: Option<&str>,
    limit: i32,
) -> Result<UsageHistoryPage, StoreError> {
    let limit: i64 = (limit as i64).clamp(1, i64::from(USAGE_PAGE_MAX));
    if let Some(cursor) = before
        && !cursor_shape_ok(cursor)
    {
        return Err(StoreError::InvalidInput);
    }
    let rows = client
        .query(
            "SELECT metric,period_start::text,period_end::text, \
                    limit_units,reserved_units,refunded_units \
             FROM usage_periods \
             WHERE account_id=$1 \
               AND ($2::text IS NULL OR period_start::text < $2::date::text) \
             ORDER BY period_start DESC, metric \
             LIMIT $3",
            &[&account_id, &before, &limit],
        )
        .await
        .map_err(invalid_date_as_invalid_input)?;
    let periods: Vec<UsagePeriodView> = rows
        .iter()
        .map(|row| UsagePeriodView {
            metric: row.get(0),
            period_start: row.get(1),
            period_end: row.get(2),
            limit_units: row.get(3),
            reserved_units: row.get(4),
            refunded_units: row.get(5),
        })
        .collect();
    let next_before = if periods.len() as i64 == limit {
        periods.last().map(|p| p.period_start.clone())
    } else {
        None
    };
    Ok(UsageHistoryPage {
        periods,
        next_before,
    })
}

/// `YYYY-MM-DD` with digit fields; calendar impossibilities are rejected by
/// the database cast in the query itself.
fn cursor_shape_ok(cursor: &str) -> bool {
    let bytes = cursor.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
}

/// A syntactically shaped but calendrically impossible cursor date is client
/// input error, not a database fault.
fn invalid_date_as_invalid_input(error: tokio_postgres::Error) -> StoreError {
    if matches!(
        error.code(),
        Some(&SqlState::INVALID_DATETIME_FORMAT) | Some(&SqlState::DATETIME_VALUE_OUT_OF_RANGE)
    ) {
        StoreError::InvalidInput
    } else {
        StoreError::Database(error)
    }
}
