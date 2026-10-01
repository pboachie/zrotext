// SPDX-License-Identifier: AGPL-3.0-only
//! Owner current-period view over the shared authoritative usage projection.
use serde::Serialize;
use tokio_postgres::Client;
use uuid::Uuid;
use zrotext_delivery_store::{StoreError, UsagePeriodView};

#[derive(Serialize)]
pub(crate) struct UsageView {
    metric: String,
    period_start: String,
    period_end: String,
    limit_units: i64,
    reserved_units: i64,
    refunded_units: i64,
    used_units: i64,
}
impl From<UsagePeriodView> for UsageView {
    fn from(period: UsagePeriodView) -> Self {
        Self {
            used_units: period.consumed_units(),
            metric: period.metric,
            period_start: period.period_start,
            period_end: period.period_end,
            limit_units: period.limit_units,
            reserved_units: period.reserved_units,
            refunded_units: period.refunded_units,
        }
    }
}

pub(crate) async fn current(db: &Client, account: Uuid) -> Result<Option<UsageView>, StoreError> {
    // Capture a UTC date once, exclude future periods with the same bounded
    // history cursor the API uses, and never substitute a historical counter.
    let clock = db.query_one("SELECT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date::text, (date_trunc('month', CURRENT_TIMESTAMP AT TIME ZONE 'UTC') + interval '1 month')::date::text", &[]).await?;
    let today: String = clock.get(0);
    let before: String = clock.get(1);
    let history = zrotext_delivery_store::usage_history(db, account, Some(&before), 1).await?;
    Ok(history
        .periods
        .into_iter()
        .next()
        .filter(|period| period.period_start <= today && period.period_end > today)
        .map(UsageView::from))
}
