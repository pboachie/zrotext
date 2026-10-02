// SPDX-License-Identifier: AGPL-3.0-only
//! Local forwarding state; acknowledgements never prove invoice settlement.
use serde::Serialize;
use tokio_postgres::Client;
use uuid::Uuid;

#[cfg(test)]
mod tests;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Synchronization {
    configured: bool,
    pending: i64,
    leased: i64,
    acknowledged: i64,
    review: i64,
    uncertain: i64,
}

pub(super) async fn current(
    db: &Client,
    account: Uuid,
) -> Result<Option<Synchronization>, tokio_postgres::Error> {
    // An unavailable forwarding schema is not a synchronized zero and
    // never changes the shared admission ledger.
    if !db
        .query_one(
            "SELECT to_regclass('billing_usage_outbox') IS NOT NULL",
            &[],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Ok(None);
    }
    let row = db.query_one(
        "SELECT EXISTS(SELECT 1 FROM billing_usage_test_policies WHERE account_id=$1 AND active),
         count(*) FILTER (WHERE state='pending'),
         count(*) FILTER (WHERE state='leased'),
         count(*) FILTER (WHERE state='acknowledged'),
         count(*) FILTER (WHERE state='review'),
         count(*) FILTER (WHERE error_class='unknown')
         FROM billing_usage_outbox WHERE account_id=$1", &[&account]).await?;
    Ok(Some(Synchronization {
        configured: row.get(0),
        pending: row.get(1),
        leased: row.get(2),
        acknowledged: row.get(3),
        review: row.get(4),
        uncertain: row.get(5),
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExposureCap {
    start_ms: i64,
    end_ms: i64,
    soft_units: i64,
    hard_units: i64,
    outstanding_units: i64,
    finalized_units: i64,
}

pub(super) async fn exposure(
    db: &Client,
    account: Uuid,
) -> Result<Option<ExposureCap>, tokio_postgres::Error> {
    if !db
        .query_one(
            "SELECT to_regclass('exposure_scope_budgets') IS NOT NULL",
            &[],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Ok(None);
    }
    // Match admission: outstanding liability spans every original period;
    // finalized units span every version with these exact period bounds.
    let row = db
        .query_opt(
            "SELECT b.period_start_ms,b.period_end_ms,b.soft_units,b.hard_units,
         (SELECT COALESCE(sum(x.outstanding_units),0)::bigint FROM exposure_scope_budgets x
          WHERE x.account_id=b.account_id AND x.scope_kind=b.scope_kind AND x.scope_id=b.scope_id),
         (SELECT COALESCE(sum(x.finalized_units),0)::bigint FROM exposure_scope_budgets x
          WHERE x.account_id=b.account_id AND x.scope_kind=b.scope_kind AND x.scope_id=b.scope_id
            AND x.period_start_ms=b.period_start_ms AND x.period_end_ms=b.period_end_ms)
         FROM exposure_scope_budgets b WHERE b.account_id=$1 AND b.scope_kind='tenant'
          AND b.scope_id=$1 AND b.enabled
          AND b.period_start_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
          AND b.period_end_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[&account],
        )
        .await?;
    Ok(row.map(|row| ExposureCap {
        start_ms: row.get(0),
        end_ms: row.get(1),
        soft_units: row.get(2),
        hard_units: row.get(3),
        outstanding_units: row.get(4),
        finalized_units: row.get(5),
    }))
}
