// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded owner takeout and erasure; retained liabilities grant no access.
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{self, ConversationError},
};
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::{Client, Error, GenericClient, Transaction};
use uuid::Uuid;

pub(crate) async fn installed<C: GenericClient + Sync>(db: &C) -> Result<bool, Error> {
    Ok(db
        .query_one(
            "SELECT to_regclass('billing_invoice_entitlements') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}

#[derive(Default, Serialize)]
pub(crate) struct InvoiceExport {
    pub entitlement: Option<Value>,
    pub periods: Vec<Value>,
    pub usage: Vec<Value>,
    pub audit: Vec<Value>,
    pub periods_next: Option<Uuid>,
    pub usage_next: Option<Uuid>,
    pub audit_next: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PeriodStatus {
    phase: String,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    effective_limit: i64,
    consumed_units: i64,
    previous_open_units: i64,
    grace_until_ms: Option<i64>,
    cancel_at_ms: Option<i64>,
}

/// Informational current invoice projection. It creates no admission permit.
pub(crate) async fn status(
    db: &mut Client,
    owner: &SessionPrincipal,
) -> Result<Option<PeriodStatus>, ConversationError> {
    let tx = db.transaction().await?;
    http_owner_conversations::lock_owner(&tx, owner).await?;
    let account = owner.tenant.account_id();
    let result = if super::enabled(&tx, account)
        .await
        .map_err(|_| ConversationError::Unavailable)?
    {
        tx.query_opt("SELECT e.phase,p.start_ms,p.end_ms,e.effective_limit,coalesce(p.reserved_units-p.refunded_units,0),(SELECT coalesce(sum(q.open_units),0)::bigint FROM billing_invoice_periods q WHERE q.account_id=e.account_id AND q.id IS DISTINCT FROM e.period_id),e.grace_until_ms,e.cancel_at_ms FROM billing_invoice_entitlements e LEFT JOIN billing_invoice_periods p ON (p.account_id,p.id)=(e.account_id,e.period_id) WHERE e.account_id=$1", &[&account]).await?.map(|r|PeriodStatus { phase:r.get(0),start_ms:r.get(1),end_ms:r.get(2),effective_limit:r.get(3),consumed_units:r.get(4),previous_open_units:r.get(5),grace_until_ms:r.get(6),cancel_at_ms:r.get(7) })
    } else {
        None
    };
    http_owner_conversations::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}

async fn uuid_page(
    tx: &Transaction<'_>,
    account: Uuid,
    table: &str,
    key: &str,
    after: Option<Uuid>,
) -> Result<(Vec<Value>, Option<Uuid>), ConversationError> {
    // Identifiers are selected solely by the two fixed internal calls below.
    if let Some(id) = after {
        tx.query_opt(
            &format!("SELECT {key} FROM {table} WHERE account_id=$1 AND {key}=$2"),
            &[&account, &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let rows = tx.query(&format!("SELECT {key},to_jsonb(t)::text FROM {table} t WHERE account_id=$1 AND ($2::uuid IS NULL OR {key}>$2) ORDER BY {key} LIMIT 21 FOR SHARE"), &[&account,&after]).await?;
    let next = (rows.len() > 20).then(|| rows[19].get(0));
    let values = rows
        .iter()
        .take(20)
        .map(|r| {
            serde_json::from_str(&r.get::<_, String>(1)).map_err(|_| ConversationError::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((values, next))
}

pub(crate) async fn export(
    db: &mut Client,
    owner: &SessionPrincipal,
    periods: Option<Uuid>,
    usage: Option<Uuid>,
    audit: Option<i64>,
) -> Result<InvoiceExport, ConversationError> {
    let tx = db.transaction().await?;
    http_owner_conversations::lock_owner(&tx, owner).await?;
    let mut out = InvoiceExport::default();
    let account = owner.tenant.account_id();
    if installed(&tx).await? {
        out.entitlement = tx.query_opt("SELECT to_jsonb(t)::text FROM billing_invoice_entitlements t WHERE account_id=$1 FOR SHARE", &[&account]).await?.map(|r|serde_json::from_str(&r.get::<_,String>(0)).map_err(|_|ConversationError::Unavailable)).transpose()?;
        (out.periods, out.periods_next) =
            uuid_page(&tx, account, "billing_invoice_periods", "id", periods).await?;
        (out.usage, out.usage_next) =
            uuid_page(&tx, account, "billing_invoice_usage", "message_id", usage).await?;
        if let Some(id) = audit {
            tx.query_opt(
                "SELECT id FROM billing_invoice_audit WHERE account_id=$1 AND id=$2",
                &[&account, &id],
            )
            .await?
            .ok_or(ConversationError::NotFound)?;
        }
        let rows = tx.query("SELECT id,to_jsonb(t)::text FROM billing_invoice_audit t WHERE account_id=$1 AND ($2::bigint IS NULL OR id>$2) ORDER BY id LIMIT 21 FOR SHARE", &[&account,&audit]).await?;
        out.audit_next = (rows.len() > 20).then(|| rows[19].get(0));
        out.audit = rows
            .iter()
            .take(20)
            .map(|r| {
                serde_json::from_str(&r.get::<_, String>(1))
                    .map_err(|_| ConversationError::Unavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
    } else if periods.is_some() || usage.is_some() || audit.is_some() {
        return Err(ConversationError::NotFound);
    }
    http_owner_conversations::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(out)
}

/// Caller holds the existing live-owner/MFA account fence. Foreign keys keep
/// all four deletions in the same account-erasure transaction.
pub(crate) async fn erase(
    tx: &Transaction<'_>,
    account: Uuid,
) -> Result<Vec<(&'static str, u64)>, Error> {
    let mut counts = Vec::new();
    if installed(tx).await? {
        for table in [
            "billing_invoice_audit",
            "billing_invoice_usage",
            "billing_invoice_entitlements",
            "billing_invoice_periods",
        ] {
            let rows = tx
                .execute(
                    &format!("DELETE FROM {table} WHERE account_id=$1"),
                    &[&account],
                )
                .await?;
            counts.push((table, rows));
        }
    }
    Ok(counts)
}

/// Only old bounded audit metadata expires. Period identities, counters and
/// unknown liabilities survive retention and are removed only by owner erase.
pub(crate) async fn prune(db: &Client, limit: i64) -> Result<u64, Error> {
    if !installed(db).await? {
        return Ok(0);
    }
    db.execute("WITH due AS (SELECT id FROM billing_invoice_audit WHERE recorded_at<clock_timestamp()-interval '180 days' ORDER BY recorded_at,id FOR UPDATE SKIP LOCKED LIMIT $1) DELETE FROM billing_invoice_audit a USING due WHERE a.id=due.id", &[&limit]).await
}
