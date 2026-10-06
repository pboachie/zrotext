// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{self, ConversationError},
};
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::{Client, GenericClient, Transaction};
use uuid::Uuid;

async fn installed<C: GenericClient + Sync>(db: &C) -> Result<bool, tokio_postgres::Error> {
    Ok(db
        .query_one(
            "SELECT to_regclass('billing_invoice_usage_observations') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}

#[derive(Default, Serialize)]
pub(crate) struct Export {
    pub observations: Vec<Value>,
    pub next: Option<Uuid>,
}

pub(crate) async fn export(
    db: &mut Client,
    owner: &SessionPrincipal,
    after: Option<Uuid>,
) -> Result<Export, ConversationError> {
    let tx = db.transaction().await?;
    http_owner_conversations::lock_owner(&tx, owner).await?;
    let account = owner.tenant.account_id();
    let mut out = Export::default();
    if installed(&tx).await? {
        if let Some(id) = after {
            tx.query_opt("SELECT snapshot_id FROM billing_invoice_usage_observations WHERE account_id=$1 AND snapshot_id=$2 FOR SHARE",&[&account,&id]).await?.ok_or(ConversationError::NotFound)?;
        }
        let rows=tx.query("SELECT snapshot_id,to_jsonb(o)::text FROM billing_invoice_usage_observations o WHERE account_id=$1 AND ($2::uuid IS NULL OR snapshot_id>$2) ORDER BY snapshot_id LIMIT 21 FOR SHARE",&[&account,&after]).await?;
        out.next = (rows.len() > 20).then(|| rows[19].get(0));
        out.observations = rows
            .iter()
            .take(20)
            .map(|r| {
                serde_json::from_str(&r.get::<_, String>(1))
                    .map_err(|_| ConversationError::Unavailable)
            })
            .collect::<Result<_, _>>()?;
    } else if after.is_some() {
        return Err(ConversationError::NotFound);
    }
    http_owner_conversations::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(out)
}

/// Called before invoice periods/policies in the existing owner-erasure TX.
pub(crate) async fn erase(
    tx: &Transaction<'_>,
    account: Uuid,
) -> Result<Vec<(&'static str, u64)>, tokio_postgres::Error> {
    if !installed(tx).await? {
        return Ok(Vec::new());
    }
    Ok(vec![(
        "billing_invoice_usage_observations",
        tx.execute(
            "DELETE FROM billing_invoice_usage_observations WHERE account_id=$1",
            &[&account],
        )
        .await?,
    )])
}

/// Only bounded old observation metadata is deleted; original liability,
/// period identity and immutable finalized charges are unchanged.
pub(crate) async fn prune(db: &Client, limit: i64) -> Result<u64, tokio_postgres::Error> {
    if !installed(db).await? {
        return Ok(0);
    }
    db.execute("WITH due AS (SELECT account_id,snapshot_id FROM billing_invoice_usage_observations WHERE observed_at<clock_timestamp()-interval '180 days' ORDER BY observed_at,account_id,snapshot_id FOR UPDATE SKIP LOCKED LIMIT $1) DELETE FROM billing_invoice_usage_observations o USING due WHERE (o.account_id,o.snapshot_id)=(due.account_id,due.snapshot_id)",&[&limit.clamp(1,1000)]).await
}
