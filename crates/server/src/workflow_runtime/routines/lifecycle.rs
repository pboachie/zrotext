// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde::Serialize;
use serde_json::Value;

pub async fn installed(tx: &Transaction<'_>) -> Result<bool, tokio_postgres::Error> {
    Ok(tx
        .query_one(
            "SELECT to_regclass('workflow_routine_policies') IS NOT NULL",
            &[],
        )
        .await?
        .get(0))
}
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Policies,
    Calls,
    Admissions,
    Turns,
    Periods,
}
#[derive(Default, Serialize)]
pub struct Export {
    pub items: Vec<Value>,
    pub next_cursor: Option<String>,
}
pub async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    section: Section,
    before: Option<String>,
) -> Result<Export, owner::ConversationError> {
    let tx = client.transaction().await?;
    owner::lock_owner(&tx, owner).await?;
    let mut result = Export::default();
    if installed(&tx).await? {
        let account = owner.tenant.account_id();
        let (table, key, kind) = match section {
            Section::Policies => ("workflow_routine_policies", "id", "uuid"),
            Section::Calls => ("workflow_routine_calls", "id", "uuid"),
            Section::Admissions => ("workflow_routine_admission_tombstones", "call_id", "uuid"),
            Section::Turns => ("workflow_routine_turn_debits", "context_id", "uuid"),
            Section::Periods => ("workflow_routine_period_debits", "utc_day", "bigint"),
        };
        if let Some(cursor) = before.as_ref() {
            if (kind == "uuid" && Uuid::parse_str(cursor).is_err())
                || (kind == "bigint" && cursor.parse::<i64>().is_err())
            {
                return Err(owner::ConversationError::Invalid);
            }
            let found=tx.query_one(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE account_id=$1 AND {key}=$2::text::{kind})"),&[&account,&cursor]).await?.get::<_,bool>(0);
            if !found {
                return Err(owner::ConversationError::NotFound);
            }
        }
        let rows=tx.query(&format!("SELECT {key}::text,to_jsonb(t)::text FROM {table} t WHERE account_id=$1 AND ($2::text IS NULL OR {key}<$2::text::{kind}) ORDER BY {key} DESC LIMIT 101"),&[&account,&before]).await?;
        result.next_cursor = if rows.len() > 100 {
            Some(rows[99].get(0))
        } else {
            None
        };
        for row in rows.iter().take(100) {
            result.items.push(
                serde_json::from_str(row.get::<_, String>(1).as_str())
                    .map_err(|_| owner::ConversationError::Invalid)?,
            )
        }
    }
    owner::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(result)
}
/// Caller holds account serialization; stop only already-created outputs of
/// this exact policy before removing its metadata or granting a later effect.
pub(in crate::workflow_runtime) async fn stop_outputs(
    tx: &Transaction<'_>,
    account: Uuid,
    policy: Uuid,
) -> Result<(), tokio_postgres::Error> {
    let rows=tx.query("SELECT r.id FROM workflow_routines r JOIN workflow_routine_calls c ON (c.account_id,c.id)=(r.account_id,r.id) AND c.output_context_id IS NOT NULL AND r.context_id=c.output_context_id WHERE c.account_id=$1 AND c.policy_id=$2 ORDER BY r.context_id,r.id FOR UPDATE OF r",&[&account,&policy]).await?;
    for row in rows {
        let id: Uuid = row.get(0);
        tx.execute("UPDATE workflow_routines SET stopped_at=COALESCE(stopped_at,clock_timestamp()) WHERE account_id=$1 AND id=$2",&[&account,&id]).await?;
    }
    Ok(())
}
/// Context/content removal cannot refund period, turn or replay tombstones.
pub async fn erase_context(
    tx: &Transaction<'_>,
    account: Uuid,
    context: Uuid,
) -> Result<(), tokio_postgres::Error> {
    if !installed(tx).await? {
        return Ok(());
    }
    let outputs=tx.query("SELECT DISTINCT r.id FROM workflow_routine_policies p JOIN workflow_routine_calls c ON (c.account_id,c.policy_id)=(p.account_id,p.id) JOIN workflow_routines r ON (r.account_id,r.id)=(c.account_id,c.id) AND c.output_context_id IS NOT NULL AND r.context_id=c.output_context_id WHERE p.account_id=$1 AND (p.context_id=$2 OR c.output_context_id=$2) ORDER BY r.id",&[&account,&context]).await?;
    for row in outputs {
        let id: Uuid = row.get(0);
        tx.execute("UPDATE workflow_routines SET stopped_at=COALESCE(stopped_at,clock_timestamp()) WHERE account_id=$1 AND id=$2",&[&account,&id]).await?;
    }
    tx.execute("DELETE FROM workflow_routine_calls c WHERE c.account_id=$1 AND (c.output_context_id=$2 OR EXISTS(SELECT 1 FROM workflow_routine_policies p WHERE (p.account_id,p.id)=(c.account_id,c.policy_id) AND p.context_id=$2))",&[&account,&context]).await?;
    tx.execute(
        "DELETE FROM workflow_routine_policies WHERE account_id=$1 AND context_id=$2",
        &[&account, &context],
    )
    .await?;
    Ok(())
}
pub async fn erase_contact(
    tx: &Transaction<'_>,
    account: Uuid,
    contact: Uuid,
) -> Result<(), tokio_postgres::Error> {
    if !installed(tx).await? {
        return Ok(());
    }
    let policies=tx.query("SELECT DISTINCT p.id FROM workflow_routine_policies p JOIN workflow_integration_grants g ON (g.account_id,g.grant_id)=(p.account_id,p.input_grant_id) WHERE p.account_id=$1 AND g.contact_id=$2",&[&account,&contact]).await?;
    for row in policies {
        stop_outputs(tx, account, row.get(0)).await?;
    }
    tx.execute("DELETE FROM workflow_routine_calls c WHERE c.account_id=$1 AND (EXISTS(SELECT 1 FROM workflow_integration_grants g WHERE g.account_id=c.account_id AND g.grant_id=c.output_grant_id AND g.contact_id=$2) OR EXISTS(SELECT 1 FROM workflow_routine_policies p JOIN workflow_integration_grants g ON (g.account_id,g.grant_id)=(p.account_id,p.input_grant_id) WHERE (p.account_id,p.id)=(c.account_id,c.policy_id) AND g.contact_id=$2))",&[&account,&contact]).await?;
    tx.execute("DELETE FROM workflow_routine_policies p USING workflow_integration_grants g WHERE (g.account_id,g.grant_id)=(p.account_id,p.input_grant_id) AND p.account_id=$1 AND g.contact_id=$2",&[&account,&contact]).await?;
    Ok(())
}
pub async fn erase_account(
    tx: &Transaction<'_>,
    account: Uuid,
) -> Result<Vec<(&'static str, u64)>, tokio_postgres::Error> {
    let mut counts = Vec::new();
    if !installed(tx).await? {
        return Ok(counts);
    }
    for table in [
        "workflow_routine_calls",
        "workflow_routine_policies",
        "workflow_routine_admission_tombstones",
        "workflow_routine_period_debits",
        "workflow_routine_turn_debits",
    ] {
        let count = tx
            .execute(
                &format!("DELETE FROM {table} WHERE account_id=$1"),
                &[&account],
            )
            .await?;
        counts.push((table, count));
    }
    Ok(counts)
}

/// Remove bounded expired call/policy metadata under account serialization.
/// Minimal replay and usage debits remain until full account erasure.
pub async fn prune(client: &mut Client, limit: i64) -> Result<u64, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    if !installed(&tx).await? {
        return Ok(0);
    }
    let limit = limit.clamp(1, 500);
    let accounts=tx.query("SELECT a.id FROM accounts a WHERE EXISTS(SELECT 1 FROM workflow_routine_policies p WHERE p.account_id=a.id AND (p.withdrawn_ms IS NOT NULL OR p.expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint)) ORDER BY a.id FOR UPDATE OF a SKIP LOCKED LIMIT $1",&[&limit]).await?;
    let mut changed = 0;
    for account in accounts {
        if changed >= limit as u64 {
            break;
        }
        let account: Uuid = account.get(0);
        let policies=tx.query("SELECT id FROM workflow_routine_policies WHERE account_id=$1 AND (withdrawn_ms IS NOT NULL OR expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2",&[&account,&(limit-changed as i64)]).await?;
        for policy in policies {
            let policy: Uuid = policy.get(0);
            stop_outputs(&tx, account, policy).await?;
            tx.execute(
                "DELETE FROM workflow_routine_calls WHERE account_id=$1 AND policy_id=$2",
                &[&account, &policy],
            )
            .await?;
            tx.execute(
                "DELETE FROM workflow_routine_policies WHERE account_id=$1 AND id=$2",
                &[&account, &policy],
            )
            .await?;
            changed += 1;
        }
    }
    tx.commit().await?;
    Ok(changed)
}
