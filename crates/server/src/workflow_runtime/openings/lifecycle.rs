// SPDX-License-Identifier: AGPL-3.0-only
//! Borrowed reductions under the caller's existing account-leading lock.
//! No root/current-reader reacquisition, receipt admission or version overflow
//! may prevent withdrawal or erasure. Confirmed units remain occupied.
use super::{model::ClosureCounts, store};
use tokio_postgres::Transaction;
use uuid::Uuid;

enum Binding<'a> {
    Context(Uuid),
    Contact(Uuid, Option<&'a str>),
}

pub(crate) async fn erase_account(
    tx: &Transaction<'_>,
    account: Uuid,
) -> Result<Vec<(&'static str, u64)>, tokio_postgres::Error> {
    if !store::installed(tx).await? {
        return Ok(Vec::new());
    }
    let mut counts = Vec::new();
    for table in [
        "workflow_opening_requests",
        "workflow_opening_allocations",
        "workflow_opening_offers",
        "workflow_openings",
    ] {
        counts.push((
            table,
            tx.execute(
                &format!("DELETE FROM {table} WHERE account_id=$1"),
                &[&account],
            )
            .await?,
        ));
    }
    Ok(counts)
}

pub(crate) async fn stop_context(
    tx: &Transaction<'_>,
    account: Uuid,
    context: Uuid,
) -> Result<ClosureCounts, tokio_postgres::Error> {
    reduce(tx, account, Binding::Context(context), false).await
}

pub(crate) async fn erase_context(
    tx: &Transaction<'_>,
    account: Uuid,
    context: Uuid,
) -> Result<ClosureCounts, tokio_postgres::Error> {
    reduce(tx, account, Binding::Context(context), true).await
}

pub(crate) async fn withdraw_contact(
    tx: &Transaction<'_>,
    account: Uuid,
    contact: Uuid,
    purpose: &str,
) -> Result<ClosureCounts, tokio_postgres::Error> {
    reduce(tx, account, Binding::Contact(contact, Some(purpose)), false).await
}

pub(crate) async fn erase_contact(
    tx: &Transaction<'_>,
    account: Uuid,
    contact: Uuid,
) -> Result<ClosureCounts, tokio_postgres::Error> {
    reduce(tx, account, Binding::Contact(contact, None), true).await
}

async fn reduce(
    tx: &Transaction<'_>,
    account: Uuid,
    binding: Binding<'_>,
    erase: bool,
) -> Result<ClosureCounts, tokio_postgres::Error> {
    if !store::installed(tx).await? {
        return Ok(ClosureCounts::default());
    }
    let (identity, purpose, context) = match binding {
        Binding::Context(id) => (id, None, true),
        Binding::Contact(id, purpose) => (id, purpose, false),
    };
    // Resolve and lock exact affected opening IDs first, in deterministic order.
    // Account serialization held by every caller prevents a new related offer.
    let rows=tx.query("SELECT o.id,o.description_context_id=$2 FROM workflow_openings o WHERE o.account_id=$1 AND (($4 AND o.description_context_id=$2) OR EXISTS(SELECT 1 FROM workflow_opening_offers f WHERE (f.account_id,f.opening_id)=(o.account_id,o.id) AND (($4 AND f.context_id=$2) OR (NOT $4 AND f.contact_identity=$2 AND ($3::text IS NULL OR f.purpose=$3))))) ORDER BY o.id FOR UPDATE OF o", &[&account,&identity,&purpose,&context]).await?;
    let mut counts = ClosureCounts::default();
    for row in rows {
        let opening: Uuid = row.get(0);
        let description = context && row.get::<_, Option<bool>>(1).unwrap_or(false);
        // Loss of an opening's description closes all future admission. Only
        // selected offer bindings are erased; unrelated peers retain their data.
        if description {
            counts.openings += tx.execute("UPDATE workflow_openings SET phase='closed',state_version=CASE WHEN state_version=9223372036854775807 THEN state_version ELSE state_version+1 END WHERE account_id=$1 AND id=$2 AND phase='open'", &[&account,&opening]).await? as i64;
        }
        let offers=tx.query("SELECT id FROM workflow_opening_offers WHERE account_id=$1 AND opening_id=$2 AND (($5 AND context_id=$3) OR (NOT $5 AND contact_identity=$3 AND ($4::text IS NULL OR purpose=$4))) ORDER BY id FOR UPDATE", &[&account,&opening,&identity,&purpose,&context]).await?;
        for offer in offers {
            let offer: Uuid = offer.get(0);
            let allocations=tx.query("SELECT id,phase FROM workflow_opening_allocations WHERE account_id=$1 AND opening_id=$2 AND offer_id=$3 ORDER BY id FOR UPDATE", &[&account,&opening,&offer]).await?;
            for allocation in allocations {
                let id: Uuid = allocation.get(0);
                let phase: String = allocation.get(1);
                if phase == "confirmed" {
                    counts.preserved_confirmed += 1;
                }
                if phase == "pending" {
                    counts.pending_allocations += tx.execute("UPDATE workflow_opening_allocations SET phase='cancelled',state_version=CASE WHEN state_version=9223372036854775807 THEN state_version ELSE state_version+1 END WHERE account_id=$1 AND id=$2 AND phase='pending'", &[&account,&id]).await? as i64;
                }
                if erase {
                    redact(tx, account, 3, id).await?;
                    tx.execute("UPDATE workflow_opening_allocations SET binding_scrubbed=true,offer_id=NULL,offer_state_version=NULL,contact_identity=NULL,event_id=NULL,event_digest=NULL,observed_ms=NULL,accepted_ms=NULL,decision_deadline_ms=NULL,reserved_by_user=NULL,reserved_session=NULL,confirmed_by_user=NULL,confirmed_session=NULL,confirmed_ms=NULL WHERE account_id=$1 AND id=$2", &[&account,&id]).await?;
                }
            }
            counts.offers += tx.execute("UPDATE workflow_opening_offers SET phase='withdrawn',state_version=CASE WHEN state_version=9223372036854775807 THEN state_version ELSE state_version+1 END WHERE account_id=$1 AND id=$2 AND phase IN ('active','closed')", &[&account,&offer]).await? as i64;
            if erase {
                redact(tx, account, 2, offer).await?;
                tx.execute("UPDATE workflow_opening_offers SET binding_scrubbed=true,contact_identity=NULL,current_contact_id=NULL,purpose=NULL,consent_episode_id=NULL,context_id=NULL,context_revision=NULL,context_digest=NULL,issued_ms=NULL,expires_ms=NULL,created_by_user=NULL,created_session=NULL WHERE account_id=$1 AND id=$2", &[&account,&offer]).await?;
            }
        }
        if description {
            // Pending holds cannot be confirmed against a lost description.
            counts.pending_allocations += tx.execute("UPDATE workflow_opening_allocations SET phase='cancelled',state_version=CASE WHEN state_version=9223372036854775807 THEN state_version ELSE state_version+1 END WHERE account_id=$1 AND opening_id=$2 AND phase='pending'", &[&account,&opening]).await? as i64;
            if erase {
                redact(tx, account, 1, opening).await?;
                tx.execute("UPDATE workflow_openings SET description_context_id=NULL,description_revision=NULL,description_digest=NULL,decision_deadline_ms=NULL,created_by_user=NULL,created_session=NULL,created_ms=NULL WHERE account_id=$1 AND id=$2", &[&account,&opening]).await?;
            }
        }
    }
    Ok(counts)
}

async fn redact(
    tx: &Transaction<'_>,
    account: Uuid,
    kind: i16,
    subject: Uuid,
) -> Result<(), tokio_postgres::Error> {
    tx.execute("UPDATE workflow_opening_requests SET redacted=true,subject_kind=NULL,subject_id=NULL,operation=NULL,request_digest=NULL,result=NULL,actor_user_id=NULL,actor_session_id=NULL,committed_ms=NULL WHERE account_id=$1 AND subject_kind=$2 AND subject_id=$3 AND NOT redacted", &[&account,&kind,&subject]).await?;
    Ok(())
}
