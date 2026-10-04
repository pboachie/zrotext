// SPDX-License-Identifier: AGPL-3.0-only
//! Exact phone-selected registry grants; this never creates a reader grant.
use super::{ConversationError, Statement};
use crate::sealed_manifest_store::outbound::CurrentAuthority;
use tokio_postgres::Transaction;

pub(crate) async fn check_readers(
    tx: &Transaction<'_>,
    statement: &Statement,
    authority: &mut CurrentAuthority<'_, '_>,
) -> Result<(), ConversationError> {
    check_grants(tx, statement).await?;
    for selected in &statement.integration_readers {
        let row = tx.query_opt(
            "SELECT r.key_point,r.manifest_generation,r.expires_ms,g.expires_ms,k.valid_until_ms,k.valid_from_ms \
             FROM connector_registrations r JOIN connector_keys k ON \
             (k.account_id,k.connector_id,k.key_id)=(r.account_id,r.connector_id,r.key_id) \
             JOIN connector_grants g ON (g.account_id,g.connector_id)=(r.account_id,r.connector_id) \
             WHERE r.account_id=$1 AND r.connector_id=$2 AND r.key_id=$3 AND g.grant_id=$4 \
             AND r.state='active' AND r.revoked_ms IS NULL AND k.retired_ms IS NULL \
             AND g.kind='read' AND (g.read_directions::integer & 8)=8 AND g.line_id=$5 \
             AND g.revoked_ms IS NULL AND (cardinality(g.conversation_restriction)=0 OR $6=ANY(g.conversation_restriction)) \
             FOR SHARE OF r,k,g",
            &[&statement.account,&selected.connector_id,&selected.key_id.as_slice(),&selected.read_grant_id,&statement.line,&statement.interval],
        ).await?.ok_or(ConversationError::Forbidden)?;
        let point: Vec<u8> = row.get(0);
        let (snapshot, key, scope) = authority
            .integration_snapshot(statement.device, statement.line, &point)
            .await?;
        let now = super::now(tx).await?;
        if row.get::<_, i64>(5) > now
            || key != selected.key_id
            || scope & 8 != 8
            || snapshot.generation != statement.trust_generation
            || row.get::<_, i64>(1) != snapshot.generation
            || [
                row.get::<_, i64>(2),
                row.get::<_, i64>(3),
                row.get::<_, i64>(4),
            ]
            .iter()
            .any(|until| *until <= now)
        {
            return Err(ConversationError::Forbidden);
        }
    }
    Ok(())
}

pub(crate) async fn check_grants(
    tx: &Transaction<'_>,
    statement: &Statement,
) -> Result<(), ConversationError> {
    deadline(tx, statement).await.map(|_| ())
}
pub(crate) async fn deadline(
    tx: &Transaction<'_>,
    statement: &Statement,
) -> Result<i64, ConversationError> {
    let mut deadline = i64::MAX;
    for selected in &statement.integration_readers {
        let row = tx.query_opt(
            "SELECT r.expires_ms,g.expires_ms,k.valid_until_ms,k.valid_from_ms FROM connector_registrations r \
             JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(r.account_id,r.connector_id,r.key_id) \
             JOIN connector_grants g ON (g.account_id,g.connector_id)=(r.account_id,r.connector_id) \
             WHERE r.account_id=$1 AND r.connector_id=$2 AND r.key_id=$3 AND g.grant_id=$4 \
             AND r.state='active' AND r.revoked_ms IS NULL AND r.manifest_generation=$7 \
             AND k.retired_ms IS NULL AND g.revoked_ms IS NULL AND g.kind='read' \
             AND (g.read_directions::integer & 8)=8 AND g.line_id=$5 \
             AND (cardinality(g.conversation_restriction)=0 OR $6=ANY(g.conversation_restriction)) \
             FOR SHARE OF r,k,g",
            &[&statement.account,&selected.connector_id,&selected.key_id.as_slice(),&selected.read_grant_id,&statement.line,&statement.interval,&statement.trust_generation],
        ).await?.ok_or(ConversationError::Forbidden)?;
        let now = super::now(tx).await?;
        deadline = deadline
            .min(row.get::<_, i64>(0))
            .min(row.get::<_, i64>(1))
            .min(row.get::<_, i64>(2));
        if row.get::<_, i64>(3) > now || deadline <= now {
            return Err(ConversationError::Forbidden);
        }
    }
    Ok(deadline)
}
