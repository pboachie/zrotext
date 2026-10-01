// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded metadata cleanup. Content retention remains the sealed inbound worker's job.
use tokio_postgres::{Client, Error};

pub(crate) async fn prune(
    client: &mut Client,
    days: i32,
    limit: i64,
) -> Result<(u64, u64, u64), Error> {
    let tx = client.transaction().await?;
    // Account before interval matches the admission fence; no manifest changes here.
    let accounts=tx.query("SELECT a.id FROM accounts a WHERE EXISTS (SELECT 1 FROM conversation_intervals i JOIN sessions s ON (s.account_id,s.id)=(i.account_id,i.initiating_session_id) JOIN users u ON u.id=s.user_id WHERE i.account_id=a.id AND i.phase IN ('pending','install_pending','active') AND (s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp() OR u.email_verified_at IS NULL OR NOT EXISTS (SELECT 1 FROM memberships m WHERE m.account_id=a.id AND m.user_id=u.id AND m.role='owner' AND m.revoked_at IS NULL) OR (i.phase<>'active' AND i.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)))) ORDER BY a.id FOR UPDATE OF a SKIP LOCKED LIMIT $1", &[&limit]).await?;
    let mut closed = 0;
    for account in accounts {
        let account: uuid::Uuid = account.get(0);
        closed+=tx.execute("WITH due AS (SELECT i.id FROM conversation_intervals i JOIN sessions s ON (s.account_id,s.id)=(i.account_id,i.initiating_session_id) JOIN users u ON u.id=s.user_id WHERE i.account_id=$1 AND i.phase IN ('pending','install_pending','active') AND (s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp() OR u.email_verified_at IS NULL OR NOT EXISTS (SELECT 1 FROM memberships m WHERE m.account_id=$1 AND m.user_id=u.id AND m.role='owner' AND m.revoked_at IS NULL) OR (i.phase<>'active' AND i.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000))) FOR UPDATE OF i SKIP LOCKED LIMIT 1) UPDATE conversation_intervals i SET phase=CASE WHEN phase='active' THEN 'history' ELSE 'expired' END,statement=CASE WHEN phase='active' THEN statement ELSE NULL END,closed_at=clock_timestamp() FROM due WHERE (i.account_id,i.id)=($1,due.id)", &[&account]).await?;
    }
    // Erase original manifest provenance once its associated encrypted body is gone.
    let provenance=tx.execute("WITH due AS (SELECT p.account_id,p.event_id FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE e.envelope IS NULL ORDER BY p.account_id,p.event_id FOR UPDATE OF p SKIP LOCKED LIMIT $1) DELETE FROM conversation_inbound_provenance p USING due WHERE (p.account_id,p.event_id)=(due.account_id,due.event_id)", &[&limit]).await?;
    let proof_guard = if crate::http_owner_conversations::confirmation_records::installed(&tx)
        .await?
    {
        " AND NOT EXISTS (SELECT 1 FROM conversation_confirmation_records c WHERE (c.account_id,c.interval_id)=(i.account_id,i.id)) "
    } else {
        ""
    };
    if !proof_guard.is_empty() {
        // A proof FK retains interval identity, never its original peer-bearing
        // statement beyond the configured content window. This is the existing
        // irreversible history-to-withdrawn transition, preserving closed_at.
        tx.execute("WITH due AS (SELECT i.account_id,i.id FROM conversation_intervals i WHERE i.phase='history' AND i.statement IS NOT NULL AND i.closed_at<=clock_timestamp()-$1::int*interval '1 day' AND EXISTS (SELECT 1 FROM conversation_confirmation_records c WHERE (c.account_id,c.interval_id)=(i.account_id,i.id)) ORDER BY i.closed_at,i.account_id,i.id FOR UPDATE OF i SKIP LOCKED LIMIT $2) UPDATE conversation_intervals i SET phase='withdrawn',statement=NULL FROM due WHERE (i.account_id,i.id)=(due.account_id,due.id)", &[&days,&limit]).await?;
    }
    let interval_sql = format!(
        "WITH due AS (SELECT i.account_id,i.id FROM conversation_intervals i WHERE i.closed_at<=clock_timestamp()-$1::int*interval '1 day' AND NOT EXISTS (SELECT 1 FROM conversation_inbound_provenance p WHERE (p.account_id,p.interval_id)=(i.account_id,i.id)) {proof_guard} ORDER BY i.closed_at,i.account_id,i.id FOR UPDATE OF i SKIP LOCKED LIMIT $2) DELETE FROM conversation_intervals i USING due WHERE (i.account_id,i.id)=(due.account_id,due.id)"
    );
    let intervals = tx.execute(&interval_sql, &[&days, &limit]).await?;
    tx.commit().await?;
    Ok((closed, provenance, intervals))
}
