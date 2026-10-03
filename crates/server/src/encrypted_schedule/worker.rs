// SPDX-License-Identifier: AGPL-3.0-only
//! Anonymous, bounded negative/outcome projection. Never executes an actor.
use super::store;
use crate::http_owner_conversations::ConversationError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;
use tokio_postgres::Client;

const ACCOUNTS: i64 = 20;
const OCCURRENCES: u16 = 100;

/// Advances only expiry and authoritative existing message outcomes. Stored
/// actor identities are never converted into principals or execution permits.
pub async fn tick(client: &mut Client) -> Result<u64, ConversationError> {
    let accounts = client.query(&format!("SELECT o.account_id FROM workflow_schedule_occurrences o LEFT JOIN messages m ON (m.account_id,m.id)=(o.account_id,o.message_id) {} WHERE (o.phase IN ('owner_review','waiting_window','waiting_renderer','waiting_phone','claimed') AND (o.expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR {})) OR (o.phase IN ('dispatching','unknown') AND (m.state IS DISTINCT FROM o.observed_message_state OR (o.phase='dispatching' AND m.id IS NULL))) GROUP BY o.account_id ORDER BY min(o.updated_at),o.account_id LIMIT $1",store::WITHDRAWN_JOINS,store::WITHDRAWN), &[&ACCOUNTS]).await?;
    let mut changed = 0;
    for row in accounts {
        let account: uuid::Uuid = row.get(0);
        let tx = client.transaction().await?;
        tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
            .await?;
        if tx
            .query_opt(
                "SELECT id FROM accounts WHERE id=$1 FOR UPDATE SKIP LOCKED",
                &[&account],
            )
            .await?
            .is_none()
        {
            tx.rollback().await?;
            continue;
        }
        changed += store::expire_due(&tx, account, OCCURRENCES).await?;
        changed += store::project_withdrawn(&tx, account, OCCURRENCES).await?;
        changed += store::reconcile(&tx, account, OCCURRENCES).await?;
        tx.commit().await?;
    }
    Ok(changed)
}

/// Mounted only with the independently opted-in workflow runtime. A restarted
/// worker resumes durable metadata, never replays a send or a renderer call.
pub async fn run(database: String, draining: Arc<AtomicBool>, notify: Arc<Notify>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut logged = false;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if draining.load(Ordering::Acquire) { break; }
                let result = async {
                    let mut client = crate::runtime_db::connect_worker(&database).await
                        .map_err(|_| ())?;
                    tick(&mut client).await.map_err(|_| ())
                }.await;
                match result {
                    Ok(_) => logged = false,
                    Err(()) if !logged => { eprintln!("schedule metadata worker unavailable"); logged = true; }
                    Err(()) => {}
                }
            }
            _ = notify.notified() => break,
        }
    }
}
