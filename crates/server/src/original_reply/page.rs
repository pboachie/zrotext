// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub accepted_at_ms: i64,
    pub event_id: Uuid,
}
#[derive(Serialize)]
pub struct PageEvent {
    pub event_id: Uuid,
    pub accepted_at_ms: i64,
    pub observed_at_ms: i64,
    pub historical_manifest_version: i64,
    pub activation_manifest_version: i64,
    pub disposition: &'static str,
    pub active_request_ids: Vec<Uuid>,
}
#[derive(Serialize)]
pub struct Page {
    pub events: Vec<PageEvent>,
    pub next: Option<Cursor>,
    pub proof: Proof,
}
pub(crate) async fn page(
    client: &mut Client,
    p: &Principal,
    accepted: i64,
    cursor: Option<Cursor>,
    limit: u16,
) -> Result<Page, ConversationError> {
    if !(1..=32).contains(&limit)
        || cursor
            .as_ref()
            .is_some_and(|c| c.accepted_at_ms <= 0 || c.event_id.is_nil())
    {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let (_proof, s) = locked(&tx, p, accepted).await?;
    if let Some(c) = &cursor {
        tx.query_opt("SELECT 1 FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE p.account_id=$1 AND p.interval_id=$2 AND p.event_id=$3 AND p.accepted_at_ms=$4 AND e.envelope IS NOT NULL FOR SHARE OF p,e",&[&p.account,&s.interval,&c.event_id,&c.accepted_at_ms]).await?.ok_or(ConversationError::Unavailable)?;
    }
    let after_time = cursor.as_ref().map_or(0, |c| c.accepted_at_ms);
    let after_id = cursor.as_ref().map_or(Uuid::nil(), |c| c.event_id);
    let rows=tx.query("SELECT p.event_id,p.accepted_at_ms,floor(extract(epoch FROM e.observed_at)*1000)::bigint,p.manifest_version FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE p.account_id=$1 AND p.interval_id=$2 AND e.envelope IS NOT NULL AND (p.accepted_at_ms,p.event_id)>($3,$4) ORDER BY p.accepted_at_ms,p.event_id LIMIT $5 FOR SHARE OF p,e",&[&p.account,&s.interval,&after_time,&after_id,&i64::from(limit)]).await?;
    let mut events = Vec::with_capacity(rows.len());
    for r in rows {
        let event: Uuid = r.get(0);
        let observed: i64 = r.get(2);
        let candidates=tx.query("SELECT request_id FROM original_reply_requests WHERE account_id=$1 AND interval_id=$2 AND stopped_ms IS NULL AND consumed_turns<maximum_turns AND starts_ms<=$3 AND expires_ms>$3 AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint ORDER BY request_id LIMIT 9",&[&p.account,&s.interval,&observed]).await?;
        let ids: Vec<Uuid> = candidates.into_iter().map(|r| r.get(0)).collect();
        // Availability is not qualifying authority. consume independently verifies
        // source grant issuance, current action, exact recipient/purpose and timing.
        let disposition = if ids.is_empty() {
            "unassociated"
        } else if ids.len() > 8 {
            "owner_review"
        } else {
            "request_available"
        };
        events.push(PageEvent {
            event_id: event,
            accepted_at_ms: r.get(1),
            observed_at_ms: observed,
            historical_manifest_version: r.get(3),
            activation_manifest_version: s.activation_version,
            disposition,
            active_request_ids: if ids.len() > 8 { Vec::new() } else { ids },
        });
    }
    let next = if events.len() == usize::from(limit) {
        events.last().map(|e| Cursor {
            accepted_at_ms: e.accepted_at_ms,
            event_id: e.event_id,
        })
    } else {
        None
    };
    audit(&tx, p, None, "page").await?;
    let (proof, _) = locked(&tx, p, accepted).await?;
    tx.commit().await?;
    Ok(Page {
        events,
        next,
        proof,
    })
}
pub(crate) async fn status(
    client: &mut Client,
    p: &Principal,
    accepted: i64,
    id: Uuid,
) -> Result<consumption::ResultData, ConversationError> {
    if id.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let (proof, _) = locked(&tx, p, accepted).await?;
    let r=tx.query_opt("SELECT event_id,request_id,proposed_action_id,revision,binding_digest,disposition FROM original_reply_consumptions WHERE account_id=$1 AND consumption_id=$2 AND consumer_id=$3 FOR SHARE",&[&p.account,&id,&proof.connector_id]).await?.ok_or(ConversationError::NotFound)?;
    let action = r.get::<_, Option<Uuid>>(2).map(|action_id| {
        crate::http_owner_conversations::context::decisions::ActionKey {
            account_id: p.account,
            action_id,
            revision: r.get::<_, Option<i64>>(3).expect("checked revision"),
            binding_digest: r
                .get::<_, Option<Vec<u8>>>(4)
                .expect("checked digest")
                .try_into()
                .expect("checked length"),
        }
    });
    let result = consumption::ResultData {
        event_id: r.get(0),
        consumption_id: id,
        active_request_id: r.get(1),
        action,
        disposition: r.get(5),
    };
    locked(&tx, p, accepted).await?;
    tx.commit().await?;
    Ok(result)
}
