// SPDX-License-Identifier: AGPL-3.0-only
use super::{DeliveryError, retry_seconds, sender};
use crate::{
    http_owner_conversations::{activation, lock_line},
    sealed_manifest_store::outbound::{ManifestSnapshot, lock_current},
    webhook_worker::WebhookSecretVault,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{future::Future, time::Duration};
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

struct Lease {
    id: Uuid,
    account: Uuid,
    endpoint: Uuid,
    event: Uuid,
    interval: Uuid,
    generation: i64,
    token: Uuid,
    attempt: i16,
}

async fn claim(client: &mut Client) -> Result<Option<Lease>, DeliveryError> {
    let tx = client.transaction().await?;
    // A crash may have sent bytes; receiver event dedup remains required. Close
    // the durable attempt before another lease, preserving the seven-attempt cap.
    let expired = tx
        .query(
            "SELECT id,attempt_count FROM sealed_event_deliveries WHERE status='leased' \
        AND lease_until<=clock_timestamp() ORDER BY lease_until,id FOR UPDATE SKIP LOCKED LIMIT 20",
            &[],
        )
        .await?;
    for row in expired {
        let id: Uuid = row.get(0);
        let attempts: i16 = row.get(1);
        tx.execute("UPDATE sealed_event_delivery_attempts SET completed_at=clock_timestamp(),outcome='timeout' \
            WHERE delivery_id=$1 AND completed_at IS NULL",&[&id]).await?;
        let state = if attempts >= 7 { "dead" } else { "pending" };
        let delay = retry_seconds(attempts).unwrap_or(0);
        tx.execute("UPDATE sealed_event_deliveries SET status=$2,lease_id=NULL,lease_until=NULL, \
            next_attempt_at=clock_timestamp()+$3::int*interval '1 second',updated_at=clock_timestamp() WHERE id=$1",
            &[&id,&state,&delay]).await?;
    }
    let Some(row)=tx.query_opt("SELECT d.id,d.account_id,d.endpoint_id,d.event_id,d.interval_id,d.trust_generation,d.attempt_count \
        FROM sealed_event_deliveries d JOIN webhook_endpoints e ON (e.account_id,e.id)=(d.account_id,d.endpoint_id) \
        WHERE d.status='pending' AND d.next_attempt_at<=clock_timestamp() AND d.attempt_count<7 \
        AND e.enabled AND e.sealed_events_enabled AND e.paused_at IS NULL \
        ORDER BY d.next_attempt_at,d.id FOR UPDATE OF d SKIP LOCKED LIMIT 1",&[]).await? else {tx.commit().await?;return Ok(None);};
    let lease = Lease {
        id: row.get(0),
        account: row.get(1),
        endpoint: row.get(2),
        event: row.get(3),
        interval: row.get(4),
        generation: row.get(5),
        token: Uuid::new_v4(),
        attempt: row.get::<_, i16>(6) + 1,
    };
    tx.execute("UPDATE sealed_event_deliveries SET status='leased',lease_id=$2,lease_until=clock_timestamp()+interval '30 seconds', \
        attempt_count=$3,updated_at=clock_timestamp() WHERE id=$1",&[&lease.id,&lease.token,&lease.attempt]).await?;
    tx.execute(
        "INSERT INTO sealed_event_delivery_attempts(delivery_id,attempt_number) VALUES($1,$2)",
        &[&lease.id, &lease.attempt],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(lease))
}

async fn site(tx: &Transaction<'_>, s: &activation::Statement) -> Result<(), DeliveryError> {
    tx.query_opt("SELECT 1 FROM sites t CROSS JOIN deployment_authority p WHERE t.site_id=$1 \
        AND t.enabled AND NOT t.draining AND p.singleton AND p.epoch=$2 AND NOT pg_is_in_recovery() \
        FOR SHARE OF t,p",&[&s.site,&s.deployment_epoch]).await?.ok_or(DeliveryError::Forbidden)?;
    Ok(())
}

pub async fn dispatch_one(
    database_url: &str,
    vault: &WebhookSecretVault,
    enabled: bool,
) -> Result<bool, DeliveryError> {
    if !enabled {
        return Ok(false);
    }
    let mut client = crate::runtime_db::connect_worker(database_url)
        .await
        .map_err(|_| DeliveryError::Forbidden)?;
    dispatch_counted_with(&mut client, vault, |url| async move {
        sender::connect(&url).await
    })
    .await
}

// Only a dispatch result follows a successful claim and policy finish/commit.
// Pool/setup failures in the public entry point never enter this conversion.
pub(super) async fn dispatch_counted_with<F, Fut>(
    client: &mut Client,
    vault: &WebhookSecretVault,
    connector: F,
) -> Result<bool, DeliveryError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<sender::Connection, crate::webhook_egress::EgressError>>,
{
    match dispatch_with(client, vault, connector).await {
        Err(error) if policy_failure(&error) => Ok(true),
        result => result,
    }
}

pub(super) async fn dispatch_with<F, Fut>(
    client: &mut Client,
    vault: &WebhookSecretVault,
    connector: F,
) -> Result<bool, DeliveryError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<sender::Connection, crate::webhook_egress::EgressError>>,
{
    let Some(lease) = claim(client).await? else {
        return Ok(false);
    };
    let result = attempt(client, vault, &lease, connector).await;
    // Policy failure is terminal, never a plaintext fallback or failed HTTP retry.
    if result.as_ref().is_err_and(policy_failure) {
        let tx = client.transaction().await?;
        finish(&tx, &lease, "policy_rejected", None).await?;
        tx.commit().await?;
    }
    result.map(|()| true)
}

fn policy_failure(error: &DeliveryError) -> bool {
    matches!(
        error,
        DeliveryError::Forbidden
            | DeliveryError::Authority(crate::sealed_manifest_store::AdmissionError::Rejected(_))
            | DeliveryError::Conversation(
                crate::http_owner_conversations::ConversationError::Forbidden
                    | crate::http_owner_conversations::ConversationError::NotFound
                    | crate::http_owner_conversations::ConversationError::Invalid
            )
            | DeliveryError::Secret(crate::webhook_worker::WorkerError::Secret)
    )
}

async fn attempt<F, Fut>(
    client: &mut Client,
    vault: &WebhookSecretVault,
    l: &Lease,
    connector: F,
) -> Result<(), DeliveryError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<sender::Connection, crate::webhook_egress::EgressError>>,
{
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, l.account).await?;
    let raw: Vec<u8> = tx
        .query_opt(
            "SELECT statement FROM conversation_intervals WHERE account_id=$1 AND id=$2 \
        AND phase IN ('active','history') AND statement IS NOT NULL",
            &[&l.account, &l.interval],
        )
        .await?
        .ok_or(DeliveryError::Forbidden)?
        .get(0);
    let statement = activation::Statement::decode(&raw)?;
    let owner_deadline = activation::origin(&tx, &statement).await?;
    let interval = activation::load(&tx, l.account, l.interval).await?;
    if !matches!(interval.phase.as_str(), "active" | "history")
        || statement.trust_generation != l.generation
    {
        return Err(DeliveryError::Forbidden);
    }
    lock_line(
        &tx,
        l.account,
        statement.device,
        statement.line,
        statement.generation,
    )
    .await?;
    site(&tx, &statement).await?;
    let endpoint=tx.query_opt("SELECT callback_url,signing_secret_ciphertext,signing_secret_key_version FROM webhook_endpoints \
        WHERE account_id=$1 AND id=$2 AND enabled AND sealed_events_enabled AND paused_at IS NULL FOR SHARE",
        &[&l.account,&l.endpoint]).await?.ok_or(DeliveryError::Forbidden)?;
    let row=tx.query_opt("SELECT e.device_id,floor(extract(epoch FROM e.observed_at)*1000)::bigint,e.envelope,e.unsigned_digest, \
        p.trust_generation,p.manifest_version,p.manifest_digest,p.verified_manifest,p.accepted_at_ms \
        FROM sealed_inbound_events e JOIN conversation_inbound_provenance p ON (p.account_id,p.event_id)=(e.account_id,e.id) \
        WHERE e.account_id=$1 AND e.id=$2 AND e.envelope IS NOT NULL AND p.interval_id=$3 AND p.trust_generation=$4 \
        FOR SHARE OF e,p",&[&l.account,&l.event,&l.interval,&l.generation]).await?.ok_or(DeliveryError::Forbidden)?;
    let bytes: Vec<u8> = row.get(2);
    let snapshot = ManifestSnapshot {
        generation: row.get(4),
        version: row.get(5),
        digest: row
            .get::<_, Vec<u8>>(6)
            .try_into()
            .map_err(|_| DeliveryError::Forbidden)?,
        bytes: row.get(7),
        accepted_ms: row.get(8),
    };
    let readers = activation::readers(&statement);
    let wanted = activation::wanted(&statement, l.event, &readers);
    authority.verify_history(&wanted, &snapshot, &bytes).await?;
    let mut authority_deadline = authority
        .admission_deadline(&wanted)
        .await?
        .min(owner_deadline);
    let claim=tx.query_opt("SELECT floor(extract(epoch FROM lease_until)*1000)::bigint FROM sealed_event_deliveries WHERE account_id=$1 AND id=$2 AND status='leased' \
        AND lease_id=$3 AND lease_until>clock_timestamp() FOR UPDATE",&[&l.account,&l.id,&l.token]).await?.ok_or(DeliveryError::Forbidden)?;
    authority_deadline = authority_deadline.min(claim.get::<_, i64>(0));
    let secret = vault.open(
        l.account,
        l.endpoint,
        endpoint.get(2),
        &endpoint.get::<_, Vec<u8>>(1),
    )?;
    let body = event_body(
        l.event,
        l.id,
        l.account,
        row.get(0),
        row.get(1),
        &bytes,
        &row.get::<_, Vec<u8>>(3),
    )?;
    let now = activation::now(&tx).await?;
    let remaining = authority_deadline
        .checked_sub(now)
        .filter(|v| *v > 0)
        .ok_or(DeliveryError::Forbidden)?;
    // Fixed deadline starts before DNS/TCP/TLS and is never renewed after awaits.
    let deadline = Instant::now() + Duration::from_millis((remaining as u64).min(10_000));
    let connected = tokio::time::timeout_at(deadline, connector(endpoint.get(0))).await;
    // Recheck temporal and mutable authority after the actual connect barrier,
    // before sending ANY signature header or opaque byte. Locks remain held.
    activation::origin(&tx, &statement).await?;
    site(&tx, &statement).await?;
    authority.inbound_context(&wanted).await?;
    if activation::now(&tx).await? >= authority_deadline || Instant::now() >= deadline {
        return Err(DeliveryError::Forbidden);
    }
    let response = match connected {
        Ok(Ok(connection)) => connection.send(&body, &secret, deadline).await,
        _ => Err(crate::webhook_egress::EgressError::Transport),
    };
    let (outcome, status) = match response {
        Ok(r) if r.acknowledged => ("ack", Some(r.status as i16)),
        Ok(r) => ("http_error", Some(r.status as i16)),
        Err(_) => ("network_error", None),
    };
    finish(&tx, l, outcome, status).await?;
    drop(authority);
    tx.commit().await?;
    Ok(())
}

async fn finish(
    tx: &Transaction<'_>,
    l: &Lease,
    outcome: &str,
    status: Option<i16>,
) -> Result<(), DeliveryError> {
    let terminal =
        outcome == "ack" || outcome == "policy_rejected" || retry_seconds(l.attempt).is_none();
    let state = if outcome == "ack" {
        "succeeded"
    } else if terminal {
        "dead"
    } else {
        "pending"
    };
    let delay = retry_seconds(l.attempt).unwrap_or(0);
    let changed = tx
        .execute(
            "UPDATE sealed_event_deliveries SET status=$4,lease_id=NULL,lease_until=NULL, \
        next_attempt_at=clock_timestamp()+$5::int*interval '1 second',updated_at=clock_timestamp() \
        WHERE account_id=$1 AND id=$2 AND status='leased' AND lease_id=$3",
            &[&l.account, &l.id, &l.token, &state, &delay],
        )
        .await?;
    if changed == 0 {
        return Ok(());
    } // Withdrawal/purge already removed this lease.
    tx.execute("UPDATE sealed_event_delivery_attempts SET completed_at=clock_timestamp(),outcome=$3,http_status=$4 \
        WHERE delivery_id=$1 AND attempt_number=$2 AND completed_at IS NULL",&[&l.id,&l.attempt,&outcome,&status]).await?;
    if outcome == "ack" {
        tx.execute(
            "UPDATE webhook_endpoints SET failure_started_at=NULL WHERE account_id=$1 AND id=$2",
            &[&l.account, &l.endpoint],
        )
        .await?;
    } else if outcome != "policy_rejected" {
        tx.execute("UPDATE webhook_endpoints SET failure_started_at=coalesce(failure_started_at,clock_timestamp()), \
            paused_at=CASE WHEN coalesce(failure_started_at,clock_timestamp())<=clock_timestamp()-interval '72 hours' \
            THEN coalesce(paused_at,clock_timestamp()) ELSE paused_at END WHERE account_id=$1 AND id=$2",&[&l.account,&l.endpoint]).await?;
    }
    Ok(())
}

pub(super) fn event_body(
    event: Uuid,
    delivery: Uuid,
    account: Uuid,
    device: Uuid,
    observed: i64,
    envelope: &[u8],
    digest: &[u8],
) -> Result<Vec<u8>, DeliveryError> {
    if [event, delivery, account, device].iter().any(Uuid::is_nil)
        || observed <= 0
        || !(426..=36_864).contains(&envelope.len())
        || digest.len() != 32
    {
        return Err(DeliveryError::Forbidden);
    }
    let body=serde_json::to_vec(&serde_json::json!({"v":1,"type":"sealed.inbound_event","event_id":event,"delivery_id":delivery,"account_id":account,"device_id":device,"observed_at_ms":observed,"envelope_b64":STANDARD.encode(envelope),"unsigned_digest_b64":STANDARD.encode(digest)})).map_err(|_|DeliveryError::Forbidden)?;
    if body.len() > 65_536 {
        return Err(DeliveryError::Forbidden);
    }
    Ok(body)
}

#[cfg(test)]
mod tests;
