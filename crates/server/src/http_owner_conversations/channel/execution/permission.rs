// SPDX-License-Identifier: AGPL-3.0-only
//! Fresh submission permission, distinct from retained historical radio evidence.
use super::*;

pub(crate) async fn current(
    client: &mut Client,
    authenticated: &AuthenticatedChannelSession<'_>,
    message: Uuid,
    attempt: Uuid,
) -> Result<bool, ConversationError> {
    let tx = client.transaction().await?;
    if !lifecycle::validate(&tx).await? || !send::queue::lifecycle::validate(&tx).await? {
        return Ok(false);
    }
    let authority = lock_current(&tx, authenticated.device.account_id).await?;
    live(&tx, authenticated.device).await?;
    let row=tx.query_opt("SELECT p.initiating_session_id,m.transport_payload,p.confirmation,p.signature \
        FROM conversation_execution_records r JOIN conversation_confirmation_records p ON (p.account_id,p.message_id)=(r.account_id,r.message_id) \
        JOIN messages m ON (m.account_id,m.id)=(r.account_id,r.message_id) \
        JOIN message_attempts a ON a.id=r.attempt_id JOIN dispatch_fences f ON f.attempt_id=a.id \
        JOIN dispatch_jobs j ON (j.account_id,j.message_id)=(r.account_id,r.message_id) \
        WHERE (r.account_id,r.device_id,r.message_id,r.attempt_id)=($1,$2,$3,$4) \
        AND r.phone_session=$5 AND r.origin_hash=$6 AND r.site_id=$7 AND r.instance_id=$8 \
        AND r.session_epoch=$9 AND r.deployment_epoch=$10 AND r.generation=1 \
        AND (a.account_id,a.message_id,a.device_id,a.generation,a.session_epoch,a.deployment_epoch)= \
        (r.account_id,r.message_id,r.device_id,r.generation,r.session_epoch,r.deployment_epoch) \
        AND (f.account_id,f.message_id,f.device_id,f.generation,f.session_epoch,f.deployment_epoch)= \
        (r.account_id,r.message_id,r.device_id,r.generation,r.session_epoch,r.deployment_epoch) \
        AND a.status=f.outcome AND f.outcome IN ('granted','submitting') \
        AND m.state IN ('claimed','submitting') AND j.generation=r.generation AND j.finished_at IS NULL \
        AND j.grant_issued_at IS NOT NULL AND j.lease_owner='conversation:'||r.phone_session::text \
        AND j.lease_until=to_timestamp(r.expires_at_ms::double precision/1000) AND f.grant_expires_at=j.lease_until \
        AND conversation_execution_initial_valid(r) FOR SHARE OF m",
        &[&authenticated.device.account_id,&authenticated.device.device_id,&message,&attempt,&authenticated.phone_session,
          &authenticated.origin_hash.as_slice(),&authenticated.device.site_id,&authenticated.device.instance_id,
          &authenticated.device.connection_epoch,&authenticated.device.deployment_epoch]).await?;
    let Some(row) = row else { return Ok(false) };
    let envelope: Option<Vec<u8>> = row.get(1);
    let confirmation: Option<Vec<u8>> = row.get(2);
    let signature: Option<Vec<u8>> = row.get(3);
    let (Some(envelope), Some(confirmation), Some(signature)) = (envelope, confirmation, signature)
    else {
        return Ok(false);
    };
    let origin: Uuid = row.get(0);
    let c = send::authorize_delivery(
        &tx,
        authenticated.device,
        origin,
        &envelope,
        &confirmation,
        &signature,
    )
    .await?;
    if c.message != message {
        return Ok(false);
    }
    // Sample after signature verification and every lock wait. Historical
    // events may still reconcile after this permission becomes false.
    let valid:bool=tx.query_one("SELECT conversation_execution_initial_valid(r) FROM conversation_execution_records r WHERE account_id=$1 AND message_id=$2",&[&c.account,&message]).await?.get(0);
    live(&tx, authenticated.device).await?;
    let valid=valid && tx.query_one("SELECT expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000) FROM conversation_execution_records WHERE account_id=$1 AND message_id=$2",&[&c.account,&message]).await?.get::<_,bool>(0);
    drop(authority);
    tx.commit().await?;
    Ok(valid)
}
