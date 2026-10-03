// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::context::decisions::{
        self, ActionKey, Descriptor, reply::ReplyDisposition,
    },
    workflow_runtime::{self, IntegrationPrincipal},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: Uuid,
    pub event_id: Uuid,
    pub active_request_id: Option<Uuid>,
    pub descriptor: Option<Descriptor>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultData {
    pub event_id: Uuid,
    pub consumption_id: Uuid,
    pub disposition: String,
    pub active_request_id: Option<Uuid>,
    pub action: Option<ActionKey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveRequest {
    pub request_id: Uuid,
    pub action: ActionKey,
    pub message_id: Uuid,
    pub expires_at_ms: i64,
    pub maximum_turns: i32,
}
/// Existing owner approval and exact confirmed-message identity remain authority.
pub async fn register_request(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: &ActiveRequest,
) -> Result<(), ConversationError> {
    if input.request_id.is_nil()
        || input.message_id.is_nil()
        || !(1..=8).contains(&input.maximum_turns)
    {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    input.action.validate()?;
    if input.action.account_id != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    let descriptor = decisions::store::descriptor(&tx, input.action).await?;
    let (mut authority, header) =
        decisions::fence::checked_descriptor(&tx, owner, &descriptor).await?;
    decisions::fence::live_routine(&tx, &descriptor, &header).await?;
    let head = decisions::store::head(&tx, input.action.account_id, input.action.action_id).await?;
    if head.key != input.action
        || !matches!(
            head.phase,
            decisions::model::Phase::Approved
                | decisions::model::Phase::Dispatching
                | decisions::model::Phase::Unknown
        )
    {
        return Err(ConversationError::Forbidden);
    }
    let interval_id: Uuid = tx
        .query_one(
            "SELECT interval_id FROM workflow_contexts WHERE account_id=$1 AND id=$2",
            &[&input.action.account_id, &header.context],
        )
        .await?
        .get(0);
    let now = activation::now(&tx).await?;
    if input.expires_at_ms <= now || input.expires_at_ms > descriptor.expires_at_ms()? {
        return Err(ConversationError::Invalid);
    }
    tx.query_opt("SELECT 1 FROM workflow_message_links WHERE account_id=$1 AND action_id=$2 AND revision=$3 AND binding_digest=$4 AND message_id=$5 FOR SHARE",&[&input.action.account_id,&input.action.action_id,&input.action.revision,&input.action.binding_digest.as_slice(),&input.message_id]).await?.ok_or(ConversationError::Forbidden)?;
    if let Some(row)=tx.query_opt("SELECT interval_id,action_id,revision,binding_digest,message_id,expires_ms,maximum_turns FROM original_reply_requests WHERE account_id=$1 AND request_id=$2 FOR UPDATE",&[&input.action.account_id,&input.request_id]).await?{
  if row.get::<_,Uuid>(0)!=interval_id||row.get::<_,Uuid>(1)!=input.action.action_id||row.get::<_,i64>(2)!=input.action.revision||row.get::<_,Vec<u8>>(3)!=input.action.binding_digest||row.get::<_,Uuid>(4)!=input.message_id||row.get::<_,i64>(5)!=input.expires_at_ms||row.get::<_,i32>(6)!=input.maximum_turns{return Err(ConversationError::Conflict)}
 }else{
  if tx.query_one("SELECT count(*) FROM original_reply_requests WHERE account_id=$1",&[&input.action.account_id]).await?.get::<_,i64>(0)>=128{return Err(ConversationError::Conflict)}
  tx.execute("INSERT INTO original_reply_requests(account_id,request_id,interval_id,action_id,revision,binding_digest,message_id,created_by_user,created_session,starts_ms,expires_ms,maximum_turns) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",&[&input.action.account_id,&input.request_id,&interval_id,&input.action.action_id,&input.action.revision,&input.action.binding_digest.as_slice(),&input.message_id,&owner.user_id,&owner.session_id,&now,&input.expires_at_ms,&input.maximum_turns]).await?;
 }
    decisions::fence::recheck_descriptor(&tx, owner, &mut authority, &header, &descriptor).await?;
    decisions::fence::live_routine(&tx, &descriptor, &header).await?;
    let head = decisions::store::head(&tx, input.action.account_id, input.action.action_id).await?;
    if head.key != input.action
        || !matches!(
            head.phase,
            decisions::model::Phase::Approved
                | decisions::model::Phase::Dispatching
                | decisions::model::Phase::Unknown
        )
        || activation::now(&tx).await? >= input.expires_at_ms
    {
        return Err(ConversationError::Forbidden);
    }
    drop(authority);
    tx.commit().await?;
    Ok(())
}
fn auth(e: crate::auth::AuthError) -> ConversationError {
    match e {
        crate::auth::AuthError::Database(e) => ConversationError::Database(e),
        crate::auth::AuthError::Conflict => ConversationError::Conflict,
        _ => ConversationError::Forbidden,
    }
}
pub(crate) async fn consume(
    client: &mut Client,
    p: &Principal,
    accepted: i64,
    input: Request,
    output: Option<&IntegrationPrincipal>,
) -> Result<ResultData, ConversationError> {
    if input.request_id.is_nil()
        || input.event_id.is_nil()
        || input.active_request_id.is_some_and(|i| i.is_nil())
    {
        return Err(ConversationError::Invalid);
    }
    let bytes = serde_json::to_vec(&input).map_err(|_| ConversationError::Invalid)?;
    let digest = Sha256::digest([b"ZT/original-reply-consume/v1\0".as_slice(), &bytes].concat());
    let tx = client.transaction().await?;
    let (proof, s) = locked(&tx, p, accepted).await?;
    if let Some(r)=tx.query_opt("SELECT consumption_id,consumer_id,event_id,request_id,proposed_action_id,revision,binding_digest,disposition,request_digest FROM original_reply_consumptions WHERE account_id=$1 AND (consumption_id=$2 OR (consumer_id=$3 AND event_id=$4)) FOR UPDATE",&[&p.account,&input.request_id,&proof.connector_id,&input.event_id]).await?{
  if r.get::<_,Uuid>(0)!=input.request_id||r.get::<_,Uuid>(1)!=proof.connector_id||r.get::<_,Uuid>(2)!=input.event_id||r.get::<_,Vec<u8>>(8)!=digest.as_slice(){return Err(ConversationError::Conflict)}
  let action=r.get::<_,Option<Uuid>>(4).map(|action_id|ActionKey{account_id:p.account,action_id,revision:r.get::<_,Option<i64>>(5).expect("checked revision"),binding_digest:r.get::<_,Option<Vec<u8>>>(6).expect("checked digest").try_into().expect("checked length")});
  let result=ResultData{event_id:input.event_id,consumption_id:input.request_id,active_request_id:r.get(3),action,disposition:r.get(7)};
  locked(&tx,p,accepted).await?;tx.commit().await?;return Ok(result)
 }
    if tx
        .query_one(
            "SELECT count(*) FROM original_reply_consumptions WHERE account_id=$1",
            &[&p.account],
        )
        .await?
        .get::<_, i64>(0)
        >= 8192
    {
        return Err(ConversationError::Conflict);
    }
    let event=tx.query_opt("SELECT e.envelope,p.trust_generation,p.manifest_version,p.manifest_digest,p.verified_manifest,p.accepted_at_ms FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE p.account_id=$1 AND p.event_id=$2 AND p.interval_id=$3 FOR SHARE OF p,e",&[&p.account,&input.event_id,&s.interval]).await?.ok_or(ConversationError::NotFound)?;
    let envelope: Vec<u8> = event
        .get::<_, Option<Vec<u8>>>(0)
        .ok_or(ConversationError::NotFound)?;
    let readers = activation::readers(&s);
    let wanted = activation::wanted(&s, input.event_id, &readers);
    let mut authority = lock_current(&tx, p.account).await?;
    let snapshot = crate::sealed_manifest_store::outbound::ManifestSnapshot {
        generation: event.get(1),
        version: event.get(2),
        digest: event
            .get::<_, Vec<u8>>(3)
            .try_into()
            .map_err(|_| ConversationError::Forbidden)?,
        bytes: event.get(4),
        accepted_ms: event.get(5),
    };
    authority
        .verify_history(&wanted, &snapshot, &envelope)
        .await?;
    let claims =
        crate::sealed_envelope::parse(&envelope, crate::sealed_envelope::Profile::Draft02Candidate)
            .map_err(|_| ConversationError::Forbidden)?;
    let candidates=tx.query("SELECT request_id FROM original_reply_requests WHERE account_id=$1 AND interval_id=$2 AND stopped_ms IS NULL ORDER BY request_id FOR UPDATE",&[&p.account,&s.interval]).await?;
    if candidates.len() > 128 {
        return Err(ConversationError::Conflict);
    }
    let mut qualifying_requests = Vec::new();
    for candidate in candidates {
        let id: Uuid = candidate.get(0);
        if let Some(d) = qualifying_request(&tx, p, &s, id, claims.observed_ms as i64).await? {
            qualifying_requests.push((id, d));
        }
    }
    let mut request_descriptor = None;
    let qualifying =
        qualifying_requests.len() == 1 && input.active_request_id == Some(qualifying_requests[0].0);
    if qualifying {
        request_descriptor = qualifying_requests.pop().map(|(_, d)| d);
    }
    let mut action = None;
    let mut output_permit = None;
    if qualifying && input.descriptor.is_some() {
        let descriptor = input.descriptor.as_ref().expect("present");
        let source = request_descriptor.as_ref().expect("qualifying");
        if descriptor.recipient_id != source.recipient_id
            || descriptor.purpose_id != source.purpose_id
            || descriptor.line_id != source.line_id
        {
            return Err(ConversationError::Forbidden);
        }
        let id = descriptor.identities()?.content;
        let output_scope=tx.query_opt("SELECT interval_id,device_id,line_id,peer_digest FROM workflow_contexts WHERE account_id=$1 AND id=$2 FOR SHARE",&[&p.account,&id]).await?.ok_or(ConversationError::Forbidden)?;
        if output_scope.get::<_, Uuid>(0) != s.interval
            || output_scope.get::<_, Uuid>(1) != s.device
            || output_scope.get::<_, Uuid>(2) != s.line
            || output_scope.get::<_, Vec<u8>>(3) != Sha256::digest(s.peer.as_bytes()).as_slice()
        {
            return Err(ConversationError::Forbidden);
        }
        let output = output.ok_or(ConversationError::Forbidden)?;
        if output.account_id() != p.account {
            return Err(ConversationError::Forbidden);
        }
        let descriptor_key = descriptor.key()?;
        if descriptor_key.action_id == source.key()?.action_id {
            return Err(ConversationError::Forbidden);
        }
        let deadline=tx.query_one("SELECT expires_ms FROM original_reply_requests WHERE account_id=$1 AND request_id=$2",&[&p.account,&input.active_request_id.expect("qualifying")]).await?.get::<_,i64>(0).min(proof.expires_at_ms);
        if descriptor.expires_at_ms()? > deadline {
            return Err(ConversationError::Forbidden);
        }
        tx.execute("INSERT INTO original_reply_sources(account_id,action_id,revision,binding_digest,source_grant_id,source_event_id,request_id,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&p.account,&descriptor_key.action_id,&descriptor_key.revision,&descriptor_key.binding_digest.as_slice(),&p.grant,&input.event_id,&input.active_request_id.expect("qualifying"),&deadline]).await?;
        let (result, permit) = workflow_runtime::propose_held_in_transaction(
            &tx,
            output,
            input.request_id,
            descriptor.clone(),
        )
        .await
        .map_err(auth)?;
        action = Some(result.key);
        output_permit = Some(permit);
        tx.execute("UPDATE original_reply_requests SET consumed_turns=consumed_turns+1 WHERE account_id=$1 AND request_id=$2",&[&p.account,&input.active_request_id.expect("qualifying")]).await?;
    }
    let disposition = if action.is_some() {
        "proposal"
    } else {
        "owner_review"
    };
    let action_id = action.map(|k| k.action_id);
    let revision = action.map(|k| k.revision);
    let binding = action.map(|k| k.binding_digest.to_vec());
    tx.execute("INSERT INTO original_reply_consumptions(account_id,consumption_id,consumer_id,event_id,interval_id,request_id,proposed_action_id,revision,binding_digest,disposition,request_digest,created_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",&[&p.account,&input.request_id,&proof.connector_id,&input.event_id,&s.interval,&input.active_request_id,&action_id,&revision,&binding,&disposition,&digest.as_slice(),&activation::now(&tx).await?]).await?;
    audit(&tx, p, Some(input.event_id), "consume").await?;
    locked(&tx, p, accepted).await?;
    if let Some(permit) = output_permit.as_mut() {
        permit.recheck_current().await.map_err(auth)?;
    }
    if action.is_some() {
        source::recheck(&tx, input.descriptor.as_ref().expect("proposal descriptor")).await?;
    }
    let result = ResultData {
        event_id: input.event_id,
        consumption_id: input.request_id,
        disposition: disposition.into(),
        active_request_id: input.active_request_id,
        action,
    };
    drop(output_permit);
    drop(authority);
    tx.commit().await?;
    Ok(result)
}

async fn qualifying_request(
    tx: &Transaction<'_>,
    p: &Principal,
    s: &activation::Statement,
    request: Uuid,
    observed: i64,
) -> Result<Option<Descriptor>, ConversationError> {
    let Some(r)=tx.query_opt("SELECT action_id,revision,binding_digest,message_id,starts_ms,expires_ms,maximum_turns,consumed_turns,stopped_ms FROM original_reply_requests WHERE account_id=$1 AND request_id=$2 AND interval_id=$3 FOR UPDATE",&[&p.account,&request,&s.interval]).await? else{return Ok(None)};
    let owner_until = match source::request_owner_deadline(tx, p.account, request).await {
        Ok(v) => v,
        Err(ConversationError::Forbidden) => return Ok(None),
        Err(e) => return Err(e),
    };
    let key = ActionKey {
        account_id: p.account,
        action_id: r.get(0),
        revision: r.get(1),
        binding_digest: r
            .get::<_, Vec<u8>>(2)
            .try_into()
            .map_err(|_| ConversationError::Forbidden)?,
    };
    let descriptor = match decisions::store::descriptor(tx, key).await {
        Ok(d) => d,
        Err(ConversationError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    let current = decisions::store::head(tx, p.account, key.action_id).await?;
    let issued=tx.query_opt("SELECT floor(extract(epoch FROM j.grant_issued_at)*1000)::bigint FROM workflow_message_links l JOIN dispatch_jobs j ON (j.account_id,j.message_id)=(l.account_id,l.message_id) WHERE l.account_id=$1 AND l.action_id=$2 AND l.revision=$3 AND l.message_id=$4 FOR SHARE OF l,j",&[&p.account,&key.action_id,&key.revision,&r.get::<_,Uuid>(3)]).await?.and_then(|r|r.get::<_,Option<i64>>(0));
    let stopped=tx.query_opt("SELECT stopped_at IS NOT NULL FROM workflow_routines WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&p.account,&descriptor.identities()?.routine]).await?.is_none_or(|r|r.get::<_,bool>(0));
    let now = activation::now(tx).await?;
    let good = current.key == key
        && !stopped
        && r.get::<_, Option<i64>>(8).is_none()
        && r.get::<_, i32>(7) < r.get::<_, i32>(6)
        && now < r.get::<_, i64>(5).min(owner_until)
        && observed >= r.get::<_, i64>(4)
        && decisions::reply::disposition(
            current.phase,
            descriptor.not_before * 1000,
            descriptor.expires_at_ms()?,
            issued,
            observed,
            now,
        ) == ReplyDisposition::Qualifying;
    Ok(good.then_some(descriptor))
}
