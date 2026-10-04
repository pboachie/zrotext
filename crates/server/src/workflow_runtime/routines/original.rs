// SPDX-License-Identifier: AGPL-3.0-only
//! Exact original-event admission, independently authorized from owner context.
use super::*;
use crate::original_reply::{self, Principal};

async fn scope_matches(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    original: &Principal,
    checked: &CheckedScope<'_, '_>,
    accepted: i64,
) -> Result<original_reply::Proof, AuthError> {
    if original.account_id() != input.account_id() {
        return Err(AuthError::Forbidden);
    }
    let (proof, statement) = original_reply::locked(tx, original, accepted)
        .await
        .map_err(error)?;
    if (
        checked.header.account,
        checked.header.device,
        checked.header.line,
        checked.header.interval,
        checked.header.binding_generation,
        checked.header.trust_generation,
    ) != (
        proof.account_id,
        proof.device_id,
        proof.line_id,
        proof.interval_id,
        statement.generation,
        proof.root_generation,
    ) || checked.header.peer_digest
        != <[u8; 32]>::from(Sha256::digest(statement.peer.as_bytes()))
        || hex(&checked.reader) != proof.reader_id
    {
        return Err(AuthError::Forbidden);
    }
    tx.query_opt("SELECT 1 FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$2 AND connector_id=$3 AND reader_key_id=$4 FOR SHARE",
        &[&input.account_id(),&input.grant_id(),&proof.connector_id,&checked.reader.as_slice()])
        .await?.ok_or(AuthError::Forbidden)?;
    Ok(proof)
}

pub(super) async fn configure_check(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    original: Option<&Principal>,
    checked: &CheckedScope<'_, '_>,
    policy: &Policy,
) -> Result<(), AuthError> {
    match (&policy.original_input, original) {
        (None, None) => Ok(()),
        (Some(binding), Some(original)) if binding.grant_id == original.grant_id() => {
            let version:i64 = tx.query_opt("SELECT manifest_version FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2",
                &[&original.account_id(),&original.grant_id()]).await?.ok_or(AuthError::Forbidden)?.get(0);
            scope_matches(tx, input, original, checked, version).await?;
            Ok(())
        }
        _ => Err(AuthError::Forbidden),
    }
}

pub(crate) async fn admit(
    client: &mut Client,
    input: &IntegrationPrincipal,
    original: &Principal,
    v: OriginalAdmit,
) -> Result<Call, AuthError> {
    if v.request_id.is_nil()
        || v.event_id.is_nil()
        || v.input_revision < 1
        || v.accepted_manifest_version < 1
    {
        return Err(AuthError::InvalidInput);
    }
    let tx = begin(client).await?;
    let mut checked =
        scope::lock_scope(&tx, input, v.context_id, Operation::ContextContent).await?;
    let policy = store::policy(&tx, input, v.policy_id).await?;
    if policy
        .original_input
        .as_ref()
        .map(|binding| binding.grant_id)
        != Some(original.grant_id())
        || policy.context_id != v.context_id
        || checked.header.revision != v.input_revision
        || decode(&v.input_source_digest)?.as_slice() != checked.source_digest()
    {
        return Err(AuthError::Forbidden);
    }
    live(&tx, &mut checked, &policy).await?;
    let proof = scope_matches(&tx, input, original, &checked, v.accepted_manifest_version).await?;
    let (_, _, event_digest) =
        original_reply::verified_event(&tx, original, v.event_id, v.accepted_manifest_version)
            .await
            .map_err(error)?;
    if decode(&v.event_envelope_digest)?.as_slice() != event_digest {
        return Err(AuthError::Forbidden);
    }
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM original_reply_sources source JOIN original_reply_consumptions consumption ON (consumption.account_id,consumption.proposed_action_id)=(source.account_id,source.action_id) WHERE source.account_id=$1 AND source.source_event_id=$2 AND consumption.consumer_id=$3)",
        &[&input.account_id(),&v.event_id,&proof.connector_id]).await?.get::<_,bool>(0) {return Err(AuthError::Conflict);}
    let hash = Sha256::digest(
        [
            b"ZT/customer-routine-original-admit/v1\0".as_slice(),
            &serde_json::to_vec(&v).map_err(|_| AuthError::InvalidInput)?,
        ]
        .concat(),
    )
    .to_vec();
    if let Some(row)=tx.query_opt("SELECT call_id,policy_id,original_grant_id,event_id,request_digest FROM workflow_routine_original_sources WHERE account_id=$1 AND (call_id=$2 OR (connector_id=$3 AND event_id=$4)) FOR UPDATE",
        &[&input.account_id(),&v.request_id,&proof.connector_id,&v.event_id]).await? {
        if row.get::<_,Uuid>(0)!=v.request_id || row.get::<_,Uuid>(1)!=policy.policy_id
            || row.get::<_,Uuid>(2)!=original.grant_id() || row.get::<_,Uuid>(3)!=v.event_id
            || row.get::<_,Vec<u8>>(4)!=hash { return Err(AuthError::Conflict); }
    } else {
        if tx.query_one("SELECT EXISTS(SELECT 1 FROM workflow_actions WHERE account_id=$1 AND id=$2) OR EXISTS(SELECT 1 FROM workflow_routines WHERE account_id=$1 AND id=$2) OR EXISTS(SELECT 1 FROM workflow_contexts WHERE account_id=$1 AND id=$2)",
            &[&input.account_id(),&v.request_id]).await?.get::<_,bool>(0) { return Err(AuthError::Conflict); }
        let expires=proof.expires_at_ms.min(policy.expires_ms).min(checked.header.expires_ms);
        tx.execute("INSERT INTO workflow_routine_original_sources(account_id,call_id,policy_id,connector_id,original_grant_id,event_id,accepted_manifest_version,event_digest,request_digest,input_grant_id,context_id,input_revision,input_digest,device_id,line_id,interval_id,binding_generation,root_generation,reader_key_id,peer_digest,contact_id,purpose,expires_ms,policy_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)",
            &[&input.account_id(),&v.request_id,&policy.policy_id,&proof.connector_id,&original.grant_id(),&v.event_id,&v.accepted_manifest_version,&event_digest.as_slice(),&hash,&input.grant_id(),&v.context_id,&v.input_revision,&checked.source_digest().as_slice(),&checked.header.device,&checked.header.line,&checked.header.interval,&checked.header.binding_generation,&checked.header.trust_generation,&checked.reader.as_slice(),&checked.header.peer_digest.as_slice(),&checked.contact(),&checked.purpose(),&expires,&digest(&policy)?]).await?;
    }
    let result = store::admit(&tx, input, &policy, v.request_id, &hash).await?;
    live(&tx, &mut checked, &policy).await?;
    recheck(&tx, input, Some(original), v.request_id, &policy, &checked).await?;
    drop(checked);
    tx.commit().await?;
    Ok(result)
}

pub(super) async fn recheck(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    original: Option<&Principal>,
    call: Uuid,
    policy: &Policy,
    checked: &CheckedScope<'_, '_>,
) -> Result<(), AuthError> {
    match (&policy.original_input, original) {
        (None, None) => Ok(()),
        (Some(binding), Some(original)) if binding.grant_id == original.grant_id() => {
            let row=tx.query_opt("SELECT event_id,accepted_manifest_version,event_digest FROM workflow_routine_original_sources WHERE account_id=$1 AND call_id=$2 AND policy_id=$3 AND original_grant_id=$4 AND input_grant_id=$5 FOR SHARE",
                &[&input.account_id(),&call,&policy.policy_id,&original.grant_id(),&input.grant_id()]).await?.ok_or(AuthError::Forbidden)?;
            let event: Uuid = row.get(0);
            let accepted: i64 = row.get(1);
            scope_matches(tx, input, original, checked, accepted).await?;
            let (_, _, digest) = original_reply::verified_event(tx, original, event, accepted)
                .await
                .map_err(error)?;
            if row.get::<_, Vec<u8>>(2) != digest
                || !tx
                    .query_one(
                        "SELECT workflow_routine_original_current($1,$2)",
                        &[&input.account_id(), &call],
                    )
                    .await?
                    .get::<_, bool>(0)
            {
                return Err(AuthError::Forbidden);
            }
            Ok(())
        }
        _ => Err(AuthError::Forbidden),
    }
}

pub(crate) async fn current(
    client: &mut Client,
    input: &IntegrationPrincipal,
    original: &Principal,
    call: Uuid,
) -> Result<Call, AuthError> {
    let tx = begin(client).await?;
    let context:Uuid=tx.query_opt("SELECT p.context_id FROM workflow_routine_calls c JOIN workflow_routine_policies p ON (p.account_id,p.id)=(c.account_id,c.policy_id) WHERE c.account_id=$1 AND c.id=$2",&[&input.account_id(),&call]).await?.ok_or(AuthError::Forbidden)?.get(0);
    let mut checked = scope::lock_scope(&tx, input, context, Operation::ContextContent).await?;
    let policy = store::call_policy(&tx, input, call).await?;
    if policy.original_input.is_none() {
        return Err(AuthError::Forbidden);
    }
    live(&tx, &mut checked, &policy).await?;
    recheck(&tx, input, Some(original), call, &policy, &checked).await?;
    let result = store::response(&store::load(&tx, input.account_id(), call).await?)?;
    live(&tx, &mut checked, &policy).await?;
    recheck(&tx, input, Some(original), call, &policy, &checked).await?;
    drop(checked);
    tx.commit().await?;
    Ok(result)
}

pub(super) async fn cap_descriptor(
    tx: &Transaction<'_>,
    input: &IntegrationPrincipal,
    policy: &Policy,
    call: Uuid,
    descriptor: &mut Descriptor,
) -> Result<(), AuthError> {
    if policy.original_input.is_some() {
        let expiry:i64=tx.query_opt("SELECT expires_ms FROM workflow_routine_original_sources WHERE account_id=$1 AND call_id=$2 AND policy_id=$3",
            &[&input.account_id(),&call,&policy.policy_id]).await?.ok_or(AuthError::Forbidden)?.get(0);
        descriptor.expires_at = descriptor.expires_at.min(expiry / 1000);
        if activation::now(tx).await.map_err(error)? >= descriptor.expires_at_ms().map_err(error)? {
            return Err(AuthError::Forbidden);
        }
    }
    Ok(())
}
