// SPDX-License-Identifier: AGPL-3.0-only
//! Current source fencing for every later shared action decision/effect.
use super::*;
use crate::http_owner_conversations::context::decisions::{self, Descriptor};
pub(crate) async fn recheck(
    tx: &Transaction<'_>,
    descriptor: &Descriptor,
) -> Result<(), ConversationError> {
    // Partial historical fixtures/installations cannot contain original sources.
    // Enabled startup separately requires the genuine additive schema.
    if !tx
        .query_one(
            "SELECT to_regclass('original_reply_sources') IS NOT NULL",
            &[],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Ok(());
    }
    let mut current = descriptor.clone();
    let mut visited = Vec::new();
    loop {
        let key = current.key()?;
        if visited.contains(&key) {
            return Err(ConversationError::Forbidden);
        }
        visited.push(key);
        match recheck_one(tx, &current).await? {
            None => {
                // All ancestor locks are now held. Resample the initial source
                // and the complete SQL lineage after any intervening lock waits.
                recheck_one(tx, descriptor).await?;
                return Ok(());
            }
            Some(parent) => {
                if visited.len() > 128 {
                    return Err(ConversationError::Forbidden);
                }
                current = parent;
            }
        }
    }
}
async fn recheck_one(
    tx: &Transaction<'_>,
    descriptor: &Descriptor,
) -> Result<Option<Descriptor>, ConversationError> {
    let key = descriptor.key()?;
    let Some(source)=tx.query_opt("SELECT binding_digest,source_grant_id,source_event_id,request_id,expires_at_ms FROM original_reply_sources WHERE account_id=$1 AND action_id=$2 AND revision=$3 FOR SHARE",&[&key.account_id,&key.action_id,&key.revision]).await? else{
        if tx.query_one("SELECT EXISTS(SELECT 1 FROM original_reply_sources WHERE account_id=$1 AND action_id=$2)",&[&key.account_id,&key.action_id]).await?.get::<_,bool>(0){return Err(ConversationError::Forbidden)}
        return Ok(None)
    };
    if source.get::<_, Vec<u8>>(0) != key.binding_digest {
        return Err(ConversationError::Forbidden);
    }
    let grant: Uuid = source.get(1);
    let event: Uuid = source.get(2);
    let request: Uuid = source.get(3);
    let hash: Vec<u8> = tx
        .query_opt(
            "SELECT credential_hash FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2",
            &[&key.account_id, &grant],
        )
        .await?
        .ok_or(ConversationError::Forbidden)?
        .get(0);
    let p = Principal {
        account: key.account_id,
        grant,
        hash: hash.try_into().map_err(|_| ConversationError::Forbidden)?,
    };
    let version: i64 = tx
        .query_one(
            "SELECT version FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&key.account_id],
        )
        .await?
        .get(0);
    let (proof, s) = locked(tx, &p, version).await?;
    tx.query_opt("SELECT 1 FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE p.account_id=$1 AND p.event_id=$2 AND p.interval_id=$3 AND e.envelope IS NOT NULL FOR SHARE OF p,e",&[&key.account_id,&event,&s.interval]).await?.ok_or(ConversationError::Forbidden)?;
    let r=tx.query_opt("SELECT action_id,revision,binding_digest,expires_ms FROM original_reply_requests WHERE account_id=$1 AND request_id=$2 AND interval_id=$3 AND stopped_ms IS NULL FOR SHARE",&[&key.account_id,&request,&s.interval]).await?.ok_or(ConversationError::Forbidden)?;
    let source_key = decisions::ActionKey {
        account_id: key.account_id,
        action_id: r.get(0),
        revision: r.get(1),
        binding_digest: r
            .get::<_, Vec<u8>>(2)
            .try_into()
            .map_err(|_| ConversationError::Forbidden)?,
    };
    let source_descriptor = decisions::store::descriptor(tx, source_key).await?;
    let head = decisions::store::head(tx, key.account_id, source_key.action_id).await?;
    let stopped=tx.query_opt("SELECT stopped_at IS NOT NULL FROM workflow_routines WHERE account_id=$1 AND id=$2 FOR SHARE",&[&key.account_id,&source_descriptor.identities()?.routine]).await?.is_none_or(|r|r.get::<_,bool>(0));
    let deadline = source
        .get::<_, i64>(4)
        .min(r.get::<_, i64>(3))
        .min(proof.expires_at_ms)
        .min(request_owner_deadline(tx, key.account_id, request).await?);
    if stopped
        || head.key != source_key
        || !matches!(
            head.phase,
            decisions::model::Phase::Dispatching | decisions::model::Phase::Unknown
        )
        || activation::now(tx).await? >= deadline
    {
        return Err(ConversationError::Forbidden);
    }
    // During initial registration the output head does not exist yet; its
    // descriptor is checked by register_core. Later decisions/effects require
    // the exact persisted output head as well as every retained source fence.
    let exists: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM workflow_actions WHERE account_id=$1 AND id=$2)",
            &[&key.account_id, &key.action_id],
        )
        .await?
        .get(0);
    if exists
        && !tx
            .query_one(
                "SELECT original_reply_source_current($1,$2) AND workflow_action_origin_current($1,$2)",
                &[&key.account_id, &key.action_id],
            )
            .await?
            .get::<_, bool>(0)
    {
        return Err(ConversationError::Forbidden);
    }
    if !tx
        .query_one(
            "SELECT workflow_action_origin_current($1,$2) AND original_reply_source_current($1,$2)",
            &[&key.account_id, &source_key.action_id],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Err(ConversationError::Forbidden);
    }
    Ok(Some(source_descriptor))
}

pub(crate) async fn request_owner_deadline(
    tx: &Transaction<'_>,
    account: Uuid,
    request: Uuid,
) -> Result<i64, ConversationError> {
    let r=tx.query_opt("SELECT floor(extract(epoch FROM s.expires_at)*1000)::bigint FROM original_reply_requests r JOIN sessions s ON (s.account_id,s.user_id,s.id)=(r.account_id,r.created_by_user,r.created_session) JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN users u ON u.id=s.user_id WHERE r.account_id=$1 AND r.request_id=$2 AND s.revoked_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled FOR SHARE OF s,m,u",&[&account,&request]).await?.ok_or(ConversationError::Forbidden)?;
    let until: i64 = r.get(0);
    if activation::now(tx).await? >= until {
        return Err(ConversationError::Forbidden);
    }
    Ok(until)
}
