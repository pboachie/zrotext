// SPDX-License-Identifier: AGPL-3.0-only
//! Transactional policy snapshots and exact action reservations. Callers own
//! the account/manifest fences and transaction; this module never commits.

use super::{Action, Approval, Current, Denial, Grant, Operation, Permissions};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::{
    auth::TokenHasher,
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::outbound,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("agent authority rejected")]
    Denied,
    #[error("agent authority storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}

impl From<Denial> for StoreError {
    fn from(_: Denial) -> Self {
        Self::Denied
    }
}

pub(crate) struct LockedGrant {
    pub policy: Grant,
    pub current: Current,
    pub connector_key: [u8; 32],
    pub signer_key: [u8; 32],
}

/// Load only from a live authenticated credential and independently current
/// owner, connector, key and line records. The grant lock serializes all
/// reservations, revocation and owner takeover. Account locks precede this.
pub(crate) async fn load(
    tx: &Transaction<'_>,
    account: Uuid,
    grant: Uuid,
    key: Uuid,
    operation: Operation,
) -> Result<LockedGrant, StoreError> {
    let row = tx.query_opt(
        "SELECT device_id,line_id,binding_generation,recipient_digest,metadata_allowed,content_allowed,\
         draft_allowed,send_allowed,expires_ms,revoked_ms,taken_over_ms,owner_self_notification,\
         reader_identity,model_provider_identity,model_reads_content,message_limit,turn_limit,\
         messages_reserved,turns_consumed,connector_id,connector_key_id,signer_key_id \
         FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2 AND api_key_id=$3 FOR UPDATE",
        &[&account,&grant,&key],
    ).await?.ok_or(StoreError::Denied)?;
    let policy = Grant {
        account,
        id: grant,
        device: row.get(0),
        line: row.get(1),
        binding_generation: row.get(2),
        recipient: row
            .get::<_, Vec<u8>>(3)
            .try_into()
            .map_err(|_| StoreError::Denied)?,
        permissions: Permissions {
            metadata: row.get(4),
            read_content: row.get(5),
            draft: row.get(6),
            send: row.get(7),
        },
        expires_ms: row.get(8),
        revoked: row.get::<_, Option<i64>>(9).is_some(),
        taken_over: row.get::<_, Option<i64>>(10).is_some(),
        owner_self_notification: row.get(11),
        reader_identity: row.get(12),
        model_provider_identity: row.get(13),
        model_reads_content: row.get(14),
        message_limit: row.get(15),
        turn_limit: row.get(16),
    };
    let connector: Uuid = row.get(19);
    let connector_key: [u8; 32] = row
        .get::<_, Vec<u8>>(20)
        .try_into()
        .map_err(|_| StoreError::Denied)?;
    let signer_key = row
        .get::<_, Vec<u8>>(21)
        .try_into()
        .map_err(|_| StoreError::Denied)?;
    let identity = tx.query_opt(
        "SELECT l.current_binding_generation, floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
         FROM api_keys k \
         JOIN memberships member ON member.account_id=k.account_id AND member.user_id=k.created_by_user_id \
         JOIN users u ON u.id=member.user_id JOIN accounts tenant ON tenant.id=k.account_id \
         JOIN devices d ON d.account_id=k.account_id AND d.id=$4 \
         JOIN phone_lines l ON l.account_id=k.account_id AND l.id=$5 \
         JOIN device_line_bindings b ON b.account_id=l.account_id AND b.line_id=l.id \
             AND b.device_id=d.id AND b.generation=l.current_binding_generation \
         JOIN connector_registrations c ON c.account_id=k.account_id AND c.connector_id=$3 \
         JOIN sealed_manifest_authorities ma ON ma.account_id=c.account_id AND ma.generation=c.manifest_generation \
         JOIN connector_keys ck ON ck.account_id=c.account_id AND ck.connector_id=c.connector_id \
             AND ck.key_id=c.key_id AND ck.key_id=$6 \
         WHERE k.account_id=$1 AND k.id=$2 AND k.revoked_at IS NULL \
             AND (k.expires_at IS NULL OR k.expires_at>clock_timestamp()) AND k.bound_device_id=d.id \
             AND member.role='owner' AND member.revoked_at IS NULL AND u.email_verified_at IS NOT NULL \
             AND tenant.disabled_at IS NULL AND d.revoked_at IS NULL AND l.state='active' \
             AND l.approved_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' \
             AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL \
             AND b.activated_at IS NOT NULL AND c.state='active' \
             AND ma.revoked_at IS NULL AND ma.version>0 \
             AND c.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
             AND ck.retired_ms IS NULL \
             AND ck.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
             AND ck.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
         FOR SHARE OF k,member,u,d,l,b,c,ck",
        &[&account,&key,&connector,&policy.device,&policy.line,&connector_key.as_slice()],
    ).await?.ok_or(StoreError::Denied)?;
    let now_ms = identity.get(1);
    let reader_revoked = if let Some(reader) = policy.reader_identity {
        !tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM connector_registrations c \
             JOIN connector_keys ck ON ck.account_id=c.account_id AND ck.connector_id=c.connector_id AND ck.key_id=c.key_id \
             JOIN connector_grants cg ON cg.account_id=c.account_id AND cg.connector_id=c.connector_id \
             WHERE c.account_id=$1 AND c.connector_id=$2 AND c.state='active' AND c.expires_ms>$4 \
             AND ck.retired_ms IS NULL AND ck.valid_from_ms<=$4 AND ck.valid_until_ms>$4 \
             AND cg.kind='read' AND cg.line_id=$3 AND cg.read_directions & 4=4 \
             AND cardinality(cg.conversation_restriction)=0 AND cg.revoked_ms IS NULL AND cg.expires_ms>$4)",
            &[&account,&reader,&policy.line,&now_ms],
        ).await?.get::<_, bool>(0)
    } else {
        true
    };
    let current = Current {
        account,
        device: policy.device,
        line: policy.line,
        binding_generation: identity.get(0),
        now_ms,
        // Exact recipient suppression is checked against the verified envelope
        // in check_action; metadata reads reveal no routing value.
        suppressed: false,
        reader_revoked,
        messages_reserved: row.get(17),
        turns_consumed: row.get(18),
    };
    policy.authorize(&current, operation)?;
    if operation == Operation::Send {
        let allowed = tx
            .query_opt(
                "SELECT grant_id FROM connector_grants WHERE account_id=$1 AND connector_id=$2 \
             AND line_id=$3 AND kind='send' AND revoked_ms IS NULL AND expires_ms>$4 \
             ORDER BY created_ms DESC,grant_id DESC LIMIT 1 FOR SHARE",
                &[&account, &connector, &policy.line, &now_ms],
            )
            .await?;
        if allowed.is_none() {
            return Err(StoreError::Denied);
        }
    }
    Ok(LockedGrant {
        policy,
        current,
        connector_key,
        signer_key,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reservation {
    New,
    Replay,
}

/// The caller supplies only a signature-verified envelope's exact identity.
/// The recipient digest was computed with the account-keyed routing domain.
pub(crate) async fn check_action(
    tx: &Transaction<'_>,
    grant: &mut LockedGrant,
    action: &Action,
    peer: &str,
) -> Result<Reservation, StoreError> {
    grant.current.now_ms = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    grant.current.suppressed = tx.query_one(
        "SELECT EXISTS(SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2 AND active)",
        &[&action.account,&peer],
    ).await?.get(0);
    grant.policy.authorize(&grant.current, Operation::Send)?;
    let row = tx.query_opt(
        "SELECT action_digest,expires_ms,revoked_ms,message_id,grant_id FROM agent_authority_approvals \
         WHERE account_id=$1 AND action_id=$2 FOR SHARE",
        &[&action.account,&action.action],
    ).await?.ok_or(StoreError::Denied)?;
    let approval = Approval {
        action_digest: row
            .get::<_, Vec<u8>>(0)
            .try_into()
            .map_err(|_| StoreError::Denied)?,
        expires_ms: row.get(1),
        revoked: row.get::<_, Option<i64>>(2).is_some(),
    };
    if row.get::<_, Uuid>(3) != action.message
        || row.get::<_, Uuid>(4) != grant.policy.id
        || approval.revoked
        || approval.expires_ms <= grant.current.now_ms
        || approval.action_digest != action.digest()
    {
        return Err(StoreError::Denied);
    }
    if let Some(record) = tx.query_opt(
        "SELECT grant_id,message_id,action_digest FROM agent_authority_actions WHERE account_id=$1 AND action_id=$2",
        &[&action.account,&action.action],
    ).await? {
        if record.get::<_, Uuid>(0)==action.grant && record.get::<_, Uuid>(1)==action.message
            && record.get::<_, Vec<u8>>(2)==action.digest() {
            return Ok(Reservation::Replay);
        }
        return Err(StoreError::Denied);
    }
    grant
        .policy
        .authorize_new_action(&grant.current, action, Some(&approval))?;
    Ok(Reservation::New)
}

/// Called only after a genuinely new queue insert, while load's grant row
/// lock remains held. A conflicting owner message cannot be adopted here.
pub(crate) async fn record(tx: &Transaction<'_>, action: &Action) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO agent_authority_actions(account_id,action_id,grant_id,message_id,action_digest,reserved_ms) \
         VALUES($1,$2,$3,$4,$5,floor(extract(epoch FROM clock_timestamp())*1000)::bigint)",
        &[&action.account,&action.action,&action.grant,&action.message,&action.digest().as_slice()],
    ).await?;
    let reserved = tx.execute(
        "UPDATE agent_authority_grants SET messages_reserved=messages_reserved+1,turns_consumed=turns_consumed+1 \
         WHERE account_id=$1 AND grant_id=$2 AND revoked_ms IS NULL AND taken_over_ms IS NULL \
         AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
         AND messages_reserved<message_limit AND turns_consumed<turn_limit",
        &[&action.account,&action.grant],
    ).await?;
    if reserved != 1 {
        return Err(StoreError::Denied);
    }
    let marked = tx.execute(
        "UPDATE messages SET agent_grant_id=$3 WHERE account_id=$1 AND id=$2 AND agent_grant_id IS NULL \
         AND transport_mode='sealed_candidate02' AND state='queued' AND request_digest=$4",
        &[&action.account,&action.message,&action.grant,&action.unsigned_envelope.as_slice()],
    ).await?;
    if marked != 1 {
        return Err(StoreError::Denied);
    }
    Ok(())
}

/// Validate the exact sealed action before owner step-up, with the canonical
/// manifest -> account -> identity/grant lock order. This returns proposed
/// identity only; the caller must authenticate the owner and persist approval
/// in this same transaction before committing. It is not an approval token.
pub(crate) async fn validate_owner_action(
    tx: &Transaction<'_>,
    hasher: &TokenHasher,
    account: Uuid,
    grant_id: Uuid,
    action_id: Uuid,
    bytes: &[u8],
    not_before_ms: i64,
) -> Result<Action, StoreError> {
    validate_action(
        tx,
        hasher,
        ActionRequest {
            account,
            grant_id,
            action_id,
            bytes,
            not_before_ms,
            key: None,
            operation: Operation::Send,
        },
    )
    .await
}

pub(crate) async fn validate_agent_draft(
    tx: &Transaction<'_>,
    hasher: &TokenHasher,
    principal: &crate::auth::agent_grants::AgentPrincipal,
    action_id: Uuid,
    bytes: &[u8],
    not_before_ms: i64,
) -> Result<Action, StoreError> {
    principal
        .require(Operation::Draft)
        .map_err(|_| StoreError::Denied)?;
    validate_action(
        tx,
        hasher,
        ActionRequest {
            account: principal.account,
            grant_id: principal.grant_id,
            action_id,
            bytes,
            not_before_ms,
            key: Some(principal.key_id),
            operation: Operation::Draft,
        },
    )
    .await
}

struct ActionRequest<'a> {
    account: Uuid,
    grant_id: Uuid,
    action_id: Uuid,
    bytes: &'a [u8],
    not_before_ms: i64,
    key: Option<Uuid>,
    operation: Operation,
}

async fn validate_action(
    tx: &Transaction<'_>,
    hasher: &TokenHasher,
    request: ActionRequest<'_>,
) -> Result<Action, StoreError> {
    let ActionRequest {
        account,
        grant_id,
        action_id,
        bytes,
        not_before_ms,
        key,
        operation,
    } = request;
    let mut authority = outbound::lock_current(tx, account)
        .await
        .map_err(|_| StoreError::Denied)?;
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
        &[&account],
    )
    .await?
    .ok_or(StoreError::Denied)?;
    let registered_key: Uuid = tx
        .query_opt(
            "SELECT api_key_id FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2",
            &[&account, &grant_id],
        )
        .await?
        .ok_or(StoreError::Denied)?
        .get(0);
    if key.is_some_and(|key| key != registered_key) {
        return Err(StoreError::Denied);
    }
    let grant = load(tx, account, grant_id, registered_key, operation).await?;
    authority
        .authorize_agent_reader(&grant.connector_key, 0)
        .await
        .map_err(|_| StoreError::Denied)?;
    let claims =
        sealed_envelope::parse(bytes, Profile::Draft02Candidate).map_err(|_| StoreError::Denied)?;
    if action_id.is_nil()
        || claims.kind != Kind::Outbound
        || claims.account_id != account.as_bytes()
        || claims.device_id != grant.policy.device.as_bytes()
        || claims.line_id != grant.policy.line.as_bytes()
        || claims.signer_key_id != grant.signer_key
    {
        return Err(StoreError::Denied);
    }
    let recipients = claims
        .wraps
        .iter()
        .map(|wrap| {
            Ok(ExpectedRecipient {
                role: wrap.role,
                key_id: wrap.key_id.try_into().map_err(|_| StoreError::Denied)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let message = Uuid::from_slice(claims.message_id).map_err(|_| StoreError::Denied)?;
    let wanted = EnvelopeAuthority {
        kind: Kind::Outbound,
        account_id: *account.as_bytes(),
        device_id: *grant.policy.device.as_bytes(),
        line_id: *grant.policy.line.as_bytes(),
        message_id: *message.as_bytes(),
        signer_key_id: grant.signer_key,
        peer: claims.peer,
        recipients: &recipients,
    };
    let context = authority
        .context(&wanted)
        .await
        .map_err(|_| StoreError::Denied)?;
    let verified = sealed_envelope::verify(bytes, &context).map_err(|_| StoreError::Denied)?;
    let peer = std::str::from_utf8(claims.peer).map_err(|_| StoreError::Denied)?;
    let recipient = hasher.agent_recipient_digest(account, peer);
    let expires_ms = i64::try_from(claims.expires_ms.ok_or(StoreError::Denied)?)
        .map_err(|_| StoreError::Denied)?;
    if recipient != grant.policy.recipient
        || not_before_ms <= 0
        || not_before_ms >= expires_ms
        || expires_ms > grant.policy.expires_ms
        || expires_ms <= grant.current.now_ms
    {
        return Err(StoreError::Denied);
    }
    let final_grant = load(tx, account, grant_id, registered_key, operation).await?;
    if expires_ms <= final_grant.current.now_ms {
        return Err(StoreError::Denied);
    }
    Ok(Action {
        account,
        grant: grant_id,
        action: action_id,
        message,
        line: grant.policy.line,
        device: grant.policy.device,
        binding_generation: grant.policy.binding_generation,
        recipient,
        unsigned_envelope: *verified.unsigned_digest(),
        not_before_ms,
        expires_ms,
    })
}
