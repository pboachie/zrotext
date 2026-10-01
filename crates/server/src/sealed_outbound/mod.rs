// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant candidate outbound admission. No transport calls this function.
//! Current independent authority and API authorization are both required. A
//! successful queue commit is neither an execution grant nor carrier evidence.

use crate::{
    agent_authority::{Action, Operation, store as agent_store},
    auth::{self, ApiPrincipal, Scope, TokenHasher},
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::{AdmissionError, outbound},
};
use tokio_postgres::{Client, IsolationLevel, Transaction};
use uuid::Uuid;
use zrotext_delivery_store::{
    AcceptOutcome, StoreError,
    sealed::{self, CandidateQueueInput},
};

pub struct WriterContext<'a> {
    pub site_id: &'a str,
    pub deployment_epoch: i64,
    pub billing_enabled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error("invalid candidate request")]
    Invalid,
    #[error("current authorization or writer fence rejected")]
    Forbidden,
    #[error("candidate admission rate limited")]
    RateLimited,
    #[error("candidate authority rejected")]
    Authority(#[from] AdmissionError),
    #[error("candidate verification rejected")]
    Verification(#[from] sealed_envelope::VerifyError),
    #[error("candidate queue rejected")]
    Queue(#[from] StoreError),
    #[error("candidate storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}

async fn bindings(
    tx: &Transaction<'_>,
    principal: &ApiPrincipal,
    writer: &WriterContext<'_>,
    device: Uuid,
    line: Uuid,
    agent_grant: Option<Uuid>,
) -> Result<i64, AdmitError> {
    let row = tx.query_opt(
        "SELECT l.current_binding_generation FROM accounts a \
         JOIN api_keys k ON k.account_id=a.id \
         JOIN memberships m ON (m.account_id,m.user_id)=(k.account_id,k.created_by_user_id) \
         JOIN users u ON u.id=k.created_by_user_id \
         JOIN devices d ON d.account_id=a.id AND d.id=$3 \
         JOIN device_keys dk ON (dk.account_id,dk.device_id)=(d.account_id,d.id) \
         JOIN phone_lines l ON l.account_id=a.id AND l.id=$4 \
         JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)= \
             (a.id,l.id,d.id,l.current_binding_generation) \
         JOIN sites s ON s.site_id=$5 CROSS JOIN deployment_authority p \
         WHERE a.id=$1 AND a.disabled_at IS NULL AND k.id=$2 AND k.revoked_at IS NULL \
           AND (k.expires_at IS NULL OR k.expires_at>clock_timestamp()) \
           AND 'messages:send'=ANY(k.scopes) AND (k.bound_device_id IS NULL OR k.bound_device_id=d.id) \
           AND (($7::uuid IS NULL AND NOT EXISTS(SELECT 1 FROM agent_authority_grants ag WHERE ag.api_key_id=k.id)) \
             OR EXISTS(SELECT 1 FROM agent_authority_grants ag WHERE ag.account_id=a.id AND ag.api_key_id=k.id AND ag.grant_id=$7)) \
           AND u.email_verified_at IS NOT NULL AND d.revoked_at IS NULL AND dk.revoked_at IS NULL \
           AND l.state='active' AND l.approved_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' \
           AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL AND b.activated_at IS NOT NULL \
           AND s.enabled AND NOT s.draining AND p.singleton AND p.epoch=$6 AND NOT pg_is_in_recovery() \
         FOR SHARE OF k,m,u,d,dk,l,b,s,p",
        &[&principal.tenant.account_id(),&principal.key_id,&device,&line,&writer.site_id,&writer.deployment_epoch,&agent_grant],
    ).await?.ok_or(AdmitError::Forbidden)?;
    Ok(row.get(0))
}

async fn fresh(tx: &Transaction<'_>, observed: i64, expires: i64) -> Result<(), AdmitError> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    if now <= 0 || observed <= 0 || now >= expires || observed > now.saturating_add(300_000) {
        return Err(AdmitError::Invalid);
    }
    Ok(())
}

/// Own the complete READ COMMITTED transaction. Queue helpers cannot commit
/// early; clock, credentials, line and manifest are rechecked after all writes.
/// A device may be offline. No inbound session or radio authority is fabricated.
pub async fn admit_candidate02(
    client: &mut Client,
    principal: &ApiPrincipal,
    hasher: &TokenHasher,
    writer: WriterContext<'_>,
    bytes: &[u8],
) -> Result<AcceptOutcome, AdmitError> {
    admit_candidate02_with_limit(client, principal, hasher, writer, bytes, None).await
}

/// The optional bounded declaration is authorization metadata, never plaintext.
/// An exact replay cannot change the originally declared ceiling.
pub async fn admit_candidate02_with_limit(
    client: &mut Client,
    principal: &ApiPrincipal,
    hasher: &TokenHasher,
    writer: WriterContext<'_>,
    bytes: &[u8],
    segment_limit: Option<u8>,
) -> Result<AcceptOutcome, AdmitError> {
    admit_inner(
        client,
        principal,
        hasher,
        writer,
        bytes,
        AdmissionOptions {
            segment_limit,
            agent_action: None,
        },
    )
    .await
}

struct AdmissionOptions {
    segment_limit: Option<u8>,
    agent_action: Option<(Uuid, Uuid)>,
}

/// Only a separately authenticated scoped agent credential can select this
/// path. A tool annotation, ordinary API key or caller approval flag cannot.
pub(crate) async fn admit_agent_candidate02(
    client: &mut Client,
    agent: &auth::agent_grants::AgentPrincipal,
    hasher: &TokenHasher,
    writer: WriterContext<'_>,
    bytes: &[u8],
    action: Uuid,
) -> Result<AcceptOutcome, AdmitError> {
    agent
        .require(Operation::Send)
        .map_err(|_| AdmitError::Forbidden)?;
    let principal = agent.sealed_principal();
    admit_inner(
        client,
        &principal,
        hasher,
        writer,
        bytes,
        AdmissionOptions {
            segment_limit: Some(1),
            agent_action: Some((agent.grant_id, action)),
        },
    )
    .await
}

async fn admit_inner(
    client: &mut Client,
    principal: &ApiPrincipal,
    hasher: &TokenHasher,
    writer: WriterContext<'_>,
    bytes: &[u8],
    options: AdmissionOptions,
) -> Result<AcceptOutcome, AdmitError> {
    let AdmissionOptions {
        segment_limit,
        agent_action,
    } = options;
    if segment_limit.is_some_and(|limit| !(1..=6).contains(&limit)) {
        return Err(AdmitError::Invalid);
    }
    let claims = sealed_envelope::parse(bytes, Profile::Draft02Candidate)
        .map_err(|_| AdmitError::Invalid)?;
    if claims.kind != Kind::Outbound || writer.site_id.is_empty() || writer.deployment_epoch <= 0 {
        return Err(AdmitError::Invalid);
    }
    let device = Uuid::from_slice(claims.device_id).map_err(|_| AdmitError::Invalid)?;
    let line = Uuid::from_slice(claims.line_id).map_err(|_| AdmitError::Invalid)?;
    let message = Uuid::from_slice(claims.message_id).map_err(|_| AdmitError::Invalid)?;
    principal
        .require(Scope::MessagesSend, Some(device))
        .map_err(|_| AdmitError::Forbidden)?;
    if claims.account_id != principal.tenant.account_id().as_bytes() {
        return Err(AdmitError::Forbidden);
    }
    let recipients = claims
        .wraps
        .iter()
        .map(|w| {
            Ok(ExpectedRecipient {
                role: w.role,
                key_id: w.key_id.try_into().map_err(|_| AdmitError::Invalid)?,
            })
        })
        .collect::<Result<Vec<_>, AdmitError>>()?;
    let wanted = EnvelopeAuthority {
        kind: Kind::Outbound,
        account_id: *principal.tenant.account_id().as_bytes(),
        device_id: *device.as_bytes(),
        line_id: *line.as_bytes(),
        message_id: *message.as_bytes(),
        signer_key_id: claims
            .signer_key_id
            .try_into()
            .map_err(|_| AdmitError::Invalid)?,
        peer: claims.peer,
        recipients: &recipients,
    };
    let expires = claims.expires_ms.ok_or(AdmitError::Invalid)? as i64;
    let observed = claims.observed_ms as i64;
    if !auth::abuse_limits::consume(
        client,
        hasher,
        auth::abuse_limits::Limit::OutboundAccept,
        Some(&principal.tenant.account_id().to_string()),
    )
    .await?
    {
        return Err(AdmitError::RateLimited);
    }
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    // Authority always precedes the billing/account locks, matching inbound admission.
    let mut authority = outbound::lock_current(&tx, principal.tenant.account_id()).await?;
    let account =
        sealed::lock_account(&tx, principal.tenant.account_id(), writer.billing_enabled).await?;
    let agent_grant = agent_action.map(|value| value.0);
    let generation = bindings(&tx, principal, &writer, device, line, agent_grant).await?;
    let manifest_generation = authority.generation();
    let context = authority.context(&wanted).await?;
    let verified = sealed_envelope::verify(bytes, &context)?;
    let manifest_version = context.keyset_version as i64;
    let manifest_digest = context.manifest_digest;
    fresh(&tx, observed, expires).await?;
    let agent_reservation = if let Some((grant_id, action_id)) = agent_action {
        let mut grant = agent_store::load(
            &tx,
            principal.tenant.account_id(),
            grant_id,
            principal.key_id,
            Operation::Send,
        )
        .await
        .map_err(map_agent_store)?;
        authority
            .authorize_agent_reader(&grant.connector_key, 0)
            .await?;
        if grant.signer_key != wanted.signer_key_id {
            return Err(AdmitError::Forbidden);
        }
        let not_before_ms: i64 = tx.query_opt(
            "SELECT not_before_ms FROM agent_authority_approvals WHERE account_id=$1 AND action_id=$2 AND grant_id=$3",
            &[&principal.tenant.account_id(),&action_id,&grant_id],
        ).await?.ok_or(AdmitError::Forbidden)?.get(0);
        let peer = std::str::from_utf8(claims.peer).map_err(|_| AdmitError::Invalid)?;
        let action = Action {
            account: principal.tenant.account_id(),
            grant: grant_id,
            action: action_id,
            message,
            line,
            device,
            binding_generation: generation,
            recipient: hasher.agent_recipient_digest(principal.tenant.account_id(), peer),
            unsigned_envelope: *verified.unsigned_digest(),
            not_before_ms,
            expires_ms: expires,
        };
        let reservation = agent_store::check_action(&tx, &mut grant, &action, peer)
            .await
            .map_err(map_agent_store)?;
        Some((action, reservation))
    } else {
        None
    };
    let outcome = account
        .enqueue(&CandidateQueueInput {
            message_id: message,
            device_id: device,
            line_id: line,
            binding_generation: generation,
            manifest_generation,
            manifest_version,
            manifest_digest: &manifest_digest,
            signer_key_id: &wanted.signer_key_id,
            unsigned_digest: verified.unsigned_digest(),
            recipient: std::str::from_utf8(claims.peer).map_err(|_| AdmitError::Invalid)?,
            envelope: bytes,
            expires_at_ms: expires,
            segment_limit,
        })
        .await?;
    if let Some((action, reservation)) = &agent_reservation {
        match (reservation, outcome.created) {
            (agent_store::Reservation::New, true) => agent_store::record(&tx, action)
                .await
                .map_err(map_agent_store)?,
            (agent_store::Reservation::Replay, false) => {}
            _ => return Err(AdmitError::Forbidden),
        }
    }
    if bindings(&tx, principal, &writer, device, line, agent_grant).await? != generation {
        return Err(AdmitError::Forbidden);
    }
    fresh(&tx, observed, expires).await?;
    authority.context(&wanted).await?;
    if let Some((action, _)) = &agent_reservation {
        tx.execute(
            "SELECT require_live_agent_action($1,$2)",
            &[&action.account, &action.message],
        )
        .await?;
    }
    drop(authority);
    tx.commit().await?;
    Ok(outcome)
}

fn map_agent_store(error: agent_store::StoreError) -> AdmitError {
    match error {
        agent_store::StoreError::Denied => AdmitError::Forbidden,
        agent_store::StoreError::Database(error) => AdmitError::Database(error),
    }
}

#[cfg(test)]
pub(crate) mod tests;
