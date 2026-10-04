// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant two-party activation. Library calls only; no HTTP/device route or key creation.
use super::{
    ConversationConsent, ConversationError, SessionPrincipal, fresh_owner, lock_line, lock_owner,
};
use crate::{
    inbound::InboundSession,
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_inbound::line_binding_ready,
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::{
        self,
        outbound::{ManifestSnapshot, lock_current},
    },
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub mod statement;
pub use statement::SelectedReader;
pub use statement::Statement;
mod selected;
pub(crate) use selected::check_readers;
mod capture;
pub use capture::CaptureInterval;
pub(crate) use capture::{check_capture, save_provenance};

#[derive(Clone)]
pub(crate) struct Interval {
    pub statement: Statement,
    pub phase: String,
    pub manifest: Vec<u8>,
    pub accepted_ms: Option<i64>,
}

pub(crate) async fn now(tx: &Transaction<'_>) -> Result<i64, ConversationError> {
    Ok(tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0))
}

pub(crate) async fn origin(tx: &Transaction<'_>, s: &Statement) -> Result<i64, ConversationError> {
    tx.query_opt("SELECT 1 FROM accounts a JOIN sessions s ON s.account_id=a.id JOIN users u ON u.id=s.user_id \
        JOIN memberships m ON (m.account_id,m.user_id)=(a.id,u.id) WHERE a.id=$1 AND s.id=$2 \
        AND a.disabled_at IS NULL AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
        AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL \
        FOR UPDATE OF a FOR SHARE OF s,u,m", &[&s.account,&s.originating_session]).await?.ok_or(ConversationError::Forbidden)?;
    tx.query_opt("SELECT floor(extract(epoch FROM s.expires_at)*1000)::bigint FROM sessions s \
        JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN users u ON u.id=s.user_id \
        WHERE s.account_id=$1 AND s.id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
        AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL",&[&s.account,&s.originating_session])
        .await?.ok_or(ConversationError::Forbidden).map(|r|r.get(0))
}

pub(crate) async fn load(
    tx: &Transaction<'_>,
    account: Uuid,
    id: Uuid,
) -> Result<Interval, ConversationError> {
    let r=tx.query_opt("SELECT statement,phase,manifest,accepted_at_ms,statement_digest,device_id,line_id,binding_generation,initiating_session_id,receipt_id,trust_generation,activation_version,activation_digest,expires_at_ms \
        FROM conversation_intervals WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&account,&id]).await?.ok_or(ConversationError::NotFound)?;
    let b: Option<Vec<u8>> = r.get(0);
    let s = Statement::decode(b.as_deref().ok_or(ConversationError::Forbidden)?)?;
    if s.account != account
        || s.interval != id
        || s.digest()?.as_slice() != r.get::<_, Vec<u8>>(4)
        || s.device != r.get::<_, Uuid>(5)
        || s.line != r.get::<_, Uuid>(6)
        || s.generation != r.get::<_, i64>(7)
        || s.originating_session != r.get::<_, Uuid>(8)
        || s.receipt != r.get::<_, Uuid>(9)
        || s.trust_generation != r.get::<_, i64>(10)
        || s.activation_version != r.get::<_, i64>(11)
        || s.activation_digest.as_slice() != r.get::<_, Vec<u8>>(12)
        || s.expires_ms != r.get::<_, i64>(13)
    {
        return Err(ConversationError::Forbidden);
    }
    Ok(Interval {
        statement: s,
        phase: r.get(1),
        manifest: r.get(2),
        accepted_ms: r.get(3),
    })
}

pub(crate) fn wanted<'a>(
    s: &'a Statement,
    event: Uuid,
    readers: &'a [ExpectedRecipient],
) -> EnvelopeAuthority<'a> {
    EnvelopeAuthority {
        kind: Kind::Inbound,
        account_id: *s.account.as_bytes(),
        device_id: *s.device.as_bytes(),
        line_id: *s.line.as_bytes(),
        message_id: *event.as_bytes(),
        signer_key_id: s.signer,
        peer: s.peer.as_bytes(),
        recipients: readers,
    }
}
pub(crate) fn readers(s: &Statement) -> Vec<ExpectedRecipient> {
    let mut readers = vec![ExpectedRecipient {
        role: 2,
        key_id: s.reader,
    }];
    let mut integrations: Vec<_> = s
        .integration_readers
        .iter()
        .map(|r| ExpectedRecipient {
            role: 3,
            key_id: r.key_id,
        })
        .collect();
    integrations.sort_by_key(|r| r.key_id);
    readers.extend(integrations);
    readers
}

fn verify_phone(
    point: &[u8],
    s: &Statement,
    domain: &[u8],
    signature: &[u8],
) -> Result<(), ConversationError> {
    let signature = Signature::from_slice(signature).map_err(|_| ConversationError::Forbidden)?;
    if signature.to_bytes() != signature.normalize_s().to_bytes() {
        return Err(ConversationError::Forbidden);
    }
    VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| ConversationError::Forbidden)?
        .verify(&s.transcript(domain)?, &signature)
        .map_err(|_| ConversationError::Forbidden)
}

pub async fn begin(
    client: &mut Client,
    owner: &SessionPrincipal,
    consent: &ConversationConsent,
    next_manifest: &[u8],
) -> Result<Statement, ConversationError> {
    begin_selected(client, owner, consent, next_manifest, &[]).await
}

pub async fn begin_selected(
    client: &mut Client,
    owner: &SessionPrincipal,
    consent: &ConversationConsent,
    next_manifest: &[u8],
    integration_readers: &[SelectedReader],
) -> Result<Statement, ConversationError> {
    if !consent.valid() {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, owner.tenant.account_id()).await?;
    let (reader, signer) = authority
        .conversation_keys(consent.device_id, consent.line_id)
        .await?;
    let next = authority.next_snapshot(next_manifest).await?;
    lock_owner(&tx, owner).await?;
    lock_line(
        &tx,
        owner.tenant.account_id(),
        consent.device_id,
        consent.line_id,
        consent.binding_generation,
    )
    .await?;
    // Release expired admission slots, preserving unwithdrawn already-ingested history.
    tx.execute("UPDATE conversation_intervals i SET phase='history',closed_at=clock_timestamp() WHERE account_id=$1 AND phase='active' \
        AND NOT EXISTS(SELECT 1 FROM sessions s JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) \
            JOIN users u ON u.id=s.user_id WHERE s.account_id=i.account_id AND s.id=i.initiating_session_id AND s.revoked_at IS NULL \
            AND s.expires_at>clock_timestamp() AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL)", &[&owner.tenant.account_id()]).await?;
    tx.execute("UPDATE conversation_intervals SET phase='expired',statement=NULL,closed_at=clock_timestamp() \
        WHERE account_id=$1 AND phase IN ('pending','install_pending') AND (expires_at_ms <= floor(extract(epoch FROM clock_timestamp())*1000)::bigint \
        OR NOT EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) WHERE s.account_id=conversation_intervals.account_id AND s.id=initiating_session_id \
            AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL))", &[&owner.tenant.account_id()]).await?;
    let remaining=tx.query("SELECT id,phase FROM conversation_intervals WHERE account_id=$1 AND phase IN ('pending','install_pending','active','history') FOR UPDATE", &[&owner.tenant.account_id()]).await?;
    for row in remaining {
        if row.get::<_, String>(1) != "history" {
            return Err(ConversationError::Conflict);
        }
        let previous = load(&tx, owner.tenant.account_id(), row.get(0))
            .await?
            .statement;
        if previous.peer != consent.peer
            || previous.device != consent.device_id
            || previous.line != consent.line_id
            || previous.generation != consent.binding_generation
            || previous.reader != reader
            || previous.trust_generation != next.generation
        {
            return Err(ConversationError::Conflict);
        }
    }
    let device = tx
        .query_opt(
            "SELECT site_id,instance_id,connection_epoch,deployment_epoch FROM device_sessions \
        WHERE account_id=$1 AND device_id=$2 AND lease_until>clock_timestamp() FOR SHARE",
            &[&owner.tenant.account_id(), &consent.device_id],
        )
        .await?
        .ok_or(ConversationError::Forbidden)?;
    let mut s = Statement {
        account: owner.tenant.account_id(),
        device: consent.device_id,
        line: consent.line_id,
        generation: consent.binding_generation,
        interval: Uuid::new_v4(),
        receipt: Uuid::new_v4(),
        originating_session: owner.session_id,
        nonce: rand::random(),
        expires_ms: now(&tx).await? + 300_000,
        peer: consent.peer.clone(),
        reader,
        integration_readers: integration_readers.to_vec(),
        signer,
        trust_generation: next.generation,
        predecessor_version: next.version - 1,
        predecessor_digest: next.bytes[53..85]
            .try_into()
            .map_err(|_| ConversationError::Invalid)?,
        activation_version: next.version,
        activation_digest: next.digest,
        site: device.get(0),
        instance: device.get(1),
        connection_epoch: device.get(2),
        deployment_epoch: device.get(3),
    };
    s.encode()?;
    check_readers(&tx, &s, &mut authority).await?;
    let r = readers(&s);
    let w = wanted(&s, s.interval, &r);
    let predecessor = authority.snapshot(&w).await?;
    if predecessor.version != s.predecessor_version || predecessor.digest != s.predecessor_digest {
        return Err(ConversationError::Forbidden);
    }
    s.expires_ms = s
        .expires_ms
        .min(origin(&tx, &s).await?)
        .min(authority.admission_deadline(&w).await? as i64);
    let bytes = s.encode()?;
    tx.execute("INSERT INTO conversation_intervals(account_id,id,receipt_id,device_id,line_id,binding_generation,initiating_session_id,statement,statement_digest,manifest,trust_generation,activation_version,activation_digest,expires_at_ms) \
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", &[&s.account,&s.interval,&s.receipt,&s.device,&s.line,&s.generation,&s.originating_session,&bytes,&s.digest()?.as_slice(),&next.bytes,&s.trust_generation,&s.activation_version,&s.activation_digest.as_slice(),&s.expires_ms]).await?;
    fresh_owner(&tx, owner).await?;
    check_readers(&tx, &s, &mut authority).await?;
    let r = readers(&s);
    let w = wanted(&s, s.interval, &r);
    authority.inbound_context(&w).await?;
    drop(authority);
    tx.commit().await?;
    Ok(s)
}

pub(super) async fn device_live(
    tx: &Transaction<'_>,
    session: InboundSession<'_>,
    s: &Statement,
) -> Result<(), ConversationError> {
    if session.account_id != s.account
        || session.device_id != s.device
        || !line_binding_ready(tx, session, s.line, s.generation).await?
    {
        return Err(ConversationError::Forbidden);
    }
    Ok(())
}

fn pending_lease(session: InboundSession<'_>, s: &Statement) -> Result<(), ConversationError> {
    if session.site_id != s.site
        || session.instance_id != s.instance
        || session.connection_epoch != s.connection_epoch
        || session.deployment_epoch != s.deployment_epoch
    {
        return Err(ConversationError::Forbidden);
    }
    Ok(())
}

pub async fn approve(
    client: &mut Client,
    session: InboundSession<'_>,
    bytes: &[u8],
    signature: &[u8],
) -> Result<(), ConversationError> {
    let s = Statement::decode(bytes)?;
    if s.account != session.account_id || s.device != session.device_id {
        return Err(ConversationError::Forbidden);
    }
    let r = readers(&s);
    let w = wanted(&s, s.interval, &r);
    let tx = client.transaction().await?;
    let mut current = lock_current(&tx, session.account_id).await?;
    origin(&tx, &s).await?;
    device_live(&tx, session, &s).await?;
    let row = load(&tx, session.account_id, s.interval).await?;
    selected::check_grants(&tx, &s).await?;
    if row.statement != s || current.generation() != s.trust_generation {
        return Err(ConversationError::Forbidden);
    }
    if row.phase != "active" {
        pending_lease(session, &s)?;
    }
    if row.phase == "pending" {
        if now(&tx).await? >= s.expires_ms {
            return Err(ConversationError::Forbidden);
        }
        let next = current.next_snapshot(&row.manifest).await?;
        if next.version != s.activation_version || next.digest != s.activation_digest {
            return Err(ConversationError::Forbidden);
        }
        drop(current);
        let mut admission =
            sealed_manifest_store::admit(&tx, session, s.line, s.generation, &row.manifest).await?;
        verify_phone(
            admission.context(&w).await?.signer_public_point,
            &s,
            statement::APPROVE_DOMAIN,
            signature,
        )?;
        tx.execute("UPDATE conversation_intervals SET phase='install_pending',accepted_at_ms=$3,approval_signature=$4 WHERE account_id=$1 AND id=$2", &[&s.account,&s.interval,&now(&tx).await?,&signature]).await?;
        origin(&tx, &s).await?;
        if now(&tx).await? >= s.expires_ms {
            return Err(ConversationError::Forbidden);
        }
        admission.context(&w).await?;
        drop(admission);
    } else {
        if !matches!(row.phase.as_str(), "install_pending" | "active")
            || (row.phase == "install_pending" && now(&tx).await? >= s.expires_ms)
        {
            return Err(ConversationError::Forbidden);
        }
        verify_phone(
            current.inbound_context(&w).await?.signer_public_point,
            &s,
            statement::APPROVE_DOMAIN,
            signature,
        )?;
        origin(&tx, &s).await?;
        device_live(&tx, session, &s).await?;
        current.inbound_context(&w).await?;
        drop(current);
    }
    selected::check_grants(&tx, &s).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn installed(
    client: &mut Client,
    session: InboundSession<'_>,
    bytes: &[u8],
    signature: &[u8],
) -> Result<(), ConversationError> {
    let s = Statement::decode(bytes)?;
    if s.account != session.account_id || s.device != session.device_id {
        return Err(ConversationError::Forbidden);
    }
    let r = readers(&s);
    let w = wanted(&s, s.interval, &r);
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, session.account_id).await?;
    origin(&tx, &s).await?;
    device_live(&tx, session, &s).await?;
    let row = load(&tx, session.account_id, s.interval).await?;
    selected::check_grants(&tx, &s).await?;
    if row.statement != s
        || authority.generation() != s.trust_generation
        || !matches!(row.phase.as_str(), "install_pending" | "active")
        || (row.phase == "install_pending" && now(&tx).await? >= s.expires_ms)
    {
        return Err(ConversationError::Forbidden);
    }
    verify_phone(
        authority.inbound_context(&w).await?.signer_public_point,
        &s,
        statement::INSTALL_DOMAIN,
        signature,
    )?;
    if row.phase == "install_pending" {
        pending_lease(session, &s)?;
        tx.execute("UPDATE conversation_intervals SET phase='active',installation_signature=$3 WHERE account_id=$1 AND id=$2", &[&s.account,&s.interval,&signature]).await?;
    }
    origin(&tx, &s).await?;
    device_live(&tx, session, &s).await?;
    authority.inbound_context(&w).await?;
    if row.phase == "install_pending" && now(&tx).await? >= s.expires_ms {
        return Err(ConversationError::Forbidden);
    }
    drop(authority);
    selected::check_grants(&tx, &s).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct ActiveLease {
    pub interval: Uuid,
    pub statement_digest: Vec<u8>,
    pub challenge: Uuid,
    pub valid_for_ms: i64,
}

pub async fn active_lease(
    client: &mut Client,
    session: InboundSession<'_>,
    interval: Uuid,
    challenge: Uuid,
) -> Result<ActiveLease, ConversationError> {
    if challenge.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, session.account_id).await?;
    // Origin account lock before interval, matching begin / approval / capture order.
    let raw:Vec<u8>=tx.query_opt("SELECT statement FROM conversation_intervals WHERE account_id=$1 AND id=$2 AND phase='active'", &[&session.account_id,&interval]).await?.ok_or(ConversationError::Forbidden)?.get(0);
    let s = Statement::decode(&raw)?;
    let origin_until = origin(&tx, &s).await?;
    device_live(&tx, session, &s).await?;
    let row = load(&tx, session.account_id, interval).await?;
    selected::check_grants(&tx, &s).await?;
    if row.phase != "active" || authority.generation() != s.trust_generation {
        return Err(ConversationError::Forbidden);
    }
    let r = readers(&s);
    let w = wanted(&s, interval, &r);
    let until = authority.admission_deadline(&w).await? as i64;
    let phone_until:i64=tx.query_one("SELECT floor(extract(epoch FROM lease_until)*1000)::bigint FROM device_sessions WHERE account_id=$1 AND device_id=$2", &[&s.account,&s.device]).await?.get(0);
    origin(&tx, &s).await?;
    device_live(&tx, session, &s).await?;
    authority.inbound_context(&w).await?;
    let selected_until = selected::deadline(&tx, &s).await?;
    let remaining = until.min(phone_until).min(origin_until).min(selected_until) - now(&tx).await?;
    if remaining <= 0 {
        return Err(ConversationError::Forbidden);
    }
    let result = ActiveLease {
        interval,
        statement_digest: s.digest()?.to_vec(),
        challenge,
        valid_for_ms: remaining.min(60_000),
    };
    drop(authority);
    selected::check_grants(&tx, &s).await?;
    tx.commit().await?;
    Ok(result)
}

/// Local stop is distinct from withdrawal: stop preserves authorized retained history.
pub async fn close(
    client: &mut Client,
    owner: &SessionPrincipal,
    id: Uuid,
    withdraw: bool,
) -> Result<(), ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    let phase: String = tx
        .query_opt(
            "SELECT phase FROM conversation_intervals WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&owner.tenant.account_id(), &id],
        )
        .await?
        .ok_or(ConversationError::NotFound)?
        .get(0);
    let next = if withdraw && !matches!(phase.as_str(), "withdrawn" | "expired") {
        "withdrawn"
    } else if phase == "active" {
        "history"
    } else if matches!(phase.as_str(), "pending" | "install_pending") {
        "expired"
    } else {
        phase.as_str()
    };
    if next != phase {
        tx.execute("UPDATE conversation_intervals SET phase=$3,statement=CASE WHEN $3 IN ('withdrawn','expired') THEN NULL ELSE statement END,closed_at=COALESCE(closed_at,clock_timestamp()) WHERE account_id=$1 AND id=$2", &[&owner.tenant.account_id(),&id,&next]).await?;
    }
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct SelectionProof {
    pub v: u8,
    pub statement: String,
    pub approval_signature: String,
    pub installation_signature: String,
    pub activation_manifest_version: String,
    pub activation_manifest_digest: String,
    pub accepted_at_ms: String,
}
pub async fn read_history(
    client: &mut Client,
    owner: &SessionPrincipal,
    event: Uuid,
) -> Result<Vec<u8>, ConversationError> {
    read_history_with_selection(client, owner, event)
        .await
        .map(|r| r.0)
}
pub async fn read_history_with_selection(
    client: &mut Client,
    owner: &SessionPrincipal,
    event: Uuid,
) -> Result<(Vec<u8>, SelectionProof), ConversationError> {
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, owner.tenant.account_id()).await?;
    lock_owner(&tx, owner).await?;
    let row=tx.query_opt("SELECT p.interval_id,p.trust_generation,p.manifest_version,p.manifest_digest,p.verified_manifest,p.accepted_at_ms,e.envelope \
        FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) \
        WHERE p.account_id=$1 AND p.event_id=$2 AND e.envelope IS NOT NULL FOR SHARE OF p,e", &[&owner.tenant.account_id(),&event]).await?.ok_or(ConversationError::NotFound)?;
    let interval = load(&tx, owner.tenant.account_id(), row.get(0)).await?;
    if !matches!(interval.phase.as_str(), "active" | "history") {
        return Err(ConversationError::Forbidden);
    }
    let s = interval.statement;
    lock_line(&tx, s.account, s.device, s.line, s.generation).await?;
    let bytes: Vec<u8> = row.get(6);
    let claims = sealed_envelope::parse(&bytes, Profile::Draft02Candidate)
        .map_err(|_| ConversationError::Forbidden)?;
    let selected = readers(&s);
    if claims.wraps.len() != selected.len()
        || claims
            .wraps
            .iter()
            .zip(&selected)
            .any(|(w, r)| w.role != r.role || w.key_id != r.key_id)
        || claims.keyset_version < s.activation_version as u64
    {
        return Err(ConversationError::Forbidden);
    }
    let snapshot = ManifestSnapshot {
        generation: row.get(1),
        version: row.get(2),
        digest: row
            .get::<_, Vec<u8>>(3)
            .try_into()
            .map_err(|_| ConversationError::Forbidden)?,
        bytes: row.get(4),
        accepted_ms: row.get(5),
    };
    let r = readers(&s);
    let w = wanted(&s, event, &r);
    authority.verify_history(&w, &snapshot, &bytes).await?;
    fresh_owner(&tx, owner).await?;
    authority.inbound_context(&w).await?;
    use base64::{Engine, engine::general_purpose::STANDARD};
    let signatures=tx.query_one("SELECT approval_signature,installation_signature,accepted_at_ms FROM conversation_intervals WHERE account_id=$1 AND id=$2",&[&s.account,&s.interval]).await?;
    let proof = SelectionProof {
        v: 1,
        statement: STANDARD.encode(s.encode()?),
        approval_signature: STANDARD.encode(
            signatures
                .get::<_, Option<Vec<u8>>>(0)
                .ok_or(ConversationError::Forbidden)?,
        ),
        installation_signature: STANDARD.encode(
            signatures
                .get::<_, Option<Vec<u8>>>(1)
                .ok_or(ConversationError::Forbidden)?,
        ),
        activation_manifest_version: s.activation_version.to_string(),
        activation_manifest_digest: STANDARD.encode(s.activation_digest),
        accepted_at_ms: signatures
            .get::<_, Option<i64>>(2)
            .ok_or(ConversationError::Forbidden)?
            .to_string(),
    };
    fresh_owner(&tx, owner).await?;
    authority.inbound_context(&w).await?;
    drop(authority);
    tx.commit().await?;
    Ok((bytes, proof))
}

#[cfg(all(test, feature = "conversation-simulator-tests"))]
mod simulator;
#[cfg(test)]
pub(crate) mod tests;
