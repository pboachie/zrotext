// SPDX-License-Identifier: AGPL-3.0-only
//! Local-only durable SEALED exchange. No shipped socket or HTTP composition mounts it.
//! Only actual authenticated InboundSession values enter phone transport methods.
//! An activation ACK is reconstructed from committed proof digests after restart;
//! its delivery never renews root registration or authorizes another activation.
use super::{
    LineActivationError, LineActivationProof, LineChallenge, SimObservation,
    activate_registered_line_binding, device_line_statement, digest,
    issue_registered_line_challenge, owner_line_statement, proof_digest, verify_der,
};
use crate::http_owner_conversations::sealed_line_setup::registration;
use crate::{auth::SessionPrincipal, inbound::InboundSession};
use thiserror::Error;
use tokio_postgres::{Client, Row, Transaction};
use uuid::Uuid;
#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("invalid sealed line activation input")]
    InvalidInput,
    #[error("sealed line activation not found")]
    NotFound,
    #[error("sealed line activation refused")]
    Refused,
    #[error("sealed line activation storage failed")]
    Database(#[from] tokio_postgres::Error),
}

impl From<LineActivationError> for ExchangeError {
    fn from(error: LineActivationError) -> Self {
        match error {
            LineActivationError::InvalidInput => Self::InvalidInput,
            LineActivationError::Unavailable => Self::Refused,
            LineActivationError::Database(error) => Self::Database(error),
        }
    }
}

/// Challenge frame content for the device stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingChallenge {
    pub challenge_id: Uuid,
    pub account_id: Uuid,
    pub line_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub nonce: [u8; 32],
    pub expires_at_ms: i64,
}

/// A device declaration as received on the device stream.
pub struct DeviceProof<'a> {
    pub challenge_id: Uuid,
    pub observation: SimObservation,
    pub signature_der: &'a [u8],
}

/// Acknowledgement content: the device installs its binding only when these
/// digests match the proof it prepared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationAck {
    pub challenge_id: Uuid,
    pub account_id: Uuid,
    pub line_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub device_statement_sha256: [u8; 32],
    pub device_signature_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeStatus {
    AwaitingDevice,
    AwaitingOwner,
    Activated,
    Closed,
}

impl ExchangeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::AwaitingDevice => "awaiting_device",
            Self::AwaitingOwner => "awaiting_owner",
            Self::Activated => "activated",
            Self::Closed => "closed",
        }
    }
}

/// Owner view. The statements are present only while the owner can still
/// approve, so the browser signs exactly `owner_statement`.
pub struct ExchangeView {
    pub status: ExchangeStatus,
    pub device_id: Uuid,
    pub generation: i64,
    pub expires_at_ms: i64,
    pub observation: Option<SimObservation>,
    pub device_statement: Option<Vec<u8>>,
    pub device_signature_der: Option<Vec<u8>>,
    pub owner_statement: Option<Vec<u8>>,
    pub phone_acknowledged: bool,
}

pub(crate) async fn persist(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    registration: Uuid,
    c: &LineChallenge,
) -> Result<(), LineActivationError> {
    let r=tx.query_one("SELECT approval_fingerprint,paired_fingerprint FROM sealed_line_key_receipts WHERE account_id=$1 AND registration_id=$2",&[&c.account_id,&registration]).await?;
    tx.execute("INSERT INTO sealed_line_activation_exchanges(registration_id,challenge_id,account_id,line_id,device_id,generation,nonce,initiating_user_id,initiating_session_id,owner_fingerprint,device_fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",&[&registration,&c.id,&c.account_id,&c.line_id,&c.device_id,&c.generation,&c.nonce.as_slice(),&p.user_id,&p.session_id,&r.get::<_,Vec<u8>>(0),&r.get::<_,Vec<u8>>(1)]).await?;
    Ok(())
}

pub async fn open(
    client: &mut Client,
    p: &SessionPrincipal,
    line: Uuid,
    device: Uuid,
    id: Uuid,
) -> Result<(LineChallenge, i64), ExchangeError> {
    // A lost opening response is reconciled from the atomically persisted nonce.
    if let Some(r)=client.query_opt("SELECT e.challenge_id,e.generation,e.nonce,(extract(epoch FROM c.expires_at)*1000)::bigint FROM sealed_line_activation_exchanges e JOIN line_activation_challenges c ON c.id=e.challenge_id WHERE e.account_id=$1 AND e.registration_id=$2 AND e.line_id=$3 AND e.device_id=$4 AND e.initiating_user_id=$5 AND e.initiating_session_id=$6",&[&p.tenant.account_id(),&id,&line,&device,&p.user_id,&p.session_id]).await? {
  let tx=client.transaction().await?;
  registration::lock_scope(&tx,p,id,line,device,Some(r.get(0)),None).await.map_err(|_|ExchangeError::Refused)?;
  let c=LineChallenge{id:r.get(0),account_id:p.tenant.account_id(),line_id:line,device_id:device,generation:r.get(1),nonce:nonce(&r,2).ok_or(ExchangeError::Refused)?};
  tx.commit().await?;return Ok((c,r.get(3)));
 }
    let c = issue_registered_line_challenge(client, p, line, device, id).await?;
    let expiry=client.query_one("SELECT (extract(epoch FROM expires_at)*1000)::bigint FROM line_activation_challenges WHERE id=$1",&[&c.id]).await?.get(0);
    Ok((c, expiry))
}

/// Current phone transport must share the exact lease used for root registration.
pub async fn next_challenge(
    client: &mut Client,
    session: InboundSession<'_>,
) -> Result<Option<PendingChallenge>, ExchangeError> {
    let rows=client.query("SELECT e.registration_id,e.challenge_id,e.line_id,e.generation,e.nonce,(extract(epoch FROM c.expires_at)*1000)::bigint,e.initiating_user_id,e.initiating_session_id FROM sealed_line_activation_exchanges e JOIN line_activation_challenges c ON c.id=e.challenge_id JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(e.account_id,e.line_id,e.device_id,e.generation) WHERE e.account_id=$1 AND e.device_id=$2 AND e.device_signature_der IS NULL AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp() AND b.state='pending' AND b.purpose='sealed' ORDER BY e.created_at LIMIT 4",&[&session.account_id,&session.device_id]).await?;
    for r in rows {
        let tx = client.transaction().await?;
        if registration::lock_phone_scope(
            &tx,
            session.account_id,
            r.get(6),
            r.get(7),
            r.get(0),
            r.get(2),
            session.device_id,
            r.get(1),
            session,
        )
        .await
        .is_err()
        {
            continue;
        }
        let Some(nonce) = nonce(&r, 4) else {
            continue;
        };
        let result = PendingChallenge {
            challenge_id: r.get(1),
            account_id: session.account_id,
            line_id: r.get(2),
            device_id: session.device_id,
            generation: r.get(3),
            nonce,
            expires_at_ms: r.get(5),
        };
        tx.commit().await?;
        return Ok(Some(result));
    }
    Ok(None)
}

pub async fn record_device_proof(
    client: &mut Client,
    session: InboundSession<'_>,
    proof: DeviceProof<'_>,
) -> Result<bool, ExchangeError> {
    let Some(r)=client.query_opt("SELECT registration_id,line_id,generation,nonce,initiating_user_id,initiating_session_id,device_signature_der,android_api_level,active_subscription_count,selected_subscription_id FROM sealed_line_activation_exchanges WHERE account_id=$1 AND device_id=$2 AND challenge_id=$3",&[&session.account_id,&session.device_id,&proof.challenge_id]).await? else {return Ok(false);};
    let tx = client.transaction().await?;
    let statement = match registration::lock_phone_scope(
        &tx,
        session.account_id,
        r.get(4),
        r.get(5),
        r.get(0),
        r.get(1),
        session.device_id,
        proof.challenge_id,
        session,
    )
    .await
    {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let Some((point, fp)) = phone_live(&tx, session).await? else {
        return Ok(false);
    };
    if fp != statement.scope().paired_signing_fingerprint {
        return Ok(false);
    }
    let locked=tx.query_one("SELECT device_signature_der,android_api_level,active_subscription_count,selected_subscription_id,nonce FROM sealed_line_activation_exchanges WHERE challenge_id=$1 FOR UPDATE",&[&proof.challenge_id]).await?;
    if let Some(sig) = locked.get::<_, Option<Vec<u8>>>(0) {
        return Ok(sig == proof.signature_der && observation(&locked, 1) == Some(proof.observation));
    }
    let Some(nonce) = nonce(&locked, 4) else {
        return Ok(false);
    };
    let c = LineChallenge {
        id: proof.challenge_id,
        account_id: session.account_id,
        line_id: r.get(1),
        device_id: session.device_id,
        generation: r.get(2),
        nonce,
    };
    let Ok(bytes) = device_line_statement(&c, proof.observation) else {
        return Ok(false);
    };
    if !verify_der(&point, &bytes, proof.signature_der) {
        return Ok(false);
    }
    tx.execute("UPDATE sealed_line_activation_exchanges SET android_api_level=$2,active_subscription_count=$3,selected_subscription_id=$4,device_signature_der=$5,proof_site_id=$6,proof_instance_id=$7,proof_connection_epoch=$8,proof_deployment_epoch=$9,proof_received_at=clock_timestamp(),device_statement_digest=$10 WHERE challenge_id=$1",&[&proof.challenge_id,&i32::from(proof.observation.android_api_level),&i16::from(proof.observation.active_subscription_count),&proof.observation.selected_subscription_id,&proof.signature_der,&session.site_id,&session.instance_id,&session.connection_epoch,&session.deployment_epoch,&digest(&bytes).as_slice()]).await?;
    registration::fresh_phone(&tx, &statement, session)
        .await
        .map_err(|_| ExchangeError::Refused)?;
    tx.commit().await?;
    Ok(true)
}

const PROOF_COLUMNS: &str = "e.registration_id,e.line_id,e.device_id,e.generation,e.nonce,e.android_api_level,e.active_subscription_count,e.selected_subscription_id,e.device_signature_der,e.proof_site_id,e.proof_instance_id,e.proof_connection_epoch,e.proof_deployment_epoch,e.initiating_user_id,e.initiating_session_id,e.device_statement_digest,e.device_fingerprint,e.ack_sent_at";
fn proof(row: &Row) -> Option<(LineChallenge, SimObservation, Vec<u8>)> {
    Some((
        LineChallenge {
            id: Uuid::nil(),
            account_id: Uuid::nil(),
            line_id: row.get(1),
            device_id: row.get(2),
            generation: row.get(3),
            nonce: nonce(row, 4)?,
        },
        observation(row, 5)?,
        row.get::<_, Option<Vec<u8>>>(8)?,
    ))
}
pub async fn view(
    client: &mut Client,
    p: &SessionPrincipal,
    line: Uuid,
    id: Uuid,
) -> Result<ExchangeView, ExchangeError> {
    let r=client.query_opt(&format!("SELECT {PROOF_COLUMNS},b.activated_at IS NOT NULL AND b.state='active',b.device_confirmation_digest FROM sealed_line_activation_exchanges e JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(e.account_id,e.line_id,e.device_id,e.generation) WHERE e.account_id=$1 AND e.line_id=$2 AND e.challenge_id=$3 AND e.initiating_user_id=$4 AND e.initiating_session_id=$5 AND b.purpose='sealed'"),&[&p.tenant.account_id(),&line,&id,&p.user_id,&p.session_id]).await?.ok_or(ExchangeError::NotFound)?;
    let tx = client.transaction().await?;

    let historical = r.get::<_, bool>(18);
    let scope = if !historical {
        registration::lock_scope(&tx, p, r.get(0), line, r.get(2), Some(id), None)
            .await
            .ok()
    } else {
        None
    };
    if !owner_live(&tx, p.tenant.account_id(), p.user_id, p.session_id).await? {
        return Err(ExchangeError::Refused);
    }
    let mut status = if historical {
        ExchangeStatus::Activated
    } else if scope.is_some() {
        ExchangeStatus::AwaitingDevice
    } else {
        ExchangeStatus::Closed
    };
    let mut bytes = None;
    let mut sig = None;
    let mut owner = None;
    let mut observed = None;
    if let Some((mut c, obs, signature)) = proof(&r) {
        c.id = id;
        c.account_id = p.tenant.account_id();
        observed = Some(obs);
        if scope.is_some() {
            let statement = device_line_statement(&c, obs)?;
            owner = Some(owner_line_statement(&statement, &signature));
            bytes = Some(statement);
            sig = Some(signature);
            status = ExchangeStatus::AwaitingOwner;
        }
    }
    let expiry = client_expiry(&tx, id).await?;
    tx.commit().await?;
    Ok(ExchangeView {
        status,
        device_id: r.get(2),
        generation: r.get(3),
        expires_at_ms: expiry,
        observation: observed,
        device_statement: bytes,
        device_signature_der: sig,
        owner_statement: owner,
        phone_acknowledged: r.get::<_, Option<std::time::SystemTime>>(17).is_some(),
    })
}
async fn client_expiry(tx: &Transaction<'_>, id: Uuid) -> Result<i64, tokio_postgres::Error> {
    Ok(tx.query_one("SELECT (extract(epoch FROM expires_at)*1000)::bigint FROM line_activation_challenges WHERE id=$1",&[&id]).await?.get(0))
}

pub async fn approve(
    client: &mut Client,
    p: &SessionPrincipal,
    line: Uuid,
    id: Uuid,
    owner_signature: &[u8],
) -> Result<(), ExchangeError> {
    let r=client.query_opt(&format!("SELECT {PROOF_COLUMNS} FROM sealed_line_activation_exchanges e WHERE e.account_id=$1 AND e.line_id=$2 AND e.challenge_id=$3 AND e.initiating_user_id=$4 AND e.initiating_session_id=$5"),&[&p.tenant.account_id(),&line,&id,&p.user_id,&p.session_id]).await?.ok_or(ExchangeError::NotFound)?;
    let (mut c, obs, sig) = proof(&r).ok_or(ExchangeError::Refused)?;
    c.id = id;
    c.account_id = p.tenant.account_id();
    let site = r
        .get::<_, Option<String>>(9)
        .ok_or(ExchangeError::Refused)?;
    let instance = r
        .get::<_, Option<String>>(10)
        .ok_or(ExchangeError::Refused)?;
    let socket = InboundSession {
        account_id: c.account_id,
        device_id: c.device_id,
        site_id: &site,
        instance_id: &instance,
        connection_epoch: r.get::<_, Option<i64>>(11).ok_or(ExchangeError::Refused)?,
        deployment_epoch: r.get::<_, Option<i64>>(12).ok_or(ExchangeError::Refused)?,
    };
    activate_registered_line_binding(
        client,
        p,
        socket,
        line,
        c.generation,
        LineActivationProof {
            challenge_id: id,
            nonce: c.nonce,
            observation: obs,
            device_signature_der: &sig,
            owner_signature_der: owner_signature,
        },
        r.get(0),
    )
    .await?;
    Ok(())
}

/// Historical ACK does not require v0 root, live registration or original proof
/// lease. It requires the same paired signer under a current authenticated lease.
pub async fn next_ack(
    client: &mut Client,
    session: InboundSession<'_>,
    sent: &[Uuid],
) -> Result<Option<ActivationAck>, ExchangeError> {
    let tx = client.transaction().await?;
    let Some((_, fp)) = phone_live(&tx, session).await? else {
        return Ok(None);
    };
    let rows=tx.query("SELECT e.challenge_id,e.line_id,e.generation,e.device_statement_digest,e.device_signature_der,b.device_confirmation_digest,e.nonce,e.android_api_level,e.active_subscription_count,e.selected_subscription_id FROM sealed_line_activation_exchanges e JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(e.account_id,e.line_id,e.device_id,e.generation) JOIN phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id) WHERE l.state='active' AND l.current_binding_generation=b.generation AND e.account_id=$1 AND e.device_id=$2 AND e.device_fingerprint=$3 AND e.ack_sent_at IS NULL AND b.activated_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' AND NOT(e.challenge_id=ANY($4)) ORDER BY e.created_at LIMIT 4 FOR SHARE OF b,l",&[&session.account_id,&session.device_id,&fp,&sent]).await?;
    for r in rows {
        let Some(nonce) = nonce(&r, 6) else {
            continue;
        };
        let Some(obs) = observation(&r, 7) else {
            continue;
        };
        let Some(sig) = r.get::<_, Option<Vec<u8>>>(4) else {
            continue;
        };
        let c = LineChallenge {
            id: r.get(0),
            account_id: session.account_id,
            line_id: r.get(1),
            device_id: session.device_id,
            generation: r.get(2),
            nonce,
        };
        let bytes = device_line_statement(&c, obs)?;
        if r.get::<_, Option<Vec<u8>>>(3).as_deref() != Some(digest(&bytes).as_slice())
            || r.get::<_, Option<Vec<u8>>>(5).as_deref()
                != Some(proof_digest(&bytes, &sig).as_slice())
        {
            continue;
        }
        let ack = ActivationAck {
            challenge_id: c.id,
            account_id: c.account_id,
            line_id: c.line_id,
            device_id: c.device_id,
            generation: c.generation,
            device_statement_sha256: digest(&bytes),
            device_signature_sha256: digest(&sig),
        };
        if phone_live(&tx, session).await?.is_none() {
            return Ok(None);
        }
        tx.commit().await?;
        return Ok(Some(ack));
    }
    Ok(None)
}
/// Only the phone's exact ACK receipt clears the pending installation nonce.
pub async fn confirm_ack(
    client: &mut Client,
    session: InboundSession<'_>,
    ack: ActivationAck,
) -> Result<bool, ExchangeError> {
    if ack.account_id != session.account_id || ack.device_id != session.device_id {
        return Ok(false);
    }
    let tx = client.transaction().await?;
    let Some((_, fp)) = phone_live(&tx, session).await? else {
        return Ok(false);
    };
    let Some(r)=tx.query_opt("SELECT e.device_statement_digest,e.device_signature_der,e.ack_sent_at IS NOT NULL FROM sealed_line_activation_exchanges e JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(e.account_id,e.line_id,e.device_id,e.generation) JOIN phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id) WHERE l.state='active' AND l.current_binding_generation=b.generation AND e.account_id=$1 AND e.device_id=$2 AND e.challenge_id=$3 AND e.line_id=$4 AND e.generation=$5 AND e.device_fingerprint=$6 AND b.activated_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' FOR UPDATE OF e FOR SHARE OF b,l",&[&session.account_id,&session.device_id,&ack.challenge_id,&ack.line_id,&ack.generation,&fp]).await? else{return Ok(false);};
    let Some(sig) = r.get::<_, Option<Vec<u8>>>(1) else {
        return Ok(false);
    };
    if r.get::<_, Option<Vec<u8>>>(0).as_deref() != Some(ack.device_statement_sha256.as_slice())
        || digest(&sig) != ack.device_signature_sha256
    {
        return Ok(false);
    }
    if !r.get::<_, bool>(2) {
        tx.execute("UPDATE sealed_line_activation_exchanges SET ack_sent_at=clock_timestamp(),nonce=NULL WHERE challenge_id=$1",&[&ack.challenge_id]).await?;
    }
    if phone_live(&tx, session).await?.is_none() {
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Expired unactivated exchanges lose public nonces. Activated ACK evidence is
/// retained until exact phone confirmation, bounded by first-activation limits.
pub async fn cleanup(client: &Client, limit: i64) -> Result<u64, tokio_postgres::Error> {
    client.execute("UPDATE sealed_line_activation_exchanges e SET nonce=NULL WHERE challenge_id IN (SELECT e.challenge_id FROM sealed_line_activation_exchanges e JOIN line_activation_challenges c ON c.id=e.challenge_id JOIN sealed_line_key_receipts r ON (r.account_id,r.registration_id)=(e.account_id,e.registration_id) WHERE e.nonce IS NOT NULL AND r.activated_ms IS NULL AND (c.expires_at<=clock_timestamp() OR r.retired_ms IS NOT NULL) ORDER BY e.created_at LIMIT $1)",&[&limit.clamp(1,100)]).await
}
#[cfg(test)]
mod tests;

fn observation(row: &Row, api: usize) -> Option<SimObservation> {
    let api_level: Option<i32> = row.get(api);
    let count: Option<i16> = row.get(api + 1);
    let selected: Option<i32> = row.get(api + 2);
    Some(SimObservation {
        android_api_level: u16::try_from(api_level?).ok()?,
        active_subscription_count: u8::try_from(count?).ok()?,
        selected_subscription_id: selected?,
    })
}

fn nonce(row: &Row, index: usize) -> Option<[u8; 32]> {
    row.get::<_, Option<Vec<u8>>>(index)?.try_into().ok()
}

async fn owner_live(
    tx: &Transaction<'_>,
    account: Uuid,
    user: Uuid,
    session: Uuid,
) -> Result<bool, tokio_postgres::Error> {
    Ok(tx
        .query_opt(
            "SELECT 1 FROM accounts a JOIN memberships m ON m.account_id=a.id \
        JOIN users u ON u.id=m.user_id JOIN sessions s ON (s.account_id,s.user_id)=(a.id,u.id) \
        WHERE a.id=$1 AND u.id=$2 AND s.id=$3 AND a.disabled_at IS NULL AND m.role='owner' \
        AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND s.revoked_at IS NULL \
        AND s.expires_at>clock_timestamp() FOR SHARE OF a,m,u,s",
            &[&account, &user, &session],
        )
        .await?
        .is_some())
}

async fn phone_live(
    tx: &Transaction<'_>,
    session: InboundSession<'_>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, tokio_postgres::Error> {
    let row = tx
        .query_opt(
            "SELECT k.signing_key_sec1,k.fingerprint FROM device_sessions s \
        JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) \
        JOIN accounts a ON a.id=d.account_id \
        JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
        JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE \
        WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 \
        AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>clock_timestamp() \
        AND a.disabled_at IS NULL AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND t.enabled AND NOT t.draining \
        AND p.epoch=$6 AND NOT pg_is_in_recovery() FOR SHARE OF a,s,d,k,t,p",
            &[
                &session.account_id,
                &session.device_id,
                &session.site_id,
                &session.instance_id,
                &session.connection_epoch,
                &session.deployment_epoch,
            ],
        )
        .await?;
    Ok(row.and_then(|r| {
        let point: Vec<u8> = r.get(0);
        let fp: Vec<u8> = r.get(1);
        (point.len() == 65
            && point[0] == 4
            && p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).is_ok()
            && digest(&point).as_slice() == fp.as_slice())
        .then_some((point, fp))
    }))
}
