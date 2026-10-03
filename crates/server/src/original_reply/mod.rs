// SPDX-License-Identifier: AGPL-3.0-only
//! Original phone-approved event access. Reader credentials confer no effect permission.
use crate::{
    auth::TokenHasher,
    http_owner_conversations::{ConversationError, activation},
    sealed_manifest_store::outbound::lock_current,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
pub mod consumption;
mod grants;
pub mod http;
pub mod lifecycle;
mod page;
pub(crate) mod source;
pub use grants::{GrantRequest, IssuedCredential, issue, withdraw};

pub(crate) struct Principal {
    account: Uuid,
    grant: Uuid,
    hash: [u8; 32],
}
pub(crate) fn credential_shape(token: &str) -> bool {
    token.strip_prefix("ztr_").is_some_and(|s| {
        s.len() == 43
            && URL_SAFE_NO_PAD
                .decode(s)
                .is_ok_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(b) == s)
    })
}
pub(crate) async fn authenticate(
    client: &Client,
    hasher: &TokenHasher,
    token: &str,
) -> Result<Principal, ConversationError> {
    if !credential_shape(token) {
        return Err(ConversationError::Forbidden);
    }
    let hash = hasher.original_reply_credential_hash(token);
    let r = client
        .query_opt(
            "SELECT account_id,grant_id FROM original_reply_grants WHERE credential_hash=$1",
            &[&hash.as_slice()],
        )
        .await?
        .ok_or(ConversationError::Forbidden)?;
    Ok(Principal {
        account: r.get(0),
        grant: r.get(1),
        hash,
    })
}
#[derive(Serialize)]
pub struct AcceptedManifest {
    pub version: i64,
    pub accepted_at_ms: i64,
    pub manifest_b64: String,
}
#[derive(Serialize)]
pub struct Proof {
    pub account_id: Uuid,
    pub interval_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub connector_id: Uuid,
    pub read_grant_id: Uuid,
    pub reader_id: String,
    pub root_generation: i64,
    pub authority_revision: i64,
    pub expires_at_ms: i64,
    pub observed_at_ms: i64,
    pub current_manifest_version: i64,
    pub current_manifest_digest: String,
    pub manifest_chain: Vec<AcceptedManifest>,
}
#[derive(Serialize)]
pub struct Read {
    pub event_id: Uuid,
    pub accepted_at_ms: i64,
    pub envelope_b64: String,
    pub historical_manifest_version: i64,
    pub statement_b64: String,
    pub approval_signature_b64: String,
    pub installation_signature_b64: String,
    pub activation_manifest_version: i64,
    pub proof: Proof,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Root -> account/session -> grant -> interval -> registry. Final clock samples
// occur after all locks; an immutable read principal is never a cached permit.
async fn locked(
    tx: &Transaction<'_>,
    p: &Principal,
    accepted: i64,
) -> Result<(Proof, activation::Statement), ConversationError> {
    let mut authority = lock_current(tx, p.account).await?;
    let hint=tx.query_opt("SELECT interval_id,created_session FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2 AND credential_hash=$3",&[&p.account,&p.grant,&p.hash.as_slice()]).await?.ok_or(ConversationError::Forbidden)?;
    let interval: Uuid = hint.get(0);
    let origin_session: Uuid = hint.get(1);
    let owner=tx.query_opt("SELECT floor(extract(epoch FROM s.expires_at)*1000)::bigint FROM accounts a JOIN sessions s ON s.account_id=a.id JOIN memberships m ON (m.account_id,m.user_id)=(a.id,s.user_id) JOIN users u ON u.id=s.user_id WHERE a.id=$1 AND s.id=$2 AND a.disabled_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND s.revoked_at IS NULL FOR UPDATE OF a FOR SHARE OF s,m,u",&[&p.account,&origin_session]).await?.ok_or(ConversationError::Forbidden)?;
    let creator_until: i64 = owner.get(0);
    let row=tx.query_opt("SELECT interval_id,connector_id,read_grant_id,reader_key_id,expires_ms,trust_generation,manifest_version,manifest_digest FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2 AND credential_hash=$3 AND revoked_ms IS NULL FOR SHARE",&[&p.account,&p.grant,&p.hash.as_slice()]).await?.ok_or(ConversationError::Forbidden)?;
    let loaded = activation::load(tx, p.account, interval).await?;
    if loaded.phase != "active" {
        return Err(ConversationError::Forbidden);
    }
    let s = loaded.statement;
    let origin_until = activation::origin(tx, &s).await?;
    crate::http_owner_conversations::lock_line(tx, s.account, s.device, s.line, s.generation)
        .await?;
    let connector: Uuid = row.get(1);
    let read_grant: Uuid = row.get(2);
    let key: Vec<u8> = row.get(3);
    if !s.integration_readers.iter().any(|r| {
        r.connector_id == connector && r.read_grant_id == read_grant && r.key_id.as_slice() == key
    }) {
        return Err(ConversationError::Forbidden);
    }
    activation::check_readers(tx, &s, &mut authority).await?;
    let point: Vec<u8> = tx
        .query_one(
            "SELECT key_point FROM connector_registrations WHERE account_id=$1 AND connector_id=$2",
            &[&p.account, &connector],
        )
        .await?
        .get(0);
    let (snapshot, reader, scope) = authority
        .integration_snapshot(s.device, s.line, &point)
        .await?;
    if (
        snapshot.generation,
        snapshot.version,
        snapshot.digest.as_slice(),
    ) != (
        row.get::<_, i64>(5),
        row.get::<_, i64>(6),
        row.get::<_, Vec<u8>>(7).as_slice(),
    ) || reader.as_slice() != key
        || scope & 8 != 8
        || snapshot.generation != s.trust_generation
    {
        return Err(ConversationError::Forbidden);
    }
    if accepted <= 0 || accepted > snapshot.version || snapshot.version - accepted >= 32 {
        return Err(ConversationError::Forbidden);
    }
    let rows=tx.query("SELECT version,accepted_at_ms,manifest FROM original_reply_manifest_history WHERE account_id=$1 AND root_generation=$2 AND version BETWEEN $3 AND $4 ORDER BY version",&[&p.account,&snapshot.generation,&accepted,&snapshot.version]).await?;
    if rows.len() != (snapshot.version - accepted + 1) as usize {
        return Err(ConversationError::Forbidden);
    }
    let mut chain = Vec::with_capacity(rows.len());
    for (i, r) in rows.into_iter().enumerate() {
        let version: i64 = r.get(0);
        if version != accepted + i as i64 {
            return Err(ConversationError::Forbidden);
        }
        chain.push(AcceptedManifest {
            version,
            accepted_at_ms: r.get(1),
            manifest_b64: STANDARD.encode(r.get::<_, Vec<u8>>(2)),
        });
    }
    let reader_until:i64=tx.query_one("SELECT LEAST(r.expires_ms,k.valid_until_ms,g.expires_ms) FROM connector_registrations r JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(r.account_id,r.connector_id,r.key_id) JOIN connector_grants g ON (g.account_id,g.connector_id)=(r.account_id,r.connector_id) WHERE r.account_id=$1 AND r.connector_id=$2 AND g.grant_id=$3",&[&p.account,&connector,&read_grant]).await?.get(0);
    let observed = activation::now(tx).await?;
    let expires = row
        .get::<_, i64>(4)
        .min(creator_until)
        .min(origin_until)
        .min(reader_until);
    if observed >= expires {
        return Err(ConversationError::Forbidden);
    }
    Ok((
        Proof {
            account_id: p.account,
            interval_id: interval,
            device_id: s.device,
            line_id: s.line,
            connector_id: connector,
            read_grant_id: read_grant,
            reader_id: hex(&reader),
            root_generation: snapshot.generation,
            authority_revision: 1,
            expires_at_ms: expires,
            observed_at_ms: observed,
            current_manifest_version: snapshot.version,
            current_manifest_digest: hex(&snapshot.digest),
            manifest_chain: chain,
        },
        s,
    ))
}
pub(crate) async fn current(
    client: &mut Client,
    p: &Principal,
    accepted: i64,
) -> Result<Proof, ConversationError> {
    let tx = client.transaction().await?;
    let (_proof, _) = locked(&tx, p, accepted).await?;
    audit(&tx, p, None, "current").await?;
    let (proof, _) = locked(&tx, p, accepted).await?;
    tx.commit().await?;
    Ok(proof)
}
pub(crate) async fn read(
    client: &mut Client,
    p: &Principal,
    event: Uuid,
    accepted: i64,
) -> Result<Read, ConversationError> {
    if event.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let (proof, s) = locked(&tx, p, accepted).await?;
    let r=tx.query_opt("SELECT e.envelope,p.accepted_at_ms,p.manifest_version,p.trust_generation,i.approval_signature,i.installation_signature,p.manifest_digest,p.verified_manifest,i.accepted_at_ms FROM sealed_inbound_events e JOIN conversation_inbound_provenance p ON (p.account_id,p.event_id)=(e.account_id,e.id) JOIN conversation_intervals i ON (i.account_id,i.id)=(p.account_id,p.interval_id) WHERE e.account_id=$1 AND e.id=$2 AND p.interval_id=$3 AND e.device_id=$4 AND e.line_id=$5 AND e.binding_generation=$6 FOR SHARE OF e,p,i",&[&p.account,&event,&proof.interval_id,&proof.device_id,&proof.line_id,&s.generation]).await?.ok_or(ConversationError::NotFound)?;
    if r.get::<_, i64>(3) != s.trust_generation {
        return Err(ConversationError::Forbidden);
    }
    let bytes: Vec<u8> = r
        .get::<_, Option<Vec<u8>>>(0)
        .ok_or(ConversationError::NotFound)?;
    let readers = activation::readers(&s);
    let wanted = activation::wanted(&s, event, &readers);
    let snapshot = crate::sealed_manifest_store::outbound::ManifestSnapshot {
        generation: r.get(3),
        version: r.get(2),
        digest: r
            .get::<_, Vec<u8>>(6)
            .try_into()
            .map_err(|_| ConversationError::Forbidden)?,
        bytes: r.get(7),
        accepted_ms: r.get(1),
    };
    let mut authority = lock_current(&tx, p.account).await?;
    authority.verify_history(&wanted, &snapshot, &bytes).await?;
    let historical: i64 = r.get(2);
    if historical < accepted || historical > proof.current_manifest_version {
        return Err(ConversationError::Forbidden);
    }
    audit(&tx, p, Some(event), "read").await?;
    let (proof, _) = locked(&tx, p, accepted).await?;
    let result = Read {
        event_id: event,
        accepted_at_ms: r
            .get::<_, Option<i64>>(8)
            .ok_or(ConversationError::Forbidden)?,
        envelope_b64: STANDARD.encode(bytes),
        historical_manifest_version: historical,
        statement_b64: STANDARD.encode(s.encode()?),
        approval_signature_b64: STANDARD.encode(
            r.get::<_, Option<Vec<u8>>>(4)
                .ok_or(ConversationError::Forbidden)?,
        ),
        installation_signature_b64: STANDARD.encode(
            r.get::<_, Option<Vec<u8>>>(5)
                .ok_or(ConversationError::Forbidden)?,
        ),
        activation_manifest_version: s.activation_version,
        proof,
    };
    drop(authority);
    tx.commit().await?;
    Ok(result)
}
async fn audit(
    tx: &Transaction<'_>,
    p: &Principal,
    event: Option<Uuid>,
    operation: &str,
) -> Result<(), ConversationError> {
    tx.execute("INSERT INTO original_reply_access(account_id,id,grant_id,event_id,operation,recorded_ms) VALUES($1,$2,$3,$4,$5,$6)",&[&p.account,&Uuid::new_v4(),&p.grant,&event,&operation,&activation::now(tx).await?]).await?;
    Ok(())
}
