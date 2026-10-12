// SPDX-License-Identifier: AGPL-3.0-only
//! Nonce-free immutable device proof values; pending nonces live in another table.
use super::*;
use tokio_postgres::{GenericClient, Row};

#[derive(Clone)]
pub(in crate::sealed_inbound::line_activation) struct Lease {
    pub site: String,
    pub instance: String,
    pub connection: i64,
    pub deployment: i64,
}
impl Lease {
    pub fn session(&self, account: Uuid, device: Uuid) -> InboundSession<'_> {
        InboundSession {
            account_id: account,
            device_id: device,
            site_id: &self.site,
            instance_id: &self.instance,
            connection_epoch: self.connection,
            deployment_epoch: self.deployment,
        }
    }
    pub fn matches(&self, s: InboundSession<'_>) -> bool {
        self.site == s.site_id
            && self.instance == s.instance_id
            && self.connection == s.connection_epoch
            && self.deployment == s.deployment_epoch
    }
}

#[derive(Clone)]
pub(in crate::sealed_inbound::line_activation) struct Pending {
    pub id: Uuid,
    pub account: Uuid,
    pub line: Uuid,
    pub device: Uuid,
    pub generation: i64,
    pub purpose: Purpose,
    pub opening: Uuid,
    pub user: Uuid,
    pub owner_session: Uuid,
    pub registration: Option<Uuid>,
    pub lease: Lease,
    pub device_fingerprint: [u8; 32],
    pub owner_fingerprint: [u8; 32],
    pub nonce: Option<[u8; 32]>,
    pub expires: i64,
    pub approved: bool,
    pub installed: bool,
    pub retired: bool,
    pub owner_signature_sha256: Option<Vec<u8>>,
}
impl Pending {
    pub fn challenge(&self) -> Result<LineChallenge> {
        Ok(LineChallenge {
            id: self.id,
            account_id: self.account,
            line_id: self.line,
            device_id: self.device,
            generation: self.generation,
            nonce: self.nonce.ok_or(LineActivationError::Unavailable)?,
        })
    }
    pub fn owner_matches(&self, p: &SessionPrincipal) -> bool {
        (self.account, self.user, self.owner_session)
            == (p.tenant.account_id(), p.user_id, p.session_id)
    }
}
fn fixed<const N: usize>(v: Vec<u8>) -> Result<[u8; N]> {
    v.try_into().map_err(|_| LineActivationError::Unavailable)
}
fn pending(r: Row) -> Result<Pending> {
    Ok(Pending {
        id: r.get(0),
        account: r.get(1),
        line: r.get(2),
        device: r.get(3),
        generation: r.get(4),
        purpose: Purpose::parse(&r.get::<_, String>(5))?,
        opening: r.get(6),
        user: r.get(7),
        owner_session: r.get(8),
        registration: r.get(9),
        lease: Lease {
            site: r.get(10),
            instance: r.get(11),
            connection: r.get(12),
            deployment: r.get(13),
        },
        device_fingerprint: fixed(r.get(14))?,
        owner_fingerprint: fixed(r.get(15))?,
        nonce: r.get::<_, Option<Vec<u8>>>(16).map(fixed).transpose()?,
        expires: r.get(17),
        approved: r.get(18),
        installed: r.get(19),
        retired: r.get(20),
        owner_signature_sha256: r.get(21),
    })
}
const SELECT: &str = "SELECT p.challenge_id,p.account_id,p.line_id,p.device_id,p.generation,p.purpose,p.opening_id,p.initiating_user_id,p.initiating_session_id,p.registration_id,p.site_id,p.instance_id,p.connection_epoch,p.deployment_epoch,p.device_fingerprint,p.owner_fingerprint,p.nonce,(extract(epoch FROM p.expires_at)*1000)::bigint,p.approved_at IS NOT NULL,p.installed_at IS NOT NULL,p.retired_at IS NOT NULL,p.owner_signature_sha256 FROM line_activation_v2_pending p JOIN line_activation_challenges c ON c.id=p.challenge_id AND c.protocol_version=2 JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(p.account_id,p.line_id,p.device_id,p.generation) AND b.purpose=p.purpose WHERE p.protocol_version=2 AND p.account_id=$1";
pub(in crate::sealed_inbound::line_activation) async fn load<C: GenericClient + Sync>(
    db: &C,
    account: Uuid,
    id: Uuid,
) -> Result<Pending> {
    let r = db
        .query_opt(&format!("{SELECT} AND p.challenge_id=$2"), &[&account, &id])
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    pending(r)
}
pub(in crate::sealed_inbound::line_activation) async fn opening<C: GenericClient + Sync>(
    db: &C,
    account: Uuid,
    purpose: Purpose,
    id: Uuid,
) -> Result<Option<Pending>> {
    db.query_opt(
        &format!("{SELECT} AND p.purpose=$2 AND p.opening_id=$3"),
        &[&account, &purpose.label(), &id],
    )
    .await?
    .map(pending)
    .transpose()
}
pub(in crate::sealed_inbound::line_activation) async fn candidates<C: GenericClient + Sync>(
    db: &C,
    s: InboundSession<'_>,
    purpose: Purpose,
    sent: &[Uuid],
) -> Result<Vec<Pending>> {
    db.query(&format!("{SELECT} AND p.device_id=$2 AND p.purpose=$3 AND p.installed_at IS NULL AND p.retired_at IS NULL AND NOT(p.challenge_id=ANY($4)) ORDER BY p.created_at LIMIT 4"),&[&s.account_id,&s.device_id,&purpose.label(),&sent])
        .await?.into_iter().map(pending).collect()
}

pub(in crate::sealed_inbound::line_activation) async fn persist(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    c: &LineChallenge,
    opening: Opening,
) -> Result<()> {
    let session = opening.lease.session(c.account_id, c.device_id);
    let (point, fp) = phone_live(tx, session).await?;
    let owner = owner_fingerprint(tx, c.account_id, opening.purpose).await?;
    tx.execute("INSERT INTO line_activation_v2_pending(challenge_id,purpose,opening_id,account_id,line_id,device_id,generation,initiating_user_id,initiating_session_id,registration_id,site_id,instance_id,connection_epoch,deployment_epoch,device_fingerprint,owner_fingerprint,nonce,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,c.expires_at FROM line_activation_challenges c WHERE c.id=$1 AND c.protocol_version=2",&[&c.id,&opening.purpose.label(),&opening.id,&c.account_id,&c.line_id,&c.device_id,&c.generation,&p.user_id,&p.session_id,&opening.registration,&session.site_id,&session.instance_id,&session.connection_epoch,&session.deployment_epoch,&&fp[..],&&owner[..],&&c.nonce[..]]).await?;
    if point.len() != 65 || !super::super::owner_session_active(tx, p).await? {
        return Err(LineActivationError::Unavailable);
    }
    phone_live(tx, session).await?;
    Ok(())
}

/// This value contains no pending nonce or nonce-containing statement.
pub(in crate::sealed_inbound::line_activation) struct StoredProof {
    pub observation: ObservationV2,
    pub der: Vec<u8>,
    pub statement_digest: [u8; 32],
    pub signature_digest: [u8; 32],
    pub confirmation: [u8; 32],
    pub fingerprint: [u8; 32],
    pub lease: Lease,
}
pub(in crate::sealed_inbound::line_activation) async fn proof<C: GenericClient + Sync>(
    db: &C,
    p: &Pending,
) -> Result<Option<StoredProof>> {
    let Some(r)=db.query_opt("SELECT observation,device_signature_der,device_statement_sha256,device_signature_sha256,confirmation_digest,device_fingerprint,proof_site_id,proof_instance_id,proof_connection_epoch,proof_deployment_epoch FROM line_activation_v2_observations WHERE challenge_id=$1 AND account_id=$2 AND line_id=$3 AND device_id=$4 AND generation=$5 AND purpose=$6 AND protocol_version=2",&[&p.id,&p.account,&p.line,&p.device,&p.generation,&p.purpose.label()]).await? else { return Ok(None); };
    let raw: Vec<u8> = r.get(0);
    let der: Vec<u8> = r.get(1);
    let value = StoredProof {
        observation: ObservationV2::decode(&raw).map_err(|_| LineActivationError::Unavailable)?,
        der,
        statement_digest: fixed(r.get(2))?,
        signature_digest: fixed(r.get(3))?,
        confirmation: fixed(r.get(4))?,
        fingerprint: fixed(r.get(5))?,
        lease: Lease {
            site: r.get(6),
            instance: r.get(7),
            connection: r.get(8),
            deployment: r.get(9),
        },
    };
    let signature =
        Signature::from_der(&value.der).map_err(|_| LineActivationError::Unavailable)?;
    if signature.to_der().as_bytes() != value.der
        || digest(&value.der) != value.signature_digest
        || value.fingerprint != p.device_fingerprint
        || !value.lease.matches(p.lease.session(p.account, p.device))
    {
        return Err(LineActivationError::Unavailable);
    }
    Ok(Some(value))
}
pub(in crate::sealed_inbound::line_activation) async fn insert_proof(
    tx: &Transaction<'_>,
    p: &Pending,
    o: ObservationV2,
    der: &[u8],
    bytes: &DeviceStatementBytesV2,
) -> Result<()> {
    let stmt = digest(&bytes.bytes());
    let sig = digest(der);
    let confirmation =
        v2::proof_digest(bytes, der).map_err(|_| LineActivationError::InvalidInput)?;
    tx.execute("INSERT INTO line_activation_v2_observations(challenge_id,purpose,account_id,line_id,device_id,generation,observation,device_signature_der,device_statement_sha256,device_signature_sha256,confirmation_digest,device_fingerprint,proof_site_id,proof_instance_id,proof_connection_epoch,proof_deployment_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(challenge_id) DO NOTHING",&[&p.id,&p.purpose.label(),&p.account,&p.line,&p.device,&p.generation,&&o.encode()[..],&der,&&stmt[..],&&sig[..],&&confirmation[..],&&p.device_fingerprint[..],&p.lease.site,&p.lease.instance,&p.lease.connection,&p.lease.deployment]).await?;
    let actual = proof(tx, p)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    if actual.observation != o
        || actual.der != der
        || actual.statement_digest != stmt
        || actual.confirmation != confirmation
    {
        return Err(LineActivationError::Unavailable);
    }
    Ok(())
}

/// Called inside the shared binding transaction, after its original locks.
pub(in crate::sealed_inbound::line_activation) async fn require_proof(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    s: InboundSession<'_>,
    c: &LineChallenge,
    o: ObservationV2,
    der: &[u8],
    purpose: Purpose,
) -> Result<()> {
    let p = load(tx, c.account_id, c.id).await?;
    if !p.owner_matches(owner)
        || p.purpose != purpose
        || p.line != c.line_id
        || p.device != c.device_id
        || p.generation != c.generation
        || p.nonce != Some(c.nonce)
        || p.approved
        || p.retired
        || !p.lease.matches(s)
    {
        return Err(LineActivationError::Unavailable);
    }
    original_live(tx, &p).await?;
    let actual = proof(tx, &p)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    let statement = v2::device_statement(purpose.codec(), c, &o)
        .map_err(|_| LineActivationError::InvalidInput)?;
    if actual.observation != o
        || actual.der != der
        || actual.statement_digest != digest(&statement.bytes())
        || actual.confirmation
            != v2::proof_digest(&statement, der).map_err(|_| LineActivationError::InvalidInput)?
    {
        return Err(LineActivationError::Unavailable);
    }
    Ok(())
}
pub(in crate::sealed_inbound::line_activation) async fn mark_approved(
    tx: &Transaction<'_>,
    c: &LineChallenge,
    owner_der: &[u8],
) -> Result<()> {
    if tx.execute("UPDATE line_activation_v2_pending SET approved_at=clock_timestamp(),owner_signature_sha256=$2 WHERE challenge_id=$1 AND protocol_version=2 AND approved_at IS NULL AND retired_at IS NULL AND nonce IS NOT NULL",&[&c.id,&&digest(owner_der)[..]]).await?!=1 {
        return Err(LineActivationError::Unavailable);
    }
    Ok(())
}
