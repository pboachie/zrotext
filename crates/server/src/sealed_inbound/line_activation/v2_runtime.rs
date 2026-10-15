// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated v2 exchange. A complete-set signature remains a declaration;
//! Android's private selected lease owns local currentness and installation.
use super::{
    v2::{self, DeviceStatementBytesV2, ObservationV2, PurposeV2},
    *,
};
use tokio_postgres::{GenericClient, Transaction};
pub(super) mod observation_store;
pub mod schema;
use observation_store::{Lease, Pending};
type Result<T> = std::result::Result<T, LineActivationError>;

/// Stream a JSON object directly into its closed typed fields. This boundary
/// rejects positional arrays without collapsing escaped duplicate field names.
pub(crate) fn decode_object<'de, D, T>(decoder: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a closed line activation object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            map: A,
        ) -> std::result::Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    decoder.deserialize_map(Object(std::marker::PhantomData))
}

macro_rules! object_body {
    ($visibility:vis struct $name:ident { $($field:ident: $ty:ty),+ $(,)? }) => {
        $visibility struct $name { $($field: $ty),+ }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields { $($field: $ty),+ }
                let Fields { $($field),+ } = crate::sealed_inbound::line_activation::v2_runtime::decode_object(decoder)?;
                Ok(Self { $($field),+ })
            }
        }
    };
}
pub(crate) use object_body;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    Sms,
    Sealed,
}
impl Purpose {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Sms => "sms",
            Self::Sealed => "sealed",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "sms" => Ok(Self::Sms),
            "sealed" => Ok(Self::Sealed),
            _ => Err(LineActivationError::Unavailable),
        }
    }
    fn codec(self) -> PurposeV2 {
        match self {
            Self::Sms => PurposeV2::Sms,
            Self::Sealed => PurposeV2::Sealed,
        }
    }
    fn line(self) -> LinePurpose {
        match self {
            Self::Sms => LinePurpose::Sms,
            Self::Sealed => LinePurpose::Sealed,
        }
    }
}

pub(super) struct Opening {
    pub id: Uuid,
    pub purpose: Purpose,
    pub registration: Option<Uuid>,
    pub lease: Lease,
}
pub(super) struct CompleteProof<'a> {
    pub challenge_id: Uuid,
    pub nonce: [u8; 32],
    pub observation: ObservationV2,
    pub device_signature_der: &'a [u8],
    pub owner_signature_der: &'a [u8],
}
pub(crate) struct Challenge {
    pub tuple: LineChallenge,
    pub expires_at_ms: i64,
}
#[derive(Clone, Copy)]
pub(crate) struct Ack {
    pub challenge_id: Uuid,
    pub account_id: Uuid,
    pub line_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub device_statement_sha256: [u8; 32],
    pub device_signature_sha256: [u8; 32],
}
pub(crate) struct View {
    pub challenge_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub expires_at_ms: i64,
    pub status: &'static str,
    pub phone_acknowledged: bool,
    pub observation: Option<Vec<u8>>,
    pub device_statement: Option<Vec<u8>>,
    pub device_signature_der: Option<Vec<u8>>,
    pub owner_statement: Option<Vec<u8>>,
}

pub(super) async fn phone_live<C: GenericClient + Sync>(
    tx: &C,
    s: InboundSession<'_>,
) -> Result<(Vec<u8>, [u8; 32])> {
    const LIVE: &str = "SELECT k.signing_key_sec1,k.fingerprint FROM device_sessions s JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=s.account_id JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.line_activation_version=2 AND s.lease_until>clock_timestamp() AND a.disabled_at IS NULL AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery() FOR SHARE OF s,d,k,a,t,p";
    let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &s.account_id,
        &s.device_id,
        &s.site_id,
        &s.instance_id,
        &s.connection_epoch,
        &s.deployment_epoch,
    ];
    tx.query_opt(LIVE, parameters)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    // All admission rows are now share-locked. Re-evaluate volatile expiry
    // after any acquisition wait rather than using its entry-time result.
    let r = tx
        .query_opt(LIVE, parameters)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    let point: Vec<u8> = r.get(0);
    let fp: Vec<u8> = r.get(1);
    if point.len() != 65
        || digest(&point).as_slice() != fp
        || VerifyingKey::from_sec1_bytes(&point).is_err()
    {
        return Err(LineActivationError::Unavailable);
    }
    Ok((
        point,
        fp.try_into()
            .map_err(|_| LineActivationError::Unavailable)?,
    ))
}
async fn owner_fingerprint<C: GenericClient + Sync>(
    tx: &C,
    account: Uuid,
    purpose: Purpose,
) -> Result<[u8; 32]> {
    let query = match purpose {
        Purpose::Sms => {
            "SELECT signing_key_sec1,fingerprint FROM sms_line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE"
        }
        Purpose::Sealed => {
            "SELECT signing_key_sec1,fingerprint FROM line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE"
        }
    };
    let row = tx
        .query_opt(query, &[&account])
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    let point: Vec<u8> = row.get(0);
    let fp: Vec<u8> = row.get(1);
    if point.len() != 65
        || digest(&point).as_slice() != fp
        || VerifyingKey::from_sec1_bytes(&point).is_err()
    {
        return Err(LineActivationError::Unavailable);
    }
    fp.try_into().map_err(|_| LineActivationError::Unavailable)
}
async fn owner_live<C: GenericClient + Sync>(tx: &C, p: &Pending) -> Result<()> {
    const LIVE: &str = "SELECT 1 FROM accounts a JOIN memberships m ON m.account_id=a.id JOIN users u ON u.id=m.user_id JOIN sessions o ON (o.account_id,o.user_id)=(a.id,u.id) WHERE a.id=$1 AND u.id=$2 AND o.id=$3 AND a.disabled_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND o.revoked_at IS NULL AND o.expires_at>clock_timestamp() FOR SHARE OF a,m,u,o";
    let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] =
        &[&p.account, &p.user, &p.owner_session];
    tx.query_opt(LIVE, parameters)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    tx.query_opt(LIVE, parameters)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    Ok(())
}
pub(super) async fn original_live<C: GenericClient + Sync>(tx: &C, p: &Pending) -> Result<()> {
    owner_live(tx, p).await?;
    let (_, fp) = phone_live(tx, p.lease.session(p.account, p.device)).await?;
    if fp != p.device_fingerprint
        || owner_fingerprint(tx, p.account, p.purpose).await? != p.owner_fingerprint
    {
        return Err(LineActivationError::Unavailable);
    }
    // Key and phone locks can outlive the earlier owner's natural expiry.
    // All authority rows are held now; refresh both clocks before the challenge.
    owner_live(tx, p).await?;
    phone_live(tx, p.lease.session(p.account, p.device)).await?;
    if tx.query_opt("SELECT 1 FROM line_activation_challenges WHERE id=$1 AND protocol_version=2 AND expires_at>clock_timestamp()",&[&p.id]).await?.is_none() {return Err(LineActivationError::Unavailable);}
    Ok(())
}
async fn unapproved(
    tx: &Transaction<'_>,
    p: &Pending,
) -> Result<Option<zrotext_root_material::line_key_registration::Statement>> {
    let scope = if let Some(id) = p.registration {
        Some(
            setup_registration::lock_phone_scope(
                tx,
                p.user,
                p.owner_session,
                id,
                p.line,
                p.id,
                p.lease.session(p.account, p.device),
            )
            .await
            .map_err(scope_error)?,
        )
    } else {
        None
    };
    original_live(tx, p).await?;
    if p.approved || p.retired || p.nonce.is_none() || tx.query_opt("SELECT 1 FROM line_activation_challenges c JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(c.account_id,c.line_id,c.device_id,c.generation) JOIN phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id) WHERE c.id=$1 AND c.protocol_version=2 AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp() AND c.nonce_digest=$2 AND b.purpose=$3 AND b.state='pending' AND l.state<>'revoked' AND l.last_issued_generation=b.generation FOR UPDATE OF c,b,l",&[&p.id,&&digest(&p.nonce.ok_or(LineActivationError::Unavailable)?)[..],&p.purpose.label()]).await?.is_none() {return Err(LineActivationError::Unavailable);}
    // The unchanged binding may have blocked beyond a challenge, owner or
    // device-lease deadline. Lock acquisition is not fresh authorization.
    original_live(tx, p).await?;
    if let Some(statement) = &scope {
        // Registration also binds the owner's activity/MFA window, which is
        // independent of the challenge's capped absolute expiry.
        setup_registration::fresh_phone(tx, statement, p.lease.session(p.account, p.device))
            .await
            .map_err(scope_error)?;
    }
    Ok(scope)
}

/// Obtains admission from the actual stored authenticated lease, never JSON.
pub(super) async fn prepare_opening(
    tx: &Transaction<'_>,
    principal: &SessionPrincipal,
    line: Uuid,
    device: Uuid,
    purpose: Purpose,
    id: Uuid,
    registration: Option<Uuid>,
) -> Result<Opening> {
    if id.is_nil()
        || (purpose == Purpose::Sealed) != registration.is_some()
        || !owner_session_active(tx, principal).await?
    {
        return Err(LineActivationError::Unavailable);
    }
    let r=tx.query_opt("SELECT site_id,instance_id,connection_epoch,deployment_epoch FROM device_sessions WHERE account_id=$1 AND device_id=$2 AND line_activation_version=2 AND lease_until>clock_timestamp() FOR SHARE",&[&principal.tenant.account_id(),&device]).await?.ok_or(LineActivationError::Unavailable)?;
    let lease = Lease {
        site: r.get(0),
        instance: r.get(1),
        connection: r.get(2),
        deployment: r.get(3),
    };
    phone_live(tx, lease.session(principal.tenant.account_id(), device)).await?;
    if line.is_nil() || device.is_nil() {
        return Err(LineActivationError::InvalidInput);
    }
    Ok(Opening {
        id,
        purpose,
        registration,
        lease,
    })
}
pub(super) async fn retry_opening(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    line: Uuid,
    device: Uuid,
    purpose: Purpose,
    id: Uuid,
    registration: Option<Uuid>,
) -> Result<Option<LineChallenge>> {
    let Some(existing) = observation_store::opening(tx, p.tenant.account_id(), purpose, id).await?
    else {
        return Ok(None);
    };
    if !existing.owner_matches(p)
        || existing.line != line
        || existing.device != device
        || existing.registration != registration
    {
        return Err(LineActivationError::Unavailable);
    }
    unapproved(tx, &existing).await?;
    Ok(Some(existing.challenge()?))
}
pub(crate) async fn open(
    client: &mut Client,
    p: &SessionPrincipal,
    line: Uuid,
    device: Uuid,
    purpose: Purpose,
    id: Uuid,
    registration: Option<Uuid>,
) -> Result<Challenge> {
    let tuple = super::issue_challenge_selected(
        client,
        p,
        line,
        device,
        CHALLENGE_LIFETIME_SECS,
        purpose.line(),
        registration,
        Some((purpose, id)),
    )
    .await?;
    let pending = observation_store::load(client, tuple.account_id, tuple.id).await?;
    if pending.line != line
        || pending.device != device
        || pending.purpose != purpose
        || pending.opening != id
        || !pending.owner_matches(p)
    {
        return Err(LineActivationError::Unavailable);
    }
    crate::device_socket::wake_sms_line_activation();
    Ok(Challenge {
        tuple,
        expires_at_ms: pending.expires,
    })
}

pub(crate) async fn record_device_proof(
    client: &mut Client,
    s: InboundSession<'_>,
    purpose: Purpose,
    id: Uuid,
    observation: &[u8],
    der: &[u8],
) -> Result<bool> {
    match record(client, s, purpose, id, observation, der).await {
        Err(LineActivationError::Unavailable | LineActivationError::InvalidInput) => Ok(false),
        other => other,
    }
}
async fn record(
    client: &mut Client,
    s: InboundSession<'_>,
    purpose: Purpose,
    id: Uuid,
    raw: &[u8],
    der: &[u8],
) -> Result<bool> {
    let observation = ObservationV2::decode(raw).map_err(|_| LineActivationError::InvalidInput)?;
    let tx = client.transaction().await?;
    let p = observation_store::load(&tx, s.account_id, id).await?;
    if p.purpose != purpose || p.device != s.device_id || !p.lease.matches(s) {
        return Err(LineActivationError::Unavailable);
    }
    let scope = unapproved(&tx, &p).await?;
    let (point, fp) = phone_live(&tx, s).await?;
    let statement = v2::device_statement(purpose.codec(), &p.challenge()?, &observation)
        .map_err(|_| LineActivationError::InvalidInput)?;
    if fp != p.device_fingerprint || !v2::verify_device_signature(&point, &statement, der) {
        return Err(LineActivationError::Unavailable);
    }
    observation_store::insert_proof(&tx, &p, observation, der, &statement).await?;
    original_live(&tx, &p).await?;
    if let Some(scope) = scope {
        setup_registration::fresh_phone(&tx, &scope, s)
            .await
            .map_err(scope_error)?;
    }
    tx.commit().await?;
    Ok(true)
}

pub(crate) async fn view(
    client: &mut Client,
    owner: &SessionPrincipal,
    line: Uuid,
    id: Uuid,
    purpose: Purpose,
) -> Result<View> {
    let tx = client.transaction().await?;
    let p = observation_store::load(&tx, owner.tenant.account_id(), id).await?;
    if !p.owner_matches(owner) || p.line != line || p.purpose != purpose {
        return Err(LineActivationError::Unavailable);
    }
    let proof = observation_store::proof(&tx, &p).await?;
    let mut result = View {
        challenge_id: id,
        device_id: p.device,
        generation: p.generation,
        expires_at_ms: p.expires,
        status: "awaiting_device",
        phone_acknowledged: p.installed,
        observation: None,
        device_statement: None,
        device_signature_der: None,
        owner_statement: None,
    };
    if p.approved {
        owner_live(&tx, &p).await?;
        let lease = current_lease(&tx, p.account, p.device).await?;
        active(&tx, &p, lease.session(p.account, p.device)).await?;
        owner_live(&tx, &p).await?;
        result.status = "activated";
    } else {
        unapproved(&tx, &p).await?;
        if let Some(proof) = &proof {
            let statement =
                v2::device_statement(purpose.codec(), &p.challenge()?, &proof.observation)
                    .map_err(|_| LineActivationError::Unavailable)?;
            if digest(&statement.bytes()) != proof.statement_digest {
                return Err(LineActivationError::Unavailable);
            }
            result.device_statement = Some(statement.bytes());
            result.owner_statement = Some(
                v2::owner_statement(&statement, &proof.der)
                    .map_err(|_| LineActivationError::Unavailable)?
                    .bytes(),
            );
            result.status = "awaiting_owner";
        }
        original_live(&tx, &p).await?;
    }
    if let Some(proof) = proof {
        result.observation = Some(proof.observation.encode().to_vec());
        result.device_signature_der = Some(proof.der);
    }
    tx.commit().await?;
    Ok(result)
}
pub(crate) async fn approve(
    client: &mut Client,
    owner: &SessionPrincipal,
    line: Uuid,
    id: Uuid,
    purpose: Purpose,
    der: &[u8],
) -> Result<()> {
    let p = observation_store::load(client, owner.tenant.account_id(), id).await?;
    if !p.owner_matches(owner) || p.line != line || p.purpose != purpose {
        return Err(LineActivationError::Unavailable);
    }
    if p.approved {
        let tx = client.transaction().await?;
        let p = observation_store::load(&tx, p.account, id).await?;
        owner_live(&tx, &p).await?;
        let lease = current_lease(&tx, p.account, p.device).await?;
        active(&tx, &p, lease.session(p.account, p.device)).await?;
        if p.owner_signature_sha256.as_deref() != Some(digest(der).as_slice()) {
            return Err(LineActivationError::Unavailable);
        }
        owner_live(&tx, &p).await?;
        tx.commit().await?;
        return Ok(());
    }
    let proof = observation_store::proof(client, &p)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    let c = p.challenge()?;
    super::activate_selected(
        client,
        owner,
        p.lease.session(p.account, p.device),
        line,
        p.generation,
        SelectedActivationProof::complete(CompleteProof {
            challenge_id: id,
            nonce: c.nonce,
            observation: proof.observation,
            device_signature_der: &proof.der,
            owner_signature_der: der,
        }),
        ActivationScope {
            purpose: purpose.line(),
            registration: p.registration,
        },
    )
    .await
}

async fn current_lease<C: GenericClient + Sync>(
    tx: &C,
    account: Uuid,
    device: Uuid,
) -> Result<Lease> {
    let r=tx.query_opt("SELECT site_id,instance_id,connection_epoch,deployment_epoch FROM device_sessions WHERE account_id=$1 AND device_id=$2 AND line_activation_version=2 FOR SHARE",&[&account,&device]).await?.ok_or(LineActivationError::Unavailable)?;
    let lease = Lease {
        site: r.get(0),
        instance: r.get(1),
        connection: r.get(2),
        deployment: r.get(3),
    };
    phone_live(tx, lease.session(account, device)).await?;
    Ok(lease)
}
async fn active<C: GenericClient + Sync>(
    tx: &C,
    p: &Pending,
    s: InboundSession<'_>,
) -> Result<Ack> {
    let (_, fp) = phone_live(tx, s).await?;
    if p.account != s.account_id
        || p.device != s.device_id
        || fp != p.device_fingerprint
        || !p.approved
        || p.retired
        || owner_fingerprint(tx, p.account, p.purpose).await? != p.owner_fingerprint
    {
        return Err(LineActivationError::Unavailable);
    }
    let proof = observation_store::proof(tx, p)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    const ACTIVE: &str = "SELECT b.device_confirmation_digest FROM device_line_bindings b JOIN phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id) JOIN line_activation_challenges c ON (c.account_id,c.line_id,c.device_id,c.generation)=(b.account_id,b.line_id,b.device_id,b.generation) WHERE c.id=$1 AND c.protocol_version=2 AND c.consumed_at IS NOT NULL AND b.account_id=$2 AND b.line_id=$3 AND b.device_id=$4 AND b.generation=$5 AND b.purpose=$6 AND b.state='active' AND b.activated_at IS NOT NULL AND b.owner_approval_digest IS NOT NULL AND l.state='active' AND l.current_binding_generation=b.generation AND ($6='sealed' OR b.activated_at>=clock_timestamp()-interval '900 seconds') FOR SHARE OF b,l,c";
    let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &p.id,
        &p.account,
        &p.line,
        &p.device,
        &p.generation,
        &p.purpose.label(),
    ];
    tx.query_opt(ACTIVE, parameters)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    if let Some(reg) = p.registration
        && tx
            .query_opt(
                "SELECT 1 FROM sealed_line_key_receipts WHERE account_id=$1 AND registration_id=$2 AND assigned_challenge_id=$3 AND activated_ms IS NOT NULL AND retired_ms IS NULL AND paired_fingerprint=$4 FOR SHARE",
                &[&p.account, &reg, &p.id, &&fp[..]],
            )
            .await?
            .is_none()
    {
        return Err(LineActivationError::Unavailable);
    }
    phone_live(tx, s).await?;
    // Re-evaluate the SMS receipt lifetime after all binding/receipt waits.
    // This exact query uses the rows already locked above, without mutation.
    let row = tx
        .query_opt(ACTIVE, parameters)
        .await?
        .ok_or(LineActivationError::Unavailable)?;
    let confirmation: Option<Vec<u8>> = row.get(0);
    if confirmation.as_deref() != Some(proof.confirmation.as_slice()) {
        return Err(LineActivationError::Unavailable);
    }
    Ok(Ack {
        challenge_id: p.id,
        account_id: p.account,
        line_id: p.line,
        device_id: p.device,
        generation: p.generation,
        device_statement_sha256: proof.statement_digest,
        device_signature_sha256: proof.signature_digest,
    })
}
pub(crate) async fn next_challenge(
    client: &mut Client,
    s: InboundSession<'_>,
    purpose: Purpose,
) -> Result<Option<Challenge>> {
    let tx = client.transaction().await?;
    phone_live(&tx, s).await?;
    for p in observation_store::candidates(&tx, s, purpose, &[]).await? {
        if p.approved || !p.lease.matches(s) {
            continue;
        }
        match unapproved(&tx, &p).await {
            Err(LineActivationError::Unavailable | LineActivationError::InvalidInput) => continue,
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if observation_store::proof(&tx, &p).await?.is_some() {
            continue;
        }
        let challenge = Challenge {
            tuple: p.challenge()?,
            expires_at_ms: p.expires,
        };
        original_live(&tx, &p).await?;
        tx.commit().await?;
        return Ok(Some(challenge));
    }
    tx.commit().await?;
    Ok(None)
}
pub(crate) async fn next_ack(
    client: &mut Client,
    s: InboundSession<'_>,
    purpose: Purpose,
    sent: &[Uuid],
) -> Result<Option<Ack>> {
    let tx = client.transaction().await?;
    phone_live(&tx, s).await?;
    for p in observation_store::candidates(&tx, s, purpose, sent).await? {
        if !p.approved {
            continue;
        }
        match active(&tx, &p, s).await {
            Err(LineActivationError::Unavailable | LineActivationError::InvalidInput) => continue,
            Err(e) => return Err(e),
            Ok(ack) => {
                tx.commit().await?;
                return Ok(Some(ack));
            }
        }
    }
    tx.commit().await?;
    Ok(None)
}

/// The accepted terminal receipt and nonce removal commit before socket ACK.
pub(crate) async fn confirm_sealed_install(
    client: &mut Client,
    s: InboundSession<'_>,
    ack: Ack,
) -> Result<bool> {
    match confirm(client, s, ack).await {
        Err(LineActivationError::Unavailable | LineActivationError::InvalidInput) => Ok(false),
        other => other,
    }
}
async fn confirm(client: &mut Client, s: InboundSession<'_>, ack: Ack) -> Result<bool> {
    if ack.account_id != s.account_id || ack.device_id != s.device_id {
        return Ok(false);
    }
    let tx = client.transaction().await?;
    phone_live(&tx, s).await?;
    // Serialize exact retries and cleanup without ever reviving the nonce.
    tx.query_opt("SELECT challenge_id FROM line_activation_v2_pending WHERE account_id=$1 AND challenge_id=$2 FOR UPDATE",&[&s.account_id,&ack.challenge_id]).await?.ok_or(LineActivationError::Unavailable)?;
    let p = observation_store::load(&tx, s.account_id, ack.challenge_id).await?;
    if p.purpose != Purpose::Sealed {
        return Ok(false);
    }
    let actual = active(&tx, &p, s).await?;
    if !same_ack(actual, ack) {
        return Ok(false);
    }
    if !p.installed
        && tx
            .execute(
                "UPDATE line_activation_v2_pending SET installed_at=clock_timestamp(),nonce=NULL WHERE challenge_id=$1 AND purpose='sealed' AND protocol_version=2 AND installed_at IS NULL AND approved_at IS NOT NULL AND retired_at IS NULL",
                &[&p.id],
            )
            .await?
            != 1
    {
        return Err(LineActivationError::Unavailable);
    }
    let readback = observation_store::load(&tx, s.account_id, p.id).await?;
    if !readback.installed
        || readback.nonce.is_some()
        || !same_ack(active(&tx, &readback, s).await?, ack)
    {
        return Err(LineActivationError::Unavailable);
    }
    tx.commit().await?;
    Ok(true)
}
fn same_ack(a: Ack, b: Ack) -> bool {
    (
        a.challenge_id,
        a.account_id,
        a.line_id,
        a.device_id,
        a.generation,
        a.device_statement_sha256,
        a.device_signature_sha256,
    ) == (
        b.challenge_id,
        b.account_id,
        b.line_id,
        b.device_id,
        b.generation,
        b.device_statement_sha256,
        b.device_signature_sha256,
    )
}
pub(crate) async fn current(client: &mut Client, s: InboundSession<'_>) -> Result<()> {
    let tx = client.transaction().await?;
    phone_live(&tx, s).await?;
    tx.commit().await?;
    Ok(())
}
pub(crate) async fn current_in_transaction(
    tx: &Transaction<'_>,
    s: InboundSession<'_>,
) -> Result<()> {
    phone_live(tx, s).await?;
    Ok(())
}
pub(crate) async fn current_challenge(
    client: &mut Client,
    s: InboundSession<'_>,
    purpose: Purpose,
    c: &Challenge,
) -> Result<()> {
    let tx = client.transaction().await?;
    let p = observation_store::load(&tx, s.account_id, c.tuple.id).await?;
    if p.purpose != purpose
        || p.account != c.tuple.account_id
        || p.line != c.tuple.line_id
        || p.device != c.tuple.device_id
        || p.generation != c.tuple.generation
        || p.nonce != Some(c.tuple.nonce)
        || p.expires != c.expires_at_ms
        || !p.lease.matches(s)
    {
        return Err(LineActivationError::Unavailable);
    }
    unapproved(&tx, &p).await?;
    original_live(&tx, &p).await?;
    tx.commit().await?;
    Ok(())
}
pub(crate) async fn current_ack(
    client: &mut Client,
    s: InboundSession<'_>,
    ack: Ack,
) -> Result<()> {
    let tx = client.transaction().await?;
    let p = observation_store::load(&tx, s.account_id, ack.challenge_id).await?;
    if !same_ack(active(&tx, &p, s).await?, ack) {
        return Err(LineActivationError::Unavailable);
    }
    tx.commit().await?;
    Ok(())
}
pub(crate) async fn retire_sms(client: &mut Client, s: InboundSession<'_>) -> Result<u64> {
    let tx = client.transaction().await?;
    phone_live(&tx, s).await?;
    let n=tx.execute("WITH old AS MATERIALIZED (SELECT p.challenge_id FROM line_activation_v2_pending p JOIN line_activation_challenges c ON c.id=p.challenge_id AND c.protocol_version=2 JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(p.account_id,p.line_id,p.device_id,p.generation) WHERE p.account_id=$1 AND p.device_id=$2 AND p.purpose='sms' AND p.nonce IS NOT NULL AND p.retired_at IS NULL AND ((b.activated_at IS NOT NULL AND b.activated_at<clock_timestamp()-interval '900 seconds') OR (b.activated_at IS NULL AND c.expires_at<clock_timestamp()-interval '900 seconds')) ORDER BY p.created_at LIMIT 100 FOR UPDATE OF p SKIP LOCKED) UPDATE line_activation_v2_pending p SET nonce=NULL,retired_at=clock_timestamp() FROM old WHERE p.challenge_id=old.challenge_id",&[&s.account_id,&s.device_id]).await?;
    phone_live(&tx, s).await?;
    tx.commit().await?;
    Ok(n)
}
pub(crate) async fn cleanup_sealed<C: GenericClient + Sync>(tx: &C, limit: i64) -> Result<u64> {
    Ok(tx.execute("WITH receipts AS MATERIALIZED (SELECT r.account_id,r.registration_id FROM sealed_line_key_receipts r WHERE r.activated_ms IS NULL AND EXISTS(SELECT 1 FROM line_activation_v2_pending p JOIN line_activation_challenges c ON c.id=p.challenge_id AND c.protocol_version=2 WHERE p.account_id=r.account_id AND p.registration_id=r.registration_id AND p.purpose='sealed' AND p.nonce IS NOT NULL AND (c.expires_at<=clock_timestamp() OR r.retired_ms IS NOT NULL)) ORDER BY r.completed_ms LIMIT $1 FOR UPDATE OF r SKIP LOCKED), expired AS MATERIALIZED (SELECT p.challenge_id FROM line_activation_v2_pending p JOIN receipts r ON (r.account_id,r.registration_id)=(p.account_id,p.registration_id) JOIN line_activation_challenges c ON c.id=p.challenge_id AND c.protocol_version=2 WHERE p.nonce IS NOT NULL AND p.approved_at IS NULL AND (c.expires_at<=clock_timestamp() OR EXISTS(SELECT 1 FROM sealed_line_key_receipts z WHERE (z.account_id,z.registration_id)=(r.account_id,r.registration_id) AND z.retired_ms IS NOT NULL)) ORDER BY p.created_at LIMIT $1 FOR UPDATE OF p SKIP LOCKED) UPDATE line_activation_v2_pending p SET nonce=NULL,retired_at=clock_timestamp() FROM expired x WHERE p.challenge_id=x.challenge_id AND p.approved_at IS NULL AND EXISTS(SELECT 1 FROM sealed_line_key_receipts r WHERE (r.account_id,r.registration_id)=(p.account_id,p.registration_id) AND r.activated_ms IS NULL)",&[&limit.clamp(1,100)]).await?)
}

#[cfg(test)]
pub(crate) mod db_tests;
#[cfg(test)]
mod schema_roles_tests;
#[cfg(test)]
mod tests;
