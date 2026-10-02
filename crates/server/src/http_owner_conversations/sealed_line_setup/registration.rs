// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded root-authorized public approval-key receipt for first SEALED activation.
use crate::{
    auth::{SessionPrincipal, TokenHasher, mfa},
    inbound::InboundSession,
    sealed_root_ceremony::{self as owner, CeremonyError},
};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
use zrotext_root_material::line_key_registration::{self as codec, Scope, Statement};
type Result<T> = std::result::Result<T, CeremonyError>;
fn reject() -> CeremonyError {
    CeremonyError::Rejected("sealed line registration unavailable")
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub struct Selection {
    pub device: Uuid,
    pub line: Uuid,
    pub generation: i64,
    pub root_fingerprint: [u8; 32],
    pub paired_fingerprint: [u8; 32],
    pub approval_point: [u8; 65],
    pub connection_epoch: i64,
    pub deployment_epoch: i64,
    pub site_id: String,
    pub instance_id: String,
}
pub async fn bootstrap(
    client: &mut Client,
    p: &SessionPrincipal,
    device: Uuid,
    line: Uuid,
) -> Result<serde_json::Value> {
    if device.is_nil() || line.is_nil() {
        return Err(reject());
    }
    let tx = owner::begin(client).await?;
    let account = p.tenant.account_id();
    let (pin, fp) = root(&tx, account).await?;
    owner::owner_locks(&tx, p, false).await?;
    first(&tx, account).await?;
    let generation = next(&tx, account, line).await?;
    let (paired, connection, deployment, site, instance) = phone(&tx, account, device).await?;
    owner::live(&tx, p).await?;
    let n = now(&tx, 0).await?;
    use base64::{Engine, engine::general_purpose::STANDARD as B};
    let value = serde_json::json!({"v":1,"untrusted_projection":true,"account_id":account,"user_id":p.user_id,"session_id":p.session_id,"device_id":device,"line_id":line,"expected_next_binding_generation":generation.to_string(),"root_pin":B.encode(pin),"root_fingerprint":B.encode(fp),"current_device_signing_fingerprint":B.encode(paired),"connection_epoch":connection.to_string(),"deployment_epoch":deployment.to_string(),"site_id":site,"instance_id":instance,"server_now_ms":n.to_string()});
    tx.commit().await?;
    Ok(value)
}
/// Lost-reply reconciliation returns public immutable evidence. It never
/// repeats MFA or silently grants a fresh registration interval.
pub async fn receipt(
    client: &mut Client,
    p: &SessionPrincipal,
    id: Uuid,
) -> Result<Option<serde_json::Value>> {
    let tx = owner::begin(client).await?;
    owner::owner_locks(&tx, p, false).await?;
    let r=tx.query_opt("SELECT transcript,root_signature,approval_signature,completed_ms,assigned_challenge_id,retired_ms,activated_ms FROM sealed_line_key_receipts WHERE account_id=$1 AND registration_id=$2 AND user_id=$3 AND session_id=$4",&[&p.tenant.account_id(),&id,&p.user_id,&p.session_id]).await?;
    use base64::{Engine, engine::general_purpose::STANDARD as B};
    let result=r.map(|r|serde_json::json!({"registration_id":id,"unsigned_statement":B.encode(r.get::<_,Vec<u8>>(0)),"root_signature":B.encode(r.get::<_,Vec<u8>>(1)),"approval_signature":B.encode(r.get::<_,Vec<u8>>(2)),"completed_ms":r.get::<_,i64>(3).to_string(),"assigned_challenge_id":r.get::<_,Option<Uuid>>(4),"retired_ms":r.get::<_,Option<i64>>(5).map(|n|n.to_string()),"activated_ms":r.get::<_,Option<i64>>(6).map(|n|n.to_string())}));
    owner::live(&tx, p).await?;
    tx.commit().await?;
    Ok(result)
}
/// Challenge cleanup has no authority effect: absent nonce/challenge rejects
/// completion. Immutable receipts/key and generation tombstones remain bounded.
pub async fn cleanup(
    client: &Client,
    limit: i64,
) -> std::result::Result<u64, tokio_postgres::Error> {
    client.execute("DELETE FROM sealed_line_key_challenges WHERE account_id IN (SELECT account_id FROM sealed_line_key_challenges WHERE expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint ORDER BY expires_ms LIMIT $1)",&[&limit.clamp(1,100)]).await
}
pub(crate) async fn now(tx: &Transaction<'_>, previous: u64) -> Result<u64> {
    let n: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    if n <= 0 || (n as u64) < previous {
        return Err(reject());
    }
    Ok(n as u64)
}
async fn root(tx: &Transaction<'_>, account: Uuid) -> Result<([u8; 94], [u8; 32])> {
    let r=tx.query_opt("SELECT root_pin,root_fingerprint FROM sealed_manifest_authorities WHERE account_id=$1 AND generation=1 AND version=0 AND manifest IS NULL AND anchor_digest=decode(repeat('00',32),'hex') AND revoked_at IS NULL FOR UPDATE",&[&account]).await?.ok_or_else(reject)?;
    let pin: [u8; 94] = r.get::<_, Vec<u8>>(0).try_into().map_err(|_| reject())?;
    let fp: [u8; 32] = r.get::<_, Vec<u8>>(1).try_into().map_err(|_| reject())?;
    if zrotext_root_material::sealed_root_enrollment::root_fingerprint(&pin, account.as_bytes())
        .map_err(|_| reject())?
        != fp
    {
        return Err(reject());
    }
    Ok((pin, fp))
}
async fn first(tx: &Transaction<'_>, account: Uuid) -> Result<()> {
    if tx.query_opt("SELECT 1 FROM device_line_bindings WHERE account_id=$1 AND purpose='sealed' AND activated_at IS NOT NULL LIMIT 1",&[&account]).await?.is_some() {return Err(reject());}
    Ok(())
}
/// Current enrolled key and actual database lease; this projection is untrusted
/// until the owner independently compares the phone fingerprint offline.
async fn phone(
    tx: &Transaction<'_>,
    account: Uuid,
    device: Uuid,
) -> Result<([u8; 32], i64, i64, String, String)> {
    let r=tx.query_opt("SELECT k.signing_key_sec1,k.fingerprint,s.connection_epoch,s.deployment_epoch,s.site_id,s.instance_id FROM device_keys k JOIN devices d ON (d.account_id,d.id)=(k.account_id,k.device_id) JOIN device_sessions s ON (s.account_id,s.device_id)=(d.account_id,d.id) JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE WHERE k.account_id=$1 AND k.device_id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND s.lease_until>clock_timestamp() AND t.enabled AND NOT t.draining AND p.epoch=s.deployment_epoch AND NOT pg_is_in_recovery() FOR SHARE OF k,d,s,t,p",&[&account,&device]).await?.ok_or_else(reject)?;
    let point: Vec<u8> = r.get(0);
    let fp: [u8; 32] = r.get::<_, Vec<u8>>(1).try_into().map_err(|_| reject())?;
    if point.len() != 65
        || point[0] != 4
        || hash(&point) != fp
        || p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).is_err()
    {
        return Err(reject());
    }
    Ok((fp, r.get(2), r.get(3), r.get(4), r.get(5)))
}
async fn next(tx: &Transaction<'_>, account: Uuid, line: Uuid) -> Result<i64> {
    let row=tx.query_opt("SELECT account_id,state,last_issued_generation FROM phone_lines WHERE id=$1 FOR UPDATE",&[&line]).await?;
    match row {
        None => Ok(1),
        Some(r) if r.get::<_, Uuid>(0) == account && r.get::<_, String>(1) != "revoked" => {
            r.get::<_, i64>(2).checked_add(1).ok_or_else(reject)
        }
        _ => Err(reject()),
    }
}
async fn distinct(tx: &Transaction<'_>, account: Uuid, point: &[u8], pin: &[u8]) -> Result<()> {
    if point==&pin[29..] || tx.query_one("SELECT EXISTS(SELECT 1 FROM device_keys WHERE account_id=$1 AND signing_key_sec1=$2) OR EXISTS(SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=$1 AND signing_key_sec1=$2) OR EXISTS(SELECT 1 FROM line_owner_approval_keys WHERE account_id=$1 AND signing_key_sec1=$2)",&[&account,&point]).await?.get::<_,bool>(0) {return Err(reject());}
    // v0 has no reader directory. Future genesis separately fences every
    // historical approval point, so later reader enrollment cannot alias it.
    Ok(())
}
pub async fn issue(
    client: &mut Client,
    p: &SessionPrincipal,
    origin: &str,
    selection: Selection,
) -> Result<Statement> {
    if selection.device.is_nil() || selection.line.is_nil() || selection.generation <= 0 {
        return Err(reject());
    }
    let tx = owner::begin(client).await?;
    let account = p.tenant.account_id();
    let (pin, fp) = root(&tx, account).await?;
    owner::owner_locks(&tx, p, false).await?;
    first(&tx, account).await?;
    if fp != selection.root_fingerprint
        || next(&tx, account, selection.line).await? != selection.generation
    {
        return Err(reject());
    }
    distinct(&tx, account, &selection.approval_point, &pin).await?;
    let (paired, connection, deployment, site, instance) =
        phone(&tx, account, selection.device).await?;
    if paired != selection.paired_fingerprint
        || connection != selection.connection_epoch
        || deployment != selection.deployment_epoch
        || site != selection.site_id
        || instance != selection.instance_id
    {
        return Err(reject());
    }
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM sealed_line_key_receipts WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    if count >= 16 {
        return Err(reject());
    }
    let issued = now(&tx, 0).await?;
    let scope = Scope {
        account: *account.as_bytes(),
        user: *p.user_id.as_bytes(),
        owner_session: *p.session_id.as_bytes(),
        device: *selection.device.as_bytes(),
        line: *selection.line.as_bytes(),
        next_generation: selection.generation as u64,
        challenge: *Uuid::new_v4().as_bytes(),
        nonce: rand::random(),
        issued_ms: issued,
        expires_ms: issued + 300_000,
        approval_fingerprint: hash(&selection.approval_point),
        paired_signing_fingerprint: paired,
        connection_epoch: connection as u64,
        deployment_epoch: deployment as u64,
        site_id: site,
        instance_id: instance,
        origin: origin.to_owned(),
    };
    let statement =
        Statement::new(scope, pin, fp, selection.approval_point).map_err(|_| reject())?;
    let bytes = codec::encode(&statement).map_err(|_| reject())?;
    let s = statement.scope();
    tx.execute("INSERT INTO sealed_line_key_challenges(account_id,challenge_id,user_id,session_id,device_id,line_id,generation,transcript,issued_ms,expires_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(account_id) DO UPDATE SET challenge_id=EXCLUDED.challenge_id,user_id=EXCLUDED.user_id,session_id=EXCLUDED.session_id,device_id=EXCLUDED.device_id,line_id=EXCLUDED.line_id,generation=EXCLUDED.generation,transcript=EXCLUDED.transcript,issued_ms=EXCLUDED.issued_ms,expires_ms=EXCLUDED.expires_ms,completed_ms=NULL",&[&account,&Uuid::from_bytes(s.challenge),&p.user_id,&p.session_id,&selection.device,&selection.line,&selection.generation,&bytes,&(issued as i64),&(s.expires_ms as i64)]).await?;
    fresh(&tx, p, &statement, None).await?;
    tx.commit().await?;
    Ok(statement)
}
fn identity(p: &SessionPrincipal, s: &Scope) -> bool {
    s.account == *p.tenant.account_id().as_bytes()
        && s.user == *p.user_id.as_bytes()
        && s.owner_session == *p.session_id.as_bytes()
}
pub(crate) async fn fresh(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    statement: &Statement,
    socket: Option<InboundSession<'_>>,
) -> Result<()> {
    if !identity(p, statement.scope()) {
        return Err(reject());
    }
    owner::live(tx, p).await?;
    fresh_bound(
        tx,
        p.tenant.account_id(),
        p.user_id,
        p.session_id,
        statement,
        socket,
    )
    .await
}
async fn fresh_bound(
    tx: &Transaction<'_>,
    account: Uuid,
    user: Uuid,
    session: Uuid,
    statement: &Statement,
    socket: Option<InboundSession<'_>>,
) -> Result<()> {
    let s = statement.scope();
    if s.account != *account.as_bytes()
        || s.user != *user.as_bytes()
        || s.owner_session != *session.as_bytes()
    {
        return Err(reject());
    }
    let tuple = phone(tx, account, Uuid::from_bytes(s.device)).await?;
    if tuple
        != (
            s.paired_signing_fingerprint,
            s.connection_epoch as i64,
            s.deployment_epoch as i64,
            s.site_id.clone(),
            s.instance_id.clone(),
        )
    {
        return Err(reject());
    }
    if let Some(socket) = socket {
        if socket.account_id != account
            || socket.device_id.as_bytes() != &s.device
            || socket.site_id != s.site_id
            || socket.instance_id != s.instance_id
            || socket.connection_epoch as u64 != s.connection_epoch
            || socket.deployment_epoch as u64 != s.deployment_epoch
        {
            return Err(reject());
        }
    }
    let n = now(tx, s.issued_ms).await?;
    if n >= s.expires_ms {
        return Err(reject());
    }
    if tx.query_opt("SELECT 1 FROM accounts a JOIN memberships m ON m.account_id=a.id JOIN users u ON u.id=m.user_id JOIN sessions o ON (o.account_id,o.user_id)=(a.id,u.id) JOIN owner_mfa f ON (f.account_id,f.user_id)=(a.id,u.id) JOIN device_sessions d ON d.account_id=a.id WHERE a.id=$1 AND u.id=$2 AND o.id=$3 AND a.disabled_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND f.enabled_at IS NOT NULL AND o.revoked_at IS NULL AND o.expires_at>clock_timestamp() AND COALESCE(o.last_used_at,o.created_at)>clock_timestamp()-interval '72 hours' AND d.device_id=$4 AND d.site_id=$5 AND d.instance_id=$6 AND d.connection_epoch=$7 AND d.deployment_epoch=$8 AND d.lease_until>clock_timestamp() AND floor(extract(epoch FROM clock_timestamp())*1000)::bigint<$9",&[&account,&user,&session,&Uuid::from_bytes(s.device),&s.site_id,&s.instance_id,&(s.connection_epoch as i64),&(s.deployment_epoch as i64),&(s.expires_ms as i64)]).await?.is_none() {return Err(reject());}
    Ok(())
}
/// Phone transport validates persisted owner identity under locks; it does not
/// manufacture a cookie principal or infer a phone session from request JSON.
pub(crate) async fn lock_phone_scope(
    tx: &Transaction<'_>,
    account: Uuid,
    user: Uuid,
    session_id: Uuid,
    id: Uuid,
    line: Uuid,
    device: Uuid,
    challenge: Uuid,
    socket: InboundSession<'_>,
) -> Result<Statement> {
    let (pin, fp) = root(tx, account).await?;
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account],
    )
    .await?
    .ok_or_else(reject)?;
    tx.query_opt("SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id JOIN sessions o ON (o.account_id,o.user_id)=(m.account_id,u.id) JOIN owner_mfa f ON (f.account_id,f.user_id)=(m.account_id,u.id) WHERE m.account_id=$1 AND u.id=$2 AND o.id=$3 AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND f.enabled_at IS NOT NULL FOR UPDATE OF u,o,f FOR SHARE OF m",&[&account,&user,&session_id]).await?.ok_or_else(reject)?;
    first(tx, account).await?;
    let r=tx.query_opt("SELECT transcript FROM sealed_line_key_receipts r JOIN line_owner_approval_keys k ON (k.account_id,k.fingerprint)=(r.account_id,r.approval_fingerprint) WHERE r.account_id=$1 AND registration_id=$2 AND r.assigned_challenge_id=$3 AND retired_ms IS NULL AND activated_ms IS NULL AND k.revoked_at IS NULL FOR UPDATE OF r FOR SHARE OF k",&[&account,&id,&challenge]).await?.ok_or_else(reject)?;
    let statement = codec::decode(&r.get::<_, Vec<u8>>(0)).map_err(|_| reject())?;
    if statement.scope().line != *line.as_bytes()
        || statement.scope().device != *device.as_bytes()
        || pin != *statement.root_pin()
        || fp != *statement.root_fingerprint()
    {
        return Err(reject());
    }
    fresh_bound(tx, account, user, session_id, &statement, Some(socket)).await?;
    Ok(statement)
}
pub(crate) async fn fresh_phone(
    tx: &Transaction<'_>,
    statement: &Statement,
    socket: InboundSession<'_>,
) -> Result<()> {
    let s = statement.scope();
    fresh_bound(
        tx,
        Uuid::from_bytes(s.account),
        Uuid::from_bytes(s.user),
        Uuid::from_bytes(s.owner_session),
        statement,
        Some(socket),
    )
    .await
}
pub struct Completion<'a> {
    pub unsigned: &'a [u8],
    pub root_signature: &'a [u8],
    pub approval_signature: &'a [u8],
    pub factor: &'a str,
}
pub async fn complete(
    client: &mut Client,
    p: &SessionPrincipal,
    origin: &str,
    hasher: &TokenHasher,
    cipher: &mfa::MfaCipher,
    id: Uuid,
    c: Completion<'_>,
) -> Result<()> {
    let statement = codec::decode(c.unsigned).map_err(|_| reject())?;
    let s = statement.scope();
    let account = p.tenant.account_id();
    if !identity(p, s) || s.origin != origin || s.challenge != *id.as_bytes() || c.factor.len() > 26
    {
        return Err(reject());
    }
    statement
        .verify_root(c.root_signature)
        .map_err(|_| reject())?;
    statement
        .verify_approval(c.approval_signature)
        .map_err(|_| reject())?;
    let tx = owner::begin(client).await?;
    let (pin, fp) = root(&tx, account).await?;
    owner::owner_locks(&tx, p, false).await?;
    first(&tx, account).await?;
    if pin != *statement.root_pin()
        || fp != *statement.root_fingerprint()
        || next(&tx, account, Uuid::from_bytes(s.line)).await? != s.next_generation as i64
    {
        return Err(reject());
    }
    let stored=tx.query_opt("SELECT transcript FROM sealed_line_key_challenges WHERE account_id=$1 AND challenge_id=$2 AND completed_ms IS NULL FOR UPDATE",&[&account,&id]).await?.ok_or_else(reject)?;
    if stored.get::<_, Vec<u8>>(0) != c.unsigned {
        return Err(reject());
    }
    distinct(&tx, account, statement.approval_point(), &pin).await?;
    fresh(&tx, p, &statement, None).await?;
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM sealed_line_key_receipts WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    if count >= 16 {
        return Err(reject());
    }
    let factor_now = now(&tx, s.issued_ms).await?;
    let Some(factor) =
        mfa::consume_ceremony_factor(&tx, cipher, hasher, p, c.factor, factor_now).await?
    else {
        tx.commit().await?;
        return Err(crate::auth::AuthError::InvalidCredentials.into());
    };
    // Retire all prior unactivated scope and its pending generation atomically.
    tx.execute("UPDATE device_line_bindings b SET state='revoked' FROM sealed_line_key_receipts r WHERE r.account_id=$1 AND r.activated_ms IS NULL AND r.retired_ms IS NULL AND r.assigned_challenge_id IS NOT NULL AND (b.account_id,b.line_id,b.device_id,b.generation)=(r.account_id,r.line_id,r.device_id,r.generation) AND b.state='pending'",&[&account]).await?;
    tx.execute("UPDATE sealed_line_key_receipts SET retired_ms=$2 WHERE account_id=$1 AND activated_ms IS NULL AND retired_ms IS NULL",&[&account,&(factor_now as i64)]).await?;
    tx.execute("UPDATE line_owner_approval_keys SET revoked_at=clock_timestamp() WHERE account_id=$1 AND revoked_at IS NULL",&[&account]).await?;
    tx.execute("INSERT INTO line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) VALUES($1,$2,$3)",&[&account,&s.approval_fingerprint.as_slice(),&statement.approval_point().as_slice()]).await?;
    let completed = now(&tx, factor_now).await?;
    tx.execute("INSERT INTO sealed_line_key_receipts(account_id,registration_id,user_id,session_id,device_id,line_id,generation,transcript,root_signature,approval_signature,approval_point,approval_fingerprint,paired_fingerprint,issued_ms,expires_ms,completed_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",&[&account,&id,&p.user_id,&p.session_id,&Uuid::from_bytes(s.device),&Uuid::from_bytes(s.line),&(s.next_generation as i64),&c.unsigned,&c.root_signature,&c.approval_signature,&statement.approval_point().as_slice(),&s.approval_fingerprint.as_slice(),&s.paired_signing_fingerprint.as_slice(),&(s.issued_ms as i64),&(s.expires_ms as i64),&(completed as i64)]).await?;
    tx.execute("UPDATE sealed_line_key_challenges SET completed_ms=$3 WHERE account_id=$1 AND challenge_id=$2",&[&account,&id,&(completed as i64)]).await?;
    fresh(&tx, p, &statement, None).await?;
    if !factor.current_at(now(&tx, completed).await?) {
        return Err(reject());
    }
    tx.commit().await?;
    Ok(())
}
/// Authority is locked before account exactly as root admission. The immutable
/// scope, absolute expiry and actual socket tuple apply at both boundaries.
pub(crate) async fn lock_scope(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    id: Uuid,
    line: Uuid,
    device: Uuid,
    challenge: Option<Uuid>,
    socket: Option<InboundSession<'_>>,
) -> Result<Statement> {
    let account = p.tenant.account_id();
    let (pin, fp) = root(tx, account).await?;
    owner::owner_locks(tx, p, false).await?;
    first(tx, account).await?;
    let r=tx.query_opt("SELECT transcript,assigned_challenge_id FROM sealed_line_key_receipts r JOIN line_owner_approval_keys k ON (k.account_id,k.fingerprint)=(r.account_id,r.approval_fingerprint) WHERE r.account_id=$1 AND registration_id=$2 AND retired_ms IS NULL AND activated_ms IS NULL AND k.revoked_at IS NULL FOR UPDATE OF r FOR SHARE OF k",&[&account,&id]).await?.ok_or_else(reject)?;
    let statement = codec::decode(&r.get::<_, Vec<u8>>(0)).map_err(|_| reject())?;
    let s = statement.scope();
    if s.line != *line.as_bytes()
        || s.device != *device.as_bytes()
        || pin != *statement.root_pin()
        || fp != *statement.root_fingerprint()
        || r.get::<_, Option<Uuid>>(1) != challenge
    {
        return Err(reject());
    }
    fresh(tx, p, &statement, socket).await?;
    Ok(statement)
}
pub(crate) async fn assign(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    id: Uuid,
    challenge: Uuid,
) -> Result<()> {
    if tx.execute("UPDATE sealed_line_key_receipts SET assigned_challenge_id=$3 WHERE account_id=$1 AND registration_id=$2 AND assigned_challenge_id IS NULL AND retired_ms IS NULL AND activated_ms IS NULL",&[&p.tenant.account_id(),&id,&challenge]).await?!=1 {return Err(reject());}
    Ok(())
}
pub(crate) async fn activated(tx: &Transaction<'_>, p: &SessionPrincipal, id: Uuid) -> Result<()> {
    let n = now(tx, 0).await?;
    if tx.execute("UPDATE sealed_line_key_receipts SET activated_ms=$3 WHERE account_id=$1 AND registration_id=$2 AND retired_ms IS NULL AND activated_ms IS NULL",&[&p.tenant.account_id(),&id,&(n as i64)]).await?!=1 {return Err(reject());}
    Ok(())
}
