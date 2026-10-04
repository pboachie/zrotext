// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{AuthError, SessionPrincipal, account, mfa};
use crate::sealed_connector_registry::{RegistryError, owner_fence};
use zeroize::Zeroizing;

pub struct GrantRequest {
    pub interval_id: Uuid,
    pub connector_id: Uuid,
    pub read_grant_id: Uuid,
    pub reader_key_id: [u8; 32],
    pub expires_at_ms: i64,
}
/// One-return secret. Intentionally neither Debug nor Serialize.
pub struct IssuedCredential {
    pub grant_id: Uuid,
    pub token: Zeroizing<String>,
}
fn err(e: ConversationError) -> AuthError {
    match e {
        ConversationError::Database(e) => AuthError::Database(e),
        ConversationError::Invalid => AuthError::InvalidInput,
        _ => AuthError::Forbidden,
    }
}
fn registry(e: RegistryError) -> AuthError {
    match e {
        RegistryError::Database(e) => AuthError::Database(e),
        RegistryError::Authentication(e) => e,
        _ => AuthError::Forbidden,
    }
}
pub async fn issue(
    client: &mut Client,
    owner: &SessionPrincipal,
    hasher: &TokenHasher,
    cipher: &mfa::MfaCipher,
    password: &str,
    code: &str,
    request: &GrantRequest,
) -> Result<IssuedCredential, AuthError> {
    if [
        request.interval_id,
        request.connector_id,
        request.read_grant_id,
    ]
    .iter()
    .any(Uuid::is_nil)
        || request.reader_key_id == [0; 32]
    {
        return Err(AuthError::InvalidInput);
    }
    let verified = account::verify_current_password(client, owner, password).await?;
    let account = owner.tenant.account_id();
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut authority = lock_current(&tx, account)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    owner_fence(&tx, owner).await.map_err(registry)?;
    let stored: String = tx
        .query_one(
            "SELECT password_hash FROM users WHERE id=$1",
            &[&owner.user_id],
        )
        .await?
        .get(0);
    if stored != verified {
        return Err(AuthError::InvalidCredentials);
    }
    let interval = activation::load(&tx, account, request.interval_id)
        .await
        .map_err(err)?;
    let s = interval.statement;
    if interval.phase != "active"
        || !s.integration_readers.iter().any(|r| {
            r.connector_id == request.connector_id
                && r.read_grant_id == request.read_grant_id
                && r.key_id == request.reader_key_id
        })
    {
        return Err(AuthError::Forbidden);
    }
    activation::origin(&tx, &s).await.map_err(err)?;
    crate::http_owner_conversations::lock_line(&tx, account, s.device, s.line, s.generation)
        .await
        .map_err(err)?;
    activation::check_readers(&tx, &s, &mut authority)
        .await
        .map_err(err)?;
    let point: Vec<u8> = tx
        .query_one(
            "SELECT key_point FROM connector_registrations WHERE account_id=$1 AND connector_id=$2",
            &[&account, &request.connector_id],
        )
        .await?
        .get(0);
    let (snapshot, reader, scope) = authority
        .integration_snapshot(s.device, s.line, &point)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    let crypto_until = authority
        .integration_reader_deadline(s.device, s.line, &point)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    // The reply path also depends on the archive reader (role 2) and the
    // phone conversation signer (role 4); a grant that outlived either key
    // would authorize reads relying on expired authority.
    let (archive_until, signer_until) = authority
        .conversation_deadlines(s.device, s.line)
        .await
        .map_err(|_| AuthError::Forbidden)?;
    let crypto_until = crypto_until.min(archive_until).min(signer_until);
    if reader != request.reader_key_id || scope & 8 != 8 || request.expires_at_ms > crypto_until {
        return Err(AuthError::InvalidInput);
    }
    let now = activation::now(&tx).await.map_err(err)?;
    if request.expires_at_ms <= now || request.expires_at_ms - now > 86_400_000 {
        return Err(AuthError::InvalidInput);
    }
    let factor = mfa::consume_ceremony_factor(&tx, cipher, hasher, owner, code, now as u64).await?;
    let Some(factor) = factor else {
        drop(authority);
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    };
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM original_reply_grants WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    if count >= 128 {
        return Err(AuthError::RateLimited);
    }
    let token = Zeroizing::new(format!(
        "ztr_{}",
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
    ));
    let hash = hasher.original_reply_credential_hash(&token);
    let grant_id = Uuid::new_v4();
    tx.execute("INSERT INTO original_reply_grants(account_id,grant_id,credential_hash,interval_id,connector_id,read_grant_id,reader_key_id,created_by_user,created_session,created_ms,expires_ms,trust_generation,manifest_version,manifest_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",&[&account,&grant_id,&hash.as_slice(),&s.interval,&request.connector_id,&request.read_grant_id,&request.reader_key_id.as_slice(),&owner.user_id,&owner.session_id,&now,&request.expires_at_ms,&snapshot.generation,&snapshot.version,&snapshot.digest.as_slice()]).await?;
    let p = Principal {
        account,
        grant: grant_id,
        hash,
    };
    // All creator, selected-reader, originating-owner and key deadlines are sampled
    // after lock waits. MFA expiry is independently rechecked at the same boundary.
    let (proof, _) = locked(&tx, &p, s.activation_version).await.map_err(err)?;
    owner_fence(&tx, owner).await.map_err(registry)?;
    let final_now = activation::now(&tx).await.map_err(err)?;
    if final_now >= proof.expires_at_ms || !factor.current_at(final_now as u64) {
        return Err(AuthError::Forbidden);
    }
    drop(authority);
    tx.commit().await?;
    Ok(IssuedCredential { grant_id, token })
}
pub async fn withdraw(
    client: &mut Client,
    owner: &SessionPrincipal,
    grant: Uuid,
) -> Result<(), AuthError> {
    if grant.is_nil() {
        return Err(AuthError::InvalidInput);
    }
    let tx = client.transaction().await?;
    let current = lock_current(&tx, owner.tenant.account_id())
        .await
        .map_err(|_| AuthError::Forbidden)?;
    owner_fence(&tx, owner).await.map_err(registry)?;
    let count=tx.execute("UPDATE original_reply_grants SET revoked_ms=COALESCE(revoked_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE account_id=$1 AND grant_id=$2",&[&owner.tenant.account_id(),&grant]).await?;
    if count != 1 {
        return Err(AuthError::Forbidden);
    }
    owner_fence(&tx, owner).await.map_err(registry)?;
    drop(current);
    tx.commit().await?;
    Ok(())
}
