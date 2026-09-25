// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-controlled SMS approval public keys. The signing key stays with the
//! owner; registration verifies a challenge-bound proof of possession.

use super::{
    AuthHttpError, AuthHttpState, CSRF_COOKIE, CSRF_HEADER, connect, cookie, map_auth, mfa,
    mfa_manage_budget, require_owner,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_postgres::Transaction;
use uuid::Uuid;

const DOMAIN: &[u8] = b"ZTSMS/owner-key/register/v1\0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChallengeBody {
    signing_key_sec1_b64: String,
}

#[derive(Serialize)]
pub(super) struct ChallengeResponse {
    challenge_id: Uuid,
    nonce_b64: String,
    fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegisterBody {
    challenge_id: Uuid,
    nonce_b64: String,
    signature_der_b64: String,
    mfa_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevokeBody {
    mfa_code: String,
}

#[derive(Serialize)]
pub(super) struct KeyView {
    fingerprint: String,
    active: bool,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn decode_canonical<const N: usize>(encoded: &str) -> Result<[u8; N], AuthHttpError> {
    if encoded.len() > N.div_ceil(3) * 4 {
        return Err(AuthHttpError::BadRequest);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| AuthHttpError::BadRequest)?;
    if decoded.len() != N || STANDARD.encode(&decoded) != encoded {
        return Err(AuthHttpError::BadRequest);
    }
    decoded.try_into().map_err(|_| AuthHttpError::BadRequest)
}

fn key_bytes(encoded: &str) -> Result<[u8; 65], AuthHttpError> {
    let bytes = decode_canonical::<65>(encoded)?;
    if bytes[0] != 4 || VerifyingKey::from_sec1_bytes(&bytes).is_err() {
        return Err(AuthHttpError::BadRequest);
    }
    Ok(bytes)
}

fn fingerprint_string(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_fingerprint(value: &str) -> Result<[u8; 32], AuthHttpError> {
    if value.len() != 43 {
        return Err(AuthHttpError::BadRequest);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthHttpError::BadRequest)?;
    if decoded.len() != 32 || fingerprint_string(&decoded) != value {
        return Err(AuthHttpError::BadRequest);
    }
    decoded.try_into().map_err(|_| AuthHttpError::BadRequest)
}

fn possession_statement(
    account_id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
    challenge_id: Uuid,
    nonce: &[u8; 32],
    fingerprint: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + 16 * 4 + 64);
    message.extend_from_slice(DOMAIN);
    for id in [account_id, user_id, session_id, challenge_id] {
        message.extend_from_slice(id.as_bytes());
    }
    message.extend_from_slice(nonce);
    message.extend_from_slice(fingerprint);
    message
}

async fn locked_owner(
    tx: &Transaction<'_>,
    owner: &crate::auth::SessionPrincipal,
) -> Result<(), AuthHttpError> {
    let account_id = owner.tenant.account_id();
    let live = tx
        .query_opt(
            "SELECT 1 FROM accounts a JOIN memberships m ON m.account_id=a.id \
         JOIN users u ON u.id=m.user_id JOIN sessions s ON s.account_id=a.id AND s.user_id=u.id \
         WHERE a.id=$1 AND u.id=$2 AND s.id=$3 AND a.disabled_at IS NULL \
         AND m.role='owner' AND u.mfa_enabled AND s.revoked_at IS NULL \
         AND s.expires_at>clock_timestamp() FOR SHARE OF m,u,s",
            &[&account_id, &owner.user_id, &owner.session_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    if live.is_some() {
        Ok(())
    } else {
        Err(AuthHttpError::Unauthorized)
    }
}

async fn alias_exists(
    tx: &Transaction<'_>,
    account_id: Uuid,
    sec1: &[u8],
) -> Result<bool, AuthHttpError> {
    let alias = tx.query_one(
        "SELECT EXISTS(SELECT 1 FROM line_owner_approval_keys WHERE account_id=$1 AND signing_key_sec1=$2) \
         OR EXISTS(SELECT 1 FROM device_keys WHERE account_id=$1 AND signing_key_sec1=$2) \
         OR EXISTS(SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=$1 AND signing_key_sec1=$2)",
        &[&account_id, &sec1],
    ).await.map_err(|_| AuthHttpError::Unavailable)?;
    Ok(alias.get(0))
}

pub(super) async fn challenge(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<ChallengeBody>,
) -> Result<Json<ChallengeResponse>, AuthHttpError> {
    let sec1 = key_bytes(&body.signing_key_sec1_b64)?;
    let fingerprint = sha256(&sec1);
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    if state.mfa_cipher.is_none() {
        return Err(AuthHttpError::Unavailable);
    }
    mfa_manage_budget(&client, &state, &owner).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let account_id = owner.tenant.account_id();
    tx.query_opt(
        "SELECT 1 FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account_id],
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    .ok_or(AuthHttpError::Unauthorized)?;
    locked_owner(&tx, &owner).await?;
    tx.execute(
        "WITH stale AS (SELECT id FROM sms_owner_key_challenges WHERE expires_at<clock_timestamp()-interval '1 hour' ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED) \
         DELETE FROM sms_owner_key_challenges c USING stale s WHERE c.id=s.id",
        &[],
    ).await.map_err(|_| AuthHttpError::Unavailable)?;
    if alias_exists(&tx, account_id, &sec1).await?
        || tx.query_opt("SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL", &[&account_id])
            .await.map_err(|_| AuthHttpError::Unavailable)?.is_some() {
        return Err(AuthHttpError::Forbidden);
    }
    tx.execute("UPDATE sms_owner_key_challenges SET consumed_at=clock_timestamp() WHERE account_id=$1 AND consumed_at IS NULL", &[&account_id])
        .await.map_err(|_| AuthHttpError::Unavailable)?;
    let id = Uuid::new_v4();
    let nonce: [u8; 32] = rand::random();
    let nonce_digest = sha256(&nonce);
    tx.execute(
        "INSERT INTO sms_owner_key_challenges(id,account_id,user_id,session_id,signing_key_sec1,fingerprint,nonce_digest,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '5 minutes')",
        &[&id,&account_id,&owner.user_id,&owner.session_id,&&sec1[..],&&fingerprint[..],&&nonce_digest[..]],
    ).await.map_err(|_| AuthHttpError::Unavailable)?;
    tx.commit().await.map_err(|_| AuthHttpError::Unavailable)?;
    Ok(Json(ChallengeResponse {
        challenge_id: id,
        nonce_b64: STANDARD.encode(nonce),
        fingerprint: fingerprint_string(&fingerprint),
    }))
}

pub(super) async fn register(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Result<StatusCode, AuthHttpError> {
    let nonce = decode_canonical::<32>(&body.nonce_b64)?;
    if body.signature_der_b64.len() > 108 || body.mfa_code.len() > 30 || body.challenge_id.is_nil()
    {
        return Err(AuthHttpError::BadRequest);
    }
    let signature_der = STANDARD
        .decode(&body.signature_der_b64)
        .map_err(|_| AuthHttpError::BadRequest)?;
    if !(8..=80).contains(&signature_der.len())
        || STANDARD.encode(&signature_der) != body.signature_der_b64
    {
        return Err(AuthHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    let cipher = state
        .mfa_cipher
        .as_deref()
        .ok_or(AuthHttpError::Unavailable)?;
    mfa_manage_budget(&client, &state, &owner).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let account_id = owner.tenant.account_id();
    tx.query_opt(
        "SELECT 1 FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account_id],
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    .ok_or(AuthHttpError::Unauthorized)?;
    locked_owner(&tx, &owner).await?;
    let row = tx
        .query_opt(
            "SELECT signing_key_sec1,fingerprint FROM sms_owner_key_challenges \
         WHERE id=$1 AND account_id=$2 AND user_id=$3 AND session_id=$4 \
         AND nonce_digest=$5 AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
            &[
                &body.challenge_id,
                &account_id,
                &owner.user_id,
                &owner.session_id,
                &&sha256(&nonce)[..],
            ],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
        .ok_or(AuthHttpError::Unauthorized)?;
    let sec1: Vec<u8> = row.get(0);
    let fingerprint: Vec<u8> = row.get(1);
    let fingerprint_bytes: [u8; 32] = fingerprint
        .as_slice()
        .try_into()
        .map_err(|_| AuthHttpError::Unavailable)?;
    if sha256(&sec1) != fingerprint_bytes || alias_exists(&tx, account_id, &sec1).await? {
        return Err(AuthHttpError::Forbidden);
    }
    let signature = Signature::from_der(&signature_der).map_err(|_| AuthHttpError::Unauthorized)?;
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| AuthHttpError::Unavailable)?;
    let statement = possession_statement(
        account_id,
        owner.user_id,
        owner.session_id,
        body.challenge_id,
        &nonce,
        &fingerprint_bytes,
    );
    if signature.to_der().as_bytes() != signature_der || key.verify(&statement, &signature).is_err()
    {
        return Err(AuthHttpError::Unauthorized);
    }
    if !mfa::verify_owner_step_up(&tx, cipher, &state.hasher, &owner, &body.mfa_code)
        .await
        .map_err(map_auth)?
    {
        tx.commit().await.map_err(|_| AuthHttpError::Unavailable)?;
        return Err(AuthHttpError::Unauthorized);
    }
    if tx
        .query_opt(
            "SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL",
            &[&account_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
        .is_some()
    {
        return Err(AuthHttpError::Forbidden);
    }
    tx.execute("INSERT INTO sms_line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) VALUES($1,$2,$3)",
        &[&account_id,&fingerprint,&sec1]).await.map_err(|_| AuthHttpError::Unavailable)?;
    tx.execute(
        "UPDATE sms_owner_key_challenges SET consumed_at=clock_timestamp() WHERE id=$1",
        &[&body.challenge_id],
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?;
    tx.execute("INSERT INTO sms_owner_key_audit(id,account_id,user_id,session_id,fingerprint,event) VALUES($1,$2,$3,$4,$5,'registered')",
        &[&Uuid::new_v4(),&account_id,&owner.user_id,&owner.session_id,&fingerprint]).await.map_err(|_| AuthHttpError::Unavailable)?;
    tx.commit().await.map_err(|_| AuthHttpError::Unavailable)?;
    Ok(StatusCode::CREATED)
}

pub(super) async fn list(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<KeyView>>, AuthHttpError> {
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let csrf_cookie = cookie(&headers, CSRF_COOKIE).ok_or(AuthHttpError::Forbidden)?;
    let csrf_header = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthHttpError::Forbidden)?;
    owner
        .require_csrf_token(&state.hasher, csrf_cookie, csrf_header)
        .map_err(map_auth)?;
    let rows = client.query(
        "SELECT fingerprint,revoked_at IS NULL FROM sms_line_owner_approval_keys WHERE account_id=$1 ORDER BY installed_at DESC LIMIT 100",
        &[&owner.tenant.account_id()],
    ).await.map_err(|_| AuthHttpError::Unavailable)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| KeyView {
                fingerprint: fingerprint_string(&row.get::<_, Vec<u8>>(0)),
                active: row.get(1),
            })
            .collect(),
    ))
}

pub(super) async fn revoke(
    State(state): State<Arc<AuthHttpState>>,
    Path(fingerprint): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RevokeBody>,
) -> Result<StatusCode, AuthHttpError> {
    let fingerprint = parse_fingerprint(&fingerprint)?;
    if body.mfa_code.len() > 30 {
        return Err(AuthHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    let cipher = state
        .mfa_cipher
        .as_deref()
        .ok_or(AuthHttpError::Unavailable)?;
    mfa_manage_budget(&client, &state, &owner).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let account_id = owner.tenant.account_id();
    tx.query_opt(
        "SELECT 1 FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account_id],
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    .ok_or(AuthHttpError::Unauthorized)?;
    locked_owner(&tx, &owner).await?;
    tx.query_opt("SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=$1 AND fingerprint=$2 AND revoked_at IS NULL FOR UPDATE",
        &[&account_id,&&fingerprint[..]]).await.map_err(|_| AuthHttpError::Unavailable)?.ok_or(AuthHttpError::NotFound)?;
    if !mfa::verify_owner_step_up(&tx, cipher, &state.hasher, &owner, &body.mfa_code)
        .await
        .map_err(map_auth)?
    {
        tx.commit().await.map_err(|_| AuthHttpError::Unavailable)?;
        return Err(AuthHttpError::Unauthorized);
    }
    // An active SMS line's identity cannot continue to advertise an active
    // generation once the key authorizing that generation is revoked.
    tx.execute(
        "UPDATE phone_lines l SET state='revoked' WHERE l.account_id=$1 AND l.state='active' \
         AND EXISTS(SELECT 1 FROM device_line_bindings b WHERE b.account_id=l.account_id \
         AND b.line_id=l.id AND b.generation=l.current_binding_generation \
         AND b.purpose='sms')",
        &[&account_id],
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?;
    let affected = tx.execute(
        "UPDATE device_line_bindings SET state='revoked' WHERE account_id=$1 AND purpose='sms' AND state IN ('active','pending')",
        &[&account_id],
    ).await.map_err(|_| AuthHttpError::Unavailable)?;
    tx.execute("UPDATE sms_line_owner_approval_keys SET revoked_at=clock_timestamp() WHERE account_id=$1 AND fingerprint=$2 AND revoked_at IS NULL",
        &[&account_id,&&fingerprint[..]]).await.map_err(|_| AuthHttpError::Unavailable)?;
    tx.execute("UPDATE sms_owner_key_challenges SET consumed_at=clock_timestamp() WHERE account_id=$1 AND consumed_at IS NULL", &[&account_id])
        .await.map_err(|_| AuthHttpError::Unavailable)?;
    tx.execute("INSERT INTO sms_owner_key_audit(id,account_id,user_id,session_id,fingerprint,event,affected_sms_bindings) VALUES($1,$2,$3,$4,$5,'revoked',$6)",
        &[&Uuid::new_v4(),&account_id,&owner.user_id,&owner.session_id,&&fingerprint[..],&(affected as i64)]).await.map_err(|_| AuthHttpError::Unavailable)?;
    tx.commit().await.map_err(|_| AuthHttpError::Unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
