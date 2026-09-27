// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant owned transactions for generation-one enrollment. No route calls this.
//!
//! The future authenticated adapter supplies a principal and configured origin,
//! enforces request authentication/CSRF, and independently establishes owner root
//! custody and comparison. Possession alone cannot establish those properties.
//! All database identity and time fences are checked again here. An enrollment
//! receipt is historical evidence, never a current dispatch authorization.

use crate::{
    auth::{AuthError, SessionPrincipal, TokenHasher, abuse_limits, mfa},
    sealed_root_enrollment::{self as proof, Challenge},
};
use rand::{Rng, rng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio_postgres::{Client, IsolationLevel, Transaction};
use uuid::Uuid;

// Local enrollment policy; this does not change general session authentication.
const ROOT_ENROLLMENT_IDLE_HOURS: i32 = 72;

#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("root ceremony rejected: {0}")]
    Rejected(&'static str),
    #[error("root ceremony authentication failed")]
    Authentication(#[from] AuthError),
    #[error("root ceremony database operation failed")]
    Database(#[from] tokio_postgres::Error),
}
impl From<&'static str> for CeremonyError {
    fn from(value: &'static str) -> Self {
        Self::Rejected(value)
    }
}

pub struct IssuedChallenge {
    pub challenge: Challenge,
    pub unsigned: Vec<u8>,
    pub root_pin: [u8; 94],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Receipt {
    pub account_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub challenge_id: Uuid,
    pub root_pin: Vec<u8>,
    pub root_fingerprint: Vec<u8>,
    pub completed_ms: i64,
}

async fn begin(client: &mut Client) -> Result<Transaction<'_>, CeremonyError> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    Ok(tx)
}

async fn clock(tx: &Transaction<'_>, previous: u64) -> Result<u64, CeremonyError> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    if now <= 0 || (now as u64) < previous {
        return Err("database time regressed".into());
    }
    Ok(now as u64)
}

/// Never acquire an existing authority lock after the account lock. Admission
/// uses authority -> account; absent genesis rejects existing history by SELECT.
async fn owner_locks(
    tx: &Transaction<'_>,
    p: &SessionPrincipal,
    genesis: bool,
) -> Result<(), CeremonyError> {
    let account = p.tenant.account_id();
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account],
    )
    .await?
    .ok_or(CeremonyError::Rejected("inactive account"))?;
    if genesis
        && tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM sealed_manifest_authorities WHERE account_id=$1) \
         OR EXISTS(SELECT 1 FROM sealed_root_enrollments WHERE account_id=$1)",
                &[&account],
            )
            .await?
            .get::<_, bool>(0)
    {
        return Err("root enrollment history exists".into());
    }
    tx.query_opt("SELECT id FROM users WHERE id=$1 AND email_verified_at IS NOT NULL AND mfa_enabled FOR UPDATE",
        &[&p.user_id]).await?.ok_or(CeremonyError::Rejected("verified MFA owner required"))?;
    tx.query_opt("SELECT user_id FROM memberships WHERE account_id=$1 AND user_id=$2 AND role='owner' FOR SHARE",
        &[&account, &p.user_id]).await?.ok_or(CeremonyError::Rejected("owner membership"))?;
    tx.query_opt(
        "SELECT id FROM sessions WHERE id=$1 AND account_id=$2 AND user_id=$3 FOR UPDATE",
        &[&p.session_id, &account, &p.user_id],
    )
    .await?
    .ok_or(CeremonyError::Rejected("session identity"))?;
    tx.query_opt("SELECT account_id FROM owner_mfa WHERE account_id=$1 AND user_id=$2 AND enabled_at IS NOT NULL FOR UPDATE",
        &[&account, &p.user_id]).await?.ok_or(CeremonyError::Rejected("enabled MFA required"))?;
    live(tx, p).await
}

async fn live(tx: &Transaction<'_>, p: &SessionPrincipal) -> Result<(), CeremonyError> {
    if !tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM accounts a JOIN memberships m ON m.account_id=a.id \
         JOIN users u ON u.id=m.user_id JOIN sessions s ON s.account_id=a.id AND s.user_id=u.id \
         JOIN owner_mfa f ON f.account_id=a.id AND f.user_id=u.id \
         WHERE a.id=$1 AND u.id=$2 AND s.id=$3 AND a.disabled_at IS NULL AND m.role='owner' \
         AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND f.enabled_at IS NOT NULL \
         AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
         AND COALESCE(s.last_used_at,s.created_at)>clock_timestamp()-make_interval(hours=>$4))",
            &[
                &p.tenant.account_id(),
                &p.user_id,
                &p.session_id,
                &ROOT_ENROLLMENT_IDLE_HOURS,
            ],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Err("owner/session/MFA fence".into());
    }
    Ok(())
}

/// Replace the one current challenge, retiring any previous proof. The existing
/// shared owner-management budget is charged after identity locks and committed
/// even when it rejects issuance. No factor or authority is consumed here.
pub async fn issue_challenge(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    configured_origin: &str,
    root_pin: [u8; 94],
) -> Result<IssuedChallenge, CeremonyError> {
    if !proof::canonical_origin(configured_origin) {
        return Err("configured origin".into());
    }
    let account = principal.tenant.account_id();
    let fingerprint = proof::root_fingerprint(&root_pin, account.as_bytes())?;
    let tx = begin(client).await?;
    owner_locks(&tx, principal, true).await?;
    if !abuse_limits::consume_owner_management(&tx, hasher, &principal.user_id.to_string()).await? {
        tx.commit().await?;
        return Err(AuthError::RateLimited.into());
    }
    let previous = tx
        .query_opt(
            "SELECT issued_ms FROM sealed_root_challenges WHERE account_id=$1 FOR UPDATE",
            &[&account],
        )
        .await?
        .map_or(0, |r| r.get::<_, i64>(0) as u64);
    let issued = clock(&tx, previous).await?;
    let mut nonce = [0; 32];
    rng().fill_bytes(&mut nonce);
    let challenge = Challenge {
        account_id: *account.as_bytes(),
        user_id: *principal.user_id.as_bytes(),
        session_id: *principal.session_id.as_bytes(),
        challenge_id: *Uuid::new_v4().as_bytes(),
        nonce,
        root_fingerprint: fingerprint,
        issued_ms: issued,
        expires_ms: issued + 300_000,
        origin: configured_origin.to_owned(),
    };
    let unsigned = proof::encode(&challenge)?;
    let digest = Sha256::digest(nonce);
    tx.execute("INSERT INTO sealed_root_challenges(account_id,challenge_id,user_id,session_id,root_pin,root_fingerprint,nonce_digest,origin,issued_ms,expires_ms) \
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(account_id) DO UPDATE SET \
        challenge_id=EXCLUDED.challenge_id,user_id=EXCLUDED.user_id,session_id=EXCLUDED.session_id,root_pin=EXCLUDED.root_pin, \
        root_fingerprint=EXCLUDED.root_fingerprint,nonce_digest=EXCLUDED.nonce_digest,origin=EXCLUDED.origin, \
        issued_ms=EXCLUDED.issued_ms,expires_ms=EXCLUDED.expires_ms,consumed_ms=NULL",
        &[&account, &Uuid::from_bytes(challenge.challenge_id), &principal.user_id, &principal.session_id,
          &&root_pin[..], &&fingerprint[..], &&digest[..], &configured_origin, &(issued as i64),
          &(challenge.expires_ms as i64)]).await?;
    live(&tx, principal).await?;
    if clock(&tx, issued).await? >= challenge.expires_ms {
        return Err("challenge expired".into());
    }
    tx.commit().await?;
    Ok(IssuedChallenge {
        challenge,
        unsigned,
        root_pin,
    })
}

/// Complete only the exact current database challenge. Expected identity, pin,
/// origin and expiry come from that locked row; the proof contributes only its
/// hash-matched nonce. Invalid factors commit only the existing failure budget.
/// Other failures roll back every write, including one-use factor consumption.
pub struct Completion<'a> {
    pub unsigned: &'a [u8],
    pub signature: &'a [u8],
    pub factor: &'a str,
}

pub async fn complete_genesis(
    client: &mut Client,
    hasher: &TokenHasher,
    cipher: &mfa::MfaCipher,
    principal: &SessionPrincipal,
    configured_origin: &str,
    completion: Completion<'_>,
) -> Result<Receipt, CeremonyError> {
    let Completion {
        unsigned,
        signature,
        factor,
    } = completion;
    let received = proof::parse(unsigned)?;
    if !proof::canonical_origin(configured_origin) || factor.len() > 26 {
        return Err("ceremony input".into());
    }
    let account = principal.tenant.account_id();
    let tx = begin(client).await?;
    owner_locks(&tx, principal, true).await?;
    let row = tx.query_opt("SELECT challenge_id,user_id,session_id,root_pin,root_fingerprint,nonce_digest,origin,issued_ms,expires_ms \
        FROM sealed_root_challenges WHERE account_id=$1 AND consumed_ms IS NULL FOR UPDATE", &[&account])
        .await?.ok_or(CeremonyError::Rejected("missing/consumed challenge"))?;
    let root_pin: Vec<u8> = row.get(3);
    let fingerprint: Vec<u8> = row.get(4);
    let nonce_digest: Vec<u8> = row.get(5);
    let origin: String = row.get(6);
    let issued: i64 = row.get(7);
    let expires: i64 = row.get(8);
    if row.get::<_, Uuid>(1) != principal.user_id
        || row.get::<_, Uuid>(2) != principal.session_id
        || origin != configured_origin
        || !bool::from(
            nonce_digest
                .as_slice()
                .ct_eq(&Sha256::digest(received.nonce)),
        )
    {
        return Err("challenge owner/session/origin/nonce".into());
    }
    let expected = Challenge {
        account_id: *account.as_bytes(),
        user_id: *principal.user_id.as_bytes(),
        session_id: *principal.session_id.as_bytes(),
        challenge_id: *row.get::<_, Uuid>(0).as_bytes(),
        nonce: received.nonce,
        root_fingerprint: fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| "stored fingerprint")?,
        issued_ms: issued as u64,
        expires_ms: expires as u64,
        origin,
    };
    let now = clock(&tx, issued as u64).await?;
    proof::verify(&root_pin, unsigned, signature, &expected, now)?;
    live(&tx, principal).await?;
    let factor_now = clock(&tx, now).await?;
    let Some(consumed) =
        mfa::consume_ceremony_factor(&tx, cipher, hasher, principal, factor, factor_now).await?
    else {
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials.into());
    };
    tx.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) \
        VALUES($1,$2,$3,1,decode(repeat('00',32),'hex'))", &[&account, &root_pin, &fingerprint]).await?;
    let completed = clock(&tx, factor_now).await?;
    tx.execute(
        "UPDATE sealed_root_challenges SET consumed_ms=$2 WHERE account_id=$1",
        &[&account, &(completed as i64)],
    )
    .await?;
    let receipt = Receipt {
        account_id: account,
        user_id: principal.user_id,
        session_id: principal.session_id,
        challenge_id: Uuid::from_bytes(expected.challenge_id),
        root_pin,
        root_fingerprint: fingerprint,
        completed_ms: completed as i64,
    };
    tx.execute("INSERT INTO sealed_root_receipts(account_id,user_id,session_id,challenge_id,root_pin,root_fingerprint,completed_ms) \
        VALUES($1,$2,$3,$4,$5,$6,$7)", &[&account, &receipt.user_id, &receipt.session_id, &receipt.challenge_id,
        &receipt.root_pin, &receipt.root_fingerprint, &receipt.completed_ms]).await?;
    live(&tx, principal).await?;
    let final_time = clock(&tx, completed).await?;
    proof::verify(
        &receipt.root_pin,
        unsigned,
        signature,
        &expected,
        final_time,
    )?;
    if !consumed.current_at(final_time) {
        return Err("factor expired after wait".into());
    }
    tx.commit().await?;
    Ok(receipt)
}

/// Read historical enrollment for an authenticated owner after a lost response.
/// The caller must compare the returned exact public pin with its intended pin.
/// This never repins, consumes a factor, or promises that authority remains live.
pub async fn read_receipt(
    client: &mut Client,
    principal: &SessionPrincipal,
) -> Result<Option<Receipt>, CeremonyError> {
    let tx = begin(client).await?;
    owner_locks(&tx, principal, false).await?;
    let row = tx.query_opt("SELECT account_id,user_id,session_id,challenge_id,root_pin,root_fingerprint,completed_ms \
        FROM sealed_root_receipts WHERE account_id=$1", &[&principal.tenant.account_id()]).await?;
    let receipt = row.map(|r| Receipt {
        account_id: r.get(0),
        user_id: r.get(1),
        session_id: r.get(2),
        challenge_id: r.get(3),
        root_pin: r.get(4),
        root_fingerprint: r.get(5),
        completed_ms: r.get(6),
    });
    live(&tx, principal).await?;
    tx.commit().await?;
    Ok(receipt)
}

#[cfg(test)]
mod tests;
