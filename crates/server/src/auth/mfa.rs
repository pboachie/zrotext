// SPDX-License-Identifier: AGPL-3.0-only
//! Owner TOTP and one-use recovery codes. Database row locks serialize factor
//! use across API hubs. The TOTP encryption key is independent of auth tokens.

use super::{AuthError, SESSION_DAYS, SessionCredentials, SessionPrincipal, TokenHasher};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::Engine;
use rand::{Rng, rng};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio_postgres::{Client, Transaction};
use totp_rs::{Builder, Secret, Totp};
use uuid::Uuid;
use zeroize::Zeroizing;

const PENDING_MINUTES: i32 = 10;
const CHALLENGE_MINUTES: i32 = 5;
const RECOVERY_COUNT: usize = 10;
const FACTOR_FAILURES_PER_WINDOW: i32 = 5;

pub struct MfaCipher(Zeroizing<[u8; 32]>);

impl MfaCipher {
    pub fn new(key: Vec<u8>) -> Result<Self, AuthError> {
        let key = Zeroizing::new(key);
        let bytes: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidInput)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn associated_data(account_id: Uuid, user_id: Uuid) -> Vec<u8> {
        let mut data = b"zrotext-owner-totp-v1".to_vec();
        data.extend_from_slice(account_id.as_bytes());
        data.extend_from_slice(user_id.as_bytes());
        data
    }

    fn seal(
        &self,
        account_id: Uuid,
        user_id: Uuid,
        secret: &[u8; 20],
    ) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0[..]).map_err(|_| AuthError::Crypto)?;
        let mut nonce = [0u8; 12];
        rng().fill_bytes(&mut nonce);
        let nonce_array = Nonce::try_from(nonce.as_slice()).map_err(|_| AuthError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                &nonce_array,
                Payload {
                    msg: secret,
                    aad: &Self::associated_data(account_id, user_id),
                },
            )
            .map_err(|_| AuthError::Crypto)?;
        Ok((nonce.to_vec(), ciphertext))
    }

    fn open(
        &self,
        account_id: Uuid,
        user_id: Uuid,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Secret, AuthError> {
        if nonce.len() != 12 || ciphertext.len() != 36 {
            return Err(AuthError::Crypto);
        }
        let cipher = Aes256Gcm::new_from_slice(&self.0[..]).map_err(|_| AuthError::Crypto)?;
        let nonce = Nonce::try_from(nonce).map_err(|_| AuthError::Crypto)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad: &Self::associated_data(account_id, user_id),
                    },
                )
                .map_err(|_| AuthError::Crypto)?,
        );
        let bytes = Zeroizing::new(
            plaintext
                .as_slice()
                .try_into()
                .map_err(|_| AuthError::Crypto)?,
        );
        Ok(Secret::new_stack(*bytes))
    }
}

/// Called before account routes are mounted. Every enabled secret must open
/// under this site's key; a missing or mismatched key fails startup. Recovery
/// mode is an explicit operator override and performs no TOTP decryption.
pub async fn validate_runtime_key(
    client: &Client,
    cipher: Option<&MfaCipher>,
    recovery_only: bool,
) -> Result<(), AuthError> {
    if recovery_only {
        return Ok(());
    }
    let mut after = Uuid::nil();
    loop {
        let rows = client
            .query(
                "SELECT account_id,user_id,secret_nonce,secret_ciphertext FROM owner_mfa WHERE enabled_at IS NOT NULL AND account_id>$1 ORDER BY account_id LIMIT 128",
                &[&after],
            )
            .await?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in &rows {
            let account_id: Uuid = row.get(0);
            let user_id: Uuid = row.get(1);
            cipher.ok_or(AuthError::Crypto)?.open(
                account_id,
                user_id,
                &row.get::<_, Vec<u8>>(2),
                &row.get::<_, Vec<u8>>(3),
            )?;
            after = account_id;
        }
    }
}

pub struct Enrollment {
    pub secret_base32: String,
    pub provisioning_uri: String,
}

pub struct RecoveryCodes {
    pub codes: Vec<String>,
}

#[derive(Clone, Copy)]
pub struct Status {
    pub enabled: bool,
    pub pending: bool,
}

fn totp(secret: Secret, account_name: Option<&str>) -> Result<Totp, AuthError> {
    let builder = Builder::new().with_secret(secret);
    let builder = if let Some(name) = account_name {
        builder.with_account_name(name).with_issuer(Some("ZROtext"))
    } else {
        builder
    };
    builder.build().map_err(|_| AuthError::Crypto)
}

fn unix_seconds() -> Result<u64, AuthError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Crypto)?
        .as_secs())
}

fn accepted_step(
    secret: Secret,
    code: &str,
    last_step: i64,
    now: u64,
) -> Result<Option<i64>, AuthError> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let totp = totp(secret, None)?;
    let current = (now / 30) as i64;
    for step in [current - 1, current, current + 1] {
        if step <= last_step || step < 0 {
            continue;
        }
        let generated = totp.generate(step as u64 * 30).to_string();
        if bool::from(generated.as_bytes().ct_eq(code.as_bytes())) {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

fn recovery_hash(hasher: &TokenHasher, account_id: Uuid, user_id: Uuid, code: &str) -> [u8; 32] {
    let subject = format!("{account_id}:{user_id}:{code}");
    hasher.digest(b"mfa-recovery-v1", &subject)
}

fn valid_recovery_code(code: &str) -> bool {
    code.strip_prefix("zrc_")
        .and_then(|value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .ok()
        })
        .is_some_and(|bytes| bytes.len() == 16 && code.len() == 26)
}

fn new_recovery_code() -> String {
    let mut bytes = [0u8; 16];
    rng().fill_bytes(&mut bytes);
    format!(
        "zrc_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// The owner row is locked before checking or spending this budget. It is
/// shared by every challenge and management flow on every API site.
pub(super) async fn ensure_factor_budget(
    tx: &Transaction<'_>,
    account_id: Uuid,
    user_id: Uuid,
) -> Result<(), AuthError> {
    let row = tx
        .query_opt(
            "SELECT failed_attempts, failed_window_started_at > clock_timestamp()-interval '15 minutes' FROM owner_mfa WHERE account_id=$1 AND user_id=$2 FOR UPDATE",
            &[&account_id, &user_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    if row.get::<_, bool>(1) && row.get::<_, i32>(0) >= FACTOR_FAILURES_PER_WINDOW {
        return Err(AuthError::RateLimited);
    }
    Ok(())
}

pub(super) async fn record_failed_factor(
    tx: &Transaction<'_>,
    account_id: Uuid,
    user_id: Uuid,
) -> Result<(), AuthError> {
    tx.execute(
        "UPDATE owner_mfa SET failed_attempts=CASE WHEN failed_window_started_at <= clock_timestamp()-interval '15 minutes' THEN 1 ELSE failed_attempts+1 END, failed_window_started_at=CASE WHEN failed_window_started_at <= clock_timestamp()-interval '15 minutes' THEN clock_timestamp() ELSE failed_window_started_at END WHERE account_id=$1 AND user_id=$2",
        &[&account_id, &user_id],
    )
    .await?;
    Ok(())
}

async fn check_owner_password(
    client: &Client,
    principal: &SessionPrincipal,
    password: &str,
) -> Result<(), AuthError> {
    let row = client.query_opt(
        "SELECT u.password_hash FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id JOIN sessions s ON s.account_id=m.account_id AND s.user_id=u.id WHERE m.account_id=$1 AND u.id=$2 AND s.id=$3 AND s.revoked_at IS NULL AND s.expires_at>now() AND a.disabled_at IS NULL",
        &[&principal.tenant.account_id(), &principal.user_id, &principal.session_id],
    ).await?.ok_or(AuthError::Unauthorized)?;
    let stored: String = row.get(0);
    super::password_work::verify(password, Some(stored)).await
}

async fn require_live_session(
    tx: &Transaction<'_>,
    principal: &SessionPrincipal,
) -> Result<(), AuthError> {
    tx.query_opt(
        "SELECT id FROM sessions WHERE id=$1 AND account_id=$2 AND user_id=$3 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE",
        &[&principal.session_id, &principal.tenant.account_id(), &principal.user_id],
    ).await?.ok_or(AuthError::Unauthorized)?;
    Ok(())
}

pub async fn status(client: &Client, principal: &SessionPrincipal) -> Result<Status, AuthError> {
    let row = client.query_opt(
        "SELECT enabled_at IS NOT NULL, COALESCE(pending_expires_at>now(),false) FROM owner_mfa WHERE account_id=$1 AND user_id=$2",
        &[&principal.tenant.account_id(), &principal.user_id],
    ).await?;
    Ok(row.map_or(
        Status {
            enabled: false,
            pending: false,
        },
        |row| Status {
            enabled: row.get(0),
            pending: row.get(1),
        },
    ))
}

/// Fresh password is required, and confirmation is bound to this session for
/// ten minutes. Pending secrets are encrypted before persistence.
pub async fn begin_enrollment(
    client: &mut Client,
    cipher: &MfaCipher,
    principal: &SessionPrincipal,
    password: &str,
) -> Result<Enrollment, AuthError> {
    check_owner_password(client, principal, password).await?;
    let tx = client.transaction().await?;
    let user = tx.query_one(
        "SELECT u.email,u.mfa_enabled FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.id=$1 AND m.account_id=$2 FOR UPDATE OF u",
        &[&principal.user_id, &principal.tenant.account_id()],
    ).await?;
    if user.get::<_, bool>(1) {
        return Err(AuthError::Forbidden);
    }
    require_live_session(&tx, principal).await?;
    let account_id = principal.tenant.account_id();
    let secret = Secret::generate();
    let bytes = Zeroizing::new(
        secret
            .as_bytes()
            .try_into()
            .map_err(|_| AuthError::Crypto)?,
    );
    let (nonce, encrypted) = cipher.seal(account_id, principal.user_id, &bytes)?;
    let changed = tx.execute(
        "INSERT INTO owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,pending_expires_at,pending_session_id) VALUES($1,$2,$3,$4,now()+($5::integer * interval '1 minute'),$6) ON CONFLICT(account_id) DO UPDATE SET secret_nonce=EXCLUDED.secret_nonce,secret_ciphertext=EXCLUDED.secret_ciphertext,pending_expires_at=EXCLUDED.pending_expires_at,pending_session_id=EXCLUDED.pending_session_id,created_at=now() WHERE owner_mfa.enabled_at IS NULL AND owner_mfa.user_id=EXCLUDED.user_id",
        &[&account_id, &principal.user_id, &nonce, &encrypted, &PENDING_MINUTES, &principal.session_id],
    ).await?;
    if changed != 1 {
        return Err(AuthError::Forbidden);
    }
    let email: String = user.get(0);
    let uri = totp(secret.clone(), Some(&email))?
        .to_url()
        .map_err(|_| AuthError::Crypto)?;
    tx.commit().await?;
    Ok(Enrollment {
        secret_base32: secret.to_base32(),
        provisioning_uri: uri,
    })
}

pub async fn confirm_enrollment(
    client: &mut Client,
    cipher: &MfaCipher,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    code: &str,
) -> Result<RecoveryCodes, AuthError> {
    let tx = client.transaction().await?;
    let user = tx
        .query_opt(
            "SELECT mfa_enabled FROM users WHERE id=$1 FOR UPDATE",
            &[&principal.user_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    if user.get::<_, bool>(0) {
        return Err(AuthError::Forbidden);
    }
    require_live_session(&tx, principal).await?;
    let account_id = principal.tenant.account_id();
    let row = tx.query_opt(
        "SELECT secret_nonce,secret_ciphertext,last_accepted_step FROM owner_mfa WHERE account_id=$1 AND user_id=$2 AND pending_session_id=$3 AND enabled_at IS NULL AND pending_expires_at>now() FOR UPDATE",
        &[&account_id, &principal.user_id, &principal.session_id],
    ).await?.ok_or(AuthError::Forbidden)?;
    ensure_factor_budget(&tx, account_id, principal.user_id).await?;
    let secret = cipher.open(
        account_id,
        principal.user_id,
        &row.get::<_, Vec<u8>>(0),
        &row.get::<_, Vec<u8>>(1),
    )?;
    let Some(step) = accepted_step(secret, code, row.get(2), unix_seconds()?)? else {
        record_failed_factor(&tx, account_id, principal.user_id).await?;
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    };
    tx.execute(
        "UPDATE owner_mfa SET enabled_at=now(),pending_expires_at=NULL,pending_session_id=NULL,last_accepted_step=$3 WHERE account_id=$1 AND user_id=$2",
        &[&account_id, &principal.user_id, &step],
    ).await?;
    tx.execute(
        "UPDATE users SET mfa_enabled=true WHERE id=$1",
        &[&principal.user_id],
    )
    .await?;
    tx.execute(
        "UPDATE sessions SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND id<>$3 AND revoked_at IS NULL",
        &[&account_id, &principal.user_id, &principal.session_id],
    ).await?;
    let mut codes = Vec::with_capacity(RECOVERY_COUNT);
    for _ in 0..RECOVERY_COUNT {
        let code = new_recovery_code();
        let hash = recovery_hash(hasher, account_id, principal.user_id, &code);
        tx.execute(
            "INSERT INTO owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)",
            &[&account_id, &principal.user_id, &&hash[..]],
        )
        .await?;
        codes.push(code);
    }
    tx.commit().await?;
    Ok(RecoveryCodes { codes })
}

pub async fn begin_login_challenge(
    client: &Client,
    hasher: &TokenHasher,
    account_id: Uuid,
    user_id: Uuid,
    password: &str,
) -> Result<String, AuthError> {
    let row = client
        .query_opt(
            "SELECT u.password_hash FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$1 AND m.account_id=$2 AND u.mfa_enabled AND a.disabled_at IS NULL",
            &[&user_id, &account_id],
        )
        .await?
        .ok_or(AuthError::InvalidCredentials)?;
    let stored: String = row.get(0);
    super::password_work::verify(password, Some(stored.clone())).await?;
    let token = super::random_token("ztm_");
    let hash = hasher.digest(b"mfa-login-challenge-v1", &token);
    let inserted = client.execute(
        "INSERT INTO owner_mfa_login_challenges(id,account_id,user_id,token_hash,expires_at) SELECT $1,$2,$3,$4,now()+($5::integer * interval '1 minute') FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$3 AND m.account_id=$2 AND u.password_hash=$6 AND u.mfa_enabled AND a.disabled_at IS NULL FOR UPDATE OF u",
        &[&Uuid::new_v4(), &account_id, &user_id, &&hash[..], &CHALLENGE_MINUTES, &stored],
    ).await?;
    if inserted != 1 {
        return Err(AuthError::InvalidCredentials);
    }
    Ok(token)
}

/// Cheap indexed probe used only after anonymous callers exhaust the MFA
/// completion budget. It never consumes the challenge or checks a factor.
pub async fn login_challenge_is_live(
    client: &Client,
    hasher: &TokenHasher,
    challenge_token: &str,
) -> Result<bool, AuthError> {
    if !super::valid_token(challenge_token, "ztm_") {
        return Ok(false);
    }
    let hash = hasher.digest(b"mfa-login-challenge-v1", challenge_token);
    Ok(client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM owner_mfa_login_challenges WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>now())",
            &[&&hash[..]],
        )
        .await?
        .get(0))
}

/// Bounded maintenance for consumed and expired challenges. Safe across hubs.
pub async fn prune_expired_challenges(client: &Client) -> Result<u64, AuthError> {
    Ok(client.execute(
        "WITH stale AS (SELECT id FROM owner_mfa_login_challenges WHERE expires_at<now()-interval '1 hour' OR consumed_at<now()-interval '1 hour' ORDER BY expires_at LIMIT 500 FOR UPDATE SKIP LOCKED) DELETE FROM owner_mfa_login_challenges c USING stale s WHERE c.id=s.id",
        &[],
    ).await?)
}

pub(super) async fn use_factor(
    tx: &Transaction<'_>,
    cipher: Option<&MfaCipher>,
    hasher: &TokenHasher,
    account_id: Uuid,
    user_id: Uuid,
    code: &str,
) -> Result<bool, AuthError> {
    let row = tx.query_opt(
        "SELECT secret_nonce,secret_ciphertext,last_accepted_step FROM owner_mfa WHERE account_id=$1 AND user_id=$2 AND enabled_at IS NOT NULL FOR UPDATE",
        &[&account_id, &user_id],
    ).await?.ok_or(AuthError::Unauthorized)?;
    if valid_recovery_code(code) {
        let hash = recovery_hash(hasher, account_id, user_id, code);
        return Ok(tx.execute(
            "UPDATE owner_mfa_recovery_codes SET used_at=now() WHERE account_id=$1 AND user_id=$2 AND code_hash=$3 AND used_at IS NULL",
            &[&account_id, &user_id, &&hash[..]],
        ).await? == 1);
    }
    let cipher = cipher.ok_or(AuthError::Crypto)?;
    let secret = cipher.open(
        account_id,
        user_id,
        &row.get::<_, Vec<u8>>(0),
        &row.get::<_, Vec<u8>>(1),
    )?;
    let Some(step) = accepted_step(secret, code, row.get(2), unix_seconds()?)? else {
        return Ok(false);
    };
    tx.execute(
        "UPDATE owner_mfa SET last_accepted_step=$3 WHERE account_id=$1 AND user_id=$2",
        &[&account_id, &user_id, &step],
    )
    .await?;
    Ok(true)
}

/// Verify a fresh factor for a high-trust owner mutation inside the caller's
/// transaction. A false result records the shared failure budget; the caller
/// must commit that transaction before returning an authentication failure.
pub(crate) async fn verify_owner_step_up(
    tx: &Transaction<'_>,
    cipher: &MfaCipher,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    code: &str,
) -> Result<bool, AuthError> {
    let account_id = principal.tenant.account_id();
    let owner = tx.query_opt(
        "SELECT u.mfa_enabled FROM users u JOIN memberships m ON m.user_id=u.id AND m.account_id=$1 \
         JOIN accounts a ON a.id=m.account_id WHERE u.id=$2 AND m.role='owner' \
         AND a.disabled_at IS NULL FOR SHARE OF u,m,a",
        &[&account_id, &principal.user_id],
    ).await?.ok_or(AuthError::Unauthorized)?;
    if !owner.get::<_, bool>(0) {
        return Err(AuthError::Forbidden);
    }
    require_live_session(tx, principal).await?;
    ensure_factor_budget(tx, account_id, principal.user_id).await?;
    let valid = use_factor(
        tx,
        Some(cipher),
        hasher,
        account_id,
        principal.user_id,
        code,
    )
    .await?;
    if !valid {
        record_failed_factor(tx, account_id, principal.user_id).await?;
    }
    Ok(valid)
}

pub async fn complete_login(
    client: &mut Client,
    cipher: Option<&MfaCipher>,
    hasher: &TokenHasher,
    challenge_token: &str,
    code: &str,
) -> Result<SessionCredentials, AuthError> {
    if !super::valid_token(challenge_token, "ztm_") {
        return Err(AuthError::Unauthorized);
    }
    let hash = hasher.digest(b"mfa-login-challenge-v1", challenge_token);
    let identity = client
        .query_opt(
            "SELECT account_id,user_id FROM owner_mfa_login_challenges WHERE token_hash=$1",
            &[&&hash[..]],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    let account_id: Uuid = identity.get(0);
    let user_id: Uuid = identity.get(1);
    let tx = client.transaction().await?;
    let user = tx.query_opt(
        "SELECT u.mfa_enabled FROM users u JOIN memberships m ON m.user_id=u.id JOIN accounts a ON a.id=m.account_id WHERE u.id=$1 AND m.account_id=$2 AND a.disabled_at IS NULL FOR UPDATE OF u",
        &[&user_id, &account_id],
    ).await?.ok_or(AuthError::Unauthorized)?;
    if !user.get::<_, bool>(0) {
        return Err(AuthError::Unauthorized);
    }
    let challenge = tx.query_opt(
        "SELECT attempts FROM owner_mfa_login_challenges WHERE token_hash=$1 AND account_id=$2 AND user_id=$3 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE",
        &[&&hash[..], &account_id, &user_id],
    ).await?.ok_or(AuthError::Unauthorized)?;
    if challenge.get::<_, i32>(0) >= 5 {
        return Err(AuthError::Unauthorized);
    }
    ensure_factor_budget(&tx, account_id, user_id).await?;
    let valid = use_factor(&tx, cipher, hasher, account_id, user_id, code).await?;
    if !valid {
        record_failed_factor(&tx, account_id, user_id).await?;
        tx.execute(
            "UPDATE owner_mfa_login_challenges SET attempts=attempts+1 WHERE token_hash=$1",
            &[&&hash[..]],
        )
        .await?;
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    }
    let token = super::random_token("zts_");
    let csrf_token = super::random_token("ztc_");
    let token_hash = hasher.digest(b"session-v1", &token);
    let csrf_hash = hasher.digest(b"csrf-v1", &csrf_token);
    let id = Uuid::new_v4();
    tx.execute(
        "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,now()+($6::integer * interval '1 day'))",
        &[&id, &account_id, &user_id, &&token_hash[..], &&csrf_hash[..], &SESSION_DAYS],
    ).await?;
    tx.execute(
        "UPDATE owner_mfa_login_challenges SET consumed_at=now() WHERE token_hash=$1",
        &[&&hash[..]],
    )
    .await?;
    tx.commit().await?;
    Ok(SessionCredentials {
        id,
        token,
        csrf_token,
    })
}

/// Disabling requires both the current password and a fresh TOTP or unused
/// recovery code. Other sessions and outstanding challenges are invalidated.
pub async fn disable(
    client: &mut Client,
    cipher: Option<&MfaCipher>,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    password: &str,
    code: &str,
) -> Result<(), AuthError> {
    check_owner_password(client, principal, password).await?;
    let account_id = principal.tenant.account_id();
    let tx = client.transaction().await?;
    // Use the same account lock as SMS key registration/revocation. Disabling
    // MFA cannot strand an active approval key whose revocation needs MFA.
    tx.query_opt(
        "SELECT 1 FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account_id],
    )
    .await?
    .ok_or(AuthError::Unauthorized)?;
    // Older isolated auth fixtures predate migration 033; production applies
    // all migrations before accepting requests.
    let sms_key_table: bool = tx
        .query_one(
            "SELECT to_regclass('sms_line_owner_approval_keys') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    if sms_key_table
        && tx
            .query_opt(
                "SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL",
                &[&account_id],
            )
            .await?
            .is_some()
    {
        return Err(AuthError::SmsOwnerKeyActive);
    }
    let user = tx
        .query_opt(
            "SELECT mfa_enabled FROM users WHERE id=$1 FOR UPDATE",
            &[&principal.user_id],
        )
        .await?
        .ok_or(AuthError::Unauthorized)?;
    if !user.get::<_, bool>(0) {
        return Err(AuthError::Forbidden);
    }
    require_live_session(&tx, principal).await?;
    ensure_factor_budget(&tx, account_id, principal.user_id).await?;
    if !use_factor(&tx, cipher, hasher, account_id, principal.user_id, code).await? {
        record_failed_factor(&tx, account_id, principal.user_id).await?;
        tx.commit().await?;
        return Err(AuthError::InvalidCredentials);
    }
    tx.execute(
        "UPDATE users SET mfa_enabled=false WHERE id=$1",
        &[&principal.user_id],
    )
    .await?;
    tx.execute(
        "DELETE FROM owner_mfa WHERE account_id=$1 AND user_id=$2",
        &[&account_id, &principal.user_id],
    )
    .await?;
    tx.execute("UPDATE owner_mfa_login_challenges SET consumed_at=now() WHERE account_id=$1 AND user_id=$2 AND consumed_at IS NULL", &[&account_id, &principal.user_id]).await?;
    tx.execute("UPDATE sessions SET revoked_at=now() WHERE account_id=$1 AND user_id=$2 AND id<>$3 AND revoked_at IS NULL", &[&account_id, &principal.user_id, &principal.session_id]).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
