// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine password and one-use factor verification over an authenticated held
//! ordinary owner. This is not root possession, elected state or effect authority.
use super::HeldOrdinaryOwner03;
use crate::auth::{AuthError, TokenHasher, abuse_limits, mfa, password_work};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("held owner step-up authentication unavailable")]
    Authentication(#[from] super::Error),
    #[error("held owner step-up credential unavailable")]
    Credential(#[from] AuthError),
    #[error("held owner step-up storage unavailable")]
    Database(#[from] tokio_postgres::Error),
    #[error("held owner step-up expired or changed")]
    Refused,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    InvalidCredentials,
    RateLimited,
}

/// A rejection carries no proof. Its pre-effect failure budget must be committed
/// before returning an HTTP refusal. Storage/refusal errors roll back instead.
#[must_use]
pub enum Outcome<'held, 'db> {
    Verified(Box<HeldStepUp03<'held, 'db>>),
    Rejected(Rejection),
}

/// Not cloneable, serializable or detached from its transaction. A later caller
/// must move this proof into the exact election transaction, revalidate just
/// before mutation and roll back factor consumption with any failed transition.
pub struct HeldStepUp03<'held, 'db> {
    owner: HeldOrdinaryOwner03<'held, 'db>,
    factor: mfa::held_profile03::HeldFactor,
    checked_ms: u64,
    expires_ms: u64,
}

impl HeldStepUp03<'_, '_> {
    pub(crate) fn selected_identity(&self) -> super::Selector {
        self.owner.selected_identity()
    }
    pub(crate) fn uses_transaction(&self, tx: &tokio_postgres::Transaction<'_>) -> bool {
        self.owner.uses_transaction(tx)
    }
    pub(crate) fn checked_primary_ms(&self) -> u64 {
        self.checked_ms
    }
    pub(crate) fn owner_session_deadline_ms(&self) -> u64 {
        self.owner.session_deadline_ms()
    }
    pub fn owner_identity(&self) -> &[u8] {
        self.owner.canonical_identity()
    }

    pub fn owner_identity_digest(&self) -> &[u8; 32] {
        self.owner.identity_digest()
    }

    pub fn origin_digest(&self) -> &[u8; 32] {
        self.owner.origin_digest()
    }

    pub fn root_fingerprint(&self) -> &[u8; 32] {
        self.owner.root_fingerprint()
    }

    pub fn selection_epoch(&self) -> u64 {
        self.owner.selection_epoch()
    }

    /// Upper temporal bound for the held owner, consumed factor and ceremony.
    /// All exact record/state checks are still required at the time of use.
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_ms
    }

    pub async fn revalidate(&mut self) -> Result<(), Error> {
        self.owner.revalidate().await?;
        if !self.factor.state_matches(self.owner.tx).await? {
            return Err(Error::Refused);
        }
        let now = clock(
            self.owner.tx,
            self.checked_ms.max(self.owner.checked_at_ms()),
        )
        .await?;
        if now >= self.expires_ms || !self.factor.current_at(now) {
            return Err(Error::Refused);
        }
        self.checked_ms = now;
        Ok(())
    }
}

async fn clock(tx: &tokio_postgres::Transaction<'_>, floor: u64) -> Result<u64, Error> {
    let row = tx.query_one("SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint", &[]).await?;
    let now = u64::try_from(row.try_get::<_, i64>(1)?).map_err(|_| Error::Refused)?;
    if row.try_get::<_, bool>(0)? || now == 0 || now < floor {
        return Err(Error::Refused);
    }
    Ok(now)
}

/// Verify only after ordinary cookie/CSRF authentication and before any effect
/// writes. The caller also owns endpoint request admission/management budgets;
/// this helper serializes the existing shared factor-failure budget and charges
/// incorrect passwords as well, before another password guess can be admitted.
/// It never trusts an unlocked principal's freshness timestamp.
pub async fn verify<'held, 'db>(
    mut owner: HeldOrdinaryOwner03<'held, 'db>,
    hasher: &TokenHasher,
    cipher: &mfa::MfaCipher,
    password: &str,
    factor: &str,
) -> Result<Outcome<'held, 'db>, Error> {
    owner.revalidate().await?;
    let selector = owner.selector;
    // Fail immediately rather than wait while upgrading an existing SHARE
    // witness. This exclusive row lock serializes failure checks and TOTP use.
    let row = owner.tx.query_opt("SELECT account_id FROM public.owner_mfa WHERE account_id=$1 AND user_id=$2 AND enabled_at IS NOT NULL FOR UPDATE NOWAIT", &[&selector.account, &selector.user]).await?.ok_or(Error::Refused)?;
    let _: uuid::Uuid = row.try_get(0)?;
    let subject = selector.user.to_string();
    if !abuse_limits::held_factor_budget_open(owner.tx, hasher, &subject).await? {
        return Ok(Outcome::Rejected(Rejection::RateLimited));
    }
    let stored: String = owner
        .tx
        .query_one(
            "SELECT password_hash FROM public.users WHERE id=$1",
            &[&selector.user],
        )
        .await?
        .try_get(0)?;
    let password_result = password_work::verify(password, Some(stored)).await;
    if matches!(password_result, Err(AuthError::InvalidCredentials)) || factor.len() > 26 {
        abuse_limits::record_held_factor_failure(owner.tx, hasher, &subject).await?;
        owner.revalidate().await?;
        return Ok(Outcome::Rejected(Rejection::InvalidCredentials));
    }
    password_result?;
    owner.revalidate().await?;
    let now = clock(owner.tx, owner.checked_at_ms()).await?;
    let Some(factor) = mfa::held_profile03::consume(
        owner.tx,
        cipher,
        hasher,
        selector.account,
        selector.user,
        factor,
        now,
    )
    .await?
    else {
        abuse_limits::record_held_factor_failure(owner.tx, hasher, &subject).await?;
        owner.revalidate().await?;
        return Ok(Outcome::Rejected(Rejection::InvalidCredentials));
    };
    let expires_ms = now
        .checked_add(300_000)
        .ok_or(Error::Refused)?
        .min(owner.session_deadline_ms())
        .min(factor.deadline_ms()?.unwrap_or(u64::MAX));
    let mut proof = HeldStepUp03 {
        owner,
        factor,
        checked_ms: now,
        expires_ms,
    };
    proof.revalidate().await?;
    Ok(Outcome::Verified(Box::new(proof)))
}
