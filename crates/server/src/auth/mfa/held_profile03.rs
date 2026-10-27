// SPDX-License-Identifier: AGPL-3.0-only
//! Factor consumption for the fixed-public held profile transaction. Legacy
//! fixture-scoped callers keep their existing namespace behavior unchanged.
use super::*;

enum State {
    Totp(i64),
    Recovery([u8; 32], [u8; 8]),
}

pub(crate) struct HeldFactor {
    account: Uuid,
    user: Uuid,
    factor: ConsumedFactor,
    state: State,
}

impl HeldFactor {
    pub(crate) fn current_at(&self, now_ms: u64) -> bool {
        self.factor.current_at(now_ms)
    }

    pub(crate) fn deadline_ms(&self) -> Result<Option<u64>, AuthError> {
        self.factor
            .step
            .map(|step| {
                u64::try_from(step)
                    .ok()
                    .and_then(|step| step.checked_add(2))
                    .and_then(|step| step.checked_mul(30_000))
                    .ok_or(AuthError::Crypto)
            })
            .transpose()
    }

    pub(crate) async fn state_matches(&self, tx: &Transaction<'_>) -> Result<bool, AuthError> {
        Ok(match &self.state {
            State::Totp(step) => tx.query_opt("SELECT 1 FROM public.owner_mfa WHERE account_id=$1 AND user_id=$2 AND enabled_at IS NOT NULL AND last_accepted_step=$3", &[&self.account, &self.user, step]).await?.is_some(),
            State::Recovery(hash, wire) => match tx.query_opt("SELECT pg_catalog.timestamptz_send(used_at) FROM public.owner_mfa_recovery_codes WHERE account_id=$1 AND user_id=$2 AND code_hash=$3 AND used_at IS NOT NULL", &[&self.account, &self.user, &&hash[..]]).await? {
                Some(row) => row.try_get::<_, Vec<u8>>(0)? == wire.as_slice(),
                None => false,
            },
        })
    }
}

pub(crate) async fn consume(
    tx: &Transaction<'_>,
    cipher: &MfaCipher,
    hasher: &TokenHasher,
    account: Uuid,
    user: Uuid,
    code: &str,
    now_ms: u64,
) -> Result<Option<HeldFactor>, AuthError> {
    let row = tx.query_opt("SELECT secret_nonce,secret_ciphertext,last_accepted_step FROM public.owner_mfa WHERE account_id=$1 AND user_id=$2 AND enabled_at IS NOT NULL FOR UPDATE NOWAIT", &[&account, &user]).await?.ok_or(AuthError::Unauthorized)?;
    if valid_recovery_code(code) {
        let hash = recovery_hash(hasher, account, user, code);
        let used = tx.query_opt("UPDATE public.owner_mfa_recovery_codes SET used_at=pg_catalog.clock_timestamp() WHERE account_id=$1 AND user_id=$2 AND code_hash=$3 AND used_at IS NULL RETURNING pg_catalog.timestamptz_send(used_at)", &[&account, &user, &&hash[..]]).await?;
        return used
            .map(|row| {
                Ok(HeldFactor {
                    account,
                    user,
                    factor: ConsumedFactor { step: None },
                    state: State::Recovery(
                        hash,
                        row.try_get::<_, Vec<u8>>(0)?
                            .try_into()
                            .map_err(|_| AuthError::Crypto)?,
                    ),
                })
            })
            .transpose();
    }
    let secret = cipher.open(
        account,
        user,
        &row.try_get::<_, Vec<u8>>(0)?,
        &row.try_get::<_, Vec<u8>>(1)?,
    )?;
    let Some(step) = accepted_step(secret, code, row.try_get(2)?, now_ms / 1000)? else {
        return Ok(None);
    };
    tx.execute(
        "UPDATE public.owner_mfa SET last_accepted_step=$3 WHERE account_id=$1 AND user_id=$2",
        &[&account, &user, &step],
    )
    .await?;
    Ok(Some(HeldFactor {
        account,
        user,
        factor: ConsumedFactor { step: Some(step) },
        state: State::Totp(step),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_deadline_is_the_exact_end_of_the_original_accepted_window() {
        let factor = HeldFactor {
            account: Uuid::new_v4(),
            user: Uuid::new_v4(),
            factor: ConsumedFactor { step: Some(42) },
            state: State::Totp(42),
        };
        let deadline = factor.deadline_ms().unwrap().unwrap();
        assert_eq!(deadline, 44 * 30_000);
        assert!(factor.current_at(deadline - 1));
        assert!(!factor.current_at(deadline));
    }

    #[test]
    fn recovery_needs_the_separate_ceremony_bound_and_unrepresentable_steps_refuse() {
        let mut factor = HeldFactor {
            account: Uuid::new_v4(),
            user: Uuid::new_v4(),
            factor: ConsumedFactor { step: None },
            state: State::Recovery([1; 32], [2; 8]),
        };
        assert_eq!(factor.deadline_ms().unwrap(), None);
        factor.factor.step = Some(i64::MAX);
        assert!(factor.deadline_ms().is_err());
        factor.factor.step = Some(-1);
        assert!(factor.deadline_ms().is_err());
    }
}
