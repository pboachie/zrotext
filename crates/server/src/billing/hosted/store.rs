// SPDX-License-Identifier: AGPL-3.0-only
//! Transaction-bound hosted billing storage. The runtime supplies a verified
//! immutable gate and authenticated scope, and owns account/usage authority.
//! Callers must roll back on every error and perform their final admission check
//! immediately before their own commit. This module never commits, opens a
//! connection, calls a provider, creates a binding, or stores a second usage ledger.
//! ROOT owns fencing its manifest before the namespace/account locks below.

use super::{
    Refusal,
    namespace::{Gate, Marker, Mode, Namespace, Scope},
    policy::{self, Fence, Observation, Phase, Plan, Projection, Purpose, Reconciliation},
};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    Refused(Refusal),
    Unavailable,
    MalformedState,
    OldBinaryNotFenced,
}

impl From<Refusal> for StoreError {
    fn from(value: Refusal) -> Self {
        Self::Refused(value)
    }
}

/// A freshly locked database snapshot, not authority to bypass another locked
/// read. Its counters are reconciliation metadata, never outbound usage counters.
#[derive(Clone, Debug)]
pub struct LockedState {
    pub marker: Marker,
    pub fence: Fence,
    pub projection: Option<Projection>,
    pub now: i64,
    pub processed_generation: u64,
    pub per_read_sequence: u64,
    pub read_token: Option<Uuid>,
}

/// Allocate and persist this claim before the bounded current provider read.
/// The store, not a webhook/provider response, selects both sequence values.
#[derive(Clone, Debug)]
pub struct ReadClaim {
    scope: Scope,
    policy_revision: u64,
    generation: u64,
    sequence: u64,
    token: Uuid,
    claimed_at: i64,
}

impl ReadClaim {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn claimed_at(&self) -> i64 {
        self.claimed_at
    }
}

// Cap database work without replacing a stricter caller-configured deadline.
// These are transaction-local settings; an error requires caller rollback.
async fn bound_waits(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let rows = tx
        .query(
            "SELECT set_config(name, least(CASE WHEN setting::bigint=0 THEN ceiling ELSE setting::bigint END, ceiling)::text || 'ms', true) FROM (SELECT name,setting,CASE WHEN name='lock_timeout' THEN 3000 ELSE 5000 END AS ceiling FROM pg_settings WHERE name IN ('lock_timeout','statement_timeout')) AS limits",
            &[],
        )
        .await
        .map_err(|_| StoreError::Unavailable)?;
    if rows.len() != 2 {
        return Err(StoreError::Unavailable);
    }
    Ok(())
}

async fn database_now(tx: &Transaction<'_>) -> Result<i64, StoreError> {
    let row = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .map_err(|_| StoreError::Unavailable)?;
    let now: i64 = row.try_get(0).map_err(|_| StoreError::MalformedState)?;
    if now < 0 {
        return Err(StoreError::MalformedState);
    }
    Ok(now)
}

fn text(row: &Row, field: &str) -> Result<String, StoreError> {
    row.try_get(field).map_err(|_| StoreError::MalformedState)
}

fn counter(row: &Row, field: &str) -> Result<u64, StoreError> {
    let value: i64 = row.try_get(field).map_err(|_| StoreError::MalformedState)?;
    u64::try_from(value).map_err(|_| StoreError::MalformedState)
}

fn sql_counter(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Refused(Refusal::InvalidConfiguration))
}

fn next_counter(value: u64) -> Result<u64, StoreError> {
    let next = value
        .checked_add(1)
        .ok_or(StoreError::Refused(Refusal::InvalidConfiguration))?;
    sql_counter(next)?;
    Ok(next)
}

fn phase(value: &str) -> Result<Phase, StoreError> {
    match value {
        "active" => Ok(Phase::Active),
        "grace" => Ok(Phase::Grace),
        "pending" => Ok(Phase::Pending),
        "restricted" => Ok(Phase::Restricted),
        "terminal" => Ok(Phase::Terminal),
        _ => Err(StoreError::MalformedState),
    }
}

fn phase_name(value: Phase) -> &'static str {
    match value {
        Phase::Active => "active",
        Phase::Grace => "grace",
        Phase::Pending => "pending",
        Phase::Restricted => "restricted",
        Phase::Terminal => "terminal",
    }
}

/// Call this after ROOT's manifest fence and before locking an authenticated
/// account. `load_locked` repeats the marker check before its projection lock.
/// A marker SHARE lock blocks operator policy/pause changes until caller commit.
pub async fn lock_marker(
    tx: &Transaction<'_>,
    gate: &Gate,
    binding: &Scope,
) -> Result<Marker, StoreError> {
    let configured = gate.marker()?;
    if binding.namespace() != &configured.namespace {
        return Err(Refusal::NamespaceMismatch.into());
    }
    bound_waits(tx).await?;
    let namespace_id = Uuid::from_bytes(configured.namespace.id());
    let row = tx
        .query_opt(
            "SELECT namespace_id,left(mode,16) AS mode,left(provider_account,129) AS provider_account,policy_revision,enabled,old_binary_fenced FROM hosted_billing_namespaces WHERE namespace_id=$1 FOR SHARE",
            &[&namespace_id],
        )
        .await
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::Refused(Refusal::Disabled))?;
    let mode = match text(&row, "mode")?.as_str() {
        "test" => Mode::Test,
        "live" => Mode::Live,
        _ => return Err(StoreError::MalformedState),
    };
    let stored_id: Uuid = row
        .try_get("namespace_id")
        .map_err(|_| StoreError::MalformedState)?;
    let namespace = Namespace::new(
        stored_id.into_bytes(),
        mode,
        &text(&row, "provider_account")?,
    )
    .map_err(|_| StoreError::MalformedState)?;
    let revision = counter(&row, "policy_revision")?;
    if revision == 0 {
        return Err(StoreError::MalformedState);
    }
    let marker = Marker {
        namespace,
        policy_revision: revision,
        enabled: row
            .try_get("enabled")
            .map_err(|_| StoreError::MalformedState)?,
    };
    gate.check_marker(&marker)?;
    let old_binary_fenced: bool = row
        .try_get("old_binary_fenced")
        .map_err(|_| StoreError::MalformedState)?;
    if !old_binary_fenced {
        return Err(StoreError::OldBinaryNotFenced);
    }
    Ok(marker)
}

fn validate_projection(projection: &Projection) -> Result<(), StoreError> {
    if projection.policy_revision == 0
        || projection.generation == 0
        || projection.issued_at < 0
        || projection.valid_until < projection.issued_at
        || projection
            .first_failure_at
            .is_some_and(|at| at < 0 || at > projection.issued_at)
    {
        return Err(StoreError::MalformedState);
    }
    match projection.phase {
        Phase::Active | Phase::Grace => {
            if projection.outbound_limit == 0
                || projection.device_limit == 0
                || projection.valid_until <= projection.issued_at
                || (projection.phase == Phase::Active && projection.first_failure_at.is_some())
                || (projection.phase == Phase::Grace && projection.first_failure_at.is_none())
            {
                return Err(StoreError::MalformedState);
            }
        }
        Phase::Pending | Phase::Restricted | Phase::Terminal => {
            if projection.outbound_limit != 0
                || projection.device_limit != 0
                || projection.valid_until != projection.issued_at
                || (projection.phase == Phase::Terminal && projection.first_failure_at.is_some())
            {
                return Err(StoreError::MalformedState);
            }
        }
    }
    Ok(())
}

/// Lock namespace first, then the exact authenticated owner's bound projection.
/// The caller retains account/quota locks for any reservation or enrollment.
/// Provider data cannot create or replace a customer/subscription binding here.
pub async fn load_locked(
    tx: &Transaction<'_>,
    gate: &Gate,
    binding: &Scope,
) -> Result<LockedState, StoreError> {
    let marker = lock_marker(tx, gate, binding).await?;
    let namespace_id = Uuid::from_bytes(binding.namespace().id());
    let account_id = Uuid::from_bytes(binding.owner());
    let row = tx
        .query_opt(
            "SELECT namespace_id,account_id,left(customer_id,129) AS customer_id,left(subscription_id,129) AS subscription_id,policy_revision,dirty_generation,processed_generation,per_read_sequence,payment_hold,review_required,left(phase,16) AS phase,outbound_limit,device_limit,issued_at,valid_until,first_failure_at,read_token FROM hosted_billing_projections WHERE namespace_id=$1 AND account_id=$2 FOR UPDATE",
            &[&namespace_id, &account_id],
        )
        .await
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::Refused(Refusal::Pending))?;
    let stored_namespace: Uuid = row
        .try_get("namespace_id")
        .map_err(|_| StoreError::MalformedState)?;
    let stored_account: Uuid = row
        .try_get("account_id")
        .map_err(|_| StoreError::MalformedState)?;
    if stored_namespace != namespace_id || stored_account != account_id {
        return Err(StoreError::MalformedState);
    }
    let scope = Scope::new(
        marker.namespace.clone(),
        stored_account.into_bytes(),
        &text(&row, "customer_id")?,
        &text(&row, "subscription_id")?,
    )
    .map_err(|_| StoreError::MalformedState)?;
    binding.check(&scope)?;
    let dirty_generation = counter(&row, "dirty_generation")?;
    let processed_generation = counter(&row, "processed_generation")?;
    let per_read_sequence = counter(&row, "per_read_sequence")?;
    let read_token: Option<Uuid> = row
        .try_get("read_token")
        .map_err(|_| StoreError::MalformedState)?;
    let policy_revision = counter(&row, "policy_revision")?;
    if policy_revision == 0
        || processed_generation > dirty_generation
        || per_read_sequence != dirty_generation
        || (per_read_sequence == 0 && read_token.is_some())
        || (processed_generation > 0
            && processed_generation == dirty_generation
            && read_token.is_none())
        || read_token.is_some_and(|token| token.get_version_num() != 4)
    {
        return Err(StoreError::MalformedState);
    }
    let projection = Projection {
        scope,
        policy_revision,
        generation: processed_generation,
        phase: phase(&text(&row, "phase")?)?,
        outbound_limit: counter(&row, "outbound_limit")?,
        device_limit: counter(&row, "device_limit")?,
        issued_at: row
            .try_get("issued_at")
            .map_err(|_| StoreError::MalformedState)?,
        valid_until: row
            .try_get("valid_until")
            .map_err(|_| StoreError::MalformedState)?,
        first_failure_at: row
            .try_get("first_failure_at")
            .map_err(|_| StoreError::MalformedState)?,
    };
    let projection = if processed_generation == 0 {
        if projection.phase != Phase::Pending
            || projection.outbound_limit != 0
            || projection.device_limit != 0
            || projection.issued_at < 0
            || projection.valid_until != projection.issued_at
            || projection.first_failure_at.is_some()
        {
            return Err(StoreError::MalformedState);
        }
        None
    } else {
        validate_projection(&projection)?;
        Some(projection)
    };
    let fence = Fence {
        dirty_generation,
        payment_hold: row
            .try_get("payment_hold")
            .map_err(|_| StoreError::MalformedState)?,
        review_required: row
            .try_get("review_required")
            .map_err(|_| StoreError::MalformedState)?,
    };
    // Take current DB time after every preceding row-lock wait, not at BEGIN.
    let now = database_now(tx).await?;
    Ok(LockedState {
        marker,
        fence,
        projection,
        now,
        processed_generation,
        per_read_sequence,
        read_token,
    })
}

pub async fn claim_read(
    tx: &Transaction<'_>,
    gate: &Gate,
    binding: &Scope,
) -> Result<ReadClaim, StoreError> {
    let loaded = load_locked(tx, gate, binding).await?;
    let generation = next_counter(loaded.fence.dirty_generation)?;
    let sequence = next_counter(loaded.per_read_sequence)?;
    // A rolled-back claim can reuse its counters, but never this UUIDv4 fence.
    let token = Uuid::new_v4();
    let namespace_id = Uuid::from_bytes(binding.namespace().id());
    let account_id = Uuid::from_bytes(binding.owner());
    let changed = tx
        .execute(
            "UPDATE hosted_billing_projections SET dirty_generation=$3,per_read_sequence=$4,read_token=$7 WHERE namespace_id=$1 AND account_id=$2 AND dirty_generation=$5 AND per_read_sequence=$6",
            &[
                &namespace_id,
                &account_id,
                &sql_counter(generation)?,
                &sql_counter(sequence)?,
                &sql_counter(loaded.fence.dirty_generation)?,
                &sql_counter(loaded.per_read_sequence)?,
                &token,
            ],
        )
        .await
        .map_err(|_| StoreError::Unavailable)?;
    if changed != 1 {
        return Err(Refusal::StaleObservation.into());
    }
    let final_state = load_locked(tx, gate, binding).await?;
    if final_state.fence.dirty_generation != generation
        || final_state.per_read_sequence != sequence
        || final_state.processed_generation != loaded.processed_generation
        || final_state.projection != loaded.projection
        || final_state.read_token != Some(token)
        || final_state.now < loaded.now
    {
        return Err(Refusal::StaleObservation.into());
    }
    Ok(ReadClaim {
        scope: binding.clone(),
        policy_revision: final_state.marker.policy_revision,
        generation,
        sequence,
        token,
        claimed_at: final_state.now,
    })
}

pub async fn commit_observation(
    tx: &Transaction<'_>,
    gate: &Gate,
    binding: &Scope,
    claim: &ReadClaim,
    observation: &Observation,
    plan: &Plan,
) -> Result<Projection, StoreError> {
    binding.check(&claim.scope)?;
    let loaded = load_locked(tx, gate, binding).await?;
    if claim.policy_revision != loaded.marker.policy_revision {
        return Err(Refusal::StalePolicy.into());
    }
    if claim.generation != loaded.fence.dirty_generation
        || claim.sequence != loaded.per_read_sequence
        || loaded.read_token != Some(claim.token)
        || observation.generation != claim.generation
        || loaded.processed_generation >= claim.generation
        || loaded.now < claim.claimed_at
    {
        return Err(Refusal::StaleObservation.into());
    }
    let projection = policy::reconcile(Reconciliation {
        gate,
        marker: &loaded.marker,
        binding,
        fence: loaded.fence,
        previous: loaded.projection.as_ref(),
        observation,
        plan,
        now: loaded.now,
    })?;
    validate_projection(&projection)?;
    let namespace_id = Uuid::from_bytes(binding.namespace().id());
    let account_id = Uuid::from_bytes(binding.owner());
    let changed = tx
        .execute(
            "UPDATE hosted_billing_projections SET policy_revision=$5,processed_generation=$6,phase=$8,outbound_limit=$9,device_limit=$10,issued_at=$11,valid_until=$12,first_failure_at=$13 WHERE namespace_id=$1 AND account_id=$2 AND customer_id=$3 AND subscription_id=$4 AND dirty_generation=$6 AND per_read_sequence=$7 AND read_token=$14",
            &[
                &namespace_id,
                &account_id,
                &binding.customer(),
                &binding.subscription(),
                &sql_counter(projection.policy_revision)?,
                &sql_counter(claim.generation)?,
                &sql_counter(claim.sequence)?,
                &phase_name(projection.phase),
                &sql_counter(projection.outbound_limit)?,
                &sql_counter(projection.device_limit)?,
                &projection.issued_at,
                &projection.valid_until,
                &projection.first_failure_at,
                &claim.token,
            ],
        )
        .await
        .map_err(|_| StoreError::Unavailable)?;
    if changed != 1 {
        return Err(Refusal::StaleObservation.into());
    }
    let final_state = load_locked(tx, gate, binding).await?;
    if final_state.fence.dirty_generation != claim.generation
        || final_state.per_read_sequence != claim.sequence
        || final_state.processed_generation != claim.generation
        || final_state.read_token != Some(claim.token)
        || final_state.projection.as_ref() != Some(&projection)
        || final_state.now < projection.issued_at
    {
        return Err(Refusal::StaleObservation.into());
    }
    if matches!(projection.phase, Phase::Active | Phase::Grace) {
        if final_state.fence.payment_hold || final_state.fence.review_required {
            return Err(Refusal::Restricted.into());
        }
        if final_state.now >= projection.valid_until {
            return Err(Refusal::Pending.into());
        }
    }
    Ok(projection)
}

/// Caller-supplied Purpose counters must come from its existing locked usage or
/// device rows. Hold this transaction through reservation/enqueue/enrollment and
/// repeat this check after any subsequent waits, immediately before caller commit.
pub async fn admit_locked(
    tx: &Transaction<'_>,
    gate: &Gate,
    binding: &Scope,
    purpose: Purpose,
) -> Result<(), StoreError> {
    let loaded = load_locked(tx, gate, binding).await?;
    policy::admit(
        gate,
        &loaded.marker,
        binding,
        loaded.fence,
        loaded.projection.as_ref(),
        purpose,
        loaded.now,
    )?;
    let final_state = load_locked(tx, gate, binding).await?;
    if final_state.now < loaded.now {
        return Err(Refusal::Pending.into());
    }
    policy::admit(
        gate,
        &final_state.marker,
        binding,
        final_state.fence,
        final_state.projection.as_ref(),
        purpose,
        final_state.now,
    )
    .map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projected() -> Projection {
        Projection {
            scope: Scope::new(
                Namespace::new([1; 16], Mode::Test, "acct_fixture").unwrap(),
                [2; 16],
                "cus_fixture",
                "sub_fixture",
            )
            .unwrap(),
            policy_revision: 1,
            generation: 1,
            phase: Phase::Active,
            outbound_limit: 10,
            device_limit: 2,
            issued_at: 200,
            valid_until: 300,
            first_failure_at: None,
        }
    }

    #[test]
    fn malformed_projection_hydration_cannot_restore_capacity() {
        for case in 0..8 {
            let mut value = projected();
            match case {
                0 => value.generation = 0,
                1 => value.issued_at = -1,
                2 => value.valid_until = 200,
                3 => value.first_failure_at = Some(150),
                4 => value.phase = Phase::Grace,
                5 => value.outbound_limit = 0,
                6 => value.phase = Phase::Restricted,
                _ => value.policy_revision = 0,
            }
            assert_eq!(validate_projection(&value), Err(StoreError::MalformedState));
        }
        assert_eq!(validate_projection(&projected()), Ok(()));
    }

    #[test]
    fn fresh_local_sequences_never_overflow_signed_database_counters() {
        assert_eq!(next_counter(0), Ok(1));
        for value in [i64::MAX as u64, u64::MAX] {
            assert_eq!(
                next_counter(value),
                Err(StoreError::Refused(Refusal::InvalidConfiguration))
            );
        }
    }

    #[test]
    fn persisted_phase_requires_the_exact_supported_state() {
        for value in ["", "ACTIVE", "paid", "active "] {
            assert_eq!(phase(value), Err(StoreError::MalformedState));
        }
        for value in [
            Phase::Active,
            Phase::Grace,
            Phase::Pending,
            Phase::Restricted,
            Phase::Terminal,
        ] {
            assert_eq!(phase(phase_name(value)), Ok(value));
        }
    }
}
