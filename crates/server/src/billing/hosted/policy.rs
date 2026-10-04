// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    Refusal,
    namespace::{Gate, Marker, Scope, valid_external_id},
};

/// Operator-approved quota mapping. No prices, currency, trial or plan defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    price: String,
    outbound_limit: u64,
    device_limit: u64,
    grace_seconds: u64,
}

impl Plan {
    pub fn new(
        price: &str,
        outbound_limit: u64,
        device_limit: u64,
        grace_seconds: u64,
    ) -> Result<Self, Refusal> {
        // SQL counters are signed bigint. Retain the existing maximum
        // seven-day grace contract without selecting an enabled duration.
        if !valid_external_id(price)
            || outbound_limit == 0
            || outbound_limit > i64::MAX as u64
            || device_limit == 0
            || device_limit > i64::MAX as u64
            || grace_seconds > 7 * 24 * 60 * 60
        {
            return Err(Refusal::InvalidConfiguration);
        }
        Ok(Self {
            price: price.to_owned(),
            outbound_limit,
            device_limit,
            grace_seconds,
        })
    }

    pub fn price(&self) -> &str {
        &self.price
    }

    pub fn outbound_limit(&self) -> u64 {
        self.outbound_limit
    }

    pub fn device_limit(&self) -> u64 {
        self.device_limit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Incomplete,
    Unpaid,
    Paused,
    Canceled,
    Deleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Active,
    Grace,
    Pending,
    Restricted,
    Terminal,
}

/// A trusted signed failure for the current obligation. Its scope and invoice
/// are still compared with the current provider read before grace is possible.
#[derive(Clone, Debug)]
pub struct FailureEvidence {
    pub scope: Scope,
    pub invoice: String,
    pub occurred_at: i64,
}

/// Adapter input from a complete, bounded current-state provider read.
/// A webhook payload, checkout return or paid invoice alone is not this input.
/// The adapter must authenticate provider data and allocate a fresh local
/// generation under the store lock before each read. These public fields are
/// trusted adapter inputs, not proof supplied by a browser or provider event.
#[derive(Clone, Debug)]
pub struct Observation {
    pub scope: Scope,
    pub policy_revision: u64,
    pub generation: u64,
    pub complete: bool,
    pub nonterminal_subscriptions: u64,
    pub status: SubscriptionStatus,
    pub price: String,
    pub invoice: String,
    pub period_start: i64,
    pub period_end: i64,
    /// Provider reads cannot grant past this explicit server lease/deadline.
    pub revalidate_at: i64,
    pub failure: Option<FailureEvidence>,
}

/// Values read and locked from local storage. A provider response cannot clear
/// a risk hold/review latch or select its own reconciliation generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fence {
    pub dirty_generation: u64,
    pub payment_hold: bool,
    pub review_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Projection {
    pub(super) scope: Scope,
    pub(super) policy_revision: u64,
    pub(super) generation: u64,
    pub(super) phase: Phase,
    pub(super) outbound_limit: u64,
    pub(super) device_limit: u64,
    pub(super) issued_at: i64,
    pub(super) valid_until: i64,
    pub(super) first_failure_at: Option<i64>,
}

impl Projection {
    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn first_failure_at(&self) -> Option<i64> {
        self.first_failure_at
    }

    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }

    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    pub fn outbound_limit(&self) -> u64 {
        self.outbound_limit
    }

    pub fn device_limit(&self) -> u64 {
        self.device_limit
    }
}

/// Reduce a fenced current provider observation into a replacement projection.
/// Persist projection and processed generation in the same transaction.
/// Every read needs a newer local sequence; durable duplicate events are a
/// store no-op rather than another reconciliation of the same generation.
/// `now` must be trusted database time, never a caller/provider timestamp.
/// A new projection cannot rewind the stored issue-time lower bound during a
/// database clock rollback or from an older transaction timestamp.
pub struct Reconciliation<'a> {
    pub gate: &'a Gate,
    pub marker: &'a Marker,
    pub binding: &'a Scope,
    pub fence: Fence,
    pub previous: Option<&'a Projection>,
    pub observation: &'a Observation,
    pub plan: &'a Plan,
    pub now: i64,
}

pub fn reconcile(input: Reconciliation<'_>) -> Result<Projection, Refusal> {
    let Reconciliation {
        gate,
        marker,
        binding,
        fence,
        previous,
        observation,
        plan,
        now,
    } = input;
    let dirty_generation = fence.dirty_generation;
    let expected = gate.check_marker(marker)?;
    if binding.namespace() != &expected.namespace {
        return Err(Refusal::NamespaceMismatch);
    }
    binding.check(&observation.scope)?;
    if observation.policy_revision != expected.policy_revision {
        return Err(Refusal::StalePolicy);
    }
    if dirty_generation == 0 || observation.generation != dirty_generation {
        return Err(Refusal::StaleObservation);
    }
    if let Some(prior) = previous {
        binding.check(&prior.scope)?;
        if prior.generation >= observation.generation || now < prior.issued_at {
        if prior.generation >= observation.generation {
            return Err(Refusal::StaleObservation);
        }
    }
    let mut result = Projection {
        scope: binding.clone(),
        policy_revision: expected.policy_revision,
        generation: dirty_generation,
        phase: Phase::Pending,
        outbound_limit: 0,
        device_limit: 0,
        issued_at: now,
        valid_until: now,
        first_failure_at: previous.and_then(|prior| prior.first_failure_at),
    };
    if !observation.complete {
        return Ok(result);
    }
    let current_period = observation.nonterminal_subscriptions == 1
        && observation.price == plan.price
        && valid_external_id(&observation.invoice)
        && now >= 0
        && observation.period_start >= 0
        && observation.period_start <= now
        && observation.period_end > now
        && observation.revalidate_at > now;
    let current_failure_start = if current_period
        && observation.status == SubscriptionStatus::PastDue
        && let Some(failure) = &observation.failure
    {
        binding.check(&failure.scope)?;
        if failure.invoice == observation.invoice && failure.occurred_at >= 0 {
            let observed_failure = failure.occurred_at.min(now);
            Some(
                previous
                    .and_then(|prior| prior.first_failure_at)
                    .map_or(observed_failure, |prior| prior.min(observed_failure)),
            )
        } else {
            None
        }
    } else {
        None
    };
    // Local holds must not hide the first verified delinquency. Record its
    // deadline without granting capacity before returning a restricted state.
    if let Some(first) = current_failure_start {
        result.first_failure_at = Some(first);
    }
    if fence.payment_hold || fence.review_required || observation.nonterminal_subscriptions > 1 {
        result.phase = Phase::Restricted;
        return Ok(result);
    }
    if matches!(
        observation.status,
        SubscriptionStatus::Canceled | SubscriptionStatus::Deleted
    ) {
        result.phase = Phase::Terminal;
        result.first_failure_at = None;
        return Ok(result);
    }
    if !current_period {
        result.phase = Phase::Restricted;
        return Ok(result);
    }
    let deadline = observation.period_end.min(observation.revalidate_at);
    match observation.status {
        SubscriptionStatus::Active => {
            result.phase = Phase::Active;
            result.first_failure_at = None;
            result.valid_until = deadline;
        }
        SubscriptionStatus::PastDue => {
            let Some(first) = current_failure_start else {
                return Ok(result);
            };
            // Invoice changes, duplicated/delayed failure events and restart
            // cannot extend continuous delinquency's first observed deadline.
            let grace_end = first
                .checked_add(plan.grace_seconds as i64)
                .ok_or(Refusal::InvalidConfiguration)?;
            if grace_end <= now {
                result.phase = Phase::Restricted;
                return Ok(result);
            }
            result.phase = Phase::Grace;
            result.valid_until = deadline.min(grace_end);
        }
        _ => {
            result.phase = Phase::Restricted;
            return Ok(result);
        }
    }
    result.outbound_limit = plan.outbound_limit;
    result.device_limit = plan.device_limit;
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    Outbound { units: u64, consumed: u64 },
    EnrollDevice { active_devices: u64 },
}

/// Must run under the existing tenant/quota transaction lock, before reservation
/// and delivery enqueue. Never call this as a separate commit before admission.
/// The adapter supplies locked current fences/counters and trusted database time;
/// the issue-time lower bound also refuses a clock rollback behind this grant.
pub fn admit(
    gate: &Gate,
    marker: &Marker,
    binding: &Scope,
    fence: Fence,
    projection: Option<&Projection>,
    purpose: Purpose,
    now: i64,
) -> Result<(), Refusal> {
    let expected = gate.check_marker(marker)?;
    if binding.namespace() != &expected.namespace {
        return Err(Refusal::NamespaceMismatch);
    }
    if fence.payment_hold || fence.review_required {
        return Err(Refusal::Restricted);
    }
    let projection = projection.ok_or(Refusal::Pending)?;
    binding.check(&projection.scope)?;
    if projection.policy_revision != expected.policy_revision {
        return Err(Refusal::StalePolicy);
    }
    if !matches!(projection.phase, Phase::Active | Phase::Grace) {
        return Err(if projection.phase == Phase::Pending {
            Refusal::Pending
        } else {
            Refusal::Restricted
        });
    }
    if projection.generation != fence.dirty_generation
        || now < 0
        || now < projection.issued_at
        || now >= projection.valid_until
    {
        return Err(Refusal::Pending);
    }
    match purpose {
        Purpose::Outbound { units, consumed } => {
            if units == 0
                || consumed
                    .checked_add(units)
                    .is_none_or(|total| total > projection.outbound_limit)
            {
                return Err(Refusal::QuotaExceeded);
            }
        }
        Purpose::EnrollDevice { active_devices } => {
            if active_devices >= projection.device_limit {
                return Err(Refusal::DeviceCapExceeded);
            }
        }
    }
    Ok(())
}

/// Local replay identity comparison for a durable, namespace-scoped inbox or
/// reservation row. Store lookup must include namespace AND authenticated owner.
pub fn check_replay(stored: &[u8; 32], delivered: &[u8; 32]) -> Result<(), Refusal> {
    if stored == delivered {
        Ok(())
    } else {
        Err(Refusal::ReplayConflict)
    }
}
