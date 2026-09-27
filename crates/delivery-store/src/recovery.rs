// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded draining for the delivery recovery sweeps, and a payload-free
//! backlog signal so operators can see when recovery falls behind.

use super::{DeliveryStore, StoreError};

/// Rows handled per sweep call; each call is one short transaction.
pub const RECOVERY_BATCH: i64 = 100;
/// Upper bound on batches of each sweep kind per recovery tick.
pub const RECOVERY_BATCHES_PER_TICK: usize = 10;

/// Rows each sweep moved during one bounded recovery pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryPass {
    pub expired: u64,
    pub silent_attempts: u64,
    pub delivery_timeouts: u64,
    /// True when any sweep still returned a full batch at the per-tick bound,
    /// so more work is probably waiting for the next tick.
    pub bound_reached: bool,
}

/// Counts of rows the recovery sweeps would act on now, each capped at the
/// requested limit. Contains no identifiers, numbers or content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryBacklog {
    pub expired_pending: i64,
    pub oldest_expired_age_seconds: Option<i64>,
    pub silent_attempts: i64,
    pub delivery_timeouts: i64,
}

/// Decides whether a sweep runs another batch within one pass: only after a
/// full batch, and never more than `max_batches` batches.
#[derive(Debug)]
pub(crate) struct BatchBudget {
    full_batch: u64,
    remaining: usize,
    bound_reached: bool,
}

impl BatchBudget {
    pub(crate) fn new(full_batch: u64, max_batches: usize) -> Self {
        Self {
            full_batch,
            remaining: max_batches,
            bound_reached: false,
        }
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.remaining == 0
    }

    /// Records one finished batch and returns whether to run another.
    pub(crate) fn after_batch(&mut self, rows: u64) -> bool {
        self.remaining = self.remaining.saturating_sub(1);
        let full = rows >= self.full_batch;
        self.bound_reached = full && self.remaining == 0;
        full && self.remaining > 0
    }
}

#[derive(Clone, Copy)]
enum Sweep {
    Expire,
    SilentAttempts,
    DeliveryTimeouts,
}

impl DeliveryStore<'_> {
    /// Runs the expiry, silent-attempt and delivery-timeout sweeps, each
    /// repeating while its batch comes back full, up to `max_batches` batches
    /// per sweep. `stop` is checked before every batch. Each batch commits
    /// separately, so refunds and state changes keep the exactly-once
    /// guarantees of the single-batch sweeps.
    pub async fn recover_bounded(
        &mut self,
        batch: i64,
        max_batches: usize,
        stop: impl Fn() -> bool,
    ) -> Result<RecoveryPass, StoreError> {
        if !(1..=1000).contains(&batch) {
            return Err(StoreError::InvalidInput);
        }
        let mut pass = RecoveryPass::default();
        for sweep in [
            Sweep::Expire,
            Sweep::SilentAttempts,
            Sweep::DeliveryTimeouts,
        ] {
            let mut budget = BatchBudget::new(batch as u64, max_batches);
            let mut rows = 0;
            while !budget.exhausted() && !stop() {
                let moved = match sweep {
                    Sweep::Expire => self.expire_due(batch).await?,
                    Sweep::SilentAttempts => self.reconcile_silent_attempts(batch).await?,
                    Sweep::DeliveryTimeouts => self.reconcile_delivery_timeouts(batch).await?,
                };
                rows += moved;
                if !budget.after_batch(moved) {
                    break;
                }
            }
            pass.bound_reached |= budget.bound_reached;
            match sweep {
                Sweep::Expire => pass.expired = rows,
                Sweep::SilentAttempts => pass.silent_attempts = rows,
                Sweep::DeliveryTimeouts => pass.delivery_timeouts = rows,
            }
        }
        Ok(pass)
    }

    /// Counts work waiting for each recovery sweep, capped at `cap` rows per
    /// kind so a large backlog cannot make the signal itself expensive. The
    /// predicates match the sweeps; rows locked by other transactions count.
    pub async fn recovery_backlog(&self, cap: i64) -> Result<RecoveryBacklog, StoreError> {
        if !(1..=100_000).contains(&cap) {
            return Err(StoreError::InvalidInput);
        }
        let row = self
            .client
            .query_one(
                "SELECT \
                 (SELECT count(*) FROM (SELECT 1 FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
                   WHERE j.grant_issued_at IS NULL AND j.finished_at IS NULL \
                     AND m.expires_at<=now() AND m.state IN ('queued','claimed') LIMIT $1) due), \
                 (SELECT floor(extract(epoch FROM now()-m.expires_at))::bigint \
                   FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
                   WHERE j.grant_issued_at IS NULL AND j.finished_at IS NULL \
                     AND m.expires_at<=now() AND m.state IN ('queued','claimed') \
                   ORDER BY m.expires_at LIMIT 1), \
                 (SELECT count(*) FROM (SELECT 1 FROM messages m \
                   JOIN dispatch_fences f ON (f.account_id,f.message_id)=(m.account_id,m.id) \
                   JOIN message_attempts a ON a.id=f.attempt_id \
                   WHERE (m.state='claimed' AND f.outcome='granted' AND f.grant_expires_at<=now()) \
                      OR (m.state='submitting' AND f.outcome='submitting' \
                          AND a.updated_at<=now()-interval '2 minutes') LIMIT $1) silent), \
                 (SELECT count(*) FROM (SELECT 1 FROM messages m \
                   JOIN dispatch_fences f ON (f.account_id,f.message_id)=(m.account_id,m.id) \
                   JOIN message_attempts a ON a.id=f.attempt_id \
                   WHERE m.state='submitted' AND f.outcome='submitted' AND a.status='submitted' \
                     AND m.updated_at<=now()-interval '24 hours' LIMIT $1) timeouts)",
                &[&cap],
            )
            .await?;
        Ok(RecoveryBacklog {
            expired_pending: row.get(0),
            oldest_expired_age_seconds: row.get(1),
            silent_attempts: row.get(2),
            delivery_timeouts: row.get(3),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simulates one pass over a backlog: (batches run, rows left, bound hit).
    fn pass(full: u64, max_batches: usize, mut backlog: u64) -> (usize, u64, bool) {
        let mut budget = BatchBudget::new(full, max_batches);
        let mut batches = 0;
        while !budget.exhausted() {
            batches += 1;
            let rows = backlog.min(full);
            backlog -= rows;
            if !budget.after_batch(rows) {
                break;
            }
        }
        (batches, backlog, budget.bound_reached)
    }

    #[test]
    fn one_pass_clears_more_than_one_batch() {
        assert_eq!(pass(100, 20, 1_050), (11, 0, false));
        assert_eq!(pass(100, RECOVERY_BATCHES_PER_TICK, 950), (10, 0, false));
    }

    #[test]
    fn a_pass_stops_at_the_bound_and_reports_it() {
        let bound = RECOVERY_BATCH as u64 * RECOVERY_BATCHES_PER_TICK as u64;
        assert_eq!(
            pass(RECOVERY_BATCH as u64, RECOVERY_BATCHES_PER_TICK, 1_500),
            (RECOVERY_BATCHES_PER_TICK, 1_500 - bound, true)
        );
    }

    #[test]
    fn a_partial_empty_or_zero_budget_pass_stops() {
        assert_eq!(pass(100, 10, 40), (1, 0, false));
        assert_eq!(pass(100, 10, 0), (1, 0, false));
        assert_eq!(pass(100, 0, 500), (0, 500, false));
    }
}
