// SPDX-License-Identifier: AGPL-3.0-only
//! The once-a-minute prune of short-lived auth and enrollment rows.
//!
//! Each task drains a bounded number of batches per tick and reports a
//! failure with a fixed, payload-free line once per failure streak, so a
//! broken prune is visible without leaking SQL error text or row data.

use std::sync::atomic::{AtomicBool, Ordering};
use tokio_postgres::Client;

use crate::{
    auth::{self, abuse_limits, mfa},
    enrollment,
};

/// Upper bound on batches each prune task runs per maintenance tick.
pub const PRUNE_BATCHES_PER_TICK: usize = 10;

/// One independently logged maintenance prune.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PruneTask {
    Connect,
    AbuseLimits,
    MfaChallenges,
    Enrollment,
    PendingOwners,
    PasswordResets,
}

impl PruneTask {
    const ALL: [Self; 6] = [
        Self::Connect,
        Self::AbuseLimits,
        Self::MfaChallenges,
        Self::Enrollment,
        Self::PendingOwners,
        Self::PasswordResets,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::AbuseLimits => "abuse_limits",
            Self::MfaChallenges => "mfa_challenges",
            Self::Enrollment => "enrollment",
            Self::PendingOwners => "pending_owners",
            Self::PasswordResets => "password_resets",
        }
    }

    /// Rows one call removes when it may have left more behind. These match
    /// the `LIMIT` in each prune function. Enrollment returns the sum of two
    /// 500-row deletes, so either table being full reaches the threshold.
    fn full_batch(self) -> u64 {
        match self {
            Self::Connect => u64::MAX,
            Self::AbuseLimits => 5_000,
            Self::MfaChallenges | Self::Enrollment | Self::PasswordResets => 500,
            Self::PendingOwners => 100,
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|task| *task == self).unwrap_or(0)
    }
}

/// Remembers which tasks are in a failure streak so each streak logs once.
#[derive(Debug, Default)]
pub struct FailureLog {
    failing: [bool; PruneTask::ALL.len()],
}

impl FailureLog {
    /// Records one outcome and returns the line to log, if any. A success
    /// ends the streak so the next failure is reported again.
    pub fn observe(&mut self, task: PruneTask, ok: bool) -> Option<String> {
        let failing = &mut self.failing[task.index()];
        let first_failure = !ok && !*failing;
        *failing = !ok;
        first_failure.then(|| format!("maintenance prune unavailable (task={})", task.name()))
    }
}

/// Decides whether a prune task runs another batch within one tick: only
/// after a full batch, and never more than the per-tick bound.
#[derive(Debug)]
pub struct BatchBudget {
    full_batch: u64,
    remaining: usize,
}

impl BatchBudget {
    pub fn new(full_batch: u64, max_batches: usize) -> Self {
        Self {
            full_batch,
            remaining: max_batches,
        }
    }

    /// Records one finished batch and returns whether to run another.
    pub fn after_batch(&mut self, removed: u64) -> bool {
        self.remaining = self.remaining.saturating_sub(1);
        removed >= self.full_batch && self.remaining > 0
    }
}

/// Runs one maintenance tick. Each task runs even when another fails, and
/// every failure is reported through `log` without error detail.
pub async fn run_tick(
    database_url: &str,
    draining: &AtomicBool,
    failures: &mut FailureLog,
    mut log: impl FnMut(&str),
) {
    let mut report = |task: PruneTask, ok: bool| {
        if let Some(line) = failures.observe(task, ok) {
            log(&line);
        }
    };
    let connected = crate::runtime_db::connect_worker(database_url).await;
    report(PruneTask::Connect, connected.is_ok());
    let Ok(mut client) = connected else {
        return;
    };
    for task in PruneTask::ALL.into_iter().skip(1) {
        let mut budget = BatchBudget::new(task.full_batch(), PRUNE_BATCHES_PER_TICK);
        let ok = loop {
            if draining.load(Ordering::Acquire) {
                break true;
            }
            match prune_once(&mut client, task).await {
                Ok(removed) if budget.after_batch(removed) => {}
                Ok(_) => break true,
                Err(()) => break false,
            }
        };
        report(task, ok);
    }
}

async fn prune_once(client: &mut Client, task: PruneTask) -> Result<u64, ()> {
    match task {
        PruneTask::Connect => Ok(0),
        PruneTask::AbuseLimits => abuse_limits::prune(client).await.map_err(drop),
        PruneTask::MfaChallenges => mfa::prune_expired_challenges(client).await.map_err(drop),
        PruneTask::Enrollment => enrollment::prune_expired(client).await.map_err(drop),
        PruneTask::PendingOwners => auth::prune_expired_pending_owners(client)
            .await
            .map_err(drop),
        PruneTask::PasswordResets => auth::account::prune_expired_password_resets(client)
            .await
            .map_err(drop),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_streak_logs_one_fixed_line_naming_the_task() {
        let mut log = FailureLog::default();
        assert_eq!(
            log.observe(PruneTask::AbuseLimits, false).as_deref(),
            Some("maintenance prune unavailable (task=abuse_limits)")
        );
        assert_eq!(log.observe(PruneTask::AbuseLimits, false), None);
        assert_eq!(log.observe(PruneTask::AbuseLimits, false), None);
    }

    #[test]
    fn success_resets_the_streak() {
        let mut log = FailureLog::default();
        assert!(log.observe(PruneTask::Enrollment, false).is_some());
        assert_eq!(log.observe(PruneTask::Enrollment, true), None);
        assert_eq!(
            log.observe(PruneTask::Enrollment, false).as_deref(),
            Some("maintenance prune unavailable (task=enrollment)")
        );
    }

    #[test]
    fn tasks_have_independent_streaks() {
        let mut log = FailureLog::default();
        assert!(log.observe(PruneTask::Connect, false).is_some());
        assert!(log.observe(PruneTask::PasswordResets, false).is_some());
        assert!(log.observe(PruneTask::PendingOwners, true).is_none());
        assert_eq!(log.observe(PruneTask::Connect, false), None);
        assert_eq!(
            log.observe(PruneTask::MfaChallenges, false).as_deref(),
            Some("maintenance prune unavailable (task=mfa_challenges)")
        );
    }

    #[test]
    fn task_names_are_distinct_fixed_identifiers() {
        let names: Vec<_> = PruneTask::ALL.iter().map(|task| task.name()).collect();
        for (index, name) in names.iter().enumerate() {
            assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            assert!(!names[..index].contains(name));
        }
    }

    /// Simulates one tick against a backlog; returns (batches run, rows left).
    fn tick(full_batch: u64, mut backlog: u64) -> (usize, u64) {
        let mut budget = BatchBudget::new(full_batch, PRUNE_BATCHES_PER_TICK);
        let mut batches = 0;
        loop {
            batches += 1;
            let removed = backlog.min(full_batch);
            backlog -= removed;
            if !budget.after_batch(removed) {
                return (batches, backlog);
            }
        }
    }

    #[test]
    fn a_backlog_larger_than_one_batch_drains_in_one_tick() {
        assert_eq!(tick(500, 5 * 500 + 120), (6, 0));
        assert_eq!(tick(PruneTask::AbuseLimits.full_batch(), 12_000), (3, 0));
    }

    #[test]
    fn an_exactly_full_last_batch_costs_one_empty_batch() {
        assert_eq!(tick(500, 1_000), (3, 0));
    }

    #[test]
    fn a_tick_stops_at_the_bound_and_later_ticks_finish() {
        let backlog = 500 * PRUNE_BATCHES_PER_TICK as u64 * 2 + 1;
        let (batches, left) = tick(500, backlog);
        assert_eq!((batches, left), (PRUNE_BATCHES_PER_TICK, backlog - 5_000));
        let (_, left) = tick(500, left);
        assert_eq!(tick(500, left), (1, 0));
    }

    #[test]
    fn a_partial_or_empty_batch_ends_the_task() {
        let mut budget = BatchBudget::new(100, PRUNE_BATCHES_PER_TICK);
        assert!(!budget.after_batch(99));
        let mut budget = BatchBudget::new(100, PRUNE_BATCHES_PER_TICK);
        assert!(!budget.after_batch(0));
        let mut budget = BatchBudget::new(100, 1);
        assert!(!budget.after_batch(100));
    }
}
