// SPDX-License-Identifier: AGPL-3.0-only
//! Member-side probe-and-report loop for independent-quorum failover.
//!
//! The [`observe`] module forms one member's quorum report from one round of
//! raw probe outcomes; the [`store`] module is the durable home such reports
//! are recorded into. This module is the loop that joins them: each round it
//! gathers probes through an injected [`ProbeSource`], forms the round's
//! observation with the existing [`MemberObserver`], and — only when the
//! round produced a report — submits it to an injected [`ObservationSink`],
//! the thin adapter over the consensus store's append path. Like the rest of
//! this crate it performs no I/O of its own: both the probe source and the
//! sink are seams, so a production network probe and any cross-member
//! transport live behind them in the server, and this build ships only
//! deterministic/test implementations.
//!
//! Safety rules, in short (their failure-scenario tests live in
//! `report/tests.rs`):
//!
//! * an abstaining round submits nothing: a member whose own probes cannot
//!   attest the writer's state contributes no evidence at all, so a faulty
//!   member never pushes a phantom vote into the durable store;
//! * a sink failure fails the loop closed **sticky** for reporting, mirroring
//!   the store's own poisoning philosophy: after a failed submit the loop
//!   still probes every round but reports nothing, until an explicit
//!   [`ReportLoop::recover`] — a report that may not have been durably
//!   recorded must never be silently retried into a second journal record,
//!   and a sink that just failed may be failing because it is corrupt, in
//!   which case more writes are the wrong medicine;
//! * one round yields at most one report and at most one submission, and the
//!   member identity is the observer's, bound at construction;
//! * the loop keeps no cross-round memory of its own: restarts resume purely
//!   from the durable journal (the store assigns contiguous sequences), so a
//!   round is never double-reported.
//!
//! [`observe`]: crate::observe
//! [`store`]: crate::store

use crate::decision::MemberReport;
use crate::observe::{AbstainReason, MemberObserver, Observation, RoundProbes};
use crate::store::{ConsensusStore, StoreError};
use std::sync::{Arc, Mutex};

/// Where one round's raw probe outcomes come from. Pure and injected: this
/// crate performs no network I/O, so the production probe lives behind this
/// seam in the server. Implementations return exactly one [`RoundProbes`]
/// per call; the loop calls them exactly once per round, including while the
/// loop is failed closed, so probe machinery keeps running.
pub trait ProbeSource {
    /// Gather one round of raw probe outcomes.
    fn probe(&mut self) -> RoundProbes;
}

/// Where formed reports go. The durable consensus store is the production
/// sink; the store remains the only writer of its journals.
pub trait ObservationSink {
    /// Errors of submitting a report.
    type Error;

    /// Durably accept one member report. An `Err` fails the reporting loop
    /// closed for reporting (sticky) — see [`ReportLoop`].
    fn submit(&mut self, report: &MemberReport) -> Result<(), Self::Error>;
}

/// How one reporting round fared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoundOutcome {
    /// The round's probes formed a report and the sink accepted it.
    Reported,
    /// The round abstained: no report existed, so nothing was submitted.
    Abstained(AbstainReason),
    /// The sink refused or failed this round's report. The loop is now
    /// failed closed for reporting (sticky) until
    /// [`ReportLoop::recover`].
    SinkFailed,
    /// The loop was already failed closed: this round's probes ran, but no
    /// report was formed or submitted.
    Suppressed,
}

/// The member-side reporting loop: probes -> [`MemberObserver`] -> sink.
/// One `run_round` is one reporting round.
pub struct ReportLoop<P: ProbeSource, S: ObservationSink> {
    observer: MemberObserver,
    probes: P,
    sink: S,
    /// Sticky failure: a loop whose sink failed reports nothing further
    /// until an explicit [`ReportLoop::recover`].
    failure: bool,
}

impl<P: ProbeSource, S: ObservationSink> ReportLoop<P, S> {
    /// Build the loop for one member identity: `observer` binds the identity
    /// stamped on every report, `probes` supplies one round of raw outcomes
    /// per round, and `sink` receives the reports that rounds produce.
    pub fn new(observer: MemberObserver, probes: P, sink: S) -> Self {
        Self {
            observer,
            probes,
            sink,
            failure: false,
        }
    }

    /// The member identity this loop reports as.
    pub fn member_id(&self) -> &str {
        self.observer.member_id()
    }

    /// Whether the loop failed closed earlier and currently reports nothing.
    pub fn failed(&self) -> bool {
        self.failure
    }

    /// Explicitly clear the sticky failure, so later rounds report again.
    /// Mirrors re-opening a failed store: the operator asserts the sink was
    /// repaired; nothing is replayed — the rounds that were suppressed were
    /// never observed as recorded, and the next round starts fresh.
    pub fn recover(&mut self) {
        self.failure = false;
    }

    /// Run one reporting round completed at `now_ms`: gather probes, form
    /// the observation, and submit the report when the round produced one.
    /// An abstaining round submits nothing. A failed submission fails the
    /// loop closed sticky; later rounds still probe but report nothing.
    pub fn run_round(&mut self, now_ms: u64) -> RoundOutcome {
        // Probes run every round, failed closed or not: the loop keeps its
        // probe machinery alive and observable while it reports nothing.
        let probes = self.probes.probe();
        if self.failure {
            return RoundOutcome::Suppressed;
        }
        match self.observer.observe(probes, now_ms) {
            Observation::Report(report) => match self.sink.submit(&report) {
                Ok(()) => RoundOutcome::Reported,
                Err(_) => {
                    self.failure = true;
                    RoundOutcome::SinkFailed
                }
            },
            Observation::Abstain(reason) => RoundOutcome::Abstained(reason),
        }
    }
}

/// Thin [`ObservationSink`] over the durable consensus store's append path
/// ([`ConsensusStore::record`]): the store stays the only writer of its
/// journals. The handle is shared (`Arc<Mutex<…>>`) because the executor
/// side reads rounds from the same store the reporter appends to; all
/// writes still go through the store's own append path under one lock.
pub struct ConsensusStoreSink {
    store: Arc<Mutex<ConsensusStore>>,
}

impl ConsensusStoreSink {
    /// Wrap a shared store handle as the reporting loop's sink.
    pub fn new(store: Arc<Mutex<ConsensusStore>>) -> Self {
        Self { store }
    }

    /// The shared store handle, for wiring an observation source over the
    /// same store.
    pub fn store(&self) -> &Arc<Mutex<ConsensusStore>> {
        &self.store
    }
}

impl ObservationSink for ConsensusStoreSink {
    type Error = StoreError;

    fn submit(&mut self, report: &MemberReport) -> Result<(), StoreError> {
        self.store
            .lock()
            .expect("the consensus store mutex was poisoned")
            .record(report)
    }
}

#[cfg(test)]
mod tests;
