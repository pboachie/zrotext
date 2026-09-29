// SPDX-License-Identifier: AGPL-3.0-only
//! Member-side observation forming for independent-quorum failover.
//!
//! This module is the reporter half of the member-reporting transport
//! planned in `MULTI-LOCATION.md`: the code a quorum member runs to turn
//! one round of raw probe outcomes into a [`MemberReport`] — the exact
//! evidence type the decision model consumes — or into a deliberate
//! abstention. It is pure logic over injected probe results and performs no
//! I/O, like the rest of this crate.
//!
//! Safety rules, in short (their failure-scenario tests live in
//! `observe/tests.rs`):
//!
//! * only a definitive connection failure is negative evidence about the
//!   writer; a probe that fails for member-local reasons (bad configuration,
//!   DNS, TLS, authentication, driver error) yields **no report at all**,
//!   so a faulty member can neither veto with a phantom reachable vote nor
//!   push the quorum toward fencing a healthy writer;
//! * an epoch the authority schema cannot hold (zero, or above the signed
//!   64-bit `deployment_authority.epoch` range) is a probe fault, never an
//!   observed epoch;
//! * evidence is per-round: nothing observed in an earlier round is carried
//!   into a later report, and only probes that completed and answered
//!   contribute evidence — an unanswered probe is absence of evidence, not
//!   negative evidence;
//! * a round that observed the writer alive carries no stop-confirmation
//!   evidence: a member never simultaneously attests a live writer and a
//!   stopped one;
//! * the member identity is bound at construction and stamped on every
//!   report; one round yields at most one report.
//!
//! The observer stays pure: it is invoked by the member-side reporting loop
//! ([`crate::report::ReportLoop`]) and by tests, never by a network listener
//! — this crate performs no I/O, and the failover feature remains disabled
//! by default.

use crate::decision::{MAX_STORED_EPOCH, MemberReport, SiteFenceState, WriterObservation};

/// Why a probe produced no evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeFault {
    /// A connection was attempted and definitively failed: the probed
    /// system did not answer. For the writer probe this is the only
    /// acceptable source of an unreachable vote; for every other probe it
    /// is merely absence of evidence.
    Unreachable,
    /// The probe could not establish anything about its target (invalid
    /// configuration, DNS resolution failure, TLS or authentication
    /// failure, driver or protocol error). Never evidence in any
    /// direction.
    Indeterminate,
}

/// The writer probe outcome for one round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterProbe {
    /// The writer answered and served this deployment epoch.
    Reachable { epoch: u64 },
    /// A connection was attempted and definitively failed (timeout,
    /// connection refused, reset, no route).
    Unreachable,
    /// The probe outcome says nothing about the writer.
    Indeterminate,
}

/// The external watchdog's attestation about the old writer's PostgreSQL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopConfirmation {
    /// Whether the watchdog confirms the old writer's PostgreSQL is stopped
    /// and cannot restart itself.
    pub confirmed: bool,
}

/// One round of raw probe outcomes for a single member. Every probe is
/// re-run each round: evidence never carries over from a previous round.
/// An `Err` field means the probe produced no evidence this round, whether
/// it was not run, could not connect, or returned an ambiguous result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundProbes {
    /// Probe of the current writer's PostgreSQL (the
    /// `deployment_authority.epoch` read).
    pub writer: WriterProbe,
    /// Probe of the old writer's site-fence state (`sites` row).
    pub writer_site_fence: Result<SiteFenceState, ProbeFault>,
    /// Probe of the external watchdog attesting the old writer's stop.
    pub writer_stop: Result<StopConfirmation, ProbeFault>,
    /// Probe of the standby's promotion readiness.
    pub standby: Result<bool, ProbeFault>,
    /// Probe of the former writer host's health (post-promotion rounds).
    pub former_writer: Result<bool, ProbeFault>,
}

/// What one member contributes to a check round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    /// Safe evidence for this round, addressed to the quorum.
    Report(MemberReport),
    /// The member abstains: its own probes could not attest the writer's
    /// state, so it contributes no evidence at all rather than guessing in
    /// either direction. The remaining members decide.
    Abstain(AbstainReason),
}

impl Observation {
    /// The report, when this round produced one.
    pub fn report(self) -> Option<MemberReport> {
        match self {
            Observation::Report(report) => Some(report),
            Observation::Abstain(_) => None,
        }
    }
}

/// Why a member abstained from a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbstainReason {
    /// The writer probe was indeterminate: neither a reachable epoch nor a
    /// definitive connection failure (member-local misconfiguration, DNS,
    /// TLS, authentication or driver fault).
    WriterIndeterminate,
    /// The writer probe reported an epoch the authority cannot hold (zero,
    /// or above the signed 64-bit `deployment_authority.epoch` range): the
    /// probe layer itself is misbehaving.
    WriterEpochImpossible,
}

/// Builds one member's quorum report per round from raw probe outcomes.
#[derive(Clone, Debug)]
pub struct MemberObserver {
    member_id: String,
}

impl MemberObserver {
    /// Create the observer for one quorum member identity. The identity is
    /// bound here and stamped on every report, so a report can never claim
    /// another member's identity.
    pub fn new(member_id: impl Into<String>) -> Result<Self, String> {
        let member_id = member_id.into();
        if member_id.is_empty() {
            return Err("member identifier must not be empty".to_owned());
        }
        Ok(Self { member_id })
    }

    /// The member identity this observer reports as.
    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    /// Form this round's contribution from raw probe outcomes. `now_ms` is
    /// the round's completion time, stamped as `observed_at_ms`; freshness
    /// is enforced downstream by the decision model's observation window.
    pub fn observe(&self, probes: RoundProbes, now_ms: u64) -> Observation {
        // The writer vote is mandatory evidence, so it decides whether the
        // member may report at all. Only a definitive connection failure is
        // an unreachable vote; a member-local fault abstains, and an epoch
        // the authority schema cannot hold is a probe fault rather than an
        // observation.
        let writer = match probes.writer {
            WriterProbe::Reachable { epoch } => {
                if epoch == 0 || epoch > MAX_STORED_EPOCH {
                    return Observation::Abstain(AbstainReason::WriterEpochImpossible);
                }
                WriterObservation::Reachable { epoch }
            }
            WriterProbe::Unreachable => WriterObservation::Unreachable,
            WriterProbe::Indeterminate => {
                return Observation::Abstain(AbstainReason::WriterIndeterminate);
            }
        };
        // A member that observed the writer alive this round cannot also
        // attest that the writer is stopped: the live observation wins and
        // no stop-confirmation evidence is carried, whatever the watchdog
        // claims.
        let writer_alive = matches!(writer, WriterObservation::Reachable { .. });
        let writer_stop_confirmed = match probes.writer_stop {
            Ok(confirmation) if !writer_alive => Some(confirmation.confirmed),
            _ => None,
        };
        // Every other probe contributes evidence only when it completed and
        // answered; a fault (or a probe that was not run) is absence of
        // evidence, never negative evidence.
        Observation::Report(MemberReport {
            member_id: self.member_id.clone(),
            observed_at_ms: now_ms,
            writer,
            writer_site_fence: probes.writer_site_fence.ok(),
            writer_stop_confirmed,
            standby_ready: probes.standby.ok(),
            former_writer_healthy: probes.former_writer.ok(),
        })
    }
}

#[cfg(test)]
mod tests;
