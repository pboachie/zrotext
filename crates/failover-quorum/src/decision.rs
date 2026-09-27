// SPDX-License-Identifier: AGPL-3.0-only
//! Pure promotion-decision model for independent-quorum automatic failover.
//!
//! This module decides *when an automatic promotion is allowed to be
//! requested*, from quorum member observations only. It performs no I/O: the
//! caller gathers one [`Round`] of member reports per check, and an executor
//! applies (or refuses) the returned [`Decision`]. The safety rules encode
//! `MULTI-LOCATION.md`, "Automatic failover needs an independent decision":
//!
//! * an action needs a majority of the three configured failure domains to
//!   agree, and any fresh reachable observation of the writer vetoes
//!   promotion (uncertain evidence fails closed). Reports are folded per
//!   member identity, so duplicated submissions can never act as extra
//!   failure domains, a reachable duplicate still vetoes, and positive
//!   fencing/readiness evidence from a member must be unanimous;
//! * promotion happens only after the old writer's site fence and an
//!   externally confirmed stop are observed by a majority, and only while the
//!   standby is observed ready — fencing is never skipped to regain
//!   availability;
//! * the promoted epoch must be strictly above every epoch any member ever
//!   observed, must fit the signed 64-bit `deployment_authority.epoch`
//!   storage, and the controller must have observed at least one epoch at
//!   all, so processes pinned to an old epoch keep refusing traffic;
//! * dispatch stays paused after an unplanned promotion until an explicit
//!   reconciliation input, never as a consequence of health checks;
//! * the former writer may rejoin only as a replica, after sustained recovery
//!   (5 successful checks and 5 minutes stable by default). Restoring it as
//!   the writer stays a planned, manual procedure; no decision variant
//!   exists for it. Hysteresis never spans a round without quorum evidence:
//!   fences, the promotion epoch and reconciliation state are preserved, but
//!   an unknown interval restarts any incomplete streak.

use crate::policy::REQUIRED_MEMBERS;

/// Failed-check threshold before fencing is requested (design default).
pub const DEFAULT_FAILED_CHECKS_REQUIRED: u32 = 3;
/// Successful-check threshold before the former writer may rejoin as replica.
pub const DEFAULT_RECOVERY_CHECKS_REQUIRED: u32 = 5;
/// Minimum stable duration before the former writer may rejoin as replica.
pub const DEFAULT_RECOVERY_STABLE_MS: u64 = 5 * 60 * 1000;
/// Age beyond which a member observation is no longer evidence.
pub const DEFAULT_OBSERVATION_FRESHNESS_MS: u64 = 10_000;
/// Highest epoch a promotion may name: `deployment_authority.epoch` is a
/// PostgreSQL bigint (signed 64-bit), so a successor above this value could
/// never be applied by the executor.
pub const MAX_STORED_EPOCH: u64 = i64::MAX as u64;

/// Configured quorum: three member identities plus the two sites whose
/// writer/standby roles the controller watches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailoverConfig {
    members: Vec<String>,
    writer_site_id: String,
    standby_site_id: String,
    failed_checks_required: u32,
    recovery_checks_required: u32,
    recovery_stable_ms: u64,
    observation_freshness_ms: u64,
}

impl FailoverConfig {
    /// Validate a configuration. Member identities must be exactly three
    /// distinct non-empty strings (one per independent failure domain) and the
    /// writer and standby must be different non-empty sites. Check thresholds
    /// start from the design defaults documented on the constants.
    pub fn new(
        members: Vec<String>,
        writer_site_id: impl Into<String>,
        standby_site_id: impl Into<String>,
    ) -> Result<Self, String> {
        if members.len() != REQUIRED_MEMBERS {
            return Err(format!(
                "the quorum needs exactly {REQUIRED_MEMBERS} independent members"
            ));
        }
        if members.iter().any(String::is_empty) {
            return Err("member identifiers must not be empty".to_owned());
        }
        for (index, member) in members.iter().enumerate() {
            if members[..index].contains(member) {
                return Err("member identifiers must be distinct".to_owned());
            }
        }
        let writer_site_id = writer_site_id.into();
        let standby_site_id = standby_site_id.into();
        if writer_site_id.is_empty() || standby_site_id.is_empty() {
            return Err("writer and standby site identifiers must not be empty".to_owned());
        }
        if writer_site_id == standby_site_id {
            return Err("writer and standby must be different sites".to_owned());
        }
        Ok(Self {
            members,
            writer_site_id,
            standby_site_id,
            failed_checks_required: DEFAULT_FAILED_CHECKS_REQUIRED,
            recovery_checks_required: DEFAULT_RECOVERY_CHECKS_REQUIRED,
            recovery_stable_ms: DEFAULT_RECOVERY_STABLE_MS,
            observation_freshness_ms: DEFAULT_OBSERVATION_FRESHNESS_MS,
        })
    }

    /// The quorum member identities.
    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// The site currently holding writer authority when the controller starts.
    pub fn writer_site_id(&self) -> &str {
        &self.writer_site_id
    }

    /// The site promoted when failover is authorized.
    pub fn standby_site_id(&self) -> &str {
        &self.standby_site_id
    }

    /// Override the failed/successful check thresholds (hysteresis is tuned
    /// per deployment after tests).
    #[must_use]
    pub fn with_check_thresholds(
        mut self,
        failed_checks_required: u32,
        recovery_checks_required: u32,
    ) -> Self {
        self.failed_checks_required = failed_checks_required;
        self.recovery_checks_required = recovery_checks_required;
        self
    }

    /// Override the minimum stable duration before a former-writer rejoin.
    #[must_use]
    pub fn with_recovery_stable_ms(mut self, recovery_stable_ms: u64) -> Self {
        self.recovery_stable_ms = recovery_stable_ms;
        self
    }

    /// Override how long a member observation counts as fresh evidence.
    #[must_use]
    pub fn with_observation_freshness_ms(mut self, observation_freshness_ms: u64) -> Self {
        self.observation_freshness_ms = observation_freshness_ms;
        self
    }
}

/// What one quorum member observed about the current PostgreSQL writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriterObservation {
    /// The member reached the writer and observed this deployment epoch.
    Reachable { epoch: u64 },
    /// The member could not reach the writer at all.
    Unreachable,
}

/// The `sites` row of the old writer as one member observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiteFenceState {
    pub enabled: bool,
    pub draining: bool,
}

impl SiteFenceState {
    /// A site is fenced when it is draining or disabled, matching the
    /// readiness and startup checks that refuse traffic for such sites.
    pub fn is_fenced(&self) -> bool {
        !self.enabled || self.draining
    }
}

/// One member's report for one check round. `None` fields mean the member
/// carries no evidence of that kind this round; they never count in favor of
/// an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberReport {
    pub member_id: String,
    pub observed_at_ms: u64,
    pub writer: WriterObservation,
    /// The old writer's `sites` row as this member last saw it.
    pub writer_site_fence: Option<SiteFenceState>,
    /// External watchdog evidence that the old writer's PostgreSQL is stopped
    /// and cannot restart itself.
    pub writer_stop_confirmed: Option<bool>,
    /// Whether the standby is caught up and safe to promote.
    pub standby_ready: Option<bool>,
    /// Post-promotion observation of the former writer host's health.
    pub former_writer_healthy: Option<bool>,
}

/// The reports one check round gathered. A member that could not be reached
/// simply contributes no report, and a member that appears more than once is
/// folded into a single vote (see [`FailoverController::observe`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Round {
    pub reports: Vec<MemberReport>,
}

/// Coarse controller phase, exposed for tests and operator introspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The configured writer is reachable per a quorum majority.
    Steady,
    /// A majority observes the writer unreachable, below the failed-check
    /// threshold; nothing has been requested yet.
    Suspecting { consecutive_failures: u32 },
    /// Fencing was requested; promotion waits for fence, stop and standby
    /// readiness evidence to reach a majority.
    FencingOldWriter,
    /// The standby was promoted under `new_epoch`.
    Promoted {
        new_epoch: u64,
        /// Whether the explicit post-promotion reconciliation input arrived.
        reconciled: bool,
        /// Whether the one-time rejoin-as-replica decision was emitted.
        rejoin_emitted: bool,
        healthy_streak: u32,
        stable_since_ms: Option<u64>,
    },
}

/// The subset of controller phase that is worth persisting across a
/// restart. Suspecting streaks are deliberately absent: a restart is an
/// unknown interval, and the decision model already refuses to count unknown
/// intervals as stable evidence, so a restored controller resumes hysteresis
/// from zero instead of inheriting a possibly-stale streak.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestorablePhase {
    /// No durable action was taken yet.
    Steady,
    /// Fencing the old writer was requested and applied.
    FencingOldWriter,
    /// A promotion was decided and its intent journaled; the promotion
    /// applies exactly `new_epoch`. Restoring re-derives the fencing phase
    /// with an epoch memory of `new_epoch - 1`, so the next promotion
    /// decision re-emits the same epoch rather than inventing a new one.
    Promoting { new_epoch: u64 },
    /// The promotion applied: the authority serves `new_epoch`.
    Promoted {
        new_epoch: u64,
        reconciled: bool,
        rejoin_emitted: bool,
    },
}

impl RestorablePhase {
    /// Stable label for the journal encoding.
    pub fn label(&self) -> &'static str {
        match self {
            RestorablePhase::Steady => "steady",
            RestorablePhase::FencingOldWriter => "fencing",
            RestorablePhase::Promoting { .. } => "promoting",
            RestorablePhase::Promoted { .. } => "promoted",
        }
    }
}

/// The action (or deliberate non-action) for one check round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Take no action this round; the reason records what the quorum saw.
    Hold(HoldReason),
    /// Fewer than a majority of distinct fresh member votes: there is no
    /// evidence to act on, and the controller must keep every fence in place.
    /// Incomplete hysteresis streaks restart; an unknown interval is not
    /// stable evidence.
    QuorumLost,
    /// Request fencing the old writer's site and stopping its PostgreSQL so it
    /// cannot accept mutations or restart as a writer.
    FenceOldWriter { site_id: String },
    /// Request promoting the standby under a strictly higher deployment
    /// epoch. The executor must keep dispatch paused after an unplanned
    /// promotion. `new_epoch` is guaranteed to fit the signed 64-bit
    /// `deployment_authority.epoch` storage.
    PromoteStandby { site_id: String, new_epoch: u64 },
    /// The promoted writer serves, but dispatch stays paused until the
    /// explicit reconciliation input arrives.
    KeepDispatchPaused,
    /// The former writer may rejoin, reseeded/rewound, as a replica only.
    RejoinFormerWriterAsReplica { site_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HoldReason {
    /// A majority observes the writer reachable.
    WriterHealthy,
    /// A majority observes the writer unreachable, but the consecutive
    /// failure threshold is not yet met.
    WriterFailureSuspected { consecutive_failures: u32 },
    /// Fresh observations disagree about writer reachability; a single fresh
    /// reachable observation vetoes promotion while evidence is uncertain.
    ConflictingEvidence {
        reachable: usize,
        unreachable: usize,
    },
    /// Fencing evidence has not reached a majority yet.
    AwaitingFencingEvidence {
        site_fenced: bool,
        stop_confirmed: bool,
    },
    /// The standby is not observed ready; promotion stays blocked.
    AwaitingStandbyReadiness,
    /// The writer recovered while fencing was pending; the failover is
    /// cancelled. Reversing an already-applied fence stays a manual action.
    FailoverCancelledWriterRecovered,
    /// No reachable epoch was ever observed, so no provably higher promotion
    /// epoch exists. This controller fails closed instead of guessing.
    EpochUnknown,
    /// No epoch representable in the authority's signed 64-bit storage exists
    /// above every observed epoch; promoting would emit an unexecutable
    /// successor.
    EpochExhausted,
    /// Promoted and reconciled; steady on the new writer.
    SteadyOnNewWriter,
    /// The former writer is recovering but hysteresis is not yet satisfied.
    FormerWriterRecovering { healthy_checks: u32, stable_ms: u64 },
}

/// The promotion-decision state machine. Deterministic and clock-injective:
/// every observation takes `now_ms` from the caller.
#[derive(Debug)]
pub struct FailoverController {
    config: FailoverConfig,
    phase: Phase,
    /// Highest writer epoch any fresh observation ever reported. Promotion
    /// epochs must be strictly above it, so stale pinned processes keep
    /// refusing traffic after a promotion.
    max_epoch_seen: u64,
}

impl FailoverController {
    pub fn new(config: FailoverConfig) -> Self {
        Self {
            config,
            phase: Phase::Steady,
            max_epoch_seen: 0,
        }
    }

    /// The current phase.
    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    /// The highest writer epoch any fresh observation ever reported. A
    /// restored controller never regresses below this value.
    pub fn max_epoch_seen(&self) -> u64 {
        self.max_epoch_seen
    }

    /// Rebuild a controller from durable state. Hysteresis streaks restart at
    /// zero (an unknown interval is not stable evidence), while fences, the
    /// promotion epoch memory and the reconciliation/rejoin flags survive.
    /// Restoring a [`RestorablePhase::Promoting`] intent pins the epoch memory
    /// to `new_epoch - 1` so the promotion decision re-emits exactly the
    /// journaled epoch; a crafted `new_epoch` of zero leaves the epoch memory
    /// unknown, which can only hold.
    pub fn restore(config: FailoverConfig, max_epoch_seen: u64, phase: RestorablePhase) -> Self {
        let max_epoch_seen = match phase {
            RestorablePhase::Promoting { new_epoch }
            | RestorablePhase::Promoted { new_epoch, .. } => new_epoch.saturating_sub(1),
            _ => max_epoch_seen,
        };
        let phase = match phase {
            RestorablePhase::Steady => Phase::Steady,
            RestorablePhase::FencingOldWriter | RestorablePhase::Promoting { .. } => {
                Phase::FencingOldWriter
            }
            RestorablePhase::Promoted {
                new_epoch,
                reconciled,
                rejoin_emitted,
            } => Phase::Promoted {
                new_epoch,
                reconciled,
                rejoin_emitted,
                healthy_streak: 0,
                stable_since_ms: None,
            },
        };
        Self {
            config,
            phase,
            max_epoch_seen,
        }
    }

    /// The configuration this controller was built with.
    pub fn config(&self) -> &FailoverConfig {
        &self.config
    }

    /// Explicit operator/controller input: the uncertain acceptance window,
    /// ledgers and device journals after an unplanned promotion were
    /// reconciled. Health checks can never produce this transition.
    pub fn reconcile_complete(&mut self) -> Result<(), &'static str> {
        match &mut self.phase {
            Phase::Promoted { reconciled, .. } if !*reconciled => {
                *reconciled = true;
                Ok(())
            }
            _ => Err("reconciliation is only outstanding immediately after promotion"),
        }
    }

    /// Evaluate one check round. Reports that are missing, stale, or from
    /// members outside the configured quorum are not evidence, and duplicate
    /// submissions from one member identity are folded into that member's
    /// single vote so they can never act as extra failure domains: a
    /// reachable report always dominates the member's writer vote (the veto
    /// is never dropped), while positive fencing, stop, standby-readiness and
    /// former-writer-health evidence counts only when unanimous across that
    /// member's reports. If fewer than a majority of distinct fresh members
    /// remains, the round fails closed with [`Decision::QuorumLost`]: fences,
    /// the promotion epoch and reconciliation state are preserved, but any
    /// incomplete hysteresis streak restarts, because an unknown interval is
    /// not stable evidence.
    pub fn observe(&mut self, round: Round, now_ms: u64) -> Decision {
        let fresh: Vec<&MemberReport> = round
            .reports
            .iter()
            .filter(|report| self.config.members.contains(&report.member_id))
            .filter(|report| {
                report.observed_at_ms <= now_ms
                    && now_ms - report.observed_at_ms <= self.config.observation_freshness_ms
            })
            .collect();
        let mut votes: Vec<MemberVote> = Vec::with_capacity(self.config.members.len());
        for report in fresh {
            if let Some(slot) = votes
                .iter_mut()
                .find(|vote| vote.member_id == report.member_id)
            {
                slot.fold(report);
            } else {
                votes.push(MemberVote::from(report));
            }
        }
        for vote in &votes {
            if let Some(epoch) = vote.reachable_epoch {
                self.max_epoch_seen = self.max_epoch_seen.max(epoch);
            }
        }
        let majority = self.majority();
        if votes.len() < majority {
            self.reset_hysteresis_on_lost_evidence();
            return Decision::QuorumLost;
        }
        let reachable = votes
            .iter()
            .filter(|vote| vote.reachable_epoch.is_some())
            .count();
        let consensus = Consensus {
            majority,
            healthy: reachable >= majority,
            // Any fresh reachable member vote vetoes a failure consensus.
            failure: votes.len() - reachable >= majority && reachable == 0,
            reachable,
            unreachable: votes.len() - reachable,
        };
        match self.phase.clone() {
            Phase::Steady => self.observe_steady(consensus),
            Phase::Suspecting {
                consecutive_failures,
            } => self.observe_suspecting(consecutive_failures, consensus),
            Phase::FencingOldWriter => self.observe_fencing(&votes, consensus),
            Phase::Promoted { .. } => self.observe_promoted(&votes, consensus.majority, now_ms),
        }
    }

    /// A round without a majority of fresh member votes preserves fences,
    /// the promotion epoch and reconciliation state, but restarts any
    /// incomplete hysteresis: an interval with no evidence is not stable.
    fn reset_hysteresis_on_lost_evidence(&mut self) {
        if matches!(self.phase, Phase::Suspecting { .. }) {
            self.phase = Phase::Steady;
        }
        if let Phase::Promoted {
            healthy_streak,
            stable_since_ms,
            ..
        } = &mut self.phase
        {
            *healthy_streak = 0;
            *stable_since_ms = None;
        }
    }

    fn majority(&self) -> usize {
        self.config.members.len() / 2 + 1
    }

    fn observe_steady(&mut self, consensus: Consensus) -> Decision {
        if consensus.healthy {
            return Decision::Hold(HoldReason::WriterHealthy);
        }
        if consensus.failure {
            return self.enter_suspecting(1);
        }
        Decision::Hold(HoldReason::ConflictingEvidence {
            reachable: consensus.reachable,
            unreachable: consensus.unreachable,
        })
    }

    fn observe_suspecting(&mut self, consecutive_failures: u32, consensus: Consensus) -> Decision {
        if consensus.healthy {
            self.phase = Phase::Steady;
            return Decision::Hold(HoldReason::WriterHealthy);
        }
        if consensus.failure {
            return self.enter_suspecting(consecutive_failures.saturating_add(1));
        }
        // Evidence turned ambiguous: reset the streak rather than fence on a
        // health flap.
        self.phase = Phase::Steady;
        Decision::Hold(HoldReason::ConflictingEvidence {
            reachable: consensus.reachable,
            unreachable: consensus.unreachable,
        })
    }

    fn enter_suspecting(&mut self, consecutive_failures: u32) -> Decision {
        if consecutive_failures >= self.config.failed_checks_required {
            self.phase = Phase::FencingOldWriter;
            return Decision::FenceOldWriter {
                site_id: self.config.writer_site_id.clone(),
            };
        }
        self.phase = Phase::Suspecting {
            consecutive_failures,
        };
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures,
        })
    }

    fn observe_fencing(&mut self, votes: &[MemberVote], consensus: Consensus) -> Decision {
        if consensus.healthy {
            // The writer recovered before promotion was authorized. Cancel the
            // failover; an already-applied fence is reversed manually, never
            // by this decision loop.
            self.phase = Phase::Steady;
            return Decision::Hold(HoldReason::FailoverCancelledWriterRecovered);
        }
        if !consensus.failure {
            // Reachability is ambiguous while a fence is pending: keep
            // waiting, never promote on uncertain evidence.
            return Decision::Hold(HoldReason::ConflictingEvidence {
                reachable: consensus.reachable,
                unreachable: consensus.unreachable,
            });
        }
        let site_fenced =
            votes.iter().filter(|vote| vote.site_fenced).count() >= consensus.majority;
        let stop_confirmed =
            votes.iter().filter(|vote| vote.stop_confirmed).count() >= consensus.majority;
        if !site_fenced || !stop_confirmed {
            return Decision::Hold(HoldReason::AwaitingFencingEvidence {
                site_fenced,
                stop_confirmed,
            });
        }
        let standby_ready =
            votes.iter().filter(|vote| vote.standby_ready).count() >= consensus.majority;
        if !standby_ready {
            return Decision::Hold(HoldReason::AwaitingStandbyReadiness);
        }
        // A controller that never observed an epoch cannot prove its
        // promotion epoch is higher; fail closed instead of guessing.
        if self.max_epoch_seen == 0 {
            return Decision::Hold(HoldReason::EpochUnknown);
        }
        // deployment_authority.epoch is a PostgreSQL bigint and the server
        // pins it to i64: a promotion epoch outside the signed 64-bit range
        // could never be applied. Refuse instead of emitting an unexecutable
        // successor epoch.
        if self.max_epoch_seen >= MAX_STORED_EPOCH {
            return Decision::Hold(HoldReason::EpochExhausted);
        }
        let Some(new_epoch) = self.max_epoch_seen.checked_add(1) else {
            return Decision::Hold(HoldReason::EpochExhausted);
        };
        self.phase = Phase::Promoted {
            new_epoch,
            reconciled: false,
            rejoin_emitted: false,
            healthy_streak: 0,
            stable_since_ms: None,
        };
        Decision::PromoteStandby {
            site_id: self.config.standby_site_id.clone(),
            new_epoch,
        }
    }

    fn observe_promoted(&mut self, votes: &[MemberVote], majority: usize, now_ms: u64) -> Decision {
        let Phase::Promoted {
            reconciled,
            rejoin_emitted,
            healthy_streak,
            stable_since_ms,
            ..
        } = &mut self.phase
        else {
            unreachable!("observe_promoted is only entered from Phase::Promoted");
        };
        if !*reconciled {
            return Decision::KeepDispatchPaused;
        }
        if *rejoin_emitted {
            return Decision::Hold(HoldReason::SteadyOnNewWriter);
        }
        let former_healthy = votes
            .iter()
            .filter(|vote| vote.former_writer_healthy)
            .count()
            >= majority;
        if !former_healthy {
            *healthy_streak = 0;
            *stable_since_ms = None;
            return Decision::Hold(HoldReason::SteadyOnNewWriter);
        }
        *healthy_streak = healthy_streak.saturating_add(1);
        let stable_since_ms = stable_since_ms.get_or_insert(now_ms);
        let stable_ms = now_ms.saturating_sub(*stable_since_ms);
        let rejoin = *healthy_streak >= self.config.recovery_checks_required
            && stable_ms >= self.config.recovery_stable_ms;
        if rejoin {
            *rejoin_emitted = true;
            return Decision::RejoinFormerWriterAsReplica {
                site_id: self.config.writer_site_id.clone(),
            };
        }
        Decision::Hold(HoldReason::FormerWriterRecovering {
            healthy_checks: *healthy_streak,
            stable_ms,
        })
    }
}

struct Consensus {
    majority: usize,
    healthy: bool,
    failure: bool,
    reachable: usize,
    unreachable: usize,
}

/// One member's folded vote for a round, built from that member's fresh
/// reports. Duplicate submissions never act as extra failure domains: a
/// reachable report always dominates the writer vote (the veto is never
/// dropped), and positive fencing/readiness/health evidence counts only when
/// unanimous across the member's reports.
#[derive(Clone, Debug)]
struct MemberVote {
    member_id: String,
    /// Highest epoch among this member's reachable reports; `None` when
    /// every report saw the writer unreachable.
    reachable_epoch: Option<u64>,
    site_fenced: bool,
    stop_confirmed: bool,
    standby_ready: bool,
    former_writer_healthy: bool,
}

impl From<&MemberReport> for MemberVote {
    fn from(report: &MemberReport) -> Self {
        let mut vote = MemberVote {
            member_id: report.member_id.clone(),
            reachable_epoch: None,
            site_fenced: true,
            stop_confirmed: true,
            standby_ready: true,
            former_writer_healthy: true,
        };
        vote.fold(report);
        vote
    }
}

impl MemberVote {
    fn fold(&mut self, report: &MemberReport) {
        if let WriterObservation::Reachable { epoch } = report.writer {
            self.reachable_epoch = Some(self.reachable_epoch.map_or(epoch, |seen| seen.max(epoch)));
        }
        self.site_fenced &= report
            .writer_site_fence
            .is_some_and(|fence| fence.is_fenced());
        self.stop_confirmed &= report.writer_stop_confirmed == Some(true);
        self.standby_ready &= report.standby_ready == Some(true);
        self.former_writer_healthy &= report.former_writer_healthy == Some(true);
    }
}
