// SPDX-License-Identifier: AGPL-3.0-only
//! Execution of quorum failover decisions against the authoritative writer
//! database.
//!
//! The [`decision`] module decides *when* an automatic promotion may be
//! requested. This module is the second half: a controller loop that gathers
//! member observations through a pluggable [`ObservationSource`], runs
//! [`decision::FailoverController`] rounds, and applies the emitted
//! [`decision::Decision`]s to the authoritative writer database through the
//! [`WriterAuthority`] port:
//!
//! * [`decision::Decision::FenceOldWriter`] sets the old writer's `sites` row
//!   draining;
//! * [`decision::Decision::PromoteStandby`] bumps `deployment_authority.epoch`
//!   to exactly `new_epoch` (compare-and-set, never backward, never twice),
//!   enables the promoted site and forces dispatch paused in one atomic
//!   operation — conditional on the old writer's site row still showing a
//!   fence, so a promotion can never pass an unfenced writer;
//! * [`decision::Decision::RejoinFormerWriterAsReplica`] is recorded
//!   one-time in the journal; the physical reseed/rewind stays an external
//!   operation;
//! * the executor has **no operation that unpauses dispatch or reverses a
//!   fence**: [`decision::Decision::KeepDispatchPaused`] holds by construction.
//!
//! Durability: the executor persists a [`ControllerJournal`] through the same
//! port *before* applying a promotion (write-ahead intent) and after every
//! applied action, so a restart resumes the interrupted failover at the exact
//! promotion epoch instead of re-deciding or double-bumping. All applications
//! are idempotent: a fence re-apply is a no-op, a promotion replay meets the
//! epoch compare-and-set and confirms rather than bumps. A journal that claims
//! a promotion the authority never applied (for example after a database
//! restore from backup) fails closed permanently instead of acting.
//!
//! This module performs no I/O itself: both the observation source and the
//! authority port are injected, which keeps every failure scenario below
//! unit-testable. The in-process source in this build collects nothing until
//! real quorum members exist (a later increment wires the consensus store).

use crate::decision::{
    Decision, FailoverConfig, FailoverController, Phase, RestorablePhase, Round, SiteFenceState,
};
use std::collections::VecDeque;
use std::fmt;

/// Where the executor gathers one round of member observations from. The
/// implementation is pluggable so a later increment can replace the
/// in-process source with the real three-member consensus store without
/// touching the executor.
pub trait ObservationSource {
    /// Gather the reports for the check round at `now_ms`.
    fn collect(&mut self, now_ms: u64) -> Round;
}

/// The in-process observation source: pops one queued round per collect and
/// contributes an empty round when nothing is queued. An empty round is never
/// a quorum, so until real members report through it the executor can only
/// hold — this is the deliberate default of this build.
#[derive(Default)]
pub struct InProcessSource {
    queued: VecDeque<Round>,
}

impl InProcessSource {
    /// Queue a round for a later collect.
    pub fn queue(&mut self, round: Round) {
        self.queued.push_back(round);
    }
}

impl ObservationSource for InProcessSource {
    fn collect(&mut self, _now_ms: u64) -> Round {
        self.queued.pop_front().unwrap_or_default()
    }
}

/// What the authoritative writer database currently looks like to the
/// executor: the deployment epoch, whether dispatch is enabled, and the
/// `sites` rows of the two configured sites (`None` when no row exists).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub epoch: u64,
    pub dispatch_enabled: bool,
    pub writer_site: Option<SiteFenceState>,
    pub standby_site: Option<SiteFenceState>,
}

/// Result of applying a fence to the old writer's `sites` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceOutcome {
    /// The row's draining flag was set by this call.
    Fenced,
    /// The row was already draining (or disabled); the fence already held.
    AlreadyFenced,
    /// No `sites` row exists for the site: the fence cannot hold, and this
    /// outcome is never treated as success.
    SiteRowMissing,
}

/// Result of applying a promotion to the authority. The epoch compare-and-set
/// means a promotion can only ever move the epoch forward to exactly
/// `new_epoch`, at most once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromoteOutcome {
    /// The epoch moved to exactly `new_epoch`, the promoted site was enabled
    /// and dispatch was forced paused, atomically.
    Promoted,
    /// The authority already serves `new_epoch`: the promotion is complete
    /// and the replay changed nothing.
    AlreadyAtEpoch,
    /// The authority epoch is beyond `new_epoch`: someone else owns the
    /// authority now and it must never move backward. Permanent refusal.
    RefusedHigherEpoch { current: u64 },
    /// The old writer's `sites` row no longer shows a fence. A promotion is
    /// never applied past an unfenced writer; retried until the fence holds
    /// again.
    RefusedWriterUnfenced,
    /// No `sites` row exists for the promoted site; never success.
    SiteRowMissing,
}

/// The authoritative writer database port all decisions are applied through.
/// Implementations must make each operation atomic and idempotent with the
/// semantics documented on its outcome type.
pub trait WriterAuthority {
    type Error;

    /// Read the current authority state for the two configured sites.
    /// Called once per executor start (and re-tried while unreachable).
    fn load_state(
        &mut self,
        writer_site: &str,
        standby_site: &str,
    ) -> Result<AuthoritySnapshot, Self::Error>;

    /// Set the old writer's `sites` row draining.
    fn fence_writer_site(&mut self, site_id: &str) -> Result<FenceOutcome, Self::Error>;

    /// Atomically: hold the `deployment_authority` row, verify the old
    /// writer's `sites` row still shows a fence, then move the epoch to
    /// exactly `new_epoch` (only forward), enable the promoted site and force
    /// dispatch paused.
    fn promote_standby(
        &mut self,
        promoted_site: &str,
        fenced_writer_site: &str,
        new_epoch: u64,
    ) -> Result<PromoteOutcome, Self::Error>;

    /// Persist the encoded controller journal durably.
    fn save_controller_state(&mut self, encoded: &str) -> Result<(), Self::Error>;

    /// Load the encoded controller journal, `None` when none was saved.
    fn load_controller_state(&mut self) -> Result<Option<String>, Self::Error>;
}

/// The durable controller journal: the subset of controller state that must
/// survive a restart, plus the configuration it belongs to. Hysteresis streaks
/// are deliberately not journaled — a restart is an unknown interval, and the
/// decision model already refuses to count unknown intervals as stable
/// evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerJournal {
    pub members: Vec<String>,
    pub writer_site_id: String,
    pub standby_site_id: String,
    pub max_epoch_seen: u64,
    pub phase: RestorablePhase,
}

/// A pending decision whose application failed against the authority and is
/// retried with identical parameters on later ticks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingAction {
    Fence { site_id: String },
    Promote { site_id: String, new_epoch: u64 },
}

/// An action the executor applied to the authority this tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppliedAction {
    Fence {
        site_id: String,
        outcome: FenceOutcome,
    },
    Promote {
        site_id: String,
        new_epoch: u64,
        outcome: PromoteOutcome,
    },
    /// The one-time rejoin emission was recorded in the journal.
    RejoinRecorded { site_id: String },
}

/// How the tick's decision fared against the authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Application {
    /// Nothing to apply.
    None,
    /// Applied this tick; `replayed` marks an idempotent confirmation of an
    /// earlier application rather than a change.
    Applied {
        action: AppliedAction,
        replayed: bool,
    },
    /// The authority could not apply the action yet (transport failure,
    /// missing site row, or an unfenced writer). The action stays pending and
    /// is retried unchanged.
    Pending { action: PendingAction },
    /// The authority epoch moved beyond the promotion epoch: the decision is
    /// permanently superseded and the executor fails closed.
    Superseded {
        promotion_epoch: u64,
        authority_epoch: u64,
    },
}

/// The outcome of one executor tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickReport {
    /// The round's decision, or `None` when no round ran (the authority is
    /// unreachable, or the executor failed closed).
    pub decision: Option<Decision>,
    pub application: Application,
    pub journal_saved: bool,
}

/// Coarse executor state, exposed for tests and operator introspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutorStatus {
    /// The authority is not reachable yet; nothing is decided or applied.
    WaitingForAuthority,
    /// Rounds are running.
    Running,
    /// The journal claims a promotion the authority never applied — for
    /// example a database restored from backup while the journal survived.
    /// The executor fails closed permanently; the operator must reconcile
    /// journal and database manually.
    JournalInconsistent {
        journal_epoch: u64,
        authority_epoch: u64,
    },
    /// The authority epoch moved beyond the journaled promotion intent, so
    /// the promotion can never be applied. The executor fails closed
    /// permanently.
    PromotionSuperseded {
        promotion_epoch: u64,
        authority_epoch: u64,
    },
}

/// Error returned by [`FailoverExecutor::reconcile_complete`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileError {
    /// The controller has not started (authority unreachable) or no promotion
    /// is outstanding.
    NotOutstanding,
    /// A promotion is still being applied; reconciliation makes no sense
    /// until the authority actually serves the promoted epoch.
    PromotionPending,
}

impl fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReconcileError::NotOutstanding => {
                write!(
                    f,
                    "reconciliation is only outstanding immediately after promotion"
                )
            }
            ReconcileError::PromotionPending => {
                write!(
                    f,
                    "reconciliation is refused while the promotion is still pending"
                )
            }
        }
    }
}

/// The controller loop: gathers observations from `source`, decides through a
/// [`FailoverController`], and applies decisions to `authority`. One `tick`
/// is one check round plus the retry of any still-pending application.
pub struct FailoverExecutor<S: ObservationSource, A: WriterAuthority> {
    config: FailoverConfig,
    source: S,
    authority: A,
    controller: Option<FailoverController>,
    journal: Option<ControllerJournal>,
    /// Decisions whose application failed and are retried unchanged, in
    /// decision order.
    pending: Vec<PendingAction>,
    status: ExecutorStatus,
}

impl<S: ObservationSource, A: WriterAuthority> FailoverExecutor<S, A> {
    /// Build an executor. Nothing is read from the authority until the first
    /// [`Self::tick`].
    pub fn new(config: FailoverConfig, source: S, authority: A) -> Self {
        Self {
            config,
            source,
            authority,
            controller: None,
            journal: None,
            pending: Vec::new(),
            status: ExecutorStatus::WaitingForAuthority,
        }
    }

    /// The current executor status.
    pub fn status(&self) -> &ExecutorStatus {
        &self.status
    }

    /// The controller's current phase, `None` before the first successful
    /// authority restore.
    pub fn controller_phase(&self) -> Option<&Phase> {
        self.controller.as_ref().map(FailoverController::phase)
    }

    /// Tear the executor down into its parts, so tests and callers can reuse
    /// the authority port across a simulated restart.
    pub fn into_parts(self) -> (FailoverConfig, S, A) {
        (self.config, self.source, self.authority)
    }

    /// Queue one round into an in-process source. A no-op for other source
    /// types; the production loop's source is `InProcessSource`, so this is
    /// also the hook an operator shim or later increment can feed rounds
    /// through without rebuilding the executor.
    pub fn queue_round(&mut self, round: Round)
    where
        S: std::any::Any,
    {
        let source: &mut dyn std::any::Any = &mut self.source;
        if let Some(source) = source.downcast_mut::<InProcessSource>() {
            source.queue(round);
        }
    }

    /// Mutable access to the authority port, for diagnostics and tests.
    pub fn authority_mut(&mut self) -> &mut A {
        &mut self.authority
    }

    /// Explicit operator input: the post-promotion reconciliation completed.
    /// Journaled on success; refused while a promotion is still pending.
    pub fn reconcile_complete(&mut self) -> Result<(), ReconcileError> {
        if !self.pending.is_empty() {
            return Err(ReconcileError::PromotionPending);
        }
        self.controller
            .as_mut()
            .ok_or(ReconcileError::NotOutstanding)?
            .reconcile_complete()
            .map_err(|_| ReconcileError::NotOutstanding)?;
        if let Some(journal) = &mut self.journal
            && let RestorablePhase::Promoted { reconciled, .. } = &mut journal.phase
        {
            *reconciled = true;
            if let Ok(encoded) = journal.encode() {
                // Best-effort: a failed save only loses the flag on
                // restart, which keeps dispatch paused — safe.
                let _ = self.authority.save_controller_state(&encoded);
            }
        }
        Ok(())
    }

    /// Run one check round: restore from the authority if needed, retry
    /// pending applications, gather observations, decide, apply, journal.
    pub fn tick(&mut self, now_ms: u64) -> TickReport {
        if matches!(
            self.status,
            ExecutorStatus::JournalInconsistent { .. } | ExecutorStatus::PromotionSuperseded { .. }
        ) {
            return TickReport {
                decision: None,
                application: Application::None,
                journal_saved: false,
            };
        }
        if self.controller.is_none() && !self.restore() {
            return TickReport {
                decision: None,
                application: Application::None,
                journal_saved: false,
            };
        }
        // Retry still-pending applications in decision order before new
        // evidence can produce more.
        let mut application = Application::None;
        let mut journal_saved = false;
        let pending_actions: Vec<PendingAction> = std::mem::take(&mut self.pending);
        let mut still_pending: Vec<PendingAction> = Vec::with_capacity(pending_actions.len());
        let mut superseded = None;
        let mut stopped = false;
        for action in pending_actions.into_iter() {
            if stopped {
                still_pending.push(action);
                continue;
            }
            match self.attempt(&action, &mut journal_saved) {
                AttemptOutcome::Applied(applied) => application = applied,
                AttemptOutcome::Pending => still_pending.push(action),
                AttemptOutcome::Superseded {
                    promotion_epoch,
                    authority_epoch,
                } => {
                    self.status = ExecutorStatus::PromotionSuperseded {
                        promotion_epoch,
                        authority_epoch,
                    };
                    superseded = Some(Application::Superseded {
                        promotion_epoch,
                        authority_epoch,
                    });
                    still_pending.push(action);
                    stopped = true;
                }
            }
        }
        self.pending = still_pending;
        if let Some(superseded) = superseded {
            return TickReport {
                decision: None,
                application: superseded,
                journal_saved,
            };
        }
        let round = self.source.collect(now_ms);
        let decision = {
            let Some(controller) = self.controller.as_mut() else {
                unreachable!("the controller is restored before any round runs");
            };
            controller.observe(round, now_ms)
        };
        let round_application = self.apply_decision(&decision, &mut journal_saved);
        if !matches!(round_application, Application::None)
            || matches!(application, Application::None)
        {
            application = round_application;
        }
        if matches!(application, Application::None) && !self.pending.is_empty() {
            application = Application::Pending {
                action: self.pending[0].clone(),
            };
        }
        TickReport {
            decision: Some(decision),
            application,
            journal_saved,
        }
    }

    /// Apply (or park) a fresh decision from this round.
    fn apply_decision(&mut self, decision: &Decision, journal_saved: &mut bool) -> Application {
        match decision {
            Decision::FenceOldWriter { site_id } => {
                let action = PendingAction::Fence {
                    site_id: site_id.clone(),
                };
                self.attempt_fresh(action, journal_saved)
            }
            Decision::PromoteStandby { site_id, new_epoch } => {
                let action = PendingAction::Promote {
                    site_id: site_id.clone(),
                    new_epoch: *new_epoch,
                };
                self.attempt_fresh(action, journal_saved)
            }
            Decision::RejoinFormerWriterAsReplica { site_id } => {
                // The physical reseed stays external; only the one-time
                // emission is recorded so a restart never re-emits it.
                let mut recorded = false;
                if let Some(journal) = &mut self.journal
                    && let RestorablePhase::Promoted { rejoin_emitted, .. } = &mut journal.phase
                    && !*rejoin_emitted
                {
                    *rejoin_emitted = true;
                    recorded = true;
                }
                if !recorded {
                    return Application::None;
                }
                if self.save_journal() {
                    *journal_saved = true;
                }
                Application::Applied {
                    action: AppliedAction::RejoinRecorded {
                        site_id: site_id.clone(),
                    },
                    replayed: false,
                }
            }
            Decision::Hold(_) | Decision::QuorumLost | Decision::KeepDispatchPaused => {
                Application::None
            }
        }
    }

    /// Attempt a decision emitted this round: an application that cannot be
    /// applied yet is queued for identical retries, a supersession fails the
    /// executor closed.
    fn attempt_fresh(&mut self, action: PendingAction, journal_saved: &mut bool) -> Application {
        match self.attempt(&action, journal_saved) {
            AttemptOutcome::Applied(application) => application,
            AttemptOutcome::Pending => {
                self.pending.push(action.clone());
                Application::Pending { action }
            }
            AttemptOutcome::Superseded {
                promotion_epoch,
                authority_epoch,
            } => {
                self.status = ExecutorStatus::PromotionSuperseded {
                    promotion_epoch,
                    authority_epoch,
                };
                Application::Superseded {
                    promotion_epoch,
                    authority_epoch,
                }
            }
        }
    }

    /// Try one action against the authority. Transport failures and
    /// operator-fixable refusals leave the action pending; only a permanent
    /// supersession is terminal.
    fn attempt(&mut self, action: &PendingAction, journal_saved: &mut bool) -> AttemptOutcome {
        match action {
            PendingAction::Fence { site_id } => {
                // Defense in depth: only the configured writer site is ever
                // fenced, whatever a decision or journal claims.
                if site_id != self.config.writer_site_id() {
                    return AttemptOutcome::Pending;
                }
                match self.authority.fence_writer_site(site_id) {
                    Ok(outcome @ (FenceOutcome::Fenced | FenceOutcome::AlreadyFenced)) => {
                        self.advance_journal_fence();
                        if self.save_journal() {
                            *journal_saved = true;
                        }
                        AttemptOutcome::Applied(Application::Applied {
                            action: AppliedAction::Fence {
                                site_id: site_id.clone(),
                                outcome,
                            },
                            replayed: outcome == FenceOutcome::AlreadyFenced,
                        })
                    }
                    Ok(FenceOutcome::SiteRowMissing) | Err(_) => AttemptOutcome::Pending,
                }
            }
            PendingAction::Promote { site_id, new_epoch } => {
                if site_id != self.config.standby_site_id() {
                    return AttemptOutcome::Pending;
                }
                // Write-ahead: the promotion intent is durable before the
                // authority is touched, so a crash can never leave an
                // unjournaled epoch bump.
                let already_durable = matches!(
                    &self.journal,
                    Some(ControllerJournal {
                        phase: RestorablePhase::Promoting { new_epoch: intent },
                        ..
                    }) if intent == new_epoch
                );
                let intent_durable = if already_durable {
                    true
                } else {
                    self.journal = Some(self.build_journal(RestorablePhase::Promoting {
                        new_epoch: *new_epoch,
                    }));
                    let saved = self.save_journal();
                    if saved {
                        *journal_saved = true;
                    }
                    saved
                };
                if !intent_durable {
                    return AttemptOutcome::Pending;
                }
                match self.authority.promote_standby(
                    site_id,
                    self.config.writer_site_id(),
                    *new_epoch,
                ) {
                    Ok(outcome @ (PromoteOutcome::Promoted | PromoteOutcome::AlreadyAtEpoch)) => {
                        self.advance_journal_promoted(*new_epoch);
                        if self.save_journal() {
                            *journal_saved = true;
                        }
                        AttemptOutcome::Applied(Application::Applied {
                            action: AppliedAction::Promote {
                                site_id: site_id.clone(),
                                new_epoch: *new_epoch,
                                outcome,
                            },
                            replayed: outcome == PromoteOutcome::AlreadyAtEpoch,
                        })
                    }
                    Ok(PromoteOutcome::RefusedHigherEpoch { current }) => {
                        AttemptOutcome::Superseded {
                            promotion_epoch: *new_epoch,
                            authority_epoch: current,
                        }
                    }
                    Ok(PromoteOutcome::RefusedWriterUnfenced)
                    | Ok(PromoteOutcome::SiteRowMissing)
                    | Err(_) => AttemptOutcome::Pending,
                }
            }
        }
    }

    /// Restore the controller from the authority and journal. Returns false
    /// when the executor must wait (authority unreachable) or has failed
    /// closed (journal and authority disagree irreconcilably).
    fn restore(&mut self) -> bool {
        let snapshot = match self
            .authority
            .load_state(self.config.writer_site_id(), self.config.standby_site_id())
        {
            Ok(snapshot) => snapshot,
            Err(_) => {
                self.status = ExecutorStatus::WaitingForAuthority;
                return false;
            }
        };
        let encoded = match self.authority.load_controller_state() {
            Ok(encoded) => encoded,
            Err(_) => {
                self.status = ExecutorStatus::WaitingForAuthority;
                return false;
            }
        };
        // A journal that cannot be parsed, or belongs to another
        // configuration, is discarded: the authority plus fresh evidence is
        // always enough to re-derive safe decisions.
        let journal = encoded
            .as_deref()
            .and_then(|line| ControllerJournal::decode(line).ok())
            .filter(|journal| {
                journal.members == self.config.members()
                    && journal.writer_site_id == self.config.writer_site_id()
                    && journal.standby_site_id == self.config.standby_site_id()
            });
        if let Some(journal) = &journal {
            match journal.phase {
                RestorablePhase::Promoting { new_epoch } => {
                    if snapshot.epoch < new_epoch.saturating_sub(1) {
                        self.status = ExecutorStatus::JournalInconsistent {
                            journal_epoch: new_epoch,
                            authority_epoch: snapshot.epoch,
                        };
                        return false;
                    }
                    if snapshot.epoch > new_epoch {
                        self.status = ExecutorStatus::PromotionSuperseded {
                            promotion_epoch: new_epoch,
                            authority_epoch: snapshot.epoch,
                        };
                        return false;
                    }
                }
                RestorablePhase::Promoted { new_epoch, .. } => {
                    if snapshot.epoch < new_epoch {
                        self.status = ExecutorStatus::JournalInconsistent {
                            journal_epoch: new_epoch,
                            authority_epoch: snapshot.epoch,
                        };
                        return false;
                    }
                }
                RestorablePhase::Steady | RestorablePhase::FencingOldWriter => {
                    if snapshot.epoch < journal.max_epoch_seen {
                        self.status = ExecutorStatus::JournalInconsistent {
                            journal_epoch: journal.max_epoch_seen,
                            authority_epoch: snapshot.epoch,
                        };
                        return false;
                    }
                }
            }
        }
        let (phase, max_epoch_seen) = match journal.clone() {
            Some(journal) => (journal.phase, journal.max_epoch_seen.max(snapshot.epoch)),
            // A fresh incarnation still knows the authority's epoch: every
            // epoch any member could ever have observed is at most this
            // value, so seeding from the row is a strictly safe bound and
            // avoids holding forever on EpochUnknown after a restart.
            None => (RestorablePhase::Steady, snapshot.epoch),
        };
        self.controller = Some(FailoverController::restore(
            self.config.clone(),
            max_epoch_seen,
            phase,
        ));
        self.journal = journal;
        self.status = ExecutorStatus::Running;
        true
    }

    fn build_journal(&self, phase: RestorablePhase) -> ControllerJournal {
        ControllerJournal {
            members: self.config.members().to_vec(),
            writer_site_id: self.config.writer_site_id().to_owned(),
            standby_site_id: self.config.standby_site_id().to_owned(),
            max_epoch_seen: self
                .controller
                .as_ref()
                .map_or(0, FailoverController::max_epoch_seen),
            phase,
        }
    }

    /// Journal that the fence decision was applied. Never moves the journal
    /// backward past a promotion.
    fn advance_journal_fence(&mut self) {
        let advance = match &self.journal {
            None => true,
            Some(journal) => matches!(journal.phase, RestorablePhase::Steady),
        };
        if advance {
            let journal = self.build_journal(RestorablePhase::FencingOldWriter);
            self.journal = Some(journal);
        }
    }

    /// Journal that the promotion completed under `new_epoch`, resetting the
    /// reconciliation and rejoin flags only on first completion.
    fn advance_journal_promoted(&mut self, new_epoch: u64) {
        match &mut self.journal {
            Some(ControllerJournal {
                phase:
                    RestorablePhase::Promoted {
                        new_epoch: existing,
                        ..
                    },
                ..
            }) if *existing == new_epoch => {}
            Some(journal) => {
                journal.phase = RestorablePhase::Promoted {
                    new_epoch,
                    reconciled: false,
                    rejoin_emitted: false,
                };
            }
            None => {
                self.journal = Some(self.build_journal(RestorablePhase::Promoted {
                    new_epoch,
                    reconciled: false,
                    rejoin_emitted: false,
                }));
            }
        }
    }

    /// Persist the journal; false when nothing was saved. Save failures are
    /// surfaced, never blocking: every authority application is idempotent,
    /// so a restart after a lost save replays to the same state.
    fn save_journal(&mut self) -> bool {
        let Some(journal) = &self.journal else {
            return false;
        };
        let Ok(encoded) = journal.encode() else {
            return false;
        };
        self.authority.save_controller_state(&encoded).is_ok()
    }
}

/// Internal result of one application attempt.
enum AttemptOutcome {
    Applied(Application),
    Pending,
    Superseded {
        promotion_epoch: u64,
        authority_epoch: u64,
    },
}

impl ControllerJournal {
    /// Encode the journal into its stable single-line format
    /// (`v1 members=… writer=… standby=… max_epoch=… phase=…`). Member
    /// identifiers containing `,` or whitespace cannot be encoded.
    pub fn encode(&self) -> Result<String, JournalEncodingError> {
        for member in &self.members {
            if member.is_empty() || member.contains(',') || member.contains(char::is_whitespace) {
                return Err(JournalEncodingError::AmbiguousMember(member.clone()));
            }
        }
        if self.writer_site_id.is_empty()
            || self.standby_site_id.is_empty()
            || self.writer_site_id.contains(char::is_whitespace)
            || self.standby_site_id.contains(char::is_whitespace)
        {
            return Err(JournalEncodingError::AmbiguousSite);
        }
        let mut line = format!(
            "v1 members={} writer={} standby={} max_epoch={} phase={}",
            self.members.join(","),
            self.writer_site_id,
            self.standby_site_id,
            self.max_epoch_seen,
            self.phase.label()
        );
        match self.phase {
            RestorablePhase::Steady | RestorablePhase::FencingOldWriter => {}
            RestorablePhase::Promoting { new_epoch } => {
                line.push_str(&format!(" new_epoch={new_epoch}"));
            }
            RestorablePhase::Promoted {
                new_epoch,
                reconciled,
                rejoin_emitted,
            } => {
                line.push_str(&format!(
                    " new_epoch={new_epoch} reconciled={} rejoin={}",
                    if reconciled { "true" } else { "false" },
                    if rejoin_emitted { "true" } else { "false" }
                ));
            }
        }
        Ok(line)
    }

    /// Parse a journal produced by [`Self::encode`]. Anything else — wrong
    /// version, missing, extra, duplicated or out-of-order fields, malformed
    /// numbers or booleans — is an error; callers treat an unparseable
    /// journal as absent rather than guessing.
    pub fn decode(line: &str) -> Result<Self, JournalEncodingError> {
        let mut fields = line.split_whitespace();
        let Some("v1") = fields.next() else {
            return Err(JournalEncodingError::Malformed);
        };
        let expect = |fields: &mut std::str::SplitWhitespace<'_>,
                      key: &str|
         -> Result<String, JournalEncodingError> {
            let Some(field) = fields.next() else {
                return Err(JournalEncodingError::Malformed);
            };
            let Some(value) = field.strip_prefix(key) else {
                return Err(JournalEncodingError::Malformed);
            };
            Ok(value.to_owned())
        };
        let members = expect(&mut fields, "members=")?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if members.is_empty() || members.iter().any(String::is_empty) {
            return Err(JournalEncodingError::Malformed);
        }
        let writer_site_id = expect(&mut fields, "writer=")?;
        let standby_site_id = expect(&mut fields, "standby=")?;
        if writer_site_id.is_empty() || standby_site_id.is_empty() {
            return Err(JournalEncodingError::Malformed);
        }
        let max_epoch_seen = expect(&mut fields, "max_epoch=")?
            .parse::<u64>()
            .map_err(|_| JournalEncodingError::Malformed)?;
        let phase_label = expect(&mut fields, "phase=")?;
        let phase = match phase_label.as_str() {
            "steady" if fields.next().is_none() => RestorablePhase::Steady,
            "fencing" if fields.next().is_none() => RestorablePhase::FencingOldWriter,
            "promoting" => {
                let new_epoch = expect(&mut fields, "new_epoch=")?
                    .parse::<u64>()
                    .map_err(|_| JournalEncodingError::Malformed)?;
                if new_epoch == 0 || fields.next().is_some() {
                    return Err(JournalEncodingError::Malformed);
                }
                RestorablePhase::Promoting { new_epoch }
            }
            "promoted" => {
                let new_epoch = expect(&mut fields, "new_epoch=")?
                    .parse::<u64>()
                    .map_err(|_| JournalEncodingError::Malformed)?;
                let reconciled = parse_bool(&expect(&mut fields, "reconciled=")?)?;
                let rejoin_emitted = parse_bool(&expect(&mut fields, "rejoin=")?)?;
                if new_epoch == 0 || fields.next().is_some() {
                    return Err(JournalEncodingError::Malformed);
                }
                RestorablePhase::Promoted {
                    new_epoch,
                    reconciled,
                    rejoin_emitted,
                }
            }
            _ => return Err(JournalEncodingError::Malformed),
        };
        Ok(Self {
            members,
            writer_site_id,
            standby_site_id,
            max_epoch_seen,
            phase,
        })
    }
}

/// Errors of the journal codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalEncodingError {
    /// The line is not a journal this version understands.
    Malformed,
    /// A member identifier cannot be encoded unambiguously.
    AmbiguousMember(String),
    /// A site identifier cannot be encoded unambiguously.
    AmbiguousSite,
}

fn parse_bool(value: &str) -> Result<bool, JournalEncodingError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(JournalEncodingError::Malformed),
    }
}

impl fmt::Display for JournalEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JournalEncodingError::Malformed => write!(f, "malformed controller journal"),
            JournalEncodingError::AmbiguousMember(member) => {
                write!(f, "member identifier cannot be journaled: {member:?}")
            }
            JournalEncodingError::AmbiguousSite => {
                write!(f, "site identifier cannot be journaled")
            }
        }
    }
}
