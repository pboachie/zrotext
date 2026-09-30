// SPDX-License-Identifier: AGPL-3.0-only
//! Adversarial corpus for the failover executor, written before the executor
//! itself. Each test names a way execution can go wrong — concurrent epoch
//! bumps, wrong-site application, decision replay after restart, crashes
//! between fence and promote, stale evidence, configuration changes
//! mid-flight, journal/database splits, authority failures, operator
//! interference — and pins the fail-closed behavior.

use super::decision::*;
use super::executor::*;
use std::collections::HashMap;

const MEMBERS: [&str; 3] = ["workload-a", "workload-b", "witness"];

fn test_config() -> FailoverConfig {
    FailoverConfig::new(
        MEMBERS.iter().map(|member| (*member).to_owned()).collect(),
        "site-a",
        "site-b",
    )
    .unwrap()
}

fn changed_config() -> FailoverConfig {
    FailoverConfig::new(
        ["workload-a", "workload-b", "witness-2"]
            .iter()
            .map(|member| (*member).to_owned())
            .collect(),
        "site-a",
        "site-b",
    )
    .unwrap()
}

fn report(member_id: &str, writer: WriterObservation, now_ms: u64) -> MemberReport {
    MemberReport {
        member_id: member_id.to_owned(),
        observed_at_ms: now_ms,
        writer,
        writer_site_fence: None,
        writer_stop_confirmed: None,
        standby_ready: None,
        former_writer_healthy: None,
    }
}

fn reachable(member_id: &str, epoch: u64, now_ms: u64) -> MemberReport {
    report(member_id, WriterObservation::Reachable { epoch }, now_ms)
}

fn unreachable(member_id: &str, now_ms: u64) -> MemberReport {
    report(member_id, WriterObservation::Unreachable, now_ms)
}

fn fenced(mut report: MemberReport) -> MemberReport {
    report.writer_site_fence = Some(SiteFenceState {
        enabled: true,
        draining: true,
    });
    report
}

fn stopped(mut report: MemberReport) -> MemberReport {
    report.writer_stop_confirmed = Some(true);
    report
}

fn standby_ready(mut report: MemberReport) -> MemberReport {
    report.standby_ready = Some(true);
    report
}

fn former_writer(mut report: MemberReport, healthy: bool) -> MemberReport {
    report.former_writer_healthy = Some(healthy);
    report
}

fn all(report_for: impl Fn(&str) -> MemberReport) -> Round {
    Round {
        reports: MEMBERS.iter().map(|member| report_for(member)).collect(),
    }
}

fn healthy_round(epoch: u64, now_ms: u64) -> Round {
    all(|member| reachable(member, epoch, now_ms))
}

fn failure_round(now_ms: u64) -> Round {
    all(|member| unreachable(member, now_ms))
}

fn evidence_round(now_ms: u64) -> Round {
    all(|member| {
        let report = unreachable(member, now_ms);
        let report = fenced(report);
        let report = stopped(report);
        standby_ready(report)
    })
}

fn former_writer_round(epoch: u64, now_ms: u64) -> Round {
    all(|member| former_writer(reachable(member, epoch, now_ms), true))
}

fn source(rounds: &[Round]) -> InProcessSource {
    let mut source = InProcessSource::default();
    for round in rounds {
        source.queue(round.clone());
    }
    source
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AuthorityCall {
    LoadState,
    LoadJournal,
    Fence {
        site_id: String,
    },
    Promote {
        promoted_site: String,
        fenced_writer_site: String,
        new_epoch: u64,
    },
    SaveJournal,
}

/// In-memory writer authority implementing exactly the SQL semantics the
/// PostgreSQL port promises, plus fault injection and a call log. Shared with
/// the consensus-store corpus, which drives full executor rounds through a
/// store-backed source.
#[derive(Default)]
pub(crate) struct MemoryAuthority {
    epoch: u64,
    dispatch_enabled: bool,
    sites: HashMap<String, SiteFenceState>,
    journal: Option<String>,
    calls: Vec<AuthorityCall>,
    promotions_applied: u64,
    fail_load_state: bool,
    fail_fence: bool,
    fail_promote: bool,
    /// Adversarial: let `n` journal saves succeed after arming, then fail
    /// the next one (None = never).
    fail_save_after: Option<usize>,
    saves_since_arm: usize,
    /// Adversarial: another writer commits this epoch just before our
    /// promotion's compare-and-set runs.
    bump_epoch_on_promote_to: Option<u64>,
    /// Adversarial: the old writer's fence is cleared (operator SQL) just
    /// before our promotion runs.
    unfence_writer_on_promote: bool,
    /// Test seam standing in for the singleton advisory lock: latched by
    /// `reacquire` to simulate the port losing and re-acquiring its write
    /// exclusivity, and read-and-cleared by
    /// `WriterAuthority::exclusivity_reacquired`.
    exclusivity_latch: bool,
}

impl MemoryAuthority {
    /// A healthy two-site authority serving `epoch` with dispatch enabled.
    pub(crate) fn new(epoch: u64) -> Self {
        let mut sites = HashMap::new();
        for site_id in ["site-a", "site-b"] {
            sites.insert(
                site_id.to_owned(),
                SiteFenceState {
                    enabled: true,
                    draining: false,
                },
            );
        }
        Self {
            epoch,
            dispatch_enabled: true,
            sites,
            journal: None,
            calls: Vec::new(),
            promotions_applied: 0,
            fail_load_state: false,
            fail_fence: false,
            fail_promote: false,
            fail_save_after: None,
            saves_since_arm: 0,
            bump_epoch_on_promote_to: None,
            unfence_writer_on_promote: false,
            exclusivity_latch: false,
        }
    }

    fn site(&self, site_id: &str) -> SiteFenceState {
        self.sites[site_id]
    }

    fn journal_phase(&self) -> Option<RestorablePhase> {
        self.journal
            .as_deref()
            .and_then(|line| ControllerJournal::decode(line).ok())
            .map(|journal| journal.phase)
    }

    pub(crate) fn fence_calls(&self) -> usize {
        self.calls
            .iter()
            .filter(|call| matches!(call, AuthorityCall::Fence { .. }))
            .count()
    }

    pub(crate) fn promote_calls(&self) -> Vec<u64> {
        self.calls
            .iter()
            .filter_map(|call| match call {
                AuthorityCall::Promote { new_epoch, .. } => Some(*new_epoch),
                _ => None,
            })
            .collect()
    }

    /// Test seam: this executor's incarnation ended (its lock died with a
    /// lost connection) and a later incarnation of the SAME process
    /// re-acquired write exclusivity, exactly as the PostgreSQL port's
    /// guard reports after a takeover round. Everything the executor cached
    /// from before is potentially stale from this point on.
    pub(crate) fn reacquire(&mut self) {
        self.exclusivity_latch = true;
    }
}

impl WriterAuthority for MemoryAuthority {
    type Error = &'static str;

    fn load_state(
        &mut self,
        writer_site: &str,
        standby_site: &str,
    ) -> Result<AuthoritySnapshot, Self::Error> {
        self.calls.push(AuthorityCall::LoadState);
        if self.fail_load_state {
            self.fail_load_state = false;
            return Err("authority unreachable");
        }
        Ok(AuthoritySnapshot {
            epoch: self.epoch,
            dispatch_enabled: self.dispatch_enabled,
            writer_site: self.sites.get(writer_site).copied(),
            standby_site: self.sites.get(standby_site).copied(),
        })
    }

    fn fence_writer_site(&mut self, site_id: &str) -> Result<FenceOutcome, Self::Error> {
        self.calls.push(AuthorityCall::Fence {
            site_id: site_id.to_owned(),
        });
        if self.fail_fence {
            self.fail_fence = false;
            return Err("authority unreachable");
        }
        match self.sites.get_mut(site_id) {
            None => Ok(FenceOutcome::SiteRowMissing),
            Some(site) if site.is_fenced() => Ok(FenceOutcome::AlreadyFenced),
            Some(site) => {
                site.draining = true;
                Ok(FenceOutcome::Fenced)
            }
        }
    }

    fn promote_standby(
        &mut self,
        promoted_site: &str,
        fenced_writer_site: &str,
        new_epoch: u64,
    ) -> Result<PromoteOutcome, Self::Error> {
        self.calls.push(AuthorityCall::Promote {
            promoted_site: promoted_site.to_owned(),
            fenced_writer_site: fenced_writer_site.to_owned(),
            new_epoch,
        });
        if let Some(bump) = self.bump_epoch_on_promote_to.take() {
            self.epoch = bump;
        }
        if self.unfence_writer_on_promote {
            self.unfence_writer_on_promote = false;
            if let Some(site) = self.sites.get_mut(fenced_writer_site) {
                site.draining = false;
            }
        }
        if self.fail_promote {
            self.fail_promote = false;
            return Err("authority unreachable");
        }
        if self.epoch > new_epoch {
            return Ok(PromoteOutcome::RefusedHigherEpoch {
                current: self.epoch,
            });
        }
        match self.sites.get(fenced_writer_site) {
            None => return Ok(PromoteOutcome::RefusedWriterUnfenced),
            Some(site) if !site.is_fenced() => return Ok(PromoteOutcome::RefusedWriterUnfenced),
            Some(_) => {}
        }
        match self.sites.get_mut(promoted_site) {
            None => Ok(PromoteOutcome::SiteRowMissing),
            Some(site) => {
                // Mirrors the SQL: at an equal epoch the promotion writes
                // still run (promoted site enabled, dispatch forced
                // paused) and only the outcome differs — a completion
                // answer always implies the full promoted state.
                let replayed = self.epoch == new_epoch;
                self.epoch = new_epoch;
                self.dispatch_enabled = false;
                site.enabled = true;
                if !replayed {
                    self.promotions_applied += 1;
                }
                Ok(if replayed {
                    PromoteOutcome::AlreadyAtEpoch
                } else {
                    PromoteOutcome::Promoted
                })
            }
        }
    }

    fn save_controller_state(&mut self, encoded: &str) -> Result<(), Self::Error> {
        self.calls.push(AuthorityCall::SaveJournal);
        if let Some(allowed) = self.fail_save_after {
            if self.saves_since_arm >= allowed {
                self.fail_save_after = None;
                return Err("authority unreachable");
            }
            self.saves_since_arm += 1;
        }
        self.journal = Some(encoded.to_owned());
        Ok(())
    }

    fn load_controller_state(&mut self) -> Result<Option<String>, Self::Error> {
        self.calls.push(AuthorityCall::LoadJournal);
        Ok(self.journal.clone())
    }

    fn exclusivity_reacquired(&mut self) -> bool {
        std::mem::take(&mut self.exclusivity_latch)
    }
}

fn journal(config: &FailoverConfig, max_epoch_seen: u64, phase: RestorablePhase) -> String {
    ControllerJournal {
        members: config.members().to_vec(),
        writer_site_id: config.writer_site_id().to_owned(),
        standby_site_id: config.standby_site_id().to_owned(),
        max_epoch_seen,
        phase,
    }
    .encode()
    .unwrap()
}

type TestExecutor = FailoverExecutor<InProcessSource, MemoryAuthority>;

/// Drive a fresh executor through a healthy round and three failure rounds,
/// leaving it right after the fence decision and application.
fn drive_to_fence(executor: &mut TestExecutor) {
    let decision = executor.tick(1_000);
    assert_eq!(
        decision.decision,
        Some(Decision::Hold(HoldReason::WriterHealthy))
    );
    let decision = executor.tick(2_000);
    assert_eq!(
        decision.decision,
        Some(Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        }))
    );
    let _ = executor.tick(3_000);
    let report = executor.tick(4_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        })
    );
    assert_eq!(
        report.application,
        Application::Applied {
            action: AppliedAction::Fence {
                site_id: "site-a".to_owned(),
                outcome: FenceOutcome::Fenced
            },
            replayed: false
        }
    );
    assert!(report.journal_saved);
    assert_eq!(executor.controller_phase(), Some(&Phase::FencingOldWriter));
}

fn full_executor(port: MemoryAuthority, rounds: &[Round]) -> TestExecutor {
    FailoverExecutor::new(test_config(), source(rounds), port)
}

#[test]
fn full_failover_applies_fence_then_exactly_one_promotion() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            evidence_round(6_000),
        ],
    );
    drive_to_fence(&mut executor);
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert_eq!(
        report.application,
        Application::Applied {
            action: AppliedAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5,
                outcome: PromoteOutcome::Promoted
            },
            replayed: false
        }
    );
    assert!(report.journal_saved);
    // Post-promotion rounds keep dispatch paused; nothing further applies.
    let report = executor.tick(6_000);
    assert_eq!(report.decision, Some(Decision::KeepDispatchPaused));
    assert_eq!(report.application, Application::None);
    let (_, _, port) = executor.into_parts();
    assert!(port.site("site-a").draining);
    assert!(port.site("site-b").enabled);
    assert_eq!(port.epoch, 5);
    assert!(!port.dispatch_enabled);
    assert_eq!(port.promotions_applied, 1, "exactly one promotion");
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            new_epoch: 5,
            reconciled: false,
            rejoin_emitted: false
        })
    );
    assert_eq!(port.fence_calls(), 1);
    assert_eq!(port.promote_calls(), vec![5]);
}

#[test]
fn a_reacquired_executor_reloads_instead_of_replaying_stale_pending_intent() {
    // Executor A drives a failover to the saved promotion intent, then its
    // exclusivity dies (connection lost) with the promote still pending.
    let mut port = MemoryAuthority::new(5);
    port.fail_promote = true;
    let mut executor_a = full_executor(
        port,
        &[
            healthy_round(5, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor_a);
    let report = executor_a.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 6
        })
    );
    assert!(
        matches!(report.application, Application::Pending { .. }),
        "the promote call failed, so A holds a stale pending intent: {:?}",
        report.application
    );

    // Executor B takes over (the same authority — the database), completes
    // the promotion and records the operator's reconciliation; the operator
    // then re-enables dispatch. That is the database's current truth.
    let (config, _source, port) = executor_a.into_parts();
    let mut executor_b =
        FailoverExecutor::new(config.clone(), source(&[evidence_round(6_000)]), port);
    let report = executor_b.tick(6_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 6
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));
    executor_b.reconcile_complete().unwrap();
    let (config, _source, mut port) = executor_b.into_parts();
    port.dispatch_enabled = true;
    let journal_after_takeover = port.journal.clone().expect("the journal row exists");
    assert!(journal_after_takeover.contains("reconciled=true"));
    let promotes_after_takeover = port.promote_calls().len();

    // A's process re-acquires exclusivity (B died). A's cached controller,
    // journal and pending promote intent are from its previous incarnation
    // and must never be replayed: the next tick discards them and restores
    // from the authority and journal row instead.
    port.reacquire();
    let mut executor_a = FailoverExecutor::new(
        config,
        source(&[evidence_round(7_000), evidence_round(8_000)]),
        port,
    );
    let report = executor_a.tick(7_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::SteadyOnNewWriter)),
        "the reload tick continues from the database's current truth"
    );
    let _ = executor_a.tick(8_000);
    assert!(
        matches!(executor_a.status(), ExecutorStatus::Running),
        "a re-acquired executor runs again from the reloaded state"
    );
    let (_, _, port) = executor_a.into_parts();
    assert_eq!(
        port.promote_calls().len(),
        promotes_after_takeover,
        "no stale promote replay after the re-acquisition: {:?}",
        port.promote_calls()
    );
    assert!(
        port.dispatch_enabled,
        "a re-acquired executor must not re-pause dispatch from stale intent"
    );
    assert_eq!(
        port.journal.as_deref(),
        Some(journal_after_takeover.as_str()),
        "a re-acquired executor must not overwrite the durable journal with \
         stale intent"
    );
    assert!(matches!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            new_epoch: 6,
            reconciled: true,
            ..
        })
    ));
}

#[test]
fn a_reacquired_executor_refuses_operator_reconciliation_until_it_reloads() {
    // Reconciliation is an authority write like any other: after a
    // re-acquisition it must be refused (and the stale state discarded)
    // rather than journaling a stale phase, and it stays refused until a
    // tick restored the controller from the database.
    let mut executor = full_executor(
        MemoryAuthority::new(5),
        &[
            healthy_round(5, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    let _ = executor.tick(5_000);
    executor.reconcile_complete().unwrap();
    let (config, _source, mut port) = executor.into_parts();
    let journal_before = port.journal.clone();
    port.reacquire();
    let mut executor = FailoverExecutor::new(config, source(&[healthy_round(6, 7_000)]), port);
    assert_eq!(
        executor.reconcile_complete(),
        Err(ReconcileError::NotOutstanding),
        "reconciliation must fail closed while the stale state is discarded"
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(
        port.journal, journal_before,
        "a refused stale reconciliation must not write the journal"
    );
}

#[test]
fn executor_only_ever_touches_the_configured_failover_sites() {
    let mut port = MemoryAuthority::new(4);
    port.sites.insert(
        "site-c".to_owned(),
        SiteFenceState {
            enabled: true,
            draining: false,
        },
    );
    let mut executor = full_executor(
        port,
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    let _ = executor.tick(5_000);
    let (_, _, port) = executor.into_parts();
    for call in &port.calls {
        match call {
            AuthorityCall::Fence { site_id } => {
                assert_eq!(site_id, "site-a", "only the configured writer is fenced");
            }
            AuthorityCall::Promote {
                promoted_site,
                fenced_writer_site,
                ..
            } => {
                assert_eq!(promoted_site, "site-b");
                assert_eq!(fenced_writer_site, "site-a");
            }
            _ => {}
        }
    }
    assert_eq!(
        port.site("site-c"),
        SiteFenceState {
            enabled: true,
            draining: false
        },
        "unrelated sites are untouched"
    );
}

#[test]
fn concurrent_epoch_bump_beyond_the_promotion_supersedes_the_failover() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            evidence_round(6_000),
        ],
    );
    drive_to_fence(&mut executor);
    // Another authority owner bumps to 9 between our decision and our apply.
    executor.authority_mut().bump_epoch_on_promote_to = Some(9);
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert_eq!(
        report.application,
        Application::Superseded {
            promotion_epoch: 5,
            authority_epoch: 9
        }
    );
    assert_eq!(
        executor.status(),
        &ExecutorStatus::PromotionSuperseded {
            promotion_epoch: 5,
            authority_epoch: 9
        }
    );
    // The executor is stuck fail-closed: later ticks decide and apply nothing.
    let report = executor.tick(6_000);
    assert_eq!(report.decision, None);
    assert_eq!(report.application, Application::None);
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 9);
    assert!(port.dispatch_enabled, "a refusal writes nothing");
    assert!(port.site("site-a").draining, "the fence stays");
    assert_eq!(port.promotions_applied, 0);
}

#[test]
fn an_external_same_epoch_bump_is_completion_only_with_the_full_promoted_state() {
    // Another owner bumps the epoch to exactly the promotion epoch just
    // before the compare-and-set runs. Answering `AlreadyAtEpoch` before
    // verifying the fence and enforcing the promoted state would report
    // "completion" while dispatch stays enabled; the equal-epoch path must
    // converge fence, promoted-site and dispatch in the same operation.
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    executor.authority_mut().bump_epoch_on_promote_to = Some(5);
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert_eq!(
        report.application,
        Application::Applied {
            action: AppliedAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5,
                outcome: PromoteOutcome::AlreadyAtEpoch
            },
            replayed: true
        }
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert!(
        !port.dispatch_enabled,
        "completion is never answered with dispatch still enabled"
    );
    assert!(port.site("site-b").enabled, "the promoted site is enabled");
    assert_eq!(
        port.promotions_applied, 0,
        "the epoch bump itself was the external writer's"
    );
}

#[test]
fn a_promotion_confirmed_only_by_the_epoch_is_never_bumped_twice() {
    // The promotion applied but the completion journal write failed; the
    // journaled intent still names the epoch, so a restart replays into the
    // compare-and-set instead of bumping again.
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            evidence_round(6_000),
        ],
    );
    drive_to_fence(&mut executor);
    // Let the write-ahead intent save succeed, fail the completion write.
    let authority = executor.authority_mut();
    authority.fail_save_after = Some(1);
    authority.saves_since_arm = 0;
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));
    // journal_saved reflects the write-ahead intent save; the completion
    // write failing is proven by the journal still naming the intent below.
    let (config, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoting { new_epoch: 5 }),
        "the write-ahead intent survived"
    );
    // Restart: the intent replays against epoch 5 and confirms, not bumps.
    let mut executor = FailoverExecutor::new(config, source(&[evidence_round(6_000)]), port);
    let report = executor.tick(6_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert_eq!(
        report.application,
        Application::Applied {
            action: AppliedAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5,
                outcome: PromoteOutcome::AlreadyAtEpoch
            },
            replayed: true
        }
    );
    assert_eq!(
        executor.controller_phase(),
        Some(&Phase::Promoted {
            new_epoch: 5,
            reconciled: false,
            rejoin_emitted: false,
            healthy_streak: 0,
            stable_since_ms: None
        })
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5, "the epoch never bumps twice");
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            new_epoch: 5,
            reconciled: false,
            rejoin_emitted: false
        })
    );
}

#[test]
fn crash_between_fence_and_promote_stays_fail_closed_and_promotes_once() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            failure_round(5_000),
            evidence_round(6_000),
        ],
    );
    drive_to_fence(&mut executor);
    let (config, _, port) = executor.into_parts();
    // The crash gap: the old writer stays fenced, nothing promoted, no
    // dispatch change — fail closed.
    assert!(port.site("site-a").draining);
    assert_eq!(port.epoch, 4);
    assert!(port.dispatch_enabled);
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::FencingOldWriter)
    );
    // Restart: fencing resumes without re-deciding the fence.
    let mut executor = FailoverExecutor::new(
        config,
        source(&[failure_round(5_000), evidence_round(6_000)]),
        port,
    );
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::AwaitingFencingEvidence {
            site_fenced: false,
            stop_confirmed: false
        }))
    );
    assert_eq!(report.application, Application::None);
    let report = executor.tick(6_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert!(!port.dispatch_enabled);
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(port.fence_calls(), 1, "no fence re-application");
    assert_eq!(port.promote_calls(), vec![5]);
}

#[test]
fn a_round_replayed_after_a_crash_produces_identical_authority_state() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    let _ = executor.tick(5_000);
    let (config, _, port) = executor.into_parts();
    let before = (
        port.epoch,
        port.dispatch_enabled,
        port.sites.clone(),
        port.journal.clone(),
        port.promotions_applied,
    );
    // The same evidence round arrives again, first to the live executor and
    // then to one restored from the journal: both must change nothing.
    let mut executor = FailoverExecutor::new(config, source(&[evidence_round(6_000)]), port);
    let report = executor.tick(6_000);
    assert_eq!(report.decision, Some(Decision::KeepDispatchPaused));
    assert_eq!(report.application, Application::None);
    let (config, _, port) = executor.into_parts();
    let mut executor = FailoverExecutor::new(config, source(&[evidence_round(7_000)]), port);
    let report = executor.tick(7_000);
    assert_eq!(report.decision, Some(Decision::KeepDispatchPaused));
    assert_eq!(report.application, Application::None);
    let (_, _, port) = executor.into_parts();
    assert_eq!(
        before,
        (
            port.epoch,
            port.dispatch_enabled,
            port.sites.clone(),
            port.journal.clone(),
            port.promotions_applied
        ),
        "a replayed round changes nothing once promoted"
    );
}

#[test]
fn stale_reports_from_a_previous_incarnation_are_not_evidence() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
        ],
    );
    drive_to_fence(&mut executor);
    let (config, _, port) = executor.into_parts();
    // The restarted incarnation receives rounds stamped before the restart;
    // the freshness bound must discard them as evidence.
    let mut executor = FailoverExecutor::new(
        config,
        source(&[evidence_round(1_000), evidence_round(90_000)]),
        port,
    );
    let report = executor.tick(80_000);
    assert_eq!(report.decision, Some(Decision::QuorumLost));
    assert_eq!(report.application, Application::None);
    let report = executor.tick(90_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(port.epoch, 5);
}

#[test]
fn a_journal_from_a_changed_configuration_is_discarded() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            failure_round(6_000),
            failure_round(7_000),
            failure_round(8_000),
        ],
    );
    drive_to_fence(&mut executor);
    let _ = executor.tick(5_000);
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5, "the first incarnation promoted");
    // Restart with a different quorum: the old journal must not resume the
    // old failover; the new incarnation re-derives its own decisions.
    let mut executor = FailoverExecutor::new(
        changed_config(),
        source(&[
            failure_round(6_000),
            failure_round(7_000),
            failure_round(8_000),
        ]),
        port,
    );
    let report = executor.tick(6_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        })),
        "the changed configuration starts from steady, not from the old journal"
    );
    assert_eq!(report.application, Application::None);
    let _ = executor.tick(7_000);
    let report = executor.tick(8_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        }),
        "a fresh incarnation re-derives its own decisions"
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5, "no resumed or duplicated promotion");
    assert_eq!(port.promotions_applied, 1);
    let journal = ControllerJournal::decode(port.journal.as_deref().unwrap()).unwrap();
    assert_eq!(journal.members, changed_config().members().to_vec());
    assert_eq!(journal.phase, RestorablePhase::FencingOldWriter);
}

#[test]
fn a_corrupt_journal_is_discarded_and_the_controller_starts_fresh() {
    let mut port = MemoryAuthority::new(4);
    port.journal = Some("not a journal at all".to_owned());
    let mut executor = full_executor(
        port,
        &[
            failure_round(1_000),
            failure_round(2_000),
            failure_round(3_000),
            evidence_round(4_000),
        ],
    );
    let report = executor.tick(1_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        }))
    );
    let _ = executor.tick(2_000);
    let report = executor.tick(3_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        })
    );
    let report = executor.tick(4_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        }),
        "a fresh controller seeds its epoch memory from the authority row"
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            new_epoch: 5,
            reconciled: false,
            rejoin_emitted: false
        }),
        "the corrupt journal was replaced by a valid one"
    );
}

#[test]
fn a_journal_claiming_an_unapplied_promotion_fails_closed() {
    // A promoting journal one step behind the authority is a legitimate
    // pending window; behind *that* (or a completed promotion the authority
    // never applied) the database was restored from backup under the
    // journal, and the executor must fail closed.
    for (phase, authority_epoch) in [
        (RestorablePhase::Promoting { new_epoch: 5 }, 3_u64),
        (
            RestorablePhase::Promoted {
                new_epoch: 5,
                reconciled: false,
                rejoin_emitted: false,
            },
            4,
        ),
    ] {
        let mut port = MemoryAuthority::new(authority_epoch);
        port.journal = Some(journal(&test_config(), 4, phase.clone()));
        let mut executor = FailoverExecutor::new(
            test_config(),
            source(&[failure_round(1_000), evidence_round(2_000)]),
            port,
        );
        let report = executor.tick(1_000);
        assert_eq!(
            report.decision, None,
            "no round runs on an inconsistent journal"
        );
        assert_eq!(report.application, Application::None);
        let report = executor.tick(2_000);
        assert_eq!(report.decision, None, "the inconsistency is permanent");
        assert_eq!(report.application, Application::None);
        assert_eq!(
            executor.status(),
            &ExecutorStatus::JournalInconsistent {
                journal_epoch: 5,
                authority_epoch
            }
        );
        let (_, _, port) = executor.into_parts();
        assert_eq!(port.epoch, authority_epoch);
        assert_eq!(port.promotions_applied, 0);
        assert!(!port.site("site-a").draining);
    }
}

#[test]
fn authority_failure_during_fence_keeps_the_decision_pending_and_retries() {
    let mut port = MemoryAuthority::new(4);
    port.fail_fence = true;
    let mut executor = full_executor(
        port,
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            failure_round(5_000),
        ],
    );
    let _ = executor.tick(1_000);
    let _ = executor.tick(2_000);
    let _ = executor.tick(3_000);
    let report = executor.tick(4_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        })
    );
    assert_eq!(
        report.application,
        Application::Pending {
            action: PendingAction::Fence {
                site_id: "site-a".to_owned()
            }
        }
    );
    let report = executor.tick(5_000);
    assert!(
        matches!(report.application, Application::Applied { .. }),
        "the pending fence retried and applied"
    );
    let (_, _, port) = executor.into_parts();
    assert!(port.site("site-a").draining);
    assert_eq!(port.fence_calls(), 2, "one failed attempt, one retry");
    assert_eq!(port.promotions_applied, 0);
}

#[test]
fn authority_failure_during_promotion_retries_the_same_epoch() {
    let mut port = MemoryAuthority::new(4);
    port.fail_promote = true;
    let mut executor = full_executor(
        port,
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            evidence_round(6_000),
        ],
    );
    drive_to_fence(&mut executor);
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert_eq!(
        report.application,
        Application::Pending {
            action: PendingAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5
            }
        }
    );
    assert!(report.journal_saved, "the intent is journaled first");
    let report = executor.tick(6_000);
    assert!(matches!(report.application, Application::Applied { .. }));
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(
        port.promote_calls(),
        vec![5, 5],
        "retries never invent a higher epoch"
    );
}

#[test]
fn promotion_forces_dispatch_paused_and_the_executor_never_reenables_it() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    let _ = executor.tick(5_000);
    executor.reconcile_complete().unwrap();
    // Sustained former-writer health through the rejoin decision.
    for minute in 0..6_u64 {
        executor.queue_round(former_writer_round(5, 6_000 + minute * 60_000));
    }
    let mut now_ms = 6_000;
    let mut saw_rejoin = false;
    for _ in 0..6 {
        let report = executor.tick(now_ms);
        now_ms += 60_000;
        if let Some(Decision::RejoinFormerWriterAsReplica { site_id }) = &report.decision {
            assert_eq!(site_id, "site-a");
            assert_eq!(
                report.application,
                Application::Applied {
                    action: AppliedAction::RejoinRecorded {
                        site_id: "site-a".to_owned()
                    },
                    replayed: false
                }
            );
            saw_rejoin = true;
        }
    }
    assert!(saw_rejoin, "the rejoin decision was emitted");
    let (_, _, port) = executor.into_parts();
    assert!(!port.dispatch_enabled, "dispatch stays paused forever");
    assert!(port.site("site-a").draining, "the executor never unfences");
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            new_epoch: 5,
            reconciled: true,
            rejoin_emitted: true
        })
    );
}

#[test]
fn reconciliation_and_one_time_rejoin_survive_a_restart() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    let _ = executor.tick(5_000);
    executor.reconcile_complete().unwrap();
    for minute in 0..6_u64 {
        executor.queue_round(former_writer_round(5, 6_000 + minute * 60_000));
    }
    let mut now_ms = 6_000;
    let mut rejoins = 0;
    for _ in 0..6 {
        let report = executor.tick(now_ms);
        now_ms += 60_000;
        if matches!(
            report.decision,
            Some(Decision::RejoinFormerWriterAsReplica { .. })
        ) {
            rejoins += 1;
        }
    }
    assert_eq!(rejoins, 1, "the rejoin is emitted exactly once");
    let (config, _, port) = executor.into_parts();
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            new_epoch: 5,
            reconciled: true,
            rejoin_emitted: true
        })
    );
    // After the restart, healthy rounds must not re-emit the one-time rejoin.
    let mut executor =
        FailoverExecutor::new(config, source(&[former_writer_round(5, 400_000)]), port);
    let report = executor.tick(400_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::SteadyOnNewWriter))
    );
    assert_eq!(report.application, Application::None);
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.promote_calls(), vec![5], "no second promotion");
    assert_eq!(port.fence_calls(), 1);
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            new_epoch: 5,
            reconciled: true,
            rejoin_emitted: true
        }),
        "the journal was not rewritten"
    );
}

#[test]
fn an_empty_source_never_touches_the_authority_beyond_the_initial_load() {
    let mut executor = FailoverExecutor::new(
        test_config(),
        InProcessSource::default(),
        MemoryAuthority::new(4),
    );
    for now_ms in [1_000_u64, 2_000, 3_000] {
        let report = executor.tick(now_ms);
        assert_eq!(report.decision, Some(Decision::QuorumLost));
        assert_eq!(report.application, Application::None);
    }
    let (_, _, port) = executor.into_parts();
    assert_eq!(
        port.calls,
        vec![AuthorityCall::LoadState, AuthorityCall::LoadJournal]
    );
    assert_eq!(port.epoch, 4);
    assert!(!port.site("site-a").draining);
}

#[test]
fn journal_encoding_round_trips_and_rejects_malformed_input() {
    let phases = [
        (RestorablePhase::Steady, "phase=steady"),
        (RestorablePhase::FencingOldWriter, "phase=fencing"),
        (
            RestorablePhase::Promoting { new_epoch: 8 },
            "phase=promoting new_epoch=8",
        ),
        (
            RestorablePhase::Promoted {
                new_epoch: 8,
                reconciled: true,
                rejoin_emitted: false,
            },
            "phase=promoted new_epoch=8 reconciled=true rejoin=false",
        ),
    ];
    for (phase, suffix) in phases {
        let encoded = journal(&test_config(), 7, phase.clone());
        assert_eq!(
            encoded,
            format!(
                "v1 members=workload-a,workload-b,witness writer=site-a standby=site-b max_epoch=7 {suffix}"
            )
        );
        let decoded = ControllerJournal::decode(&encoded).unwrap();
        assert_eq!(decoded.phase, phase);
        assert_eq!(decoded.max_epoch_seen, 7);
    }
    for malformed in [
        "",
        "v2 members=a writer=w standby=s max_epoch=1 phase=steady",
        "v1 members=a writer=w standby=s max_epoch=1",
        "v1 members=a writer=w standby=s max_epoch=1 phase=steady extra=1",
        "v1 members=a writer=w standby=s max_epoch=1 phase=steady phase=steady",
        "v1 members=a writer=w standby=s max_epoch=no phase=steady",
        "v1 members=a writer=w standby=s max_epoch=1 phase=promoted new_epoch=8 reconciled=maybe rejoin=false",
        "v1 members=a writer=w standby=s max_epoch=1 phase=promoted new_epoch=8 reconciled=true",
        "v1 members=a writer=w standby=s max_epoch=1 phase=promoting new_epoch=0",
        "v1 members= writer=w standby=s max_epoch=1 phase=steady",
        "v1 members=a writer= standby=s max_epoch=1 phase=steady",
    ] {
        assert!(
            ControllerJournal::decode(malformed).is_err(),
            "must reject: {malformed:?}"
        );
    }
    let mut ambiguous = ControllerJournal {
        members: vec!["a b".to_owned()],
        writer_site_id: "w".to_owned(),
        standby_site_id: "s".to_owned(),
        max_epoch_seen: 1,
        phase: RestorablePhase::Steady,
    };
    assert_eq!(
        ambiguous.encode(),
        Err(JournalEncodingError::AmbiguousMember("a b".to_owned()))
    );
    ambiguous.members = vec!["a".to_owned()];
    ambiguous.standby_site_id = "s s".to_owned();
    assert_eq!(ambiguous.encode(), Err(JournalEncodingError::AmbiguousSite));
}

#[test]
fn a_restarted_controller_seeds_its_epoch_memory_from_the_authority_row() {
    // No journal at all (the first incarnation never acted), and no member
    // ever reported a reachable epoch to this incarnation: the authority row
    // is the only epoch knowledge, and it must be used rather than holding
    // forever on EpochUnknown.
    let mut executor = full_executor(
        MemoryAuthority::new(9),
        &[
            failure_round(1_000),
            failure_round(2_000),
            failure_round(3_000),
            evidence_round(4_000),
        ],
    );
    let _ = executor.tick(1_000);
    let _ = executor.tick(2_000);
    let report = executor.tick(3_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        })
    );
    let report = executor.tick(4_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 10
        })
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 10);
    assert_eq!(port.promotions_applied, 1);
}

#[test]
fn unfencing_the_old_writer_before_promotion_blocks_the_promotion() {
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            evidence_round(6_000),
        ],
    );
    drive_to_fence(&mut executor);
    // The operator (or an attacker with SQL access) clears the fence just as
    // the promotion runs.
    executor.authority_mut().unfence_writer_on_promote = true;
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert_eq!(
        report.application,
        Application::Pending {
            action: PendingAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5
            }
        },
        "a promotion never passes an unfenced writer"
    );
    // The operator re-fences; the identical promotion then succeeds.
    executor
        .authority_mut()
        .sites
        .get_mut("site-a")
        .unwrap()
        .draining = true;
    let report = executor.tick(6_000);
    assert!(matches!(report.application, Application::Applied { .. }));
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert!(!port.dispatch_enabled);
    assert_eq!(port.promotions_applied, 1);
}

#[test]
fn missing_site_rows_are_never_treated_as_a_fence_or_promotion() {
    // The writer site has no sites row at all.
    let mut port = MemoryAuthority::new(4);
    port.sites.remove("site-a");
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[
            failure_round(1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
        ]),
        port,
    );
    let _ = executor.tick(1_000);
    let _ = executor.tick(2_000);
    let report = executor.tick(3_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        })
    );
    assert_eq!(
        report.application,
        Application::Pending {
            action: PendingAction::Fence {
                site_id: "site-a".to_owned()
            }
        }
    );
    let report = executor.tick(4_000);
    assert!(
        matches!(report.application, Application::Pending { .. }),
        "a missing row never becomes a fence"
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 4);
    assert_eq!(port.promotions_applied, 0);

    // The promoted site has no sites row: the fence applies, the promotion
    // must not.
    let mut port = MemoryAuthority::new(4);
    port.sites.remove("site-b");
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            evidence_round(6_000),
        ]),
        port,
    );
    drive_to_fence(&mut executor);
    let report = executor.tick(5_000);
    assert_eq!(
        report.application,
        Application::Pending {
            action: PendingAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5
            }
        }
    );
    let report = executor.tick(6_000);
    assert!(matches!(report.application, Application::Pending { .. }));
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 4, "no epoch bump without the promoted site row");
    assert!(port.site("site-a").draining);
}

#[test]
fn reconciliation_is_refused_while_a_promotion_is_still_pending() {
    let mut port = MemoryAuthority::new(4);
    port.fail_promote = true;
    let mut executor = full_executor(
        port,
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    assert_eq!(
        executor.reconcile_complete(),
        Err(ReconcileError::NotOutstanding),
        "no promotion exists yet"
    );
    drive_to_fence(&mut executor);
    let _ = executor.tick(5_000);
    assert_eq!(
        executor.reconcile_complete(),
        Err(ReconcileError::PromotionPending),
        "the promotion has not applied yet"
    );
}

#[test]
fn a_failed_intent_save_is_retried_and_never_promotes_without_durable_intent() {
    // The intent save fails twice (armed again before the retry tick). The
    // durable journal must stay at the fence and the promotion must stay
    // pending: an unsaved in-memory `Promoting` phase is never a durable
    // intent, so the retry re-attempts the save instead of skipping it and
    // promoting with no persisted intent.
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    executor.authority_mut().fail_save_after = Some(0);
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert_eq!(
        report.application,
        Application::Pending {
            action: PendingAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5
            }
        }
    );
    assert!(!report.journal_saved, "the intent save failed");
    // Arm the second failure; the retry must fail the save again rather
    // than treat the in-memory intent as already durable.
    executor.authority_mut().fail_save_after = Some(0);
    let report = executor.tick(6_000);
    assert_eq!(
        report.application,
        Application::Pending {
            action: PendingAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5
            }
        }
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 4, "no promotion without a durable intent");
    assert_eq!(port.promotions_applied, 0);
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::FencingOldWriter),
        "the durable journal never advanced past the fence"
    );
}

#[test]
fn a_promotion_blocked_by_a_failed_intent_save_applies_once_saves_recover() {
    // Continuation of the same scenario: once a save succeeds, the same
    // pending promotion applies exactly once and journals through Promoted.
    let mut executor = full_executor(
        MemoryAuthority::new(4),
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    executor.authority_mut().fail_save_after = Some(0);
    let report = executor.tick(5_000);
    assert!(matches!(report.application, Application::Pending { .. }));
    let report = executor.tick(6_000);
    assert!(matches!(report.application, Application::Applied { .. }));
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            new_epoch: 5,
            reconciled: false,
            rejoin_emitted: false
        })
    );
}

#[test]
fn crash_after_the_promotion_intent_before_the_apply_resumes_that_exact_epoch() {
    let mut port = MemoryAuthority::new(4);
    port.fail_promote = true;
    let mut executor = full_executor(
        port,
        &[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ],
    );
    drive_to_fence(&mut executor);
    let report = executor.tick(5_000);
    assert!(matches!(report.application, Application::Pending { .. }));
    let (config, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 4, "the apply never ran");
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoting { new_epoch: 5 })
    );
    // Restart: the intent names epoch 5, so the resume promotes exactly 5.
    let mut executor = FailoverExecutor::new(config, source(&[evidence_round(6_000)]), port);
    let report = executor.tick(6_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(port.promote_calls(), vec![5, 5]);
}

#[test]
fn a_promoting_intent_superseded_by_a_later_epoch_fails_closed_at_restore() {
    // The journaled intent names 5, but the authority already serves 6 (the
    // promotion window was lost to another owner). Restoring must fail
    // closed rather than re-promoting above a foreign epoch.
    let mut port = MemoryAuthority::new(6);
    port.sites.get_mut("site-a").unwrap().draining = true;
    port.journal = Some(journal(
        &test_config(),
        4,
        RestorablePhase::Promoting { new_epoch: 5 },
    ));
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[evidence_round(1_000), evidence_round(2_000)]),
        port,
    );
    for now_ms in [1_000_u64, 2_000] {
        let report = executor.tick(now_ms);
        assert_eq!(report.decision, None);
        assert_eq!(report.application, Application::None);
    }
    assert_eq!(
        executor.status(),
        &ExecutorStatus::PromotionSuperseded {
            promotion_epoch: 5,
            authority_epoch: 6
        }
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 6);
    assert_eq!(port.promotions_applied, 0);
}
