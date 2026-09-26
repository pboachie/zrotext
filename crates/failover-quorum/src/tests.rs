// SPDX-License-Identifier: AGPL-3.0-only
//! Failure-scenario tests for the promotion-decision model, mirroring the
//! scenarios `MULTI-LOCATION.md` lists for automatic failover: writer loss,
//! ambiguous partitions, missing or stale quorum evidence, fencing
//! preconditions, standby readiness, dispatch pause after promotion, and
//! former-writer rejoin hysteresis.

use super::decision::*;

const MEMBERS: [&str; 3] = ["workload-a", "workload-b", "witness"];

fn test_config() -> FailoverConfig {
    FailoverConfig::new(
        MEMBERS.iter().map(|member| (*member).to_owned()).collect(),
        "site-a",
        "site-b",
    )
    .unwrap()
}

fn test_controller() -> FailoverController {
    FailoverController::new(test_config())
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

/// One healthy round that establishes the observed writer epoch, then three
/// consecutive failure rounds: the controller sits in FencingOldWriter.
fn drive_to_fencing(controller: &mut FailoverController) {
    assert_eq!(
        controller.observe(all(|member| reachable(member, 4, 1_000)), 1_000),
        Decision::Hold(HoldReason::WriterHealthy)
    );
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 2_000)), 2_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        })
    );
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 3_000)), 3_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 2
        })
    );
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 4_000)), 4_000),
        Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        }
    );
    assert_eq!(controller.phase(), &Phase::FencingOldWriter);
}

fn evidence_round(now_ms: u64) -> Round {
    all(|member| {
        let report = unreachable(member, now_ms);
        let report = fenced(report);
        let report = stopped(report);
        standby_ready(report)
    })
}

#[test]
fn configuration_rejects_unusable_quorums() {
    let two: Vec<String> = ["only-a", "only-b"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert!(FailoverConfig::new(two, "site-a", "site-b").is_err());
    let four: Vec<String> = ["a", "b", "c", "d"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert!(FailoverConfig::new(four, "site-a", "site-b").is_err());
    let duplicate: Vec<String> = ["a", "b", "b"].iter().map(|s| (*s).to_owned()).collect();
    assert!(FailoverConfig::new(duplicate, "site-a", "site-b").is_err());
    let empty_member: Vec<String> = ["a", "", "c"].iter().map(|s| (*s).to_owned()).collect();
    assert!(FailoverConfig::new(empty_member, "site-a", "site-b").is_err());
    assert!(
        FailoverConfig::new(
            MEMBERS.iter().map(|m| (*m).to_owned()).collect(),
            "same-site",
            "same-site"
        )
        .is_err()
    );
    assert!(
        FailoverConfig::new(
            MEMBERS.iter().map(|m| (*m).to_owned()).collect(),
            "",
            "site-b"
        )
        .is_err()
    );
    let valid = test_config();
    assert_eq!(valid.members(), MEMBERS.as_slice());
    assert_eq!(valid.writer_site_id(), "site-a");
    assert_eq!(valid.standby_site_id(), "site-b");
}

#[test]
fn healthy_quorum_holds_steady_and_never_requests_an_action() {
    let mut controller = test_controller();
    for now_ms in [1_000, 2_000, 3_000] {
        let decision = controller.observe(all(|member| reachable(member, 4, now_ms)), now_ms);
        assert_eq!(decision, Decision::Hold(HoldReason::WriterHealthy));
    }
    assert_eq!(controller.phase(), &Phase::Steady);
}

#[test]
fn writer_loss_needs_three_consecutive_failed_checks_before_fencing() {
    let mut controller = test_controller();
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 1_000)), 1_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        })
    );
    assert_eq!(
        controller.phase(),
        &Phase::Suspecting {
            consecutive_failures: 1
        }
    );
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 2_000)), 2_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 2
        })
    );
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 3_000)), 3_000),
        Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        }
    );
    assert_eq!(controller.phase(), &Phase::FencingOldWriter);
}

#[test]
fn interrupted_failure_streak_resets_on_healthy_consensus() {
    let mut controller = test_controller();
    controller.observe(all(|member| unreachable(member, 1_000)), 1_000);
    controller.observe(all(|member| unreachable(member, 2_000)), 2_000);
    assert_eq!(
        controller.observe(all(|member| reachable(member, 4, 3_000)), 3_000),
        Decision::Hold(HoldReason::WriterHealthy)
    );
    assert_eq!(controller.phase(), &Phase::Steady);
    // Two failures after the interruption must not reach the threshold of
    // three consecutive checks.
    controller.observe(all(|member| unreachable(member, 4_000)), 4_000);
    let decision = controller.observe(all(|member| unreachable(member, 5_000)), 5_000);
    assert_eq!(
        decision,
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 2
        })
    );
    assert_eq!(
        controller.phase(),
        &Phase::Suspecting {
            consecutive_failures: 2
        }
    );
}

#[test]
fn quorum_lost_rounds_fail_closed_and_preserve_prior_evidence() {
    let mut controller = test_controller();
    controller.observe(all(|member| unreachable(member, 1_000)), 1_000);
    controller.observe(all(|member| unreachable(member, 2_000)), 2_000);
    // Only one member answers: no majority, no evidence, no action.
    let decision = controller.observe(
        Round {
            reports: vec![unreachable("workload-a", 3_000)],
        },
        3_000,
    );
    assert_eq!(decision, Decision::QuorumLost);
    assert_eq!(
        controller.phase(),
        &Phase::Suspecting {
            consecutive_failures: 2
        }
    );
    // The previously observed failures still count once evidence returns.
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 4_000)), 4_000),
        Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        }
    );
}

#[test]
fn a_single_silent_member_is_survivable_but_a_lone_observer_is_not() {
    let mut controller = test_controller();
    // Two of three members agree the writer is lost: that is a majority, and
    // the third member's silence alone does not block the checks.
    for now_ms in [1_000, 2_000] {
        let decision = controller.observe(
            Round {
                reports: vec![
                    unreachable("workload-a", now_ms),
                    unreachable("witness", now_ms),
                ],
            },
            now_ms,
        );
        assert!(matches!(
            decision,
            Decision::Hold(HoldReason::WriterFailureSuspected { .. })
        ));
    }
    assert_eq!(
        controller.observe(
            Round {
                reports: vec![
                    unreachable("workload-a", 3_000),
                    unreachable("witness", 3_000),
                ],
            },
            3_000,
        ),
        Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        }
    );
    assert_eq!(controller.phase(), &Phase::FencingOldWriter);
    // A lone member can never move the decision on its own.
    let mut lone = test_controller();
    for now_ms in [1_000, 2_000, 3_000, 4_000, 5_000] {
        let decision = lone.observe(
            Round {
                reports: vec![unreachable("workload-a", now_ms)],
            },
            now_ms,
        );
        assert_eq!(decision, Decision::QuorumLost);
    }
    assert_eq!(lone.phase(), &Phase::Steady);
}

#[test]
fn reachable_and_unreachable_reports_conflict_and_block_all_actions() {
    let mut controller = test_controller();
    let decision = controller.observe(
        Round {
            reports: vec![
                unreachable("workload-a", 1_000),
                unreachable("workload-b", 1_000),
                reachable("witness", 4, 1_000),
            ],
        },
        1_000,
    );
    assert_eq!(
        decision,
        Decision::Hold(HoldReason::ConflictingEvidence {
            reachable: 1,
            unreachable: 2
        })
    );
    assert_eq!(controller.phase(), &Phase::Steady);
}

#[test]
fn writer_recovery_during_fencing_cancels_the_failover() {
    let mut controller = test_controller();
    drive_to_fencing(&mut controller);
    let decision = controller.observe(all(|member| reachable(member, 4, 5_000)), 5_000);
    assert_eq!(
        decision,
        Decision::Hold(HoldReason::FailoverCancelledWriterRecovered)
    );
    assert_eq!(controller.phase(), &Phase::Steady);
    // The decision set contains no action that disables an applied fence:
    // cancellation returns to Steady and leaves reversal to the operator.
}

#[test]
fn ambiguous_evidence_while_fencing_keeps_promotion_blocked() {
    let mut controller = test_controller();
    drive_to_fencing(&mut controller);
    let decision = controller.observe(
        Round {
            reports: vec![
                unreachable("workload-a", 5_000),
                unreachable("workload-b", 5_000),
                reachable("witness", 4, 5_000),
            ],
        },
        5_000,
    );
    assert_eq!(
        decision,
        Decision::Hold(HoldReason::ConflictingEvidence {
            reachable: 1,
            unreachable: 2
        })
    );
    assert_eq!(controller.phase(), &Phase::FencingOldWriter);
}

#[test]
fn stale_observations_are_not_evidence() {
    let mut controller = test_controller();
    let decision = controller.observe(
        all(|member| unreachable(member, 1_000)),
        20_000, // every report is older than the freshness bound
    );
    assert_eq!(decision, Decision::QuorumLost);
    assert_eq!(controller.phase(), &Phase::Steady);
}

#[test]
fn reports_from_unknown_members_are_ignored() {
    let mut controller = test_controller();
    let decision = controller.observe(
        Round {
            reports: vec![
                unreachable("unknown-observer", 1_000),
                unreachable("workload-a", 1_000),
            ],
        },
        1_000,
    );
    assert_eq!(decision, Decision::QuorumLost);
    assert_eq!(controller.phase(), &Phase::Steady);
}

#[test]
fn promotion_waits_for_fence_stop_and_standby_evidence() {
    let mut controller = test_controller();
    drive_to_fencing(&mut controller);

    // Stop and readiness confirmed, but the old writer's site is not fenced.
    let missing_fence = all(|member| {
        let report = unreachable(member, 5_000);
        let report = stopped(report);
        standby_ready(report)
    });
    assert_eq!(
        controller.observe(missing_fence, 5_000),
        Decision::Hold(HoldReason::AwaitingFencingEvidence {
            site_fenced: false,
            stop_confirmed: true
        })
    );

    // Fenced and ready, but the external stop is unconfirmed.
    let missing_stop = all(|member| {
        let report = unreachable(member, 6_000);
        let report = fenced(report);
        standby_ready(report)
    });
    assert_eq!(
        controller.observe(missing_stop, 6_000),
        Decision::Hold(HoldReason::AwaitingFencingEvidence {
            site_fenced: true,
            stop_confirmed: false
        })
    );

    // Fenced and stopped, but the standby is lagging.
    let missing_readiness = all(|member| {
        let report = unreachable(member, 7_000);
        let report = fenced(report);
        stopped(report)
    });
    assert_eq!(
        controller.observe(missing_readiness, 7_000),
        Decision::Hold(HoldReason::AwaitingStandbyReadiness)
    );

    // A disabled site row fences exactly like a draining one.
    let disabled_site_round = all(|member| {
        let mut report = unreachable(member, 8_000);
        report.writer_site_fence = Some(SiteFenceState {
            enabled: false,
            draining: false,
        });
        let report = stopped(report);
        standby_ready(report)
    });
    assert_eq!(
        controller.observe(disabled_site_round, 8_000),
        Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        }
    );
    assert_eq!(
        controller.phase(),
        &Phase::Promoted {
            new_epoch: 5,
            reconciled: false,
            rejoin_emitted: false,
            healthy_streak: 0,
            stable_since_ms: None
        }
    );
}

#[test]
fn promotion_epoch_is_strictly_above_every_observed_epoch() {
    let mut controller = test_controller();
    controller.observe(all(|member| reachable(member, 4, 1_000)), 1_000);
    // A later healthy round observed a higher epoch (for example after a
    // manual promotion); the memory must not regress.
    controller.observe(all(|member| reachable(member, 6, 2_000)), 2_000);
    for now_ms in [3_000, 4_000, 5_000] {
        controller.observe(all(|member| unreachable(member, now_ms)), now_ms);
    }
    assert_eq!(
        controller.observe(evidence_round(6_000), 6_000),
        Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 7
        }
    );
}

#[test]
fn promotion_is_blocked_when_no_epoch_was_ever_observed() {
    // A controller that starts mid-outage never saw the writer's epoch and
    // cannot prove a promotion epoch is higher than what the old writer ran.
    let mut controller = test_controller();
    for now_ms in [1_000, 2_000, 3_000] {
        controller.observe(all(|member| unreachable(member, now_ms)), now_ms);
    }
    assert_eq!(controller.phase(), &Phase::FencingOldWriter);
    assert_eq!(
        controller.observe(evidence_round(4_000), 4_000),
        Decision::Hold(HoldReason::EpochUnknown)
    );
    assert_eq!(controller.phase(), &Phase::FencingOldWriter);
}

#[test]
fn epoch_exhaustion_holds_rather_than_promoting() {
    let mut controller = test_controller();
    controller.observe(all(|member| reachable(member, u64::MAX, 1_000)), 1_000);
    for now_ms in [2_000, 3_000, 4_000] {
        controller.observe(all(|member| unreachable(member, now_ms)), now_ms);
    }
    assert_eq!(
        controller.observe(evidence_round(5_000), 5_000),
        Decision::Hold(HoldReason::EpochExhausted)
    );
}

#[test]
fn dispatch_stays_paused_after_promotion_until_explicit_reconciliation() {
    let mut controller = test_controller();
    drive_to_fencing(&mut controller);
    controller.observe(evidence_round(5_000), 5_000);
    // Health of the promoted writer alone never lifts the pause.
    for now_ms in [6_000, 7_000, 8_000] {
        assert_eq!(
            controller.observe(all(|member| reachable(member, 5, now_ms)), now_ms),
            Decision::KeepDispatchPaused
        );
    }
    controller.reconcile_complete().unwrap();
    assert_eq!(
        controller.observe(all(|member| reachable(member, 5, 9_000)), 9_000),
        Decision::Hold(HoldReason::SteadyOnNewWriter)
    );
}

#[test]
fn reconciliation_input_is_only_valid_while_it_is_outstanding() {
    let mut controller = test_controller();
    assert!(controller.reconcile_complete().is_err());
    drive_to_fencing(&mut controller);
    assert!(controller.reconcile_complete().is_err());
    controller.observe(evidence_round(5_000), 5_000);
    controller.reconcile_complete().unwrap();
    // A second reconciliation is meaningless and refused.
    assert!(controller.reconcile_complete().is_err());
}

#[test]
fn former_writer_rejoins_only_as_a_replica_after_sustained_recovery() {
    let mut controller = test_controller();
    drive_to_fencing(&mut controller);
    controller.observe(evidence_round(5_000), 5_000);
    controller.reconcile_complete().unwrap();

    // Five successful checks within four minutes: not stable long enough.
    for minute in 0..5_u64 {
        let now_ms = 6_000 + minute * 60_000;
        let decision = controller.observe(
            all(|member| former_writer(reachable(member, 5, now_ms), true)),
            now_ms,
        );
        assert_eq!(
            decision,
            Decision::Hold(HoldReason::FormerWriterRecovering {
                healthy_checks: (minute + 1) as u32,
                stable_ms: minute * 60_000
            })
        );
    }
    // The sixth check crosses five stable minutes and allows a rejoin as a
    // replica. No decision variant restores the former writer as writer.
    let now_ms = 6_000 + 5 * 60_000;
    assert_eq!(
        controller.observe(
            all(|member| former_writer(reachable(member, 5, now_ms), true)),
            now_ms
        ),
        Decision::RejoinFormerWriterAsReplica {
            site_id: "site-a".to_owned()
        }
    );
    // The rejoin is emitted exactly once.
    let now_ms = 6_000 + 6 * 60_000;
    assert_eq!(
        controller.observe(
            all(|member| former_writer(reachable(member, 5, now_ms), true)),
            now_ms
        ),
        Decision::Hold(HoldReason::SteadyOnNewWriter)
    );
}

#[test]
fn former_writer_recovery_streak_resets_on_an_unhealthy_round() {
    let mut controller = test_controller();
    drive_to_fencing(&mut controller);
    controller.observe(evidence_round(5_000), 5_000);
    controller.reconcile_complete().unwrap();
    for minute in 0..4_u64 {
        let now_ms = 6_000 + minute * 60_000;
        controller.observe(
            all(|member| former_writer(reachable(member, 5, now_ms), true)),
            now_ms,
        );
    }
    // One flap resets both the check streak and the stability window.
    let flap_ms = 6_000 + 4 * 60_000;
    assert_eq!(
        controller.observe(
            all(|member| former_writer(reachable(member, 5, flap_ms), false)),
            flap_ms
        ),
        Decision::Hold(HoldReason::SteadyOnNewWriter)
    );
    let now_ms = 6_000 + 9 * 60_000;
    // Even well past the stable duration, four post-flap checks are below the
    // recovery threshold of five.
    for offset in 0..4_u64 {
        let check_ms = now_ms + offset * 60_000;
        let decision = controller.observe(
            all(|member| former_writer(reachable(member, 5, check_ms), true)),
            check_ms,
        );
        assert_eq!(
            decision,
            Decision::Hold(HoldReason::FormerWriterRecovering {
                healthy_checks: (offset + 1) as u32,
                stable_ms: offset * 60_000
            })
        );
    }
}

#[test]
fn thresholds_and_freshness_are_tunable_per_deployment() {
    let config = test_config()
        .with_check_thresholds(1, 1)
        .with_recovery_stable_ms(0)
        .with_observation_freshness_ms(5_000);
    let mut controller = FailoverController::new(config);
    // A single failed check fences immediately.
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 1_000)), 1_000),
        Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        }
    );
    // But the controller still cannot promote without ever seeing an epoch.
    assert_eq!(
        controller.observe(evidence_round(2_000), 2_000),
        Decision::Hold(HoldReason::EpochUnknown)
    );
    // Restart with epoch knowledge: promote, reconcile, rejoin in one check.
    let config = test_config()
        .with_check_thresholds(1, 1)
        .with_recovery_stable_ms(0);
    let mut controller = FailoverController::new(config);
    controller.observe(all(|member| reachable(member, 2, 1_000)), 1_000);
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 2_000)), 2_000),
        Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        }
    );
    assert_eq!(
        controller.observe(evidence_round(3_000), 3_000),
        Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 3
        }
    );
    controller.reconcile_complete().unwrap();
    assert_eq!(
        controller.observe(
            all(|member| former_writer(reachable(member, 3, 4_000), true)),
            4_000
        ),
        Decision::RejoinFormerWriterAsReplica {
            site_id: "site-a".to_owned()
        }
    );
    // A freshness bound of five seconds excludes older observations.
    let config = test_config().with_observation_freshness_ms(5_000);
    let mut controller = FailoverController::new(config);
    assert_eq!(
        controller.observe(all(|member| unreachable(member, 1_000)), 6_001),
        Decision::QuorumLost
    );
}
