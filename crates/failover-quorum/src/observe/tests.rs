// SPDX-License-Identifier: AGPL-3.0-only
//! Failure-scenario tests for member-side observation forming, mirroring
//! the reporter-side rules in `MULTI-LOCATION.md`'s failover design: a
//! member-local probe fault must be neither a phantom healthy vote nor
//! fabricated failure evidence, evidence never carries over between
//! rounds, impossible epochs are probe faults, and a member never attests
//! a live writer and a stopped writer in the same round.

use super::*;
use crate::decision::{
    Decision, FailoverConfig, FailoverController, HoldReason, MAX_STORED_EPOCH, Phase, Round,
    SiteFenceState, WriterObservation,
};

const MEMBERS: [&str; 3] = ["workload-a", "workload-b", "witness"];

fn observer(member: &str) -> MemberObserver {
    MemberObserver::new(member).unwrap()
}

fn fenced() -> SiteFenceState {
    SiteFenceState {
        enabled: true,
        draining: true,
    }
}

fn unfenced() -> SiteFenceState {
    SiteFenceState {
        enabled: true,
        draining: false,
    }
}

/// A round where no probe beyond the writer probe produced evidence.
fn bare_probes(writer: WriterProbe) -> RoundProbes {
    RoundProbes {
        writer,
        writer_site_fence: Err(ProbeFault::Indeterminate),
        writer_stop: Err(ProbeFault::Indeterminate),
        standby: Err(ProbeFault::Indeterminate),
        former_writer: Err(ProbeFault::Indeterminate),
    }
}

fn report_of(probes: &RoundProbes) -> MemberReport {
    observer("witness")
        .observe(probes.clone(), 5_000)
        .report()
        .expect("this round must produce a report")
}

fn controller() -> FailoverController {
    FailoverController::new(
        FailoverConfig::new(
            MEMBERS.iter().map(|member| (*member).to_owned()).collect(),
            "site-a",
            "site-b",
        )
        .unwrap(),
    )
}

/// Build one controller round by observing probes per member; abstaining
/// members contribute no report, exactly as the transport will deliver it.
fn observed_round(probes_for: impl Fn(&str) -> RoundProbes, now_ms: u64) -> Round {
    Round {
        reports: MEMBERS
            .iter()
            .filter_map(|member| {
                observer(member)
                    .observe(probes_for(member), now_ms)
                    .report()
            })
            .collect(),
    }
}

/// The healthy steady-state probes: writer up, site unfenced, watchdog says
/// the old writer is not stopped, standby ready.
fn healthy_probes(epoch: u64) -> RoundProbes {
    RoundProbes {
        writer: WriterProbe::Reachable { epoch },
        writer_site_fence: Ok(unfenced()),
        writer_stop: Ok(StopConfirmation { confirmed: false }),
        standby: Ok(true),
        former_writer: Ok(true),
    }
}

/// The failover evidence probes: writer down, site fenced, watchdog
/// confirms the stop, standby ready.
fn failover_probes() -> RoundProbes {
    RoundProbes {
        writer: WriterProbe::Unreachable,
        writer_site_fence: Ok(fenced()),
        writer_stop: Ok(StopConfirmation { confirmed: true }),
        standby: Ok(true),
        former_writer: Err(ProbeFault::Indeterminate),
    }
}

#[test]
fn healthy_round_forms_a_complete_report() {
    let report = report_of(&healthy_probes(7));
    assert_eq!(report.writer, WriterObservation::Reachable { epoch: 7 });
    assert_eq!(report.writer_site_fence, Some(unfenced()));
    // The watchdog answered, but a live writer round carries no
    // stop-confirmation evidence at all (see the suppression rule).
    assert_eq!(report.writer_stop_confirmed, None);
    assert_eq!(report.standby_ready, Some(true));
    assert_eq!(report.former_writer_healthy, Some(true));
}

#[test]
fn definitive_connection_failure_is_the_only_unreachable_evidence() {
    let report = report_of(&failover_probes());
    assert_eq!(report.writer, WriterObservation::Unreachable);
    assert_eq!(report.writer_site_fence, Some(fenced()));
    assert_eq!(report.writer_stop_confirmed, Some(true));
    assert_eq!(report.standby_ready, Some(true));
    assert_eq!(report.former_writer_healthy, None);
}

#[test]
fn indeterminate_writer_probe_abstains_even_with_complete_positive_evidence() {
    let mut probes = failover_probes();
    probes.writer = WriterProbe::Indeterminate;
    probes.former_writer = Ok(true);
    assert_eq!(
        observer("witness").observe(probes, 5_000),
        Observation::Abstain(AbstainReason::WriterIndeterminate)
    );
}

#[test]
fn epoch_zero_is_never_reported_as_a_reachable_epoch() {
    assert_eq!(
        observer("witness").observe(bare_probes(WriterProbe::Reachable { epoch: 0 }), 5_000),
        Observation::Abstain(AbstainReason::WriterEpochImpossible)
    );
}

#[test]
fn epoch_bounds_follow_the_authority_bigint_range() {
    // The highest value a bigint column can hold is a valid observation.
    let report = report_of(&bare_probes(WriterProbe::Reachable {
        epoch: MAX_STORED_EPOCH,
    }));
    assert_eq!(
        report.writer,
        WriterObservation::Reachable {
            epoch: MAX_STORED_EPOCH
        }
    );
    // One above it cannot come from the database: the probe layer is
    // misbehaving, and the member abstains rather than report it.
    assert_eq!(
        observer("witness").observe(
            bare_probes(WriterProbe::Reachable {
                epoch: MAX_STORED_EPOCH + 1
            }),
            5_000
        ),
        Observation::Abstain(AbstainReason::WriterEpochImpossible)
    );
}

#[test]
fn stop_confirmation_is_dropped_when_the_writer_was_observed_alive() {
    for confirmed in [true, false] {
        let mut probes = healthy_probes(3);
        probes.writer_stop = Ok(StopConfirmation { confirmed });
        let report = report_of(&probes);
        assert_eq!(
            report.writer_stop_confirmed, None,
            "a live writer round carries no stop evidence, whatever the watchdog claims"
        );
    }
}

#[test]
fn a_watchdog_not_stopped_answer_survives_an_unreachable_writer() {
    let mut probes = failover_probes();
    probes.writer_stop = Ok(StopConfirmation { confirmed: false });
    let report = report_of(&probes);
    assert_eq!(report.writer_stop_confirmed, Some(false));
}

#[test]
fn probe_faults_are_absence_of_evidence_never_negative_evidence() {
    let probes = RoundProbes {
        writer: WriterProbe::Unreachable,
        writer_site_fence: Err(ProbeFault::Unreachable),
        writer_stop: Err(ProbeFault::Unreachable),
        standby: Err(ProbeFault::Indeterminate),
        former_writer: Err(ProbeFault::Indeterminate),
    };
    let report = report_of(&probes);
    // Only the writer connection failure is negative evidence; every other
    // fault is simply no evidence of any kind.
    assert_eq!(report.writer, WriterObservation::Unreachable);
    assert_eq!(report.writer_site_fence, None);
    assert_eq!(report.writer_stop_confirmed, None);
    assert_eq!(report.standby_ready, None);
    assert_eq!(report.former_writer_healthy, None);
}

#[test]
fn fence_evidence_is_carried_for_live_and_dead_writers() {
    // A drained-but-live writer is the controlled-failover path: members
    // must be able to attest the fence while the writer still answers.
    let mut live = healthy_probes(9);
    live.writer_site_fence = Ok(fenced());
    assert_eq!(report_of(&live).writer_site_fence, Some(fenced()));

    let mut dead = failover_probes();
    dead.writer_site_fence = Ok(fenced());
    assert_eq!(report_of(&dead).writer_site_fence, Some(fenced()));
}

#[test]
fn an_answered_not_ready_standby_is_explicit_negative_evidence() {
    let mut probes = failover_probes();
    probes.standby = Ok(false);
    assert_eq!(report_of(&probes).standby_ready, Some(false));
}

#[test]
fn former_writer_health_follows_the_probe_answer() {
    let mut probes = failover_probes();
    probes.former_writer = Ok(true);
    assert_eq!(report_of(&probes).former_writer_healthy, Some(true));
    probes.former_writer = Ok(false);
    assert_eq!(report_of(&probes).former_writer_healthy, Some(false));
    probes.former_writer = Err(ProbeFault::Unreachable);
    assert_eq!(report_of(&probes).former_writer_healthy, None);
}

#[test]
fn the_observer_binds_its_identity_and_the_round_time_into_every_report() {
    assert!(MemberObserver::new("").is_err());
    let witness = observer("witness");
    assert_eq!(witness.member_id(), "witness");
    let report = witness.observe(bare_probes(WriterProbe::Reachable { epoch: 2 }), 9_999);
    let report = report.report().expect("the round must produce a report");
    assert_eq!(report.member_id, "witness");
    assert_eq!(report.observed_at_ms, 9_999);
}

#[test]
fn observer_reports_drive_the_decision_model_unchanged() {
    let mut controller = controller();
    assert_eq!(
        controller.observe(observed_round(|_| healthy_probes(4), 1_000), 1_000),
        Decision::Hold(HoldReason::WriterHealthy)
    );
    assert_eq!(
        controller.observe(observed_round(|_| failover_probes(), 2_000), 2_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        })
    );
    assert_eq!(
        controller.observe(observed_round(|_| failover_probes(), 3_000), 3_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 2
        })
    );
    assert_eq!(
        controller.observe(observed_round(|_| failover_probes(), 4_000), 4_000),
        Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        }
    );
    assert_eq!(
        controller.observe(observed_round(|_| failover_probes(), 5_000), 5_000),
        Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        }
    );
    // Dispatch stays paused after the promotion until reconciliation.
    assert_eq!(
        controller.observe(observed_round(|_| failover_probes(), 6_000), 6_000),
        Decision::KeepDispatchPaused
    );
    assert!(matches!(
        controller.phase(),
        Phase::Promoted {
            new_epoch: 5,
            reconciled: false,
            ..
        }
    ));
}

#[test]
fn one_abstaining_member_leaves_the_decision_to_the_remaining_two() {
    let mut controller = controller();
    // The witness's writer probe fails for member-local reasons while it
    // holds complete positive failover evidence: it must abstain entirely,
    // neither blocking the quorum nor contributing that evidence.
    let witness_fault = || {
        let mut probes = failover_probes();
        probes.writer = WriterProbe::Indeterminate;
        probes
    };
    // Establish the observed epoch while everyone is healthy.
    assert_eq!(
        controller.observe(observed_round(|_| healthy_probes(4), 1_000), 1_000),
        Decision::Hold(HoldReason::WriterHealthy)
    );
    for (now_ms, failures) in [(2_000, 1), (3_000, 2), (4_000, 3)] {
        let expected = if failures == 3 {
            Decision::FenceOldWriter {
                site_id: "site-a".to_owned(),
            }
        } else {
            Decision::Hold(HoldReason::WriterFailureSuspected {
                consecutive_failures: failures,
            })
        };
        assert_eq!(
            controller.observe(
                observed_round(
                    |member| {
                        if member == "witness" {
                            witness_fault()
                        } else {
                            failover_probes()
                        }
                    },
                    now_ms
                ),
                now_ms
            ),
            expected
        );
    }
    // The two healthy members' fence, stop and standby evidence is a
    // majority: the promotion proceeds without the faulty witness.
    assert_eq!(
        controller.observe(
            observed_round(
                |member| {
                    if member == "witness" {
                        witness_fault()
                    } else {
                        failover_probes()
                    }
                },
                5_000
            ),
            5_000
        ),
        Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        }
    );
}

#[test]
fn all_members_abstaining_loses_the_quorum_and_restarts_hysteresis() {
    let mut controller = controller();
    assert_eq!(
        controller.observe(observed_round(|_| healthy_probes(4), 1_000), 1_000),
        Decision::Hold(HoldReason::WriterHealthy)
    );
    assert_eq!(
        controller.observe(observed_round(|_| failover_probes(), 2_000), 2_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        })
    );
    assert_eq!(
        controller.observe(observed_round(|_| failover_probes(), 3_000), 3_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 2
        })
    );
    // Every member's probe layer fails at once (for example a shared TLS
    // or DNS fault): no evidence exists, so the quorum is lost and the
    // incomplete failure streak restarts — an unknown interval is not
    // stable evidence.
    let indeterminate = || {
        let mut probes = failover_probes();
        probes.writer = WriterProbe::Indeterminate;
        probes
    };
    assert_eq!(
        controller.observe(observed_round(|_| indeterminate(), 4_000), 4_000),
        Decision::QuorumLost
    );
    assert_eq!(controller.phase(), &Phase::Steady);
    assert_eq!(
        controller.observe(observed_round(|_| failover_probes(), 5_000), 5_000),
        Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        })
    );
}

#[test]
fn no_external_stop_confirmation_means_no_promotion() {
    let mut controller = controller();
    for now_ms in [1_000, 2_000, 3_000] {
        assert_eq!(
            controller.observe(observed_round(|_| failover_probes(), now_ms), now_ms),
            if now_ms == 3_000 {
                Decision::FenceOldWriter {
                    site_id: "site-a".to_owned(),
                }
            } else {
                Decision::Hold(HoldReason::WriterFailureSuspected {
                    consecutive_failures: u32::try_from(now_ms / 1_000).unwrap(),
                })
            }
        );
    }
    // Fence seen and standby ready, but the watchdog is silent: promotion
    // stays blocked, round after round.
    let mut no_stop = failover_probes();
    no_stop.writer_stop = Err(ProbeFault::Indeterminate);
    for now_ms in [4_000, 5_000, 6_000] {
        assert_eq!(
            controller.observe(observed_round(|_| no_stop.clone(), now_ms), now_ms),
            Decision::Hold(HoldReason::AwaitingFencingEvidence {
                site_fenced: true,
                stop_confirmed: false
            })
        );
    }
    // The watchdog answering "still running" blocks promotion just the
    // same: a partitioned writer is not a stopped writer.
    let mut not_stopped = failover_probes();
    not_stopped.writer_stop = Ok(StopConfirmation { confirmed: false });
    for now_ms in [7_000, 8_000] {
        assert_eq!(
            controller.observe(observed_round(|_| not_stopped.clone(), now_ms), now_ms),
            Decision::Hold(HoldReason::AwaitingFencingEvidence {
                site_fenced: true,
                stop_confirmed: false
            })
        );
    }
    assert_eq!(controller.phase(), &Phase::FencingOldWriter);
}
