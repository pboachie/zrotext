// SPDX-License-Identifier: AGPL-3.0-only
//! Adversarial corpus for the external writer-fencing and epoch-authority
//! binding (issue #647), written before the binding itself. Each test names a
//! way an external adapter can go wrong — an absent or partitioned authority,
//! a lost fence acknowledgment, a competing promoter's fence, a database
//! restored behind the anchored epoch, a promotion epoch the anchor already
//! witnessed, a refused witness record, an unconfirmed anchor at restore and
//! at rejoin — and pins the fail-closed behavior: the promotion never reaches
//! the epoch compare-and-set, dispatch stays paused, and nothing rolls back.

use crate::anchor::MemoryEpochAnchor;
use crate::decision::{Decision, RestorablePhase};
use crate::executor::{
    Application, AppliedAction, ExecutorStatus, FailoverExecutor, PromoteOutcome,
};
use crate::executor_tests::{
    MemoryAuthority, drive_to_fence, evidence_round, failure_round, former_writer_round,
    full_executor, healthy_round, journal, source, test_config,
};
use crate::fence::{
    AnchorReading, ExternalEpochAnchor, ExternalFencing, FenceAuthority, FenceStatus, FenceToken,
    HostFenceOutcome, MemoryFenceAuthority, NoopFenceAuthority,
};

/// The shipped production default must refuse everything: with no external
/// fencing backend configured, no fence is ever confirmed, so no promotion
/// can ever pass the external-fence precondition.
#[test]
fn the_refusing_default_fence_backend_never_confirms_anything() {
    let mut backend = NoopFenceAuthority;
    assert_eq!(backend.fence_status("site-a"), FenceStatus::Unconfirmed);
    assert_eq!(
        backend.fence_host("site-a", FenceToken::for_promotion(5)),
        HostFenceOutcome::RefusedUnconfirmed
    );
    // Refusal changed nothing: the status is still unknown, never "unfenced
    // and free to promote".
    assert_eq!(backend.fence_status("site-a"), FenceStatus::Unconfirmed);
}

/// The fence contract's idempotence rule: a re-fence under the token of the
/// same promotion is a success, a fence under any other token is refused,
/// and the held token is never overwritten.
#[test]
fn the_fence_backend_is_idempotent_per_token_and_refuses_competitors() {
    let mut backend = MemoryFenceAuthority::default();
    assert_eq!(backend.fence_status("site-a"), FenceStatus::Unfenced);
    let promotion = FenceToken::for_promotion(5);
    assert_eq!(
        backend.fence_host("site-a", promotion),
        HostFenceOutcome::Fenced { token: promotion }
    );
    assert_eq!(
        backend.fence_host("site-a", promotion),
        HostFenceOutcome::AlreadyFenced { token: promotion },
        "the idempotent re-fence of one promotion succeeds"
    );
    let competitor = FenceToken::for_promotion(6);
    assert_eq!(
        backend.fence_host("site-a", competitor),
        HostFenceOutcome::RefusedCompetingFence { holder: promotion },
        "a different promotion can never take over the fence"
    );
    assert_eq!(
        backend.fence_status("site-a"),
        FenceStatus::Fenced { token: promotion },
        "the refused competitor did not move the fence"
    );
    backend.mark_unconfirmed();
    assert_eq!(backend.fence_status("site-a"), FenceStatus::Unconfirmed);
    assert_eq!(
        backend.fence_host("site-a", promotion),
        HostFenceOutcome::RefusedUnconfirmed,
        "an absent authority refuses even the idempotent re-fence"
    );
}

/// A promotion that cannot show a confirmed external fence under its own
/// token never reaches the epoch compare-and-set: the site-row fence still
/// applies (it is independent), but the epoch never moves and the promotion
/// stays pending forever.
#[test]
fn a_promotion_without_a_confirmed_external_fence_never_reaches_the_epoch_cas() {
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            evidence_round(6_000),
            evidence_round(7_000),
        ]),
        MemoryAuthority::new(4),
        // The production shape: a refusing fence backend beside a confirming
        // anchor — the anchor alone must never be enough.
        ExternalFencing::new(NoopFenceAuthority, MemoryEpochAnchor::new()),
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
    assert!(matches!(report.application, Application::Pending { .. }));
    let _ = executor.tick(6_000);
    let report = executor.tick(7_000);
    assert!(
        matches!(report.application, Application::Pending { .. }),
        "the promotion stays pending without the external fence: {:?}",
        report.application
    );
    let (_, _, port) = executor.into_parts();
    assert!(
        port.promote_calls().is_empty(),
        "the epoch compare-and-set never ran: {:?}",
        port.promote_calls()
    );
    assert_eq!(port.epoch, 4, "the epoch never moved");
    assert!(port.site("site-a").draining, "the site-row fence applied");
    assert_eq!(port.promotions_applied, 0);
}

/// A confirmed fence is not enough either: an unconfirmed epoch anchor holds
/// the promotion before the compare-and-set exactly the same way.
#[test]
fn a_promotion_without_a_confirmed_anchor_never_reaches_the_epoch_cas() {
    let anchor = MemoryEpochAnchor::new();
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
        MemoryAuthority::new(4),
        ExternalFencing::new(MemoryFenceAuthority::default(), anchor.clone()),
    );
    drive_to_fence(&mut executor);
    // The anchor confirms through the restore and the fence, then turns
    // unconfirmed right before the promotion.
    anchor.mark_unconfirmed();
    let report = executor.tick(5_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert!(matches!(report.application, Application::Pending { .. }));
    let report = executor.tick(6_000);
    assert!(matches!(report.application, Application::Pending { .. }));
    let (_, _, port) = executor.into_parts();
    assert!(port.promote_calls().is_empty());
    assert_eq!(port.epoch, 4);
}

/// A fence whose acknowledgment was lost still holds in the backend: the
/// retry's status read confirms it under the same token, and the promotion
/// proceeds — idempotence makes acknowledgment loss a delay, never a
/// double-fence or a stall.
#[test]
fn a_lost_fence_acknowledgment_recovers_through_the_idempotent_re_fence() {
    let fence = MemoryFenceAuthority::default();
    fence.drop_acknowledgments(1);
    let anchor = MemoryEpochAnchor::new();
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
        MemoryAuthority::new(4),
        ExternalFencing::new(fence.clone(), anchor),
    );
    drive_to_fence(&mut executor);
    // The backend applied the fence but its acknowledgment was lost, so this
    // attempt refuses unconfirmed and the promotion stays pending.
    let report = executor.tick(5_000);
    assert!(matches!(report.application, Application::Pending { .. }));
    // The retry observes the held fence under the same token and proceeds.
    let report = executor.tick(6_000);
    assert!(matches!(report.application, Application::Applied { .. }));
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert_eq!(port.promotions_applied, 1);
    assert_eq!(
        fence.held_by("site-a"),
        Some(FenceToken::for_promotion(5)),
        "exactly one fence under the promotion's token"
    );
    assert_eq!(
        fence.fence_calls(),
        vec![("site-a".to_owned(), FenceToken::for_promotion(5))],
        "the retry confirmed through the status read, not a second fence"
    );
}

/// Another promotion's fence on the old writer blocks the promotion
/// indefinitely: the executor never takes over a foreign fence and never
/// proceeds past it, whatever rounds arrive.
#[test]
fn a_competing_fence_token_blocks_the_promotion_indefinitely() {
    let fence = MemoryFenceAuthority::default();
    fence.pre_fence("site-a", FenceToken::for_promotion(99));
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
            evidence_round(6_000),
            evidence_round(7_000),
        ]),
        MemoryAuthority::new(4),
        ExternalFencing::new(fence.clone(), MemoryEpochAnchor::new()),
    );
    drive_to_fence(&mut executor);
    for now_ms in [5_000_u64, 6_000, 7_000] {
        let report = executor.tick(now_ms);
        assert!(
            matches!(report.application, Application::Pending { .. }),
            "a foreign fence never becomes a promotion at {now_ms}ms"
        );
    }
    let (_, _, port) = executor.into_parts();
    assert!(port.promote_calls().is_empty());
    assert_eq!(port.epoch, 4);
    assert_eq!(
        fence.held_by("site-a"),
        Some(FenceToken::for_promotion(99)),
        "the competing fence was never overwritten"
    );
}

/// A fence adapter in front of a partitioned authority — one replica says
/// fenced, one says unfenced — must refuse rather than pick a side. This
/// double is the executable form of that contract: disagreement answers
/// `Unconfirmed`, and the executor's promotion stays pending.
#[test]
fn a_partitioned_fence_authority_refuses_rather_than_picking_a_side() {
    struct SplitFenceView {
        left: MemoryFenceAuthority,
        right: MemoryFenceAuthority,
    }
    impl FenceAuthority for SplitFenceView {
        fn fence_host(&mut self, host: &str, token: FenceToken) -> HostFenceOutcome {
            match (
                self.left.fence_host(host, token),
                self.right.fence_host(host, token),
            ) {
                (HostFenceOutcome::Fenced { token }, HostFenceOutcome::Fenced { token: other })
                    if token == other =>
                {
                    HostFenceOutcome::Fenced { token }
                }
                (
                    HostFenceOutcome::AlreadyFenced { token },
                    HostFenceOutcome::AlreadyFenced { token: other },
                ) if token == other => HostFenceOutcome::AlreadyFenced { token },
                _ => HostFenceOutcome::RefusedUnconfirmed,
            }
        }
        fn fence_status(&mut self, host: &str) -> FenceStatus {
            match (self.left.fence_status(host), self.right.fence_status(host)) {
                (FenceStatus::Fenced { token }, FenceStatus::Fenced { token: other })
                    if token == other =>
                {
                    FenceStatus::Fenced { token }
                }
                (FenceStatus::Unfenced, FenceStatus::Unfenced) => FenceStatus::Unfenced,
                _ => FenceStatus::Unconfirmed,
            }
        }
    }

    // Pure form: one side fenced, one unfenced — uncertain, never "fenced".
    let mut split = SplitFenceView {
        left: MemoryFenceAuthority::default(),
        right: MemoryFenceAuthority::default(),
    };
    split.left.pre_fence("site-a", FenceToken::for_promotion(5));
    assert_eq!(split.fence_status("site-a"), FenceStatus::Unconfirmed);
    assert_eq!(
        split.fence_host("site-a", FenceToken::for_promotion(5)),
        HostFenceOutcome::RefusedUnconfirmed,
        "a partitioned authority refuses to fence at all"
    );

    // Executor form: the promotion stays pending while the views disagree.
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
        MemoryAuthority::new(4),
        ExternalFencing::new(
            SplitFenceView {
                left: {
                    let left = MemoryFenceAuthority::default();
                    left.pre_fence("site-a", FenceToken::for_promotion(5));
                    left
                },
                right: MemoryFenceAuthority::default(),
            },
            MemoryEpochAnchor::new(),
        ),
    );
    drive_to_fence(&mut executor);
    for now_ms in [5_000_u64, 6_000] {
        let report = executor.tick(now_ms);
        assert!(
            matches!(report.application, Application::Pending { .. }),
            "a partitioned authority is not a confirmed fence at {now_ms}ms"
        );
    }
    let (_, _, port) = executor.into_parts();
    assert!(port.promote_calls().is_empty());
    assert_eq!(port.epoch, 4);
}

/// A database behind the confirmed anchor is a restore from an older backup:
/// the anchor is the independent second witness and the executor fails
/// closed at restore, permanently — even though the journal itself is absent
/// (the case the journal-vs-authority check alone cannot catch).
#[test]
fn a_restored_database_behind_the_confirmed_anchor_fails_closed_at_restore() {
    let anchor = MemoryEpochAnchor::new();
    anchor.seed(6);
    let mut port = MemoryAuthority::new(4);
    // No journal at all: from the journal's point of view this authority is
    // perfectly consistent; only the external anchor knows the deployment
    // already served epoch 6.
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[failure_round(1_000), evidence_round(2_000)]),
        port.clone(),
        ExternalFencing::new(MemoryFenceAuthority::default(), anchor),
    );
    let report = executor.tick(1_000);
    assert_eq!(report.decision, None, "no round runs behind the anchor");
    assert_eq!(report.application, Application::None);
    assert_eq!(
        executor.status(),
        &ExecutorStatus::EpochAnchorAhead {
            anchored_epoch: 6,
            authority_epoch: 4
        }
    );
    // The inconsistency is permanent and nothing is ever applied.
    let report = executor.tick(2_000);
    assert_eq!(report.decision, None);
    port = executor.into_parts().2;
    assert_eq!(port.epoch, 4);
    assert!(!port.site("site-a").draining);
    assert_eq!(port.promotions_applied, 0);
}

/// A promotion epoch the external anchor already witnessed while the
/// authority is still behind it is a recycled epoch: the anchor only moves
/// forward, so the promotion is refused even though the compare-and-set
/// alone would have applied it.
#[test]
fn a_promotion_epoch_the_anchor_already_witnessed_is_refused() {
    let anchor = MemoryEpochAnchor::new();
    let mut port = MemoryAuthority::new(4);
    port.sites.get_mut("site-a").unwrap().draining = true;
    port.journal = Some(journal(
        &test_config(),
        4,
        RestorablePhase::Promoting { new_epoch: 5 },
    ));
    // The first compare-and-set attempt fails at the authority, so the
    // pending promotion survives into the tick where the anchor has moved.
    port.fail_promote = true;
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[evidence_round(1_000), evidence_round(2_000)]),
        port,
        ExternalFencing::new(MemoryFenceAuthority::default(), anchor.clone()),
    );
    // The restore itself is consistent (the anchor starts behind), and the
    // pending promotion intent is the legitimate crash window...
    let report = executor.tick(1_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 5
        })
    );
    assert!(matches!(report.application, Application::Pending { .. }));
    // ...but meanwhile another owner promoted through epoch 7 and the
    // external anchor witnessed it. Epoch 5 can never be issued again: the
    // retry never reaches the compare-and-set.
    anchor.seed(7);
    let report = executor.tick(2_000);
    assert!(
        matches!(report.application, Application::Pending { .. }),
        "an already-witnessed epoch is a refused promotion: {:?}",
        report.application
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(
        port.promote_calls(),
        vec![5],
        "only the pre-seed attempt reached the compare-and-set"
    );
    assert_eq!(port.epoch, 4);
}

/// The witness record happens only after the epoch compare-and-set succeeds,
/// and its refusal never blocks or rolls the promotion back: an anchor that
/// lags can only force refusals later, never authorize anything now.
#[test]
fn a_successful_promotion_witnesses_the_epoch_after_the_cas_and_survives_refusal() {
    // Part one: the witness follows the compare-and-set. A failed CAS leaves
    // the anchor untouched; the successful retry records the epoch.
    let mut anchor = MemoryEpochAnchor::new();
    let mut port = MemoryAuthority::new(4);
    port.fail_promote = true;
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
        ExternalFencing::new(MemoryFenceAuthority::default(), anchor.clone()),
    );
    drive_to_fence(&mut executor);
    let report = executor.tick(5_000);
    assert!(matches!(report.application, Application::Pending { .. }));
    assert_eq!(
        anchor.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: 0 },
        "a failed compare-and-set witnesses nothing"
    );
    let report = executor.tick(6_000);
    assert!(matches!(report.application, Application::Applied { .. }));
    assert_eq!(
        anchor.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: 5 }
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);

    // Part two: an authority that cannot witness at all never blocks the
    // promotion — the fail-safe direction is an anchor that lags.
    let mut refusing = MemoryEpochAnchor::new();
    refusing.refuse_records();
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ]),
        MemoryAuthority::new(4),
        ExternalFencing::new(MemoryFenceAuthority::default(), refusing.clone()),
    );
    drive_to_fence(&mut executor);
    let report = executor.tick(5_000);
    assert!(
        matches!(report.application, Application::Applied { .. }),
        "a refused witness record never blocks the promotion: {:?}",
        report.application
    );
    assert_eq!(
        refusing.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: 0 },
        "nothing was recorded"
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5);
    assert!(!port.dispatch_enabled);
}

/// The crash window between a successful compare-and-set and the completion
/// journal write replays idempotently even with the anchor already
/// witnessing the epoch: the authority serves the promotion epoch, so the
/// replay converges through `AlreadyAtEpoch` instead of pending forever on
/// the strict-anchored-epoch rule.
#[test]
fn the_completion_replay_at_the_anchored_epoch_converges_instead_of_pending() {
    let mut anchor = MemoryEpochAnchor::new();
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[
            healthy_round(4, 1_000),
            failure_round(2_000),
            failure_round(3_000),
            failure_round(4_000),
            evidence_round(5_000),
        ]),
        MemoryAuthority::new(4),
        ExternalFencing::new(MemoryFenceAuthority::default(), anchor.clone()),
    );
    drive_to_fence(&mut executor);
    // The promotion applies and is witnessed; the completion journal write
    // fails, so the durable journal still names the intent.
    let authority = executor.authority_mut();
    authority.fail_save_after = Some(1);
    let report = executor.tick(5_000);
    assert!(matches!(report.application, Application::Applied { .. }));
    assert_eq!(
        anchor.confirmed_epoch(),
        AnchorReading::Confirmed { epoch: 5 }
    );
    let (config, _, port) = executor.into_parts();
    assert_eq!(
        port.journal_phase(),
        Some(RestorablePhase::Promoting { new_epoch: 5 }),
        "the write-ahead intent survived"
    );
    // Restart with the same anchor — it already witnesses epoch 5 and the
    // authority serves epoch 5: only the idempotent completion replay is
    // allowed at an already-anchored epoch, and it must happen.
    let mut executor = FailoverExecutor::new(
        config,
        source(&[evidence_round(6_000)]),
        port,
        ExternalFencing::new(MemoryFenceAuthority::default(), anchor),
    );
    let report = executor.tick(6_000);
    assert_eq!(
        report.application,
        Application::Applied {
            action: AppliedAction::Promote {
                site_id: "site-b".to_owned(),
                new_epoch: 5,
                outcome: PromoteOutcome::AlreadyAtEpoch
            },
            replayed: true
        },
        "the replay converges at the anchored epoch"
    );
    let (_, _, port) = executor.into_parts();
    assert_eq!(port.epoch, 5, "the epoch never bumps twice");
    assert_eq!(port.promotions_applied, 1);
}

/// The one-time rejoin record needs the confirmed anchor at the promoted
/// epoch: without it the decision is emitted but never journaled — the
/// rejoin stays unrecorded and dispatch stays paused — and a later
/// incarnation with a confirming anchor records it exactly once.
#[test]
fn the_one_time_rejoin_record_waits_for_a_confirmed_anchor() {
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
    let (config, _, port) = executor.into_parts();
    // The anchor confirms for the restore, then turns unconfirmed before the
    // rejoin window opens.
    let unavailable = MemoryEpochAnchor::new();
    let mut executor = FailoverExecutor::new(
        config.clone(),
        source(&[former_writer_round(5, 6_000)]),
        port,
        ExternalFencing::new(MemoryFenceAuthority::default(), unavailable.clone()),
    );
    let _ = executor.tick(6_000);
    unavailable.mark_unconfirmed();
    let mut saw_rejoin = false;
    for minute in 1..7_u64 {
        executor.queue_round(former_writer_round(5, 6_000 + minute * 60_000));
        let report = executor.tick(6_000 + minute * 60_000);
        if matches!(
            report.decision,
            Some(Decision::RejoinFormerWriterAsReplica { .. })
        ) {
            saw_rejoin = true;
            assert_eq!(
                report.application,
                Application::None,
                "an unconfirmed anchor never journals the rejoin"
            );
        }
    }
    assert!(saw_rejoin, "the decision itself is still emitted");
    let (config, _, port) = executor.into_parts();
    assert!(matches!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            rejoin_emitted: false,
            ..
        })
    ));
    assert!(!port.dispatch_enabled, "dispatch stays paused");
    // A later incarnation with a confirming anchor records the one-time
    // rejoin for real.
    let confirming = MemoryEpochAnchor::new();
    confirming.seed(5);
    let mut executor = FailoverExecutor::new(
        config,
        source(&[]),
        port,
        ExternalFencing::new(MemoryFenceAuthority::default(), confirming),
    );
    let mut rejoins = 0;
    for minute in 0..6_u64 {
        executor.queue_round(former_writer_round(5, 6_000 + minute * 60_000));
        let report = executor.tick(6_000 + minute * 60_000);
        if matches!(
            report.decision,
            Some(Decision::RejoinFormerWriterAsReplica { .. })
        ) {
            rejoins += 1;
        }
    }
    assert_eq!(rejoins, 1, "the rejoin is recorded exactly once");
    let (_, _, port) = executor.into_parts();
    assert!(matches!(
        port.journal_phase(),
        Some(RestorablePhase::Promoted {
            rejoin_emitted: true,
            ..
        })
    ));
}

/// An unconfirmed anchor holds the executor before it reads anything else:
/// no authority read, no round, no fence — the witness comes first, so an
/// absent external authority is indistinguishable from an absent writer.
#[test]
fn an_unconfirmed_anchor_holds_the_executor_before_any_authority_read() {
    let anchor = MemoryEpochAnchor::new();
    anchor.mark_unconfirmed();
    let mut executor = FailoverExecutor::new(
        test_config(),
        source(&[failure_round(1_000), failure_round(2_000)]),
        MemoryAuthority::new(4),
        ExternalFencing::new(MemoryFenceAuthority::default(), anchor),
    );
    for now_ms in [1_000_u64, 2_000] {
        let report = executor.tick(now_ms);
        assert_eq!(report.decision, None);
        assert_eq!(report.application, Application::None);
    }
    assert_eq!(executor.status(), &ExecutorStatus::WaitingForAuthority);
    let (_, _, port) = executor.into_parts();
    assert!(
        port.calls.is_empty(),
        "nothing is read from the authority while the anchor is unconfirmed"
    );
}
