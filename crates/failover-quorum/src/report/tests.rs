// SPDX-License-Identifier: AGPL-3.0-only
//! Failure-scenario corpus for the member-side reporting loop, written
//! before the loop itself. Each test names a way a reporting round can go
//! wrong — a member-local probe fault that must abstain rather than vote, a
//! sink that refuses a non-member identity, a sink that fails mid-flight and
//! must stop reporting without touching the authority, a restart that must
//! resume from the durable journal without double-reporting — and pins the
//! fail-closed behavior: no phantom evidence ever reaches the durable store
//! or a decision round.

use super::*;
use crate::anchor::MemoryEpochAnchor;
use crate::decision::{
    DEFAULT_OBSERVATION_FRESHNESS_MS, Decision, FailoverConfig, FailoverController, HoldReason,
    MemberReport, Round, SiteFenceState, WriterObservation,
};
use crate::executor::{Application, FailoverExecutor, WriterAuthority};
use crate::executor_tests::MemoryAuthority;
use crate::fence::{ExternalFencing, MemoryFenceAuthority};
use crate::observe::{ProbeFault, StopConfirmation, WriterProbe};
use crate::store::StoreObservationSource;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The corpus's default external adapters (see `executor_tests`).
fn confirming_fencing() -> ExternalFencing {
    ExternalFencing::new(MemoryFenceAuthority::default(), MemoryEpochAnchor::new())
}

const MEMBERS: [&str; 3] = ["workload-a", "workload-b", "witness"];

fn members() -> Vec<String> {
    MEMBERS.iter().map(|member| (*member).to_owned()).collect()
}

fn test_config() -> FailoverConfig {
    FailoverConfig::new(members(), "site-a", "site-b").unwrap()
}

fn open_store(temp: &TempDir) -> Arc<Mutex<ConsensusStore>> {
    Arc::new(Mutex::new(
        ConsensusStore::open(temp.path(), members(), DEFAULT_OBSERVATION_FRESHNESS_MS).unwrap(),
    ))
}

/// Reclaim sole ownership of a shared store after every loop and sink using
/// it was dropped, so the executor can be wired over the same store.
fn unwrap_store(store: Arc<Mutex<ConsensusStore>>) -> ConsensusStore {
    match Arc::try_unwrap(store) {
        Ok(mutex) => mutex
            .into_inner()
            .expect("the consensus store mutex was not poisoned"),
        Err(_) => panic!("no reporting loop may outlive the store it reported into"),
    }
}

fn unfenced() -> SiteFenceState {
    SiteFenceState {
        enabled: true,
        draining: false,
    }
}

fn fenced() -> SiteFenceState {
    SiteFenceState {
        enabled: true,
        draining: true,
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

/// The writer is definitively down and nothing else produced evidence.
fn down_probes() -> RoundProbes {
    RoundProbes {
        writer: WriterProbe::Unreachable,
        writer_site_fence: Err(ProbeFault::Indeterminate),
        writer_stop: Err(ProbeFault::Indeterminate),
        standby: Err(ProbeFault::Indeterminate),
        former_writer: Err(ProbeFault::Indeterminate),
    }
}

/// The full failover evidence: writer down, fence observed, watchdog
/// confirms the stop, standby ready.
fn evidence_probes() -> RoundProbes {
    RoundProbes {
        writer: WriterProbe::Unreachable,
        writer_site_fence: Ok(fenced()),
        writer_stop: Ok(StopConfirmation { confirmed: true }),
        standby: Ok(true),
        former_writer: Err(ProbeFault::Indeterminate),
    }
}

/// The writer probe fails for member-local reasons (timeout, DNS, TLS,
/// authentication, driver) while every other probe holds complete positive
/// failover evidence.
fn indeterminate_probes() -> RoundProbes {
    RoundProbes {
        writer: WriterProbe::Indeterminate,
        ..evidence_probes()
    }
}

/// The writer probe answered an epoch the authority schema cannot hold.
fn impossible_epoch_probes() -> RoundProbes {
    RoundProbes {
        writer: WriterProbe::Reachable { epoch: 0 },
        ..down_probes()
    }
}

/// Deterministic probe source replaying a scripted outcome per round and
/// counting its calls, so tests prove the loop probes every round.
struct ScriptedProbes {
    rounds: VecDeque<RoundProbes>,
    calls: usize,
}

impl ScriptedProbes {
    fn new(rounds: impl IntoIterator<Item = RoundProbes>) -> Self {
        Self {
            rounds: rounds.into_iter().collect(),
            calls: 0,
        }
    }
}

impl ProbeSource for ScriptedProbes {
    fn probe(&mut self) -> RoundProbes {
        self.calls += 1;
        self.rounds
            .pop_front()
            .expect("the script must cover every round")
    }
}

/// Sink wrapper that forwards to the real store sink but fails exactly its
/// `fail_at`-th submission and forwards again afterwards: deterministic
/// mid-flight sink failure injection (followed by a repaired sink) without
/// OS-specific write-failure tricks.
struct FailingSubmit {
    inner: ConsensusStoreSink,
    fail_at: usize,
    submits: usize,
}

impl FailingSubmit {
    fn new(inner: ConsensusStoreSink, fail_at: usize) -> Self {
        Self {
            inner,
            fail_at,
            submits: 0,
        }
    }
}

impl ObservationSink for FailingSubmit {
    type Error = StoreError;

    fn submit(&mut self, report: &MemberReport) -> Result<(), StoreError> {
        self.submits += 1;
        if self.submits == self.fail_at {
            return Err(StoreError::Failed);
        }
        self.inner.submit(report)
    }
}

/// One reporting loop over a shared store, with a scripted probe timeline.
fn member_loop(
    member: &str,
    store: &Arc<Mutex<ConsensusStore>>,
    probes: impl IntoIterator<Item = RoundProbes>,
) -> ReportLoop<ScriptedProbes, ConsensusStoreSink> {
    ReportLoop::new(
        MemberObserver::new(member).unwrap(),
        ScriptedProbes::new(probes),
        ConsensusStoreSink::new(store.clone()),
    )
}

fn expected_report(member: &str, at_ms: u64, writer: WriterObservation) -> MemberReport {
    MemberReport {
        member_id: member.to_owned(),
        observed_at_ms: at_ms,
        writer,
        writer_site_fence: None,
        writer_stop_confirmed: None,
        standby_ready: None,
        former_writer_healthy: None,
    }
}

/// Scratch directory removed on drop, mirroring the consensus-store corpus.
/// The root is derived only from the compile-time manifest directory — never
/// from an environment variable, argument or the system temp dir — under the
/// workspace `target/`, which Git ignores.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/zrotext-failover-report-tests");
        let path = root.join(format!("{label}-{}-{unique}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create scratch store directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn journal_lines(temp: &TempDir, member: &str) -> Vec<String> {
    let path = temp
        .path()
        .join("observations")
        .join(format!("{member}.journal"));
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// One round: probe, observe, record exactly one report.
// ---------------------------------------------------------------------------

#[test]
fn a_reporting_round_probes_observes_and_records_exactly_one_report() {
    let temp = TempDir::new("round-reports");
    let store = open_store(&temp);
    let mut reporting = member_loop("workload-a", &store, [healthy_probes(5)]);
    assert_eq!(reporting.member_id(), "workload-a");
    assert_eq!(reporting.run_round(1_000), RoundOutcome::Reported);
    assert_eq!(reporting.probes.calls, 1, "one round probes exactly once");
    let store = store.lock().unwrap();
    assert_eq!(
        store.round(1_000).reports,
        vec![MemberReport {
            writer_site_fence: Some(unfenced()),
            // A live writer round carries no stop-confirmation evidence.
            writer_stop_confirmed: None,
            standby_ready: Some(true),
            former_writer_healthy: Some(true),
            ..expected_report(
                "workload-a",
                1_000,
                WriterObservation::Reachable { epoch: 5 }
            )
        }]
    );
    assert_eq!(store.next_sequence("workload-a"), Some(2));
    drop(store);
    assert_eq!(
        journal_lines(&temp, "workload-a").len(),
        1,
        "one round yields at most one durable record"
    );
}

// ---------------------------------------------------------------------------
// Member-local probe faults abstain; nothing is recorded.
// ---------------------------------------------------------------------------

#[test]
fn an_indeterminate_writer_probe_abstains_and_records_nothing() {
    let temp = TempDir::new("indeterminate-abstains");
    let store = open_store(&temp);
    // Complete positive failover evidence everywhere except the mandatory
    // writer vote, which timed out for member-local reasons: the round must
    // abstain, never vote unreachable.
    let mut reporting = member_loop("witness", &store, [indeterminate_probes()]);
    assert_eq!(
        reporting.run_round(1_000),
        RoundOutcome::Abstained(AbstainReason::WriterIndeterminate)
    );
    let store = store.lock().unwrap();
    assert_eq!(store.round(1_000), Round::default());
    assert_eq!(store.next_sequence("witness"), Some(1));
    drop(store);
    for member in MEMBERS {
        assert!(
            journal_lines(&temp, member).is_empty(),
            "{member} recorded nothing"
        );
    }
}

#[test]
fn only_a_definitive_connection_failure_becomes_an_unreachable_vote() {
    let temp = TempDir::new("refusal-versus-indeterminate");
    let store = open_store(&temp);
    let mut reporting = member_loop(
        "workload-a",
        &store,
        [down_probes(), indeterminate_probes()],
    );
    // A connection that was attempted and definitively failed is the one
    // acceptable source of an unreachable vote; every other probe's fault
    // stays absence of evidence.
    assert_eq!(reporting.run_round(1_000), RoundOutcome::Reported);
    {
        let store = store.lock().unwrap();
        assert_eq!(
            store.round(1_000).reports,
            vec![expected_report(
                "workload-a",
                1_000,
                WriterObservation::Unreachable
            )]
        );
    }
    // The next round's writer probe is transport-indeterminate: the member
    // abstains instead of repeating the earlier unreachable vote, and the
    // durable evidence does not grow.
    assert_eq!(
        reporting.run_round(2_000),
        RoundOutcome::Abstained(AbstainReason::WriterIndeterminate)
    );
    assert_eq!(journal_lines(&temp, "workload-a").len(), 1);
}

#[test]
fn an_epoch_the_authority_cannot_hold_abstains_and_records_nothing() {
    let temp = TempDir::new("impossible-epoch");
    let store = open_store(&temp);
    let mut reporting = member_loop("workload-b", &store, [impossible_epoch_probes()]);
    assert_eq!(
        reporting.run_round(1_000),
        RoundOutcome::Abstained(AbstainReason::WriterEpochImpossible)
    );
    assert!(journal_lines(&temp, "workload-b").is_empty());
}

#[test]
fn an_abstain_only_sequence_leaves_the_store_empty() {
    let temp = TempDir::new("abstain-only");
    let store = open_store(&temp);
    let script = [
        indeterminate_probes(),
        impossible_epoch_probes(),
        indeterminate_probes(),
        impossible_epoch_probes(),
    ];
    let mut reporting = member_loop("witness", &store, script);
    for (round, at_ms) in (0_u64..).zip([1_000_u64, 2_000, 3_000, 4_000]) {
        let expected = if round % 2 == 0 {
            RoundOutcome::Abstained(AbstainReason::WriterIndeterminate)
        } else {
            RoundOutcome::Abstained(AbstainReason::WriterEpochImpossible)
        };
        assert_eq!(reporting.run_round(at_ms), expected);
    }
    for member in MEMBERS {
        assert!(journal_lines(&temp, member).is_empty());
    }
    let mut controller = FailoverController::new(test_config());
    assert_eq!(
        controller.observe(store.lock().unwrap().round(4_000), 4_000),
        Decision::QuorumLost,
        "an abstain-only sequence is never a quorum"
    );
}

// ---------------------------------------------------------------------------
// Evidence rules survive the trip into the durable store.
// ---------------------------------------------------------------------------

#[test]
fn a_live_writer_round_records_no_stop_confirmation() {
    let temp = TempDir::new("live-writer-no-stop");
    let store = open_store(&temp);
    // The watchdog claims the old writer is stopped while the writer probe
    // just answered: the live observation wins and no stop evidence is
    // carried into the durable record.
    let mut probes = healthy_probes(7);
    probes.writer_stop = Ok(StopConfirmation { confirmed: true });
    let mut reporting = member_loop("workload-a", &store, [probes]);
    assert_eq!(reporting.run_round(1_000), RoundOutcome::Reported);
    {
        let store = store.lock().unwrap();
        assert_eq!(
            store.round(1_000).reports[0].writer_stop_confirmed,
            None,
            "a member never attests a live writer and a stopped one at once"
        );
    }
    let line = &journal_lines(&temp, "workload-a")[0];
    assert!(
        line.contains(" stop=-"),
        "the durable record marks the stop confirmation as not carried: {line}"
    );
    assert!(
        !line.contains(" stop=true") && !line.contains(" stop=false"),
        "no stop-confirmation value is ever recorded for a live writer: {line}"
    );
}

// ---------------------------------------------------------------------------
// The sink refuses identities outside the membership; the loop fails closed.
// ---------------------------------------------------------------------------

#[test]
fn a_non_member_identity_is_refused_at_the_sink_and_fails_the_loop_closed() {
    let temp = TempDir::new("non-member-refused");
    let store = open_store(&temp);
    let mut rogue = member_loop("rogue", &store, [healthy_probes(5), healthy_probes(5)]);
    assert_eq!(rogue.run_round(1_000), RoundOutcome::SinkFailed);
    assert!(rogue.failed());
    // The store refused the record, not the journal file of a stranger.
    assert!(
        !temp
            .path()
            .join("observations")
            .join("rogue.journal")
            .exists()
    );
    {
        let store = store.lock().unwrap();
        assert!(
            !store.failed(),
            "a refused identity does not poison the store"
        );
    }
    // A real member still records through the same store afterwards.
    let mut member = member_loop("workload-a", &store, [healthy_probes(5)]);
    assert_eq!(member.run_round(2_000), RoundOutcome::Reported);
    assert_eq!(journal_lines(&temp, "workload-a").len(), 1);
}

// ---------------------------------------------------------------------------
// Sink failure: sticky fail-closed, probes continue, nothing is reported,
// and the authority is never touched by phantom rounds.
// ---------------------------------------------------------------------------

#[test]
fn a_sink_failure_is_sticky_and_no_further_reports_reach_the_store_or_authority() {
    let temp = TempDir::new("sticky-sink-failure");
    let shared = open_store(&temp);
    let mut reporting = ReportLoop::new(
        MemberObserver::new("workload-a").unwrap(),
        ScriptedProbes::new([
            healthy_probes(5),
            healthy_probes(5),
            down_probes(),
            down_probes(),
            healthy_probes(5),
        ]),
        FailingSubmit::new(ConsensusStoreSink::new(shared.clone()), 2),
    );
    assert_eq!(reporting.run_round(1_000), RoundOutcome::Reported);
    // The second submit fails (the journal append failed): the loop fails
    // closed for reporting from here on.
    assert_eq!(reporting.run_round(2_000), RoundOutcome::SinkFailed);
    assert!(reporting.failed());
    // Later rounds still probe — even with failover evidence — but report
    // nothing: a report that may not have been recorded must never be
    // silently retried into a second journal record.
    assert_eq!(reporting.run_round(3_000), RoundOutcome::Suppressed);
    assert_eq!(reporting.run_round(4_000), RoundOutcome::Suppressed);
    assert_eq!(reporting.probes.calls, 4, "every round probes, always");
    assert_eq!(
        journal_lines(&temp, "workload-a").len(),
        1,
        "only the first, accepted report is durable"
    );
    // Recovery is explicit; the next round reports again.
    reporting.recover();
    assert!(!reporting.failed());
    assert_eq!(reporting.run_round(5_000), RoundOutcome::Reported);
    assert_eq!(journal_lines(&temp, "workload-a").len(), 2);
    drop(reporting);
    let store = unwrap_store(shared);
    // The store never serves phantom rounds: with only one fresh report
    // there is no quorum, and the executor never touches the authority.
    let mut executor = FailoverExecutor::new(
        test_config(),
        StoreObservationSource::new(store),
        MemoryAuthority::new(5),
        confirming_fencing(),
    );
    for at_ms in [1_000_u64, 2_000, 3_000] {
        let report = executor.tick(at_ms);
        assert_eq!(
            report.decision,
            Some(Decision::QuorumLost),
            "a sticky-failed reporter must not fabricate a quorum"
        );
        assert_eq!(report.application, Application::None);
    }
    let (_, _, authority) = executor.into_parts();
    assert_eq!(authority.fence_calls(), 0, "no fence without a quorum");
    assert!(
        authority.promote_calls().is_empty(),
        "no promotion without a quorum"
    );
}

// ---------------------------------------------------------------------------
// Restarts resume from the durable journal, never double-reporting a round.
// ---------------------------------------------------------------------------

#[test]
fn a_restart_between_rounds_resumes_from_the_durable_journal() {
    let temp = TempDir::new("restart-resumes");
    {
        let shared = open_store(&temp);
        let mut first = member_loop("workload-a", &shared, [healthy_probes(5)]);
        assert_eq!(first.run_round(1_000), RoundOutcome::Reported);
        drop(first);
        unwrap_store(shared);
    }
    // A true restart: the store is re-opened from disk, and a fresh loop for
    // the same member continues after the durable records.
    let shared = open_store(&temp);
    {
        let shared = shared.lock().unwrap();
        assert_eq!(shared.next_sequence("workload-a"), Some(2));
        assert_eq!(shared.round(1_000).reports.len(), 1);
    }
    let mut second = member_loop("workload-a", &shared, [healthy_probes(6)]);
    assert_eq!(second.run_round(2_000), RoundOutcome::Reported);
    drop(second);
    let store = unwrap_store(shared);
    let lines = journal_lines(&temp, "workload-a");
    assert_eq!(lines.len(), 2, "one record per round, never a replay");
    assert!(lines[0].contains("seq=1") && lines[1].contains("seq=2"));
    assert_eq!(store.next_sequence("workload-a"), Some(3));
    assert_eq!(
        store.round(2_000).reports,
        vec![
            MemberReport {
                writer: WriterObservation::Reachable { epoch: 5 },
                writer_site_fence: Some(unfenced()),
                standby_ready: Some(true),
                former_writer_healthy: Some(true),
                writer_stop_confirmed: None,
                ..expected_report(
                    "workload-a",
                    1_000,
                    WriterObservation::Reachable { epoch: 5 }
                )
            },
            MemberReport {
                writer: WriterObservation::Reachable { epoch: 6 },
                writer_site_fence: Some(unfenced()),
                standby_ready: Some(true),
                former_writer_healthy: Some(true),
                writer_stop_confirmed: None,
                ..expected_report(
                    "workload-a",
                    2_000,
                    WriterObservation::Reachable { epoch: 6 }
                )
            }
        ],
        "each round is reported exactly once, before and after the restart"
    );
}

// ---------------------------------------------------------------------------
// End to end: scripted probes -> reports -> durable store -> the executor.
// ---------------------------------------------------------------------------

#[test]
fn recorded_reports_drive_a_full_failover_through_the_store_backed_executor() {
    let temp = TempDir::new("end-to-end");
    let shared = open_store(&temp);
    // The whole timeline is one script per member, replayed through the
    // reporting loops into the durable store before any check runs.
    let timeline = [
        healthy_probes(5),
        down_probes(),
        down_probes(),
        down_probes(),
        evidence_probes(),
        healthy_probes(6),
    ];
    let times = [1_000_u64, 12_000, 13_000, 14_000, 25_000, 36_000];
    let mut reporting: Vec<_> = MEMBERS
        .iter()
        .map(|member| member_loop(member, &shared, timeline.clone()))
        .collect();
    for (at_ms, _) in times.into_iter().zip(timeline.iter()) {
        for reporting in &mut reporting {
            assert_eq!(reporting.run_round(at_ms), RoundOutcome::Reported);
        }
    }
    drop(reporting);
    let mut executor = FailoverExecutor::new(
        test_config(),
        StoreObservationSource::new(unwrap_store(shared)),
        MemoryAuthority::new(5),
        confirming_fencing(),
    );

    // Steady: all three members observe the writer healthy at epoch 5.
    let report = executor.tick(1_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::WriterHealthy))
    );

    // Three failed checks fence the old writer.
    let report = executor.tick(12_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        }))
    );
    let report = executor.tick(13_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(HoldReason::WriterFailureSuspected {
            consecutive_failures: 2
        }))
    );
    let report = executor.tick(14_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));

    // Fence, stop and standby readiness evidence promotes under epoch 6.
    let report = executor.tick(25_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 6
        })
    );
    assert!(matches!(report.application, Application::Applied { .. }));

    // Dispatch stays paused after the unplanned promotion.
    let report = executor.tick(36_000);
    assert_eq!(report.decision, Some(Decision::KeepDispatchPaused));

    let (_, _, mut authority) = executor.into_parts();
    assert_eq!(authority.fence_calls(), 1, "exactly one fence");
    assert_eq!(authority.promote_calls(), vec![6], "exactly one promotion");
    let snapshot = authority.load_state("site-a", "site-b").unwrap();
    assert_eq!(snapshot.epoch, 6);
    assert!(!snapshot.dispatch_enabled, "dispatch stays paused");
    assert!(
        snapshot.writer_site.is_some_and(|site| site.is_fenced()),
        "the old writer stays fenced"
    );
}
