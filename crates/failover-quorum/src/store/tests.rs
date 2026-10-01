// SPDX-License-Identifier: AGPL-3.0-only
//! Adversarial corpus for the consensus store, written before the store
//! itself. Each test names a way a durable observation journal can go wrong —
//! corruption and truncation mid-record, torn membership, membership changes
//! mid-flight, identity spoofing inside a journal, sequence gaps from
//! deletion or interleaved concurrent appends, clock skew, stale-freshness
//! boundaries, duplicates, restarts, exhaustion and write failures — and pins
//! the fail-closed behavior: corrupt or uncertain evidence never reaches a
//! decision round.

use super::*;
use crate::anchor::MemoryEpochAnchor;
use crate::decision::{
    DEFAULT_OBSERVATION_FRESHNESS_MS, Decision, FailoverConfig, FailoverController, MemberReport,
    Round, SiteFenceState, WriterObservation,
};
use crate::executor::{FailoverExecutor, WriterAuthority};
use crate::executor_tests::MemoryAuthority;
use crate::fence::{ExternalFencing, MemoryFenceAuthority};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// The corpus's default external adapters (see `executor_tests`).
fn confirming_fencing() -> ExternalFencing {
    ExternalFencing::new(MemoryFenceAuthority::default(), MemoryEpochAnchor::new())
}

pub(super) const MEMBERS: [&str; 3] = ["workload-a", "workload-b", "witness"];

pub(super) fn members() -> Vec<String> {
    MEMBERS.iter().map(|member| (*member).to_owned()).collect()
}

fn changed_members() -> Vec<String> {
    ["workload-a", "workload-b", "witness-2"]
        .iter()
        .map(|member| (*member).to_owned())
        .collect()
}

pub(super) fn test_config() -> FailoverConfig {
    FailoverConfig::new(members(), "site-a", "site-b").unwrap()
}

pub(super) fn report(member_id: &str, writer: WriterObservation, at_ms: u64) -> MemberReport {
    MemberReport {
        member_id: member_id.to_owned(),
        observed_at_ms: at_ms,
        writer,
        writer_site_fence: None,
        writer_stop_confirmed: None,
        standby_ready: None,
        former_writer_healthy: None,
    }
}

pub(super) fn reachable(member_id: &str, epoch: u64, at_ms: u64) -> MemberReport {
    report(member_id, WriterObservation::Reachable { epoch }, at_ms)
}

pub(super) fn unreachable(member_id: &str, at_ms: u64) -> MemberReport {
    report(member_id, WriterObservation::Unreachable, at_ms)
}

pub(super) fn evidence(member_id: &str, at_ms: u64) -> MemberReport {
    let report = unreachable(member_id, at_ms);
    MemberReport {
        writer_site_fence: Some(SiteFenceState {
            enabled: true,
            draining: true,
        }),
        writer_stop_confirmed: Some(true),
        standby_ready: Some(true),
        ..report
    }
}

/// Scratch directory removed on drop, clearing read-only attributes first so
/// Windows can delete the files. The root is derived only from the
/// compile-time manifest directory — never from an environment variable,
/// argument or the system temp dir — under the workspace `target/`, which
/// Git ignores; the name is a fixed per-test label plus a process-unique
/// suffix.
pub(super) struct TempDir(PathBuf);

impl TempDir {
    pub(super) fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/zrotext-failover-store-tests");
        let path = root.join(format!("{label}-{}-{unique}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create scratch store directory");
        Self(path)
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    // The corruption corpus leaves read-only journal files behind on the
    // only platform where `remove_dir_all` refuses them (Windows), and
    // clearing the attribute is the documented std path there; clippy's
    // Unix-oriented lint would otherwise suggest a non-portable fix.
    #[allow(clippy::permissions_set_readonly_false)]
    fn drop(&mut self) {
        let journals = self.0.join("observations");
        if let Ok(entries) = fs::read_dir(&journals) {
            for entry in entries.flatten() {
                if let Ok(mut permissions) = entry.metadata().map(|meta| meta.permissions()) {
                    permissions.set_readonly(false);
                    let _ = fs::set_permissions(entry.path(), permissions);
                }
            }
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn open(directory: &Path) -> Result<ConsensusStore, StoreError> {
    ConsensusStore::open(directory, members(), DEFAULT_OBSERVATION_FRESHNESS_MS)
}

pub(super) fn observations_dir(directory: &Path) -> PathBuf {
    directory.join("observations")
}

pub(super) fn journal_path(directory: &Path, member: &str) -> PathBuf {
    observations_dir(directory).join(format!("{member}.journal"))
}

pub(super) fn checkpoint_path(directory: &Path, member: &str) -> PathBuf {
    observations_dir(directory).join(format!("{member}.checkpoint"))
}

pub(super) fn membership_path(directory: &Path) -> PathBuf {
    directory.join("membership")
}

/// Append raw bytes to a member journal on disk (store must be dropped).
pub(super) fn append_journal_bytes(directory: &Path, member: &str, bytes: &[u8]) {
    let path = journal_path(directory, member);
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open journal");
    file.write_all(bytes).expect("append journal bytes");
}

fn encoded(record: &JournalRecord) -> String {
    record.encode().unwrap()
}

// ---------------------------------------------------------------------------
// Load-time integrity: corruption and truncation fail closed on open.
// ---------------------------------------------------------------------------

#[test]
fn fresh_directory_initializes_membership_and_empty_journals() {
    let temp = TempDir::new("fresh-init");
    let store = open(temp.path()).unwrap();
    assert_eq!(store.members(), MEMBERS.as_slice());
    assert_eq!(store.directory(), temp.path());
    let membership = fs::read_to_string(membership_path(temp.path())).unwrap();
    assert_eq!(membership, "v1 members=workload-a,workload-b,witness\n");
    for member in MEMBERS {
        assert!(
            journal_path(temp.path(), member).is_file(),
            "{member} journal exists and is empty"
        );
    }
    for member in MEMBERS {
        assert_eq!(store.next_sequence(member), Some(1));
    }
    assert_eq!(store.next_sequence("rogue"), None);
}

#[test]
fn empty_store_rounds_lose_quorum() {
    let temp = TempDir::new("empty-rounds");
    let store = open(temp.path()).unwrap();
    let mut controller = FailoverController::new(test_config());
    assert_eq!(
        controller.observe(store.round(1_000), 1_000),
        Decision::QuorumLost,
        "an empty store is never a quorum"
    );
}

#[test]
fn empty_journal_file_loads_as_a_member_without_records() {
    let temp = TempDir::new("empty-journal");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    // An existing store whose member never reported has a zero-byte journal.
    assert_eq!(
        fs::read(journal_path(temp.path(), "witness")).unwrap(),
        Vec::<u8>::new()
    );
    let store = open(temp.path()).unwrap();
    assert_eq!(store.round(1_000), Round::default());
    assert_eq!(store.next_sequence("witness"), Some(1));
}

#[test]
fn membership_file_corruption_fails_closed_on_open() {
    let corrupt_memberships = [
        "garbage\n",
        "v2 members=workload-a,workload-b,witness\n",
        "v1 members=workload-a,workload-b,witness\nv1 members=workload-a,workload-b,witness\n",
        "v1 members=workload-a,workload-b,witness",
        "v1 members=workload-a,workload-a,workload-b\n",
        "v1 members=workload-a,workload-b\n",
        "v1 members=\n",
        "v1 members=workload-a,workload-b,witness,extra\n",
        "v1members=workload-a,workload-b,witness\n",
        "v1 members=workload-a,workload-b witness\n",
    ];
    for membership in corrupt_memberships {
        let temp = TempDir::new("membership-corrupt");
        {
            let store = open(temp.path()).unwrap();
            drop(store);
        }
        fs::write(membership_path(temp.path()), membership).unwrap();
        let error = open(temp.path()).unwrap_err();
        assert!(
            matches!(error, StoreError::MembershipCorrupt(_)),
            "membership {membership:?} must fail closed, got {error:?}"
        );
    }
}

#[test]
fn membership_change_mid_flight_fails_closed_on_open() {
    let temp = TempDir::new("membership-change");
    {
        let mut store = open(temp.path()).unwrap();
        // Only a member kept by both memberships reports, so no journal of
        // the old quorum is foreign to the new one: the durable membership
        // record itself must refuse the change.
        store.record(&unreachable("workload-a", 1_000)).unwrap();
        drop(store);
    }
    let error = ConsensusStore::open(
        temp.path(),
        changed_members(),
        DEFAULT_OBSERVATION_FRESHNESS_MS,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::MembershipMismatch { ref on_disk, ref configured }
                if on_disk == &members() && configured == &changed_members()
        ),
        "a reconfigured quorum must not mix evidence across memberships, got {error:?}"
    );
}

#[test]
fn membership_comparison_is_order_insensitive() {
    let temp = TempDir::new("membership-order");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    let reordered = ["witness", "workload-b", "workload-a"]
        .iter()
        .map(|member| (*member).to_owned())
        .collect::<Vec<_>>();
    let store =
        ConsensusStore::open(temp.path(), reordered, DEFAULT_OBSERVATION_FRESHNESS_MS).unwrap();
    assert_eq!(store.next_sequence("workload-a"), Some(1));
}

#[test]
fn journal_for_an_unknown_member_fails_closed_on_open() {
    let temp = TempDir::new("foreign-journal");
    fs::create_dir_all(observations_dir(temp.path())).unwrap();
    fs::write(journal_path(temp.path(), "rogue"), b"anything\n").unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::ForeignJournal(ref name) if name.contains("rogue")),
        "a journal outside the membership must fail closed, got {error:?}"
    );
}

#[test]
fn directory_inside_observations_fails_closed_on_open() {
    let temp = TempDir::new("foreign-entry");
    fs::create_dir_all(observations_dir(temp.path()).join("workload-a.journal")).unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::ForeignJournal(_)),
        "a non-file observations entry must fail closed, got {error:?}"
    );
}

#[test]
fn membership_missing_with_journals_present_fails_closed() {
    let temp = TempDir::new("membership-missing");
    {
        let mut store = open(temp.path()).unwrap();
        store.record(&unreachable("witness", 1_000)).unwrap();
        drop(store);
    }
    fs::remove_file(membership_path(temp.path())).unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::MembershipMissing),
        "journals without a membership record must fail closed, got {error:?}"
    );
}

#[test]
fn torn_tail_record_fails_closed_on_reload() {
    let temp = TempDir::new("torn-tail");
    {
        let mut store = open(temp.path()).unwrap();
        store.record(&unreachable("workload-a", 1_000)).unwrap();
        store.record(&unreachable("workload-a", 2_000)).unwrap();
        drop(store);
    }
    // Crash mid-append: the last line loses its terminating newline.
    let full = fs::read(journal_path(temp.path(), "workload-a")).unwrap();
    assert_eq!(full.last(), Some(&b'\n'));
    fs::write(
        journal_path(temp.path(), "workload-a"),
        &full[..full.len() - 5],
    )
    .unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::TruncatedTail { ref member } if member == "workload-a"),
        "a torn trailing record must fail closed, got {error:?}"
    );
}

#[test]
fn corrupt_line_mid_journal_fails_closed_on_reload() {
    let temp = TempDir::new("corrupt-line");
    {
        let mut store = open(temp.path()).unwrap();
        store.record(&unreachable("workload-a", 1_000)).unwrap();
        store.record(&unreachable("workload-a", 2_000)).unwrap();
        store.record(&unreachable("workload-a", 3_000)).unwrap();
        drop(store);
    }
    let lines: Vec<String> = fs::read_to_string(journal_path(temp.path(), "workload-a"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let mut corrupted = lines.clone();
    corrupted[1] = "not a journal record at all".to_owned();
    fs::write(
        journal_path(temp.path(), "workload-a"),
        format!("{}\n", corrupted.join("\n")),
    )
    .unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::CorruptRecord { ref member, line } if member == "workload-a" && line == 2),
        "a corrupt middle line must fail closed with its position, got {error:?}"
    );
}

#[test]
fn journal_sequence_gap_fails_closed_on_reload() {
    let temp = TempDir::new("sequence-gap");
    {
        let mut store = open(temp.path()).unwrap();
        for at_ms in [1_000_u64, 2_000, 3_000] {
            store.record(&unreachable("workload-a", at_ms)).unwrap();
        }
        drop(store);
    }
    let lines: Vec<String> = fs::read_to_string(journal_path(temp.path(), "workload-a"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    // A deleted middle record leaves a sequence hole.
    let gapped = [lines[0].clone(), lines[2].clone()].join("\n");
    fs::write(
        journal_path(temp.path(), "workload-a"),
        format!("{gapped}\n"),
    )
    .unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::SequenceBroken { ref member, expected: 2, found: 3 } if member == "workload-a"),
        "a sequence gap must fail closed, got {error:?}"
    );
}

#[test]
fn journal_head_truncation_fails_closed_on_reload() {
    let temp = TempDir::new("head-truncation");
    {
        let mut store = open(temp.path()).unwrap();
        for at_ms in [1_000_u64, 2_000] {
            store.record(&unreachable("workload-a", at_ms)).unwrap();
        }
        drop(store);
    }
    let lines: Vec<String> = fs::read_to_string(journal_path(temp.path(), "workload-a"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    fs::write(
        journal_path(temp.path(), "workload-a"),
        format!("{}\n", lines[1]),
    )
    .unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(
            error,
            // Since compaction, the precise diagnosis is a journal
            // continuing above one without a checkpoint; a deleted head is
            // still fail-closed.
            StoreError::CheckpointMissing { ref member, journal_first: 2 }
                if member == "workload-a"
        ),
        "a head-truncated journal must fail closed, got {error:?}"
    );
}

#[test]
fn record_claiming_another_member_fails_closed_on_reload() {
    let temp = TempDir::new("identity-spoof");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    let spoofed = JournalRecord {
        sequence: 1,
        report: unreachable("witness", 1_000),
    }
    .encode()
    .unwrap();
    append_journal_bytes(temp.path(), "workload-a", format!("{spoofed}\n").as_bytes());
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::IdentitySpoof { ref journal_member, ref record_member }
                if journal_member == "workload-a" && record_member == "witness"
        ),
        "a record claiming another identity must fail closed, got {error:?}"
    );
}

#[test]
fn record_for_an_unknown_member_is_refused() {
    let temp = TempDir::new("unknown-member");
    let mut store = open(temp.path()).unwrap();
    let error = store.record(&unreachable("rogue", 1_000)).unwrap_err();
    assert!(
        matches!(error, StoreError::UnknownMember(ref member) if member == "rogue"),
        "reports outside the membership must be refused, got {error:?}"
    );
    assert!(!journal_path(temp.path(), "rogue").exists());
}

#[test]
fn concurrent_stores_on_one_directory_are_detected_on_reload() {
    let temp = TempDir::new("concurrent-writers");
    let mut first = open(temp.path()).unwrap();
    let mut second = open(temp.path()).unwrap();
    first.record(&unreachable("workload-a", 1_000)).unwrap();
    second.record(&unreachable("workload-a", 1_100)).unwrap();
    drop(first);
    drop(second);
    // Both instances believed they owned sequence one; the interleaved file
    // cannot be a contiguous journal anymore.
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::SequenceBroken { .. }),
        "interleaved concurrent appends must be detected as a broken sequence, got {error:?}"
    );
}

#[test]
fn unwritable_journal_file_fails_closed_on_open() {
    let temp = TempDir::new("unwritable-journal");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    let mut permissions = fs::metadata(journal_path(temp.path(), "workload-a"))
        .unwrap()
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(journal_path(temp.path(), "workload-a"), permissions).unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::Io(_)),
        "a journal that cannot be appended to must fail closed, got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Append-time failure, exhaustion, and the sticky fail-closed state.
// ---------------------------------------------------------------------------

#[test]
fn sequence_exhaustion_fails_closed_and_poisons_the_store() {
    let temp = TempDir::new("sequence-exhausted");
    let mut store = open(temp.path()).unwrap();
    store
        .journals
        .get_mut("workload-a")
        .expect("member journal")
        .next_sequence = u64::MAX;
    let error = store.record(&unreachable("workload-a", 1_000)).unwrap_err();
    assert!(
        matches!(error, StoreError::SequenceExhausted),
        "the last sequence must refuse to wrap, got {error:?}"
    );
    assert!(store.failed());
    assert!(matches!(
        store.failure(),
        Some(StoreError::SequenceExhausted)
    ));
}

#[test]
fn poisoned_store_returns_empty_rounds_and_refuses_records() {
    let temp = TempDir::new("poisoned-store");
    let mut store = open(temp.path()).unwrap();
    store.record(&reachable("workload-a", 5, 1_000)).unwrap();
    // Poison the store without OS-specific write-failure injection: the
    // exhausted sequence marks it failed.
    store
        .journals
        .get_mut("workload-a")
        .expect("member journal")
        .next_sequence = u64::MAX;
    store.record(&unreachable("workload-a", 2_000)).unwrap_err();
    assert!(store.failed());
    assert_eq!(
        store.round(1_000),
        Round::default(),
        "a failed store must not serve even the records it still holds"
    );
    let error = store
        .record(&reachable("workload-b", 5, 3_000))
        .unwrap_err();
    assert!(
        matches!(error, StoreError::Failed),
        "a failed store must refuse further records, got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Round semantics: freshness boundaries, clock skew, duplicates, restarts.
// ---------------------------------------------------------------------------

#[test]
fn freshness_boundaries_match_the_decision_model() {
    let temp = TempDir::new("freshness-boundaries");
    let now = 100_000_u64;
    let window = DEFAULT_OBSERVATION_FRESHNESS_MS;
    let mut store = open(temp.path()).unwrap();
    store
        .record(&reachable("workload-a", 5, now - window))
        .unwrap();
    store
        .record(&reachable("workload-b", 5, now - window - 1))
        .unwrap();
    store.record(&reachable("witness", 5, now + 1)).unwrap();
    let round = store.round(now);
    assert_eq!(
        round.reports,
        vec![reachable("workload-a", 5, now - window)],
        "the boundary age is fresh, one millisecond older and any future date are not"
    );
    // The decision model reaches the same verdict on the same reports.
    let mut controller = FailoverController::new(test_config());
    assert_eq!(
        controller.observe(round, now),
        Decision::QuorumLost,
        "one fresh member is below the majority"
    );
}

#[test]
fn future_dated_reports_never_become_evidence() {
    let temp = TempDir::new("future-dated");
    let mut store = open(temp.path()).unwrap();
    for member in MEMBERS {
        store.record(&unreachable(member, 60_000)).unwrap();
    }
    let mut controller = FailoverController::new(test_config());
    assert_eq!(
        controller.observe(store.round(1_000), 1_000),
        Decision::QuorumLost,
        "clock-skewed future observations are not evidence; never even suspecting"
    );
}

#[test]
fn out_of_order_timestamps_arrive_in_append_order_and_keep_the_veto() {
    let temp = TempDir::new("out-of-order");
    let mut store = open(temp.path()).unwrap();
    store.record(&reachable("workload-a", 5, 5_000)).unwrap();
    store.record(&unreachable("workload-a", 4_000)).unwrap();
    for member in &MEMBERS[1..] {
        store.record(&unreachable(member, 5_000)).unwrap();
    }
    let round = store.round(5_000);
    assert_eq!(
        round.reports.len(),
        4,
        "all four fresh records are served; the store never rewrites evidence"
    );
    assert_eq!(round.reports[0], reachable("workload-a", 5, 5_000));
    assert_eq!(round.reports[1], unreachable("workload-a", 4_000));
    let mut controller = FailoverController::new(test_config());
    assert_eq!(
        controller.observe(round, 5_000),
        Decision::Hold(crate::decision::HoldReason::ConflictingEvidence {
            reachable: 1,
            unreachable: 2
        }),
        "the member's folded vote keeps the reachable veto"
    );
}

#[test]
fn duplicate_reports_from_one_member_remain_one_vote_end_to_end() {
    let temp = TempDir::new("duplicate-reports");
    let mut store = open(temp.path()).unwrap();
    for member in &MEMBERS[..2] {
        // Duplicated failure submissions must not act as extra domains.
        store.record(&unreachable(member, 5_000)).unwrap();
        store.record(&unreachable(member, 5_000)).unwrap();
    }
    let mut controller = FailoverController::new(test_config());
    assert_eq!(
        controller.observe(store.round(5_000), 5_000),
        Decision::Hold(crate::decision::HoldReason::WriterFailureSuspected {
            consecutive_failures: 1
        }),
        "two distinct members with duplicates are still exactly two votes"
    );
    // A duplicated member whose reports conflict keeps the reachable veto.
    store.record(&unreachable("witness", 5_000)).unwrap();
    store.record(&reachable("witness", 7, 5_000)).unwrap();
    let mut controller = FailoverController::new(test_config());
    assert_eq!(
        controller.observe(store.round(5_000), 5_000),
        Decision::Hold(crate::decision::HoldReason::ConflictingEvidence {
            reachable: 1,
            unreachable: 2
        }),
        "the witness's reachable duplicate vetoes the failure consensus"
    );
}

#[test]
fn stale_pre_restart_observations_are_not_resurrected() {
    let temp = TempDir::new("stale-after-restart");
    let window = DEFAULT_OBSERVATION_FRESHNESS_MS;
    {
        let mut store = open(temp.path()).unwrap();
        store.record(&unreachable("workload-a", 1_000)).unwrap();
        drop(store);
    }
    let reloaded = open(temp.path()).unwrap();
    assert_eq!(reloaded.round(1_000 + window).reports.len(), 1);
    assert_eq!(
        reloaded.round(1_000 + window + 1).reports,
        Vec::new(),
        "one millisecond past the window the pre-restart observation is gone"
    );
}

#[test]
fn store_history_survives_restart() {
    let temp = TempDir::new("restart-history");
    let expected_round;
    {
        let mut store = open(temp.path()).unwrap();
        for member in MEMBERS {
            store.record(&reachable(member, 5, 1_000)).unwrap();
        }
        expected_round = store.round(2_000);
        assert_eq!(store.next_sequence("workload-a"), Some(2));
    }
    let mut reloaded = open(temp.path()).unwrap();
    assert_eq!(reloaded.round(2_000), expected_round);
    assert_eq!(reloaded.next_sequence("workload-a"), Some(2));
    reloaded.record(&reachable("workload-a", 6, 3_000)).unwrap();
    assert_eq!(reloaded.next_sequence("workload-a"), Some(3));
    let lines = fs::read_to_string(journal_path(temp.path(), "workload-a"))
        .unwrap()
        .lines()
        .count();
    assert_eq!(lines, 2, "the restart appended rather than rewrote");
}

// ---------------------------------------------------------------------------
// End to end: the store drives the existing executor unchanged.
// ---------------------------------------------------------------------------

#[test]
fn store_backed_source_drives_a_full_failover_unchanged() {
    let temp = TempDir::new("end-to-end");
    let mut store = open(temp.path()).unwrap();
    // The whole timeline is recorded up front. Records dated after a tick
    // are future-dated at that tick and not yet evidence, and the source
    // serves each record at most once, so every tick's round is exactly the
    // records dated at that tick: at tick 14_000 the 12_000 and 13_000
    // records are still inside the freshness window but were already served
    // (and counted) at their own ticks, so they are not counted again.
    for member in MEMBERS {
        store.record(&reachable(member, 5, 1_000)).unwrap();
    }
    for at_ms in [12_000_u64, 13_000, 14_000] {
        for member in MEMBERS {
            store.record(&unreachable(member, at_ms)).unwrap();
        }
    }
    for member in MEMBERS {
        store.record(&evidence(member, 25_000)).unwrap();
    }
    for member in MEMBERS {
        store.record(&reachable(member, 6, 36_000)).unwrap();
    }
    let mut executor = FailoverExecutor::new(
        test_config(),
        StoreObservationSource::new(store),
        MemoryAuthority::new(5),
        confirming_fencing(),
    );

    // Steady: all three members observe the writer healthy at epoch 5.
    let report = executor.tick(1_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(crate::decision::HoldReason::WriterHealthy))
    );

    // Three failed checks fence the old writer; the pre-window healthy
    // observations have aged out of every later round.
    let report = executor.tick(12_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(
            crate::decision::HoldReason::WriterFailureSuspected {
                consecutive_failures: 1
            }
        ))
    );
    let report = executor.tick(13_000);
    assert_eq!(
        report.decision,
        Some(Decision::Hold(
            crate::decision::HoldReason::WriterFailureSuspected {
                consecutive_failures: 2
            }
        ))
    );
    let report = executor.tick(14_000);
    assert_eq!(
        report.decision,
        Some(Decision::FenceOldWriter {
            site_id: "site-a".to_owned()
        })
    );

    // Fence, stop and standby readiness evidence promotes under epoch 6.
    let report = executor.tick(25_000);
    assert_eq!(
        report.decision,
        Some(Decision::PromoteStandby {
            site_id: "site-b".to_owned(),
            new_epoch: 6
        })
    );
    assert!(matches!(
        report.application,
        crate::executor::Application::Applied { .. }
    ));

    // Dispatch stays paused after the unplanned promotion.
    let report = executor.tick(36_000);
    assert_eq!(report.decision, Some(Decision::KeepDispatchPaused));

    let (config, source, authority) = executor.into_parts();
    // A true restart: the store is re-opened from disk, so the final round's
    // evidence must come from the durable journals.
    let store = source.into_store();
    drop(store);
    let mut reopened = open(temp.path()).unwrap();
    for member in MEMBERS {
        reopened.record(&evidence(member, 47_000)).unwrap();
    }
    let mut executor = FailoverExecutor::new(
        config,
        StoreObservationSource::new(reopened),
        authority,
        confirming_fencing(),
    );
    let report = executor.tick(47_000);
    assert_eq!(report.decision, Some(Decision::KeepDispatchPaused));
    assert_eq!(report.application, crate::executor::Application::None);

    let (_, _, mut authority) = executor.into_parts();
    let snapshot = authority.load_state("site-a", "site-b").unwrap();
    assert_eq!(
        snapshot.epoch, 6,
        "the restart never bumped the epoch again"
    );
    assert!(!snapshot.dispatch_enabled, "dispatch stays paused");
    assert!(
        snapshot.writer_site.is_some_and(|site| site.is_fenced()),
        "the old writer stays fenced"
    );
    assert_eq!(authority.promote_calls(), vec![6], "exactly one promotion");
}

#[test]
fn corrupted_store_source_holds_fail_closed() {
    let temp = TempDir::new("corrupt-source");
    let mut store = open(temp.path()).unwrap();
    for member in MEMBERS {
        store.record(&unreachable(member, 1_000)).unwrap();
    }
    // Poison the store: from here it can only serve empty rounds.
    store
        .journals
        .get_mut("workload-a")
        .expect("member journal")
        .next_sequence = u64::MAX;
    store.record(&unreachable("workload-a", 2_000)).unwrap_err();
    let mut executor = FailoverExecutor::new(
        test_config(),
        StoreObservationSource::new(store),
        MemoryAuthority::new(5),
        confirming_fencing(),
    );
    for at_ms in [1_000_u64, 2_000, 3_000, 4_000] {
        let report = executor.tick(at_ms);
        assert_eq!(
            report.decision,
            Some(Decision::QuorumLost),
            "a failed store must never let a round reach evidence"
        );
    }
    let (_, _, authority) = executor.into_parts();
    assert_eq!(authority.fence_calls(), 0, "no fence without a quorum");
    assert!(
        authority.promote_calls().is_empty(),
        "no promotion without a quorum"
    );
}

// ---------------------------------------------------------------------------
// Issue #512: hysteresis counts distinct member reports, not executor ticks.
// ---------------------------------------------------------------------------

fn former_healthy(member_id: &str, at_ms: u64) -> MemberReport {
    MemberReport {
        former_writer_healthy: Some(true),
        ..reachable(member_id, 6, at_ms)
    }
}

/// A controller restored straight into a reconciled promotion, so the next
/// rounds exercise only the rejoin hysteresis (5 successful checks). The
/// stable-duration gate is zero so the check count alone decides.
fn reconciled_promotion() -> FailoverController {
    FailoverController::restore(
        test_config().with_recovery_stable_ms(0),
        6,
        crate::decision::RestorablePhase::Promoted {
            new_epoch: 6,
            reconciled: true,
            rejoin_emitted: false,
        },
    )
}

#[test]
fn source_serves_each_record_in_at_most_one_round() {
    let temp = TempDir::new("serve-once");
    let mut store = open(temp.path()).unwrap();
    for member in MEMBERS {
        store.record(&unreachable(member, 10_000)).unwrap();
    }
    let mut source = StoreObservationSource::new(store);
    assert_eq!(source.collect(10_000).reports.len(), 3);
    for now in [10_001_u64, 15_000, 20_000] {
        assert_eq!(
            source.collect(now),
            Round::default(),
            "a report already served must not be served again inside its window"
        );
    }
    // A new report is served once, alongside nothing already served.
    source
        .store_mut()
        .record(&unreachable("witness", 20_000))
        .unwrap();
    assert_eq!(
        source.collect(20_000).reports,
        vec![unreachable("witness", 20_000)]
    );
    assert_eq!(source.collect(20_000), Round::default());
    // The pure windowed view is unchanged by serving.
    assert_eq!(source.store().round(20_000).reports.len(), 4);
}

#[test]
fn issue_512_one_stored_report_per_member_must_not_satisfy_three_failed_checks() {
    // Reproducer from the PR 439 pre-review (hub note 1013).
    let temp = TempDir::new("issue-512");
    let mut store = open(temp.path()).unwrap();
    for member in MEMBERS {
        store.record(&unreachable(member, 10_000)).unwrap();
    }
    let mut executor = FailoverExecutor::new(
        test_config(),
        StoreObservationSource::new(store),
        MemoryAuthority::new(5),
        confirming_fencing(),
    );
    let mut decisions = Vec::new();
    for now in [10_000_u64, 15_000, 20_000] {
        decisions.push(executor.tick(now).decision);
    }
    let (_, _, authority) = executor.into_parts();
    assert_eq!(
        authority.fence_calls(),
        0,
        "one report per member fenced the writer: {decisions:?}"
    );
    assert!(
        !decisions
            .iter()
            .any(|decision| matches!(decision, Some(Decision::FenceOldWriter { .. }))),
        "one report per member must never decide a fence: {decisions:?}"
    );
}

#[test]
fn issue_512_three_distinct_successive_reports_per_member_still_fence() {
    let temp = TempDir::new("issue-512-distinct");
    let mut store = open(temp.path()).unwrap();
    // One report per member per check, recorded up front: each is
    // future-dated (not yet evidence) until its own check.
    let checks = [10_000_u64, 15_000, 20_000];
    for at_ms in checks {
        for member in MEMBERS {
            store.record(&unreachable(member, at_ms)).unwrap();
        }
    }
    let mut executor = FailoverExecutor::new(
        test_config(),
        StoreObservationSource::new(store),
        MemoryAuthority::new(5),
        confirming_fencing(),
    );
    let decisions: Vec<_> = checks
        .into_iter()
        .map(|now| executor.tick(now).decision)
        .collect();
    assert_eq!(
        decisions,
        vec![
            Some(Decision::Hold(
                crate::decision::HoldReason::WriterFailureSuspected {
                    consecutive_failures: 1
                }
            )),
            Some(Decision::Hold(
                crate::decision::HoldReason::WriterFailureSuspected {
                    consecutive_failures: 2
                }
            )),
            Some(Decision::FenceOldWriter {
                site_id: "site-a".to_owned()
            }),
        ]
    );
    let (_, _, authority) = executor.into_parts();
    assert_eq!(authority.fence_calls(), 1, "three distinct checks fence");
}

#[test]
fn issue_512_one_stored_report_per_member_must_not_satisfy_five_recovery_checks() {
    let temp = TempDir::new("issue-512-rejoin");
    let mut store = open(temp.path()).unwrap();
    for member in MEMBERS {
        store.record(&former_healthy(member, 10_000)).unwrap();
    }
    let mut source = StoreObservationSource::new(store);
    let mut controller = reconciled_promotion();
    // Six checks inside the one report's freshness window.
    let decisions: Vec<Decision> = [10_000_u64, 12_000, 14_000, 16_000, 18_000, 20_000]
        .into_iter()
        .map(|now| controller.observe(source.collect(now), now))
        .collect();
    assert!(
        !decisions
            .iter()
            .any(|decision| matches!(decision, Decision::RejoinFormerWriterAsReplica { .. })),
        "one healthy report per member must never satisfy the rejoin hysteresis: {decisions:?}"
    );
}

#[test]
fn issue_512_five_distinct_successive_recovery_reports_still_rejoin() {
    let temp = TempDir::new("issue-512-rejoin-distinct");
    let store = open(temp.path()).unwrap();
    let mut source = StoreObservationSource::new(store);
    let mut controller = reconciled_promotion();
    let mut decisions = Vec::new();
    for now in [10_000_u64, 12_000, 14_000, 16_000, 18_000] {
        for member in MEMBERS {
            source
                .store_mut()
                .record(&former_healthy(member, now))
                .unwrap();
        }
        decisions.push(controller.observe(source.collect(now), now));
    }
    assert_eq!(
        decisions.last(),
        Some(&Decision::RejoinFormerWriterAsReplica {
            site_id: "site-a".to_owned()
        }),
        "five distinct successful checks rejoin: {decisions:?}"
    );
    assert!(
        !decisions[..4]
            .iter()
            .any(|decision| matches!(decision, Decision::RejoinFormerWriterAsReplica { .. })),
        "no rejoin before the fifth distinct check: {decisions:?}"
    );
}

// ---------------------------------------------------------------------------
// Journal record codec.
// ---------------------------------------------------------------------------

#[test]
fn record_codec_round_trips_every_field_shape() {
    let minimal = JournalRecord {
        sequence: 1,
        report: unreachable("workload-a", 1_000),
    };
    let line = encoded(&minimal);
    assert_eq!(
        line, "v1 member=workload-a seq=1 at=1000 writer=unreachable",
        "a report without optional evidence encodes compactly"
    );
    assert_eq!(JournalRecord::decode(&line).unwrap(), minimal);

    let full = JournalRecord {
        sequence: 42,
        report: MemberReport {
            member_id: "witness".to_owned(),
            observed_at_ms: 1_712_345_678_901,
            writer: WriterObservation::Reachable { epoch: 9 },
            writer_site_fence: Some(SiteFenceState {
                enabled: false,
                draining: true,
            }),
            writer_stop_confirmed: Some(true),
            standby_ready: Some(false),
            former_writer_healthy: Some(true),
        },
    };
    let line = encoded(&full);
    assert_eq!(
        line,
        "v1 member=witness seq=42 at=1712345678901 writer=reachable:9 \
         fence=false,true stop=true standby=false former=true"
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert_eq!(JournalRecord::decode(&line).unwrap(), full);
}

#[test]
fn record_codec_represents_every_evidence_combination() {
    // A live-writer round suppresses the stop confirmation while carrying
    // fence, standby and former-writer evidence: the omitted middle field
    // is a `-`, so the record reloads instead of failing the store closed
    // on the steady-state healthy shape.
    let suppressed_stop = JournalRecord {
        sequence: 7,
        report: MemberReport {
            member_id: "workload-a".to_owned(),
            observed_at_ms: 1_000,
            writer: WriterObservation::Reachable { epoch: 5 },
            writer_site_fence: Some(SiteFenceState {
                enabled: true,
                draining: false,
            }),
            writer_stop_confirmed: None,
            standby_ready: Some(true),
            former_writer_healthy: Some(true),
        },
    };
    let line = encoded(&suppressed_stop);
    assert_eq!(
        line,
        "v1 member=workload-a seq=7 at=1000 writer=reachable:5 \
         fence=true,false stop=- standby=true former=true"
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert_eq!(JournalRecord::decode(&line).unwrap(), suppressed_stop);

    let former_only = JournalRecord {
        sequence: 1,
        report: MemberReport {
            member_id: "witness".to_owned(),
            observed_at_ms: 2_000,
            writer: WriterObservation::Reachable { epoch: 6 },
            writer_site_fence: None,
            writer_stop_confirmed: None,
            standby_ready: None,
            former_writer_healthy: Some(true),
        },
    };
    let line = encoded(&former_only);
    assert_eq!(JournalRecord::decode(&line).unwrap(), former_only);
}

#[test]
fn pre_sentinel_journal_lines_still_decode() {
    // Journals written before the `-` sentinel simply end at the last
    // carried field; they must keep loading.
    let legacy = JournalRecord::decode(
        "v1 member=workload-a seq=3 at=1000 writer=unreachable \
         fence=true,true stop=true standby=true",
    )
    .unwrap();
    assert_eq!(legacy.sequence, 3);
    assert!(legacy.report.writer_site_fence.is_some());
    assert_eq!(legacy.report.writer_stop_confirmed, Some(true));
    assert_eq!(legacy.report.standby_ready, Some(true));
    assert_eq!(legacy.report.former_writer_healthy, None);
    // A `-` is only a whole-field marker, never part of a value.
    assert!(
        JournalRecord::decode("v1 member=workload-a seq=1 at=1000 writer=unreachable fence=-,true")
            .is_err()
    );
    assert!(
        JournalRecord::decode("v1 member=workload-a seq=1 at=1000 writer=unreachable stop=-maybe")
            .is_err()
    );
}

#[test]
fn record_codec_rejects_malformed_lines() {
    let malformed = [
        "",
        "v2 member=workload-a seq=1 at=1000 writer=unreachable",
        "member=workload-a seq=1 at=1000 writer=unreachable",
        "v1 seq=1 at=1000 writer=unreachable member=workload-a",
        "v1 member=workload-a at=1000 writer=unreachable seq=1",
        "v1 member=workload-a seq=1 writer=unreachable at=1000",
        "v1 member=workload-a seq=one at=1000 writer=unreachable",
        "v1 member=workload-a seq=1 at=-5 writer=unreachable",
        "v1 member=workload-a seq=1 at=1000 writer=reachable:",
        "v1 member=workload-a seq=1 at=1000 writer=bogus",
        "v1 member=workload-a seq=1 at=1000 writer=reachable:5.5",
        "v1 member=workload-a seq=1 at=1000 writer=unreachable stop=true",
        // Optional fields may only appear in fence, stop, standby, former
        // order, without gaps or duplicates.
        "v1 member=workload-a seq=1 at=1000 writer=unreachable stop=true fence=true,true",
        "v1 member=workload-a seq=1 at=1000 writer=unreachable fence=true,true fence=true,true",
        "v1 member=workload-a seq=1 at=1000 writer=unreachable standby=true",
        "v1 member=workload-a seq=1 at=1000 writer=unreachable fence=true,true former=true",
        "v1 member=workload-a seq=1 at=1000 writer=unreachable fence=maybe,true",
        "v1 member=workload-a seq=1 at=1000 writer=unreachable fence=true",
        "v1 member=workload-a seq=1 at=1000 writer=unreachable fence=true,true stop=1",
        "v1 member=workload-a seq=1 at=1000 writer=unreachable former=true extra=x",
        "v1 member= seq=1 at=1000 writer=unreachable",
        "v1 member=work load-a seq=1 at=1000 writer=unreachable",
    ];
    for line in malformed {
        assert!(
            matches!(
                JournalRecord::decode(line),
                Err(StoreError::MalformedRecord)
            ),
            "line {line:?} must be rejected as malformed"
        );
    }
}

#[test]
fn unsafe_member_identifiers_are_refused() {
    let unsafe_members = [
        "",
        "work load-a",
        "workload/a",
        "workload\\a",
        "workload:a",
        "workload*a",
        "workload?a",
        "workload\"a",
        "workload<a",
        "workload>a",
        "workload|a",
        ".",
        "..",
        "...",
        "con",
        "CON",
        "com1",
        "LPT9.journal",
        "workload-a.",
        "workload-a\u{0}b",
        "workload-a\nb",
    ];
    for member in unsafe_members {
        let members = vec![
            "workload-a".to_owned(),
            "workload-b".to_owned(),
            member.to_owned(),
        ];
        let temp = TempDir::new("unsafe-member");
        let error = ConsensusStore::open(
            temp.path(),
            members.clone(),
            DEFAULT_OBSERVATION_FRESHNESS_MS,
        )
        .unwrap_err();
        assert!(
            matches!(error, StoreError::InvalidMembers(_)),
            "member {member:?} must be refused as a journal file name, got {error:?}"
        );
        let record = JournalRecord {
            sequence: 1,
            report: unreachable(member, 1_000),
        };
        assert!(
            matches!(record.encode(), Err(StoreError::InvalidMembers(_))),
            "member {member:?} must not be encodable into a journal record"
        );
    }
    // The full membership shape is still validated.
    let temp = TempDir::new("unsafe-membership-shape");
    for members in [vec![], members()[..2].to_vec(), {
        let mut duplicated = members();
        duplicated[2] = duplicated[0].clone();
        duplicated
    }] {
        let error = ConsensusStore::open(temp.path(), members, DEFAULT_OBSERVATION_FRESHNESS_MS)
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidMembers(_)));
    }
}

#[test]
fn membership_codec_round_trips_and_rejects_ambiguity() {
    let encoded = encode_membership(&members()).unwrap();
    assert_eq!(encoded, "v1 members=workload-a,workload-b,witness\n");
    assert_eq!(decode_membership(&encoded).unwrap(), members());
    assert!(matches!(
        encode_membership(&members()[..2]),
        Err(StoreError::InvalidMembers(_))
    ));
    assert!(matches!(
        decode_membership("v1 members=\n"),
        Err(StoreError::MembershipCorrupt(_))
    ));
}
