// SPDX-License-Identifier: AGPL-3.0-only
//! Adversarial corpus for checkpoint-based journal compaction (issue #507),
//! written before the compaction exists. Each test names one compaction
//! behavior: stale prefixes physically shrink on open, the freshness window
//! and a bounded floor bound what may ever be dropped, the fence/promote
//! decision replay survives compaction, the legacy no-checkpoint layout
//! still loads, every corruption shape around the new checkpoint artifact
//! fails closed, and the crash window between the journal rewrite and the
//! checkpoint write leaves one loadable state or the other — never a hybrid
//! the checkpoint and journal disagree about.

use super::tests::{
    MEMBERS, TempDir, checkpoint_path, evidence, journal_path, open, reachable, test_config,
    unreachable,
};
use super::*;
use crate::anchor::MemoryEpochAnchor;
use crate::decision::{DEFAULT_OBSERVATION_FRESHNESS_MS, Decision};
use crate::executor::FailoverExecutor;
use crate::executor_tests::MemoryAuthority;
use crate::fence::{ExternalFencing, MemoryFenceAuthority};

/// The corpus's default external adapters (see `executor_tests`).
fn confirming_fencing() -> ExternalFencing {
    ExternalFencing::new(MemoryFenceAuthority::default(), MemoryEpochAnchor::new())
}
use std::path::Path;

/// The retention floor the corpus pins: the number of records every member
/// journal keeps after compaction even when all of them are stale.
const RETAINED_FLOOR: usize = 8;

fn journal_line_count(directory: &Path, member: &str) -> usize {
    fs::read_to_string(journal_path(directory, member))
        .unwrap()
        .lines()
        .count()
}

/// Handcraft a journal whose first record takes `first_sequence`, so tests
/// can build the intermediate states a compaction (or a crash inside one)
/// leaves behind.
fn write_journal(directory: &Path, member: &str, first_sequence: u64, at_ms: &[u64]) {
    let mut body = String::new();
    for (index, at) in at_ms.iter().enumerate() {
        let record = JournalRecord {
            sequence: first_sequence + index as u64,
            report: unreachable(member, *at),
        };
        body.push_str(&record.encode().unwrap());
        body.push('\n');
    }
    fs::write(journal_path(directory, member), body).unwrap();
}

/// A syntactically valid checkpoint line with the given fields (digests are
/// dummy unless the test needs real ones).
fn checkpoint_line(member: &str, seq: u64, at_ms: u64) -> String {
    format!(
        "v1 member={member} seq={seq} at={at_ms} prefix=0123456789abcdef \
             head=fedcba9876543210\n"
    )
}

/// Arm the compaction crash seam: after `succeeds` successful atomic
/// writes on this thread, the next one fails before touching either file —
/// a simulated crash at that point of the journal-first, checkpoint-second
/// order. The seam disarms itself when it fires.
fn crash_after(succeeds: u32) {
    FAIL_ATOMIC_WRITE_AFTER.with(|slot| slot.set(Some(succeeds)));
}

/// Disarm the compaction crash seam regardless of whether it fired.
fn disarm_crash_seam() {
    FAIL_ATOMIC_WRITE_AFTER.with(|slot| slot.set(None));
}

/// Craft the on-disk state just before a SECOND compaction: a journal
/// continuing at sequence 25 from a genuine first checkpoint (sequence 24,
/// real head digest) whose stale prefix has again grown past the floor.
/// The reload takes the head-digest-checked path, so the checkpoint must
/// genuinely anchor the journal's first record.
fn second_compaction_fixture(directory: &Path) {
    let at_ms = [
        1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 500_000,
    ];
    write_journal(directory, "workload-a", 25, &at_ms);
    let first_line = JournalRecord {
        sequence: 25,
        report: unreachable("workload-a", 1_000),
    }
    .encode()
    .unwrap();
    fs::write(
        checkpoint_path(directory, "workload-a"),
        format!(
            "v1 member=workload-a seq=24 at=1000 prefix=0123456789abcdef \
             head={:016x}\n",
            fnv1a64(FNV_OFFSET_BASIS, first_line.as_bytes())
        ),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Retention: what compaction may and may not drop.
// ---------------------------------------------------------------------------

#[test]
fn stale_records_beyond_the_floor_are_compacted_on_open() {
    let temp = TempDir::new("compact-stale");
    {
        let mut store = open(temp.path()).unwrap();
        // Thirty stale observations, then one fresh anchor: everything but
        // the anchor has aged out of the freshness window measured from it.
        for _ in 0..30 {
            store.record(&unreachable("workload-a", 1_000)).unwrap();
        }
        store.record(&reachable("workload-a", 7, 500_000)).unwrap();
        drop(store);
    }
    let store = open(temp.path()).unwrap();
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR,
        "a journal with more stale records than the floor must physically \
         shrink on open"
    );
    assert_eq!(
        store.next_sequence("workload-a"),
        Some(32),
        "sequence numbering continues past the compacted prefix"
    );
    let journal = fs::read_to_string(journal_path(temp.path(), "workload-a")).unwrap();
    assert!(
        journal.lines().next().unwrap().contains("seq=24"),
        "the retained journal starts just after the compacted prefix: {journal:?}"
    );
    assert!(
        checkpoint_path(temp.path(), "workload-a").is_file(),
        "compaction must leave a checkpoint artifact"
    );
    // The retained stale tail is not evidence; only the anchor is fresh.
    assert_eq!(store.round(500_000).reports.len(), 1);
}

#[test]
fn records_inside_the_freshness_window_are_never_compacted() {
    let temp = TempDir::new("fresh-kept");
    {
        let mut store = open(temp.path()).unwrap();
        for _ in 0..15 {
            store.record(&unreachable("workload-a", 1_000)).unwrap();
        }
        for _ in 0..5 {
            store.record(&unreachable("workload-a", 100_000)).unwrap();
        }
        drop(store);
    }
    let store = open(temp.path()).unwrap();
    // Twelve of the fifteen stale records leave; the five fresh ones and the
    // floor tail stay.
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR
    );
    let round = store.round(100_000);
    assert_eq!(round.reports.len(), 5, "all five fresh records survive");
    assert!(
        round
            .reports
            .iter()
            .all(|report| report.observed_at_ms == 100_000),
        "no fresh record may be compacted away"
    );
    // The window boundary itself still holds, exactly as the decision model
    // draws it.
    assert_eq!(store.round(110_000).reports.len(), 5);
    assert_eq!(
        store.round(110_001).reports,
        Vec::new(),
        "one millisecond past the window the observations age out"
    );
}

#[test]
fn the_stale_prefix_is_compacted_only_down_to_the_floor_tail() {
    let temp = TempDir::new("floor-tail");
    {
        let mut store = open(temp.path()).unwrap();
        for _ in 0..11 {
            store.record(&unreachable("workload-a", 1_000)).unwrap();
        }
        store.record(&reachable("workload-a", 7, 500_000)).unwrap();
        drop(store);
    }
    let store = open(temp.path()).unwrap();
    // Only four of the eleven stale records may leave: eight must remain.
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR
    );
    assert_eq!(store.next_sequence("workload-a"), Some(13));
    let journal = fs::read_to_string(journal_path(temp.path(), "workload-a")).unwrap();
    assert!(journal.lines().next().unwrap().contains("seq=5"));
}

#[test]
fn journals_at_or_below_the_floor_are_neither_compacted_nor_checkpointed() {
    let temp = TempDir::new("no-compaction");
    {
        let mut store = open(temp.path()).unwrap();
        for _ in 0..7 {
            store.record(&unreachable("workload-a", 1_000)).unwrap();
        }
        store.record(&reachable("workload-a", 7, 500_000)).unwrap();
        drop(store);
    }
    let store = open(temp.path()).unwrap();
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR,
        "a journal the floor already covers is left alone"
    );
    assert!(
        !checkpoint_path(temp.path(), "workload-a").exists(),
        "no records compacted means no checkpoint artifact"
    );
    assert_eq!(store.next_sequence("workload-a"), Some(9));
}

// ---------------------------------------------------------------------------
// Decision behavior after compaction.
// ---------------------------------------------------------------------------

#[test]
fn a_full_fence_and_promote_replay_survives_compaction() {
    let temp = TempDir::new("replay-after-compaction");
    {
        let mut store = open(temp.path()).unwrap();
        for member in MEMBERS {
            // Ten stale observations pad the journal past the floor so the
            // reopen actually compacts; as unreachable duplicates they fold
            // into one vote whenever they are still fresh.
            for step in 1..=10_u64 {
                store.record(&unreachable(member, 500 * step)).unwrap();
            }
            store.record(&reachable(member, 5, 1_000)).unwrap();
            for at_ms in [12_000_u64, 13_000, 14_000] {
                store.record(&unreachable(member, at_ms)).unwrap();
            }
            store.record(&evidence(member, 25_000)).unwrap();
            store.record(&reachable(member, 6, 36_000)).unwrap();
        }
        drop(store);
    }
    // The reopen compacts: sixteen records per member shrink to the floor.
    let store = open(temp.path()).unwrap();
    for member in MEMBERS {
        assert_eq!(
            journal_line_count(temp.path(), member),
            RETAINED_FLOOR,
            "{member} journal compacted on reopen"
        );
    }
    let mut executor = FailoverExecutor::new(
        test_config(),
        StoreObservationSource::new(store),
        MemoryAuthority::new(5),
        confirming_fencing(),
    );
    let decisions: Vec<Option<Decision>> = [12_000_u64, 13_000, 14_000, 25_000, 36_000]
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
            Some(Decision::PromoteStandby {
                site_id: "site-b".to_owned(),
                new_epoch: 6
            }),
            Some(Decision::KeepDispatchPaused),
        ],
        "the full fence-and-promote replay works from the checkpointed store"
    );
    let (_, _, authority) = executor.into_parts();
    assert_eq!(authority.fence_calls(), 1, "exactly one fence");
    assert_eq!(authority.promote_calls(), vec![6], "exactly one promotion");
}

#[test]
fn a_reopened_compacted_store_appends_and_reopens_contiguously() {
    let temp = TempDir::new("append-after-compaction");
    {
        let mut store = open(temp.path()).unwrap();
        for _ in 0..30 {
            store.record(&unreachable("workload-a", 1_000)).unwrap();
        }
        store.record(&reachable("workload-a", 7, 500_000)).unwrap();
        drop(store);
    }
    let mut store = open(temp.path()).unwrap();
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR
    );
    assert_eq!(store.next_sequence("workload-a"), Some(32));
    store.record(&unreachable("workload-a", 500_001)).unwrap();
    assert_eq!(store.next_sequence("workload-a"), Some(33));
    let journal = fs::read_to_string(journal_path(temp.path(), "workload-a")).unwrap();
    let lines: Vec<&str> = journal.lines().collect();
    // The append itself crosses the bound again (seven stale tail records
    // aged out by the new anchor), so the continuous compaction keeps the
    // journal at the floor instead of growing to floor + 1.
    assert_eq!(lines.len(), RETAINED_FLOOR);
    assert!(
        lines.last().unwrap().contains("seq=32"),
        "the append continues the compacted sequence space: {journal:?}"
    );
    drop(store);
    let reopened = open(temp.path()).unwrap();
    assert_eq!(
        reopened.next_sequence("workload-a"),
        Some(33),
        "a compacted journal reloads after further appends"
    );
    assert_eq!(reopened.round(500_001).reports.len(), 2);
}

#[test]
fn the_serve_once_high_water_continues_across_the_compacted_offset() {
    let temp = TempDir::new("high-water-offset");
    {
        let mut store = open(temp.path()).unwrap();
        for _ in 0..30 {
            store.record(&unreachable("workload-a", 1_000)).unwrap();
        }
        store.record(&reachable("workload-a", 7, 500_000)).unwrap();
        drop(store);
    }
    let mut source = StoreObservationSource::new(open(temp.path()).unwrap());
    // Sequence numbers no longer start at one after compaction; the source's
    // high-water cursor must follow the absolute sequence, not the index.
    assert_eq!(source.collect(500_000).reports.len(), 1);
    assert_eq!(
        source.collect(500_000),
        crate::decision::Round::default(),
        "the served record is not served twice"
    );
    source
        .store_mut()
        .record(&unreachable("workload-a", 500_002))
        .unwrap();
    assert_eq!(
        source.collect(500_002).reports,
        vec![unreachable("workload-a", 500_002)],
        "a record appended past the compacted prefix is served exactly once"
    );
    assert_eq!(source.collect(500_002), crate::decision::Round::default());
}

// ---------------------------------------------------------------------------
// Legacy layout and the crash window between journal rewrite and checkpoint.
// ---------------------------------------------------------------------------

#[test]
fn a_legacy_journal_without_a_checkpoint_still_loads() {
    let temp = TempDir::new("legacy-loads");
    {
        let mut store = open(temp.path()).unwrap();
        for member in MEMBERS {
            store.record(&reachable(member, 5, 1_000)).unwrap();
        }
        drop(store);
    }
    assert!(
        !checkpoint_path(temp.path(), "workload-a").exists(),
        "nothing compacted, so no checkpoint exists"
    );
    let store = open(temp.path()).unwrap();
    assert_eq!(store.round(2_000).reports.len(), 3);
    assert_eq!(store.next_sequence("workload-a"), Some(2));
}

#[test]
fn a_journal_hand_continued_without_a_checkpoint_fails_closed() {
    // A journal that starts above one without a checkpoint describes a head
    // that was lost with no evidence it was ever compacted.
    let temp = TempDir::new("missing-checkpoint");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    write_journal(temp.path(), "workload-a", 3, &[1_000, 2_000, 3_000]);
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::CheckpointMissing { ref member, journal_first: 3 }
                if member == "workload-a"
        ),
        "a continued journal without a checkpoint must fail closed, got {error:?}"
    );
}

#[test]
fn a_crash_between_the_journal_rewrite_and_the_checkpoint_still_loads() {
    // The compaction writes the rewritten journal first and the checkpoint
    // second; a crash between the two leaves the new journal with the old
    // (here: no) checkpoint. The journal on disk is the ground truth, so the
    // store must open.
    let temp = TempDir::new("crash-window");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    write_journal(
        temp.path(),
        "workload-a",
        9,
        &[60_000, 61_000, 62_000, 63_000],
    );
    fs::write(
        checkpoint_path(temp.path(), "workload-a"),
        checkpoint_line("workload-a", 4, 5_000),
    )
    .unwrap();
    let store = open(temp.path()).unwrap();
    assert_eq!(store.next_sequence("workload-a"), Some(13));
    // All four retained records are still inside the freshness window at
    // their newest timestamp: the crash window loses no evidence.
    assert_eq!(store.round(63_000).reports.len(), 4);
}

#[test]
fn leftover_compaction_temp_files_do_not_fail_the_store() {
    let temp = TempDir::new("temp-leftovers");
    {
        let mut store = open(temp.path()).unwrap();
        store.record(&unreachable("workload-a", 1_000)).unwrap();
        drop(store);
    }
    fs::write(
        journal_path(temp.path(), "witness").with_extension("journal.tmp"),
        b"torn",
    )
    .unwrap();
    fs::write(
        checkpoint_path(temp.path(), "witness").with_extension("checkpoint.tmp"),
        b"torn",
    )
    .unwrap();
    let store = open(temp.path()).unwrap();
    assert_eq!(store.next_sequence("witness"), Some(1));
}

// ---------------------------------------------------------------------------
// Checkpoint corruption fails closed. (The variant-specific error matching
// lands with the checkpoint implementation; today these pin only that every
// shape refuses to open.)
// ---------------------------------------------------------------------------

#[test]
fn a_torn_checkpoint_fails_closed_on_open() {
    let temp = TempDir::new("torn-checkpoint");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    write_journal(temp.path(), "workload-a", 3, &[1_000, 2_000]);
    fs::write(
        checkpoint_path(temp.path(), "workload-a"),
        "v1 member=workload-a seq=2 at=1000 prefix=0123456789abcde",
    )
    .unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::CheckpointCorrupt { ref member, .. } if member == "workload-a"
        ),
        "a torn checkpoint must fail closed, got {error:?}"
    );
}

#[test]
fn a_checkpoint_disagreeing_with_the_journal_fails_closed_on_open() {
    // The checkpoint claims records the journal still holds: the only way
    // that happens is a journal restored over a newer checkpoint.
    let temp = TempDir::new("checkpoint-ahead");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    write_journal(temp.path(), "workload-a", 5, &[1_000, 2_000, 3_000, 4_000]);
    fs::write(
        checkpoint_path(temp.path(), "workload-a"),
        checkpoint_line("workload-a", 10, 4_000),
    )
    .unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::CheckpointDisagrees {
                ref member,
                checkpoint_last_compacted: 10,
                journal_first: 5,
            } if member == "workload-a"
        ),
        "a checkpoint ahead of the journal must fail closed, got {error:?}"
    );
}

#[test]
fn a_checkpoint_over_an_empty_journal_fails_closed_on_open() {
    // Compaction never empties a journal — the floor keeps a retained tail —
    // so a checkpoint beside an empty journal can only be tampering.
    let temp = TempDir::new("checkpoint-empty");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    fs::write(
        checkpoint_path(temp.path(), "workload-a"),
        checkpoint_line("workload-a", 10, 4_000),
    )
    .unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::CheckpointDisagrees {
                journal_first: 0,
                ..
            }
        ),
        "a checkpoint over an empty journal must fail closed, got {error:?}"
    );
}

#[test]
fn a_checkpoint_spoofing_another_member_fails_closed_on_open() {
    let temp = TempDir::new("spoofed-checkpoint");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    write_journal(temp.path(), "workload-a", 3, &[1_000, 2_000]);
    fs::write(
        checkpoint_path(temp.path(), "workload-a"),
        checkpoint_line("witness", 2, 1_000),
    )
    .unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::CheckpointIdentitySpoof {
                ref journal_member,
                ref checkpoint_member,
            } if journal_member == "workload-a" && checkpoint_member == "witness"
        ),
        "a checkpoint claiming another identity must fail closed, got {error:?}"
    );
}

#[test]
fn a_checkpoint_head_digest_mismatch_fails_closed_on_open() {
    let temp = TempDir::new("head-mismatch");
    {
        let mut store = open(temp.path()).unwrap();
        for _ in 0..30 {
            store.record(&unreachable("workload-a", 1_000)).unwrap();
        }
        store.record(&reachable("workload-a", 7, 500_000)).unwrap();
        drop(store);
    }
    // The reopen compacts and writes the checkpoint; tamper with the head
    // digest so it no longer anchors the retained journal's first record.
    open(temp.path()).unwrap();
    let checkpoint = fs::read_to_string(checkpoint_path(temp.path(), "workload-a")).unwrap();
    let marker = "head=";
    let start = checkpoint.find(marker).expect("head digest field") + marker.len();
    let digits = &checkpoint[start..];
    assert_eq!(digits.len(), 17, "16 hex digits and the final newline");
    let mut tampered = checkpoint[..start].to_owned();
    // Flip the first hex digit, keeping the checkpoint well formed so the
    // mismatch — not a parse failure — is what fails the load.
    tampered.push(if digits.starts_with('0') { '1' } else { '0' });
    tampered.push_str(&digits[1..]);
    assert_ne!(tampered, checkpoint, "the digest must change");
    fs::write(checkpoint_path(temp.path(), "workload-a"), tampered).unwrap();
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::CheckpointHeadMismatch { ref member } if member == "workload-a"
        ),
        "a head digest mismatch must fail closed, got {error:?}"
    );
}

#[test]
fn malformed_checkpoint_fields_fail_closed_on_open() {
    let malformed = [
        "",
        "\n",
        "v2 member=workload-a seq=2 at=1000 prefix=0123456789abcdef \
          head=fedcba9876543210\n",
        "v1 member=workload-a seq=0 at=1000 prefix=0123456789abcdef \
          head=fedcba9876543210\n",
        "v1 member=workload-a seq=2 at=1000 prefix=xyz \
          head=fedcba9876543210\n",
        "v1 member=workload-a seq=2 at=1000 head=fedcba9876543210\n",
        "v1 member=workload-a seq=2 at=1000 prefix=0123456789abcdef \
          head=fedcba9876543210 extra=1\n",
        "v1 member= seq=2 at=1000 prefix=0123456789abcdef \
          head=fedcba9876543210\n",
        "v1 member=workload-a seq=2 at=1000 prefix=0123456789abcdef \
          head=fedcba9876543210\nv1 member=workload-a seq=2 at=1000 \
          prefix=0123456789abcdef head=fedcba9876543210\n",
    ];
    for checkpoint in malformed {
        let temp = TempDir::new("malformed-checkpoint");
        {
            let store = open(temp.path()).unwrap();
            drop(store);
        }
        write_journal(temp.path(), "workload-a", 3, &[1_000, 2_000]);
        fs::write(checkpoint_path(temp.path(), "workload-a"), checkpoint).unwrap();
        let error = open(temp.path()).unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::CheckpointCorrupt { ref member, .. } if member == "workload-a"
            ),
            "checkpoint {checkpoint:?} must fail closed, got {error:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Pure retention and checkpoint codec rules.
// ---------------------------------------------------------------------------

#[test]
fn the_compactable_prefix_stops_at_the_first_record_inside_the_window() {
    let window = 10_000_u64;
    // All records fresh relative to the journal's newest observation (the
    // whole journal spans less than one window): nothing may leave.
    let all_fresh: Vec<_> = (0..20_u64)
        .map(|step| unreachable("workload-a", 10_000 + step * 500))
        .collect();
    assert_eq!(compactable_prefix_len(&all_fresh, window), 0);
    // Stale prefix, fresh tail: only the stale leading run leaves, and the
    // window boundary itself (exactly `freshness` old) is retained. The
    // journal is longer than the floor so the floor does not clamp it.
    let mixed: Vec<_> = [1_000_u64, 5_000]
        .into_iter()
        .chain([
            90_000, 100_000, 100_000, 100_000, 100_000, 100_000, 100_000, 100_000, 100_000,
        ])
        .map(|at| unreachable("workload-a", at))
        .collect();
    // Records at 1_000 and 5_000 are older than 100_000 - 10_000 = 90_000;
    // the record at exactly 90_000 is on the boundary and stays.
    assert_eq!(compactable_prefix_len(&mixed, window), 2);
    // An all-stale-but-one journal compacts only down to the floor.
    let stale_then_anchor: Vec<_> = std::iter::repeat_n(unreachable("workload-a", 1_000), 30)
        .chain([reachable("workload-a", 7, 500_000)])
        .collect();
    assert_eq!(
        compactable_prefix_len(&stale_then_anchor, window),
        31 - RETAINED_FLOOR
    );
    // A journal the floor already covers never compacts, even all-stale.
    let tiny: Vec<_> = std::iter::repeat_n(unreachable("workload-a", 1_000), RETAINED_FLOOR - 1)
        .chain([unreachable("workload-a", 500_000)])
        .collect();
    assert_eq!(compactable_prefix_len(&tiny, window), 0);
    assert_eq!(compactable_prefix_len(&[], window), 0);
}

#[test]
fn the_checkpoint_codec_round_trips_and_pins_the_format() {
    let checkpoint = Checkpoint {
        member_id: "workload-a".to_owned(),
        last_compacted_sequence: 23,
        newest_compacted_at_ms: 1_000,
        prefix_digest: 0x0123_4567_89ab_cdef,
        head_digest: 0xfedc_ba98_7654_3210,
    };
    let encoded = checkpoint.encode().unwrap();
    assert_eq!(
        encoded,
        "v1 member=workload-a seq=23 at=1000 prefix=0123456789abcdef \
         head=fedcba9876543210\n"
    );
    assert_eq!(
        decode_checkpoint("workload-a", &encoded).unwrap(),
        checkpoint
    );
    // A checkpoint naming another member decodes but is caught by the
    // journal reconciliation, not the codec.
    assert_eq!(
        decode_checkpoint("witness", &encoded).unwrap().member_id,
        "workload-a"
    );
    assert!(matches!(
        Checkpoint {
            last_compacted_sequence: 0,
            ..checkpoint.clone()
        }
        .encode(),
        Err(StoreError::InvalidMembers(_))
    ));
}

// ---------------------------------------------------------------------------
// The continuous bound: compaction on append, not only on open.
// ---------------------------------------------------------------------------

#[test]
fn appends_far_past_the_bound_keep_memory_and_disk_bounded_without_reopening() {
    let temp = TempDir::new("continuous-bound");
    let mut store = open(temp.path()).unwrap();
    // Two hundred records, each spaced beyond the freshness window from the
    // last: from the ninth append on, every append ages the previous
    // records out of the window, so the rotation must run on the append
    // itself — without a single reopen in between.
    let spacing = DEFAULT_OBSERVATION_FRESHNESS_MS + 1;
    for step in 0..200_u64 {
        store
            .record(&unreachable("workload-a", step * spacing))
            .unwrap();
        let journal = store.journals.get("workload-a").unwrap();
        assert!(
            journal.records.len() <= RETAINED_FLOOR,
            "append {step} must keep the in-memory tail bounded at the floor, \
             held {} records",
            journal.records.len()
        );
    }
    // The on-disk journal is bounded by the same rule and checkpointed, all
    // without reopening the store.
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR,
        "the journal on disk must stay bounded between opens"
    );
    assert!(
        checkpoint_path(temp.path(), "workload-a").is_file(),
        "the append-time rotations leave a checkpoint artifact"
    );
    assert_eq!(store.next_sequence("workload-a"), Some(201));
    drop(store);
    // The bounded store still loads and serves rounds correctly: the
    // retained sequence space is contiguous, the newest record is fresh
    // evidence at its own timestamp, and appends continue.
    let mut reopened = open(temp.path()).unwrap();
    assert_eq!(reopened.next_sequence("workload-a"), Some(201));
    assert_eq!(reopened.round(199 * spacing).reports.len(), 1);
    reopened
        .record(&unreachable("workload-a", 199 * spacing + 1))
        .unwrap();
    assert_eq!(reopened.next_sequence("workload-a"), Some(202));
}

#[test]
fn a_failed_append_time_compaction_poisons_the_store_like_corruption() {
    let temp = TempDir::new("sticky-append-compaction");
    let mut store = open(temp.path()).unwrap();
    let spacing = DEFAULT_OBSERVATION_FRESHNESS_MS + 1;
    for step in 0..8_u64 {
        store
            .record(&unreachable("workload-a", step * spacing))
            .unwrap();
    }
    // The ninth append is the first to cross the bound; its rotation's
    // journal rewrite crashes. The append itself was durable before the
    // rotation, but the failure is sticky: today's corruption semantics,
    // never silently growing past the bound.
    crash_after(0);
    let error = store
        .record(&unreachable("workload-a", 8 * spacing))
        .unwrap_err();
    assert!(
        matches!(error, StoreError::Io(ref inner)
            if inner.to_string().contains("injected compaction crash")),
        "got {error:?}"
    );
    assert!(
        store.failed(),
        "a failed append-time rotation poisons the store"
    );
    assert_eq!(
        store.round(8 * spacing),
        crate::decision::Round::default(),
        "a poisoned store serves no evidence"
    );
    assert!(matches!(
        store.record(&unreachable("workload-a", 0)),
        Err(StoreError::Failed)
    ));
    disarm_crash_seam();
    // A reopen loads everything the durable journal holds — the ninth
    // record included — and completes the rotation the crash interrupted.
    drop(store);
    let reopened = open(temp.path()).unwrap();
    assert_eq!(reopened.next_sequence("workload-a"), Some(10));
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR
    );
    assert_eq!(reopened.round(8 * spacing).reports.len(), 1);
}

// ---------------------------------------------------------------------------
// The crash-order contract: journal rewrite durable BEFORE the checkpoint.
// ---------------------------------------------------------------------------

#[test]
fn a_crash_at_the_checkpoint_write_leaves_a_loadable_new_journal() {
    // The second atomic write of a compaction is the checkpoint. Crashing
    // exactly there leaves the rewritten journal beside the PREVIOUS
    // checkpoint — the crash window the journal-first order exists for. The
    // reload must accept the new journal against the old checkpoint (the
    // journal on disk is the ground truth): old journal or new journal,
    // never a hybrid.
    let temp = TempDir::new("crash-at-checkpoint");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    second_compaction_fixture(temp.path());
    let checkpoint_before = fs::read_to_string(checkpoint_path(temp.path(), "workload-a")).unwrap();
    crash_after(1); // the journal rewrite succeeds, the checkpoint write crashes
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::Io(ref inner)
            if inner.to_string().contains("injected compaction crash")),
        "got {error:?}"
    );
    // The crash-window state: the NEW journal (rotated to eight records
    // from sequence 28) beside the UNCHANGED old checkpoint.
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR
    );
    let journal = fs::read_to_string(journal_path(temp.path(), "workload-a")).unwrap();
    assert!(
        journal.lines().next().unwrap().contains("seq=27"),
        "the rewritten journal is the durable one: {journal:?}"
    );
    assert_eq!(
        fs::read_to_string(checkpoint_path(temp.path(), "workload-a")).unwrap(),
        checkpoint_before,
        "the crashed checkpoint write changed nothing on disk"
    );
    disarm_crash_seam();
    let mut store =
        open(temp.path()).expect("the new journal against the old checkpoint must load");
    assert_eq!(store.next_sequence("workload-a"), Some(35));
    // Not a hybrid: exactly the retained tail loads, with only the fresh
    // anchor as evidence.
    assert_eq!(store.round(500_000).reports.len(), 1);
    // And the store keeps working: the sequence space continues.
    store.record(&unreachable("workload-a", 500_002)).unwrap();
    assert_eq!(store.next_sequence("workload-a"), Some(36));
}

#[test]
fn a_crash_at_the_journal_rewrite_leaves_the_original_state_intact() {
    // The equivalent crash on the FIRST atomic write (the journal rewrite)
    // leaves the original journal and checkpoint exactly as they were; the
    // healthy open afterwards completes the rotation normally.
    let temp = TempDir::new("crash-at-journal");
    {
        let store = open(temp.path()).unwrap();
        drop(store);
    }
    second_compaction_fixture(temp.path());
    let journal_before = fs::read_to_string(journal_path(temp.path(), "workload-a")).unwrap();
    let checkpoint_before = fs::read_to_string(checkpoint_path(temp.path(), "workload-a")).unwrap();
    crash_after(0);
    let error = open(temp.path()).unwrap_err();
    assert!(
        matches!(error, StoreError::Io(ref inner)
            if inner.to_string().contains("injected compaction crash")),
        "got {error:?}"
    );
    assert_eq!(
        fs::read_to_string(journal_path(temp.path(), "workload-a")).unwrap(),
        journal_before,
        "a crash before the journal rewrite leaves the original journal"
    );
    assert_eq!(
        fs::read_to_string(checkpoint_path(temp.path(), "workload-a")).unwrap(),
        checkpoint_before,
        "a crash before the journal rewrite leaves the original checkpoint"
    );
    disarm_crash_seam();
    let store = open(temp.path()).unwrap();
    assert_eq!(store.next_sequence("workload-a"), Some(35));
    assert_eq!(
        journal_line_count(temp.path(), "workload-a"),
        RETAINED_FLOOR
    );
    assert_eq!(store.round(500_000).reports.len(), 1);
}
