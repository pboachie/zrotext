// SPDX-License-Identifier: AGPL-3.0-only
//! Durable consensus store for quorum member observations.
//!
//! The decision model in [`crate::decision`] and the executor in
//! [`crate::executor`] are deliberately I/O-free: they consume [`Round`]s of
//! [`crate::decision::MemberReport`]s through the
//! [`crate::executor::ObservationSource`] seam. This module is the durable
//! home those reports are recorded into and read back from, mirroring the
//! executor's write-ahead journal conventions on the local filesystem (no
//! database requirement, no network listener):
//!
//! * one `membership` record fixes the three configured member identities —
//!   exactly [`crate::policy::REQUIRED_MEMBERS`] distinct ids, each safe as a
//!   journal file name — and a store whose durable membership disagrees with
//!   the configuration fails closed on open instead of mixing evidence from
//!   two different quorums;
//! * one append-only journal file per member under `observations/`, where
//!   every record carries the member identity (a record claiming another
//!   identity is identity spoofing and fails the load), a store-assigned
//!   sequence number that must be contiguous from one (gaps, reorders,
//!   deletions and interleaved concurrent appends all fail the load), the
//!   member's observation timestamp and the full report evidence;
//! * the store fails closed on corruption: a torn trailing record, a
//!   malformed line, a broken sequence or a foreign journal file makes
//!   [`ConsensusStore::open`] return an error, and a store that failed while
//!   appending stays failed — its rounds are empty, so the controller can
//!   only lose quorum and hold;
//! * journals do not grow forever: once per open, each member journal is
//!   compacted by rewriting it without the leading records that have aged
//!   out of the decision model's freshness window (measured from the newest
//!   observation in that journal — the store takes no clock), always
//!   retaining a bounded floor of records and never compacting a record
//!   inside the window. A per-member checkpoint file records the member
//!   identity, the last-compacted sequence, the newest compacted timestamp
//!   and digest anchors over the compacted prefix and the retained head, so
//!   the dropped history stays tamper-evidenced and the retained journal
//!   stays bound to its checkpoint. The rewrite is journal-first,
//!   checkpoint-second, both atomic (temp file, fsync, rename): a crash in
//!   between leaves the rewritten journal with the previous checkpoint,
//!   which load accepts as the ground truth, while a checkpoint ahead of
//!   the journal, a torn or malformed checkpoint, a spoofed identity or a
//!   head-digest mismatch all fail the store closed exactly like in-journal
//!   corruption. A journal starting at sequence one with no checkpoint is
//!   the legacy layout and still loads;
//! * rounds are served through the decision model's freshness window
//!   (`observed_at <= now` and `now - observed_at <= freshness`), so
//!   future-dated (skewed) observations are never evidence and stale
//!   pre-restart observations are not resurrected after a restart. Duplicate
//!   or out-of-order submissions are preserved and left to the controller's
//!   per-member folding, which already fails closed on them;
//! * the executor's [`StoreObservationSource`] serves each record in at most
//!   one check round (a per-member high-water sequence), so the controller's
//!   failed-check and successful-check hysteresis counts distinct member
//!   reports, not executor ticks inside one report's freshness window.
//!
//! Not in this increment: a cross-member network transport that carries
//! member reports between machines (no listener exists; the member-side
//! reporting loop of [`crate::report`] records only what its injected probe
//! source observes, and no production probe source exists yet, so a
//! production store stays empty and every round fails closed), journal
//! rotation beyond the open-time compaction above (each open still re-reads
//! the retained journal in full), and any
//! external coordination between store instances — one writer per directory
//! is assumed, and concurrent writers are detected as corruption on the
//! next load.
use crate::decision::{MemberReport, Round, SiteFenceState, WriterObservation};
use crate::executor::ObservationSource;
use crate::policy::REQUIRED_MEMBERS;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A durable per-member observation journal file plus its in-memory tail.
struct MemberJournal {
    /// Handle opened for appending; one write per record, flushed and synced.
    file: File,
    /// Sequence of the first retained record: one after the last
    /// checkpointed sequence, or one for a full journal. Sequence numbers of
    /// `records` are this plus the record index.
    first_sequence: u64,
    /// Sequence number the next append will take (`u64::MAX` is exhausted).
    next_sequence: u64,
    /// Reports in append order.
    records: Vec<MemberReport>,
}

/// The durable consensus store: a membership record plus one append-only
/// observation journal per member under a configurable directory.
pub struct ConsensusStore {
    directory: PathBuf,
    members: Vec<String>,
    observation_freshness_ms: u64,
    journals: HashMap<String, MemberJournal>,
    /// Sticky failure: a store that failed mid-append serves empty rounds.
    failure: Option<StoreError>,
}

impl fmt::Debug for ConsensusStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsensusStore")
            .field("directory", &self.directory)
            .field("members", &self.members)
            .field("observation_freshness_ms", &self.observation_freshness_ms)
            .field(
                "journals",
                &self
                    .journals
                    .iter()
                    .map(|(member, journal)| (member, journal.next_sequence))
                    .collect::<HashMap<_, _>>(),
            )
            .field("failure", &self.failure)
            .finish()
    }
}

impl ConsensusStore {
    /// Open (and on first use initialize) the store under `directory`.
    ///
    /// Fails closed — an `Err` store must not serve evidence — when the
    /// configured membership is invalid, the durable membership disagrees
    /// with it, the membership record is corrupt or missing while journals
    /// exist, an observations entry belongs to no configured member, or any
    /// journal is corrupt: a torn trailing record, a malformed line, a record
    /// claiming another member's identity, or non-contiguous sequences.
    pub fn open(
        directory: impl Into<PathBuf>,
        members: Vec<String>,
        observation_freshness_ms: u64,
    ) -> Result<Self, StoreError> {
        validate_members(&members)?;
        let directory = directory.into();
        let membership_path = directory.join(MEMBERSHIP_FILE);
        let observations = directory.join(OBSERVATIONS_DIR);
        // The store's identity comes first: a durable membership that
        // disagrees with the configuration never serves this quorum's
        // evidence, whatever else is on disk.
        let durable_membership = match fs::read_to_string(&membership_path) {
            Ok(content) => Some(decode_membership(&content)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(StoreError::Io(error)),
        };
        if let Some(on_disk) = &durable_membership
            && !same_membership(on_disk, &members)
        {
            return Err(StoreError::MembershipMismatch {
                on_disk: on_disk.clone(),
                configured: members,
            });
        }
        // Foreign entries are named before deciding whether a missing
        // membership record means a fresh store or a deleted one.
        scan_observations(&observations, &members)?;
        if durable_membership.is_none() {
            if directory_has_entries(&observations)? {
                return Err(StoreError::MembershipMissing);
            }
            fs::create_dir_all(&observations).map_err(StoreError::Io)?;
            let encoded = encode_membership(&members)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&membership_path)
                .map_err(StoreError::Io)?;
            file.write_all(encoded.as_bytes()).map_err(StoreError::Io)?;
            file.sync_all().map_err(StoreError::Io)?;
        }
        let mut journals = HashMap::with_capacity(members.len());
        for member in &members {
            journals.insert(
                member.clone(),
                open_journal(&observations, member, observation_freshness_ms)?,
            );
        }
        Ok(Self {
            directory,
            members,
            observation_freshness_ms,
            journals,
            failure: None,
        })
    }

    /// Durably append one member's report to that member's journal. The
    /// report's member identity must belong to the durable membership; the
    /// record is written, flushed and synced before this returns. A failed
    /// append poisons the store: later calls fail and rounds stay empty.
    pub fn record(&mut self, report: &MemberReport) -> Result<(), StoreError> {
        if self.failure.is_some() {
            return Err(StoreError::Failed);
        }
        let journal = self
            .journals
            .get_mut(&report.member_id)
            .ok_or_else(|| StoreError::UnknownMember(report.member_id.clone()))?;
        let sequence = journal.next_sequence;
        let Some(next_sequence) = sequence.checked_add(1) else {
            self.failure = Some(StoreError::SequenceExhausted);
            return Err(StoreError::SequenceExhausted);
        };
        let mut line = JournalRecord {
            sequence,
            report: report.clone(),
        }
        .encode()?;
        line.push('\n');
        let durable = journal
            .file
            .write_all(line.as_bytes())
            .and_then(|()| journal.file.flush())
            .and_then(|()| journal.file.sync_all());
        if let Err(error) = durable {
            self.failure = Some(StoreError::Failed);
            return Err(StoreError::Io(error));
        }
        journal.next_sequence = next_sequence;
        journal.records.push(report.clone());
        Ok(())
    }

    /// Every fresh observation as of `now_ms`, members in membership order
    /// and records in append order. The controller's per-member folding
    /// handles duplicates; a failed store returns an empty round.
    pub fn round(&self, now_ms: u64) -> Round {
        if self.failure.is_some() {
            return Round::default();
        }
        let mut reports = Vec::new();
        for member in &self.members {
            let Some(journal) = self.journals.get(member) else {
                continue;
            };
            reports.extend(
                journal
                    .records
                    .iter()
                    .filter(|report| {
                        is_fresh(report.observed_at_ms, now_ms, self.observation_freshness_ms)
                    })
                    .cloned(),
            );
        }
        Round { reports }
    }

    /// The fresh observations as of `now_ms` that were appended after each
    /// member's entry in `served` (the last sequence already handed to the
    /// controller; absent means none), in the same order as [`Self::round`].
    /// `served` advances to the highest sequence returned per member, so a
    /// record is served at most once however many checks fall inside its
    /// freshness window. A record that is not fresh when a later record of
    /// the same member is served — a future-dated (clock-skewed) record
    /// overtaken by a fresh one — is skipped for good: it never becomes
    /// evidence. A failed store returns an empty round and advances nothing.
    pub fn unserved_round(&self, now_ms: u64, served: &mut HashMap<String, u64>) -> Round {
        if self.failure.is_some() {
            return Round::default();
        }
        let mut reports = Vec::new();
        for member in &self.members {
            let Some(journal) = self.journals.get(member) else {
                continue;
            };
            let cursor = served.get(member).copied().unwrap_or(0);
            let mut last_served = cursor;
            // A record's sequence is the journal's first sequence (one after
            // any checkpointed prefix) plus its index, so the records after
            // `cursor` start at the index of sequence `cursor + 1`. A cursor
            // below the first retained sequence — only possible when a fresh
            // in-memory cursor meets a compacted journal — restarts at the
            // first retained record, which compaction itself has already
            // made stale.
            let skip = match cursor.checked_add(1) {
                Some(next) if next > journal.first_sequence => {
                    usize::try_from(next - journal.first_sequence).unwrap_or(usize::MAX)
                }
                _ => 0,
            };
            for (index, report) in journal.records.iter().enumerate().skip(skip) {
                if is_fresh(report.observed_at_ms, now_ms, self.observation_freshness_ms) {
                    reports.push(report.clone());
                    last_served = journal
                        .first_sequence
                        .saturating_add(u64::try_from(index).unwrap_or(u64::MAX));
                }
            }
            if last_served > cursor {
                served.insert(member.clone(), last_served);
            }
        }
        Round { reports }
    }

    /// Whether the store failed earlier and now fails closed.
    pub fn failed(&self) -> bool {
        self.failure.is_some()
    }

    /// The sticky failure, if any.
    pub fn failure(&self) -> Option<&StoreError> {
        self.failure.as_ref()
    }

    /// The durable membership this store was opened with.
    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// The directory this store lives in.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The sequence number the member's next append would take (`None` for a
    /// member outside the membership).
    pub fn next_sequence(&self, member: &str) -> Option<u64> {
        self.journals
            .get(member)
            .map(|journal| journal.next_sequence)
    }
}

/// The [`ObservationSource`] adapter: reports recorded into a
/// [`ConsensusStore`] flow into the existing [`crate::executor::FailoverExecutor`]
/// without being synthesized or re-attributed, and each report is served in
/// at most one check round.
///
/// Each collect serves only the fresh records a member appended since the
/// last record of that member this source served (a per-member high-water
/// sequence, see [`ConsensusStore::unserved_round`]). The controller counts
/// one failed or successful check per round, so re-serving a record on every
/// tick of its freshness window would let one report per member satisfy the
/// "3 failed checks" fence hysteresis or the "5 successful checks" rejoin
/// hysteresis on its own (issue #512). A check at which no member appended a
/// new fresh report is an empty round — quorum lost — which restarts any
/// incomplete streak, exactly as the in-process source's empty rounds do.
///
/// The high-water marks live in memory: after a restart the first round
/// serves the still-fresh journal records once more. That cannot double-count
/// a streak, because the controller never persists an incomplete streak — a
/// restored controller starts suspecting from zero and a restored promotion
/// starts its healthy streak from zero.
pub struct StoreObservationSource {
    store: ConsensusStore,
    served: HashMap<String, u64>,
}

impl StoreObservationSource {
    /// Wrap a store as the executor's observation source. Nothing has been
    /// served yet, so the first round holds every fresh record.
    pub fn new(store: ConsensusStore) -> Self {
        Self {
            store,
            served: HashMap::new(),
        }
    }

    /// Read-only access to the backing store.
    pub fn store(&self) -> &ConsensusStore {
        &self.store
    }

    /// Access to the backing store, so a member-reporting shim (or tests)
    /// can record observations without rebuilding the executor.
    pub fn store_mut(&mut self) -> &mut ConsensusStore {
        &mut self.store
    }

    /// Unwrap the backing store, for example to re-open it across a
    /// simulated restart.
    pub fn into_store(self) -> ConsensusStore {
        self.store
    }
}

impl ObservationSource for StoreObservationSource {
    fn collect(&mut self, now_ms: u64) -> Round {
        self.store.unserved_round(now_ms, &mut self.served)
    }
}

/// One journal record: the store-assigned sequence plus the member's report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRecord {
    pub sequence: u64,
    pub report: MemberReport,
}

impl JournalRecord {
    /// Encode into the stable single-line journal format
    /// (`v1 member=… seq=… at=… writer=… [fence=…,…] [stop=…] [standby=…]
    /// [former=…]`, where a `-` in an optional field marks evidence the
    /// report does not carry — a round that observed the writer alive
    /// carries no stop confirmation, whatever else it observed). Member
    /// identifiers that cannot be safe journal file names cannot be
    /// encoded.
    pub fn encode(&self) -> Result<String, StoreError> {
        if !member_is_file_safe(&self.report.member_id) {
            return Err(StoreError::InvalidMembers(format!(
                "member {:?} is not a safe journal file name",
                self.report.member_id
            )));
        }
        let mut line = format!(
            "v1 member={} seq={} at={} writer=",
            self.report.member_id, self.sequence, self.report.observed_at_ms
        );
        match self.report.writer {
            WriterObservation::Reachable { epoch } => {
                line.push_str("reachable:");
                line.push_str(epoch.to_string().as_str());
            }
            WriterObservation::Unreachable => line.push_str("unreachable"),
        }
        // Optional evidence appears in a fixed order. Once any field is
        // carried, every field is emitted and `-` marks the kinds this
        // report does not carry, so every evidence combination the observer
        // can form encodes unambiguously and reloads; journals written
        // before the sentinel (trailing fields simply absent) still decode.
        let carries_evidence = self.report.writer_site_fence.is_some()
            || self.report.writer_stop_confirmed.is_some()
            || self.report.standby_ready.is_some()
            || self.report.former_writer_healthy.is_some();
        if carries_evidence {
            line.push_str(" fence=");
            match self.report.writer_site_fence {
                Some(fence) => {
                    line.push_str(if fence.enabled { "true" } else { "false" });
                    line.push(',');
                    line.push_str(if fence.draining { "true" } else { "false" });
                }
                None => line.push('-'),
            }
            line.push_str(" stop=");
            match self.report.writer_stop_confirmed {
                Some(confirmed) => line.push_str(if confirmed { "true" } else { "false" }),
                None => line.push('-'),
            }
            line.push_str(" standby=");
            match self.report.standby_ready {
                Some(ready) => line.push_str(if ready { "true" } else { "false" }),
                None => line.push('-'),
            }
            line.push_str(" former=");
            match self.report.former_writer_healthy {
                Some(healthy) => line.push_str(if healthy { "true" } else { "false" }),
                None => line.push('-'),
            }
        }
        Ok(line)
    }

    /// Parse a record produced by [`Self::encode`]. Anything else — wrong
    /// version, missing, extra, duplicated or out-of-order fields, malformed
    /// numbers or booleans, an unknown writer state — is an error; callers
    /// treat an unparsable record as corruption and fail closed.
    pub fn decode(line: &str) -> Result<Self, StoreError> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() != Some(&"v1") {
            return Err(StoreError::MalformedRecord);
        }
        let field = |prefix: &str, index: usize| -> Result<&str, StoreError> {
            let field = fields.get(index).ok_or(StoreError::MalformedRecord)?;
            field
                .strip_prefix(prefix)
                .ok_or(StoreError::MalformedRecord)
        };
        let member_id = field("member=", 1)?.to_owned();
        if !member_is_file_safe(&member_id) {
            return Err(StoreError::MalformedRecord);
        }
        let sequence = field("seq=", 2)?
            .parse::<u64>()
            .map_err(|_| StoreError::MalformedRecord)?;
        let observed_at_ms = field("at=", 3)?
            .parse::<u64>()
            .map_err(|_| StoreError::MalformedRecord)?;
        let writer_field = field("writer=", 4)?;
        let writer = if writer_field == "unreachable" {
            WriterObservation::Unreachable
        } else {
            let epoch = writer_field
                .strip_prefix("reachable:")
                .ok_or(StoreError::MalformedRecord)?
                .parse::<u64>()
                .map_err(|_| StoreError::MalformedRecord)?;
            WriterObservation::Reachable { epoch }
        };
        // Optional evidence fields appear in a fixed order without gaps or
        // duplicates; anything else at their position is malformed. A `-`
        // marks evidence the report does not carry (see [`Self::encode`]).
        let mut index = 5;
        let mut optional = |prefix: &str| -> Result<Option<&str>, StoreError> {
            match fields.get(index) {
                None => Ok(None),
                Some(field) => {
                    let value = field
                        .strip_prefix(prefix)
                        .ok_or(StoreError::MalformedRecord)?;
                    index += 1;
                    Ok(Some(value))
                }
            }
        };
        let writer_site_fence = match optional("fence=")? {
            None | Some("-") => None,
            Some(value) => {
                let (enabled, draining) =
                    value.split_once(',').ok_or(StoreError::MalformedRecord)?;
                Some(SiteFenceState {
                    enabled: parse_bool(enabled)?,
                    draining: parse_bool(draining)?,
                })
            }
        };
        let writer_stop_confirmed = match optional("stop=")? {
            None | Some("-") => None,
            Some(value) => Some(parse_bool(value)?),
        };
        let standby_ready = match optional("standby=")? {
            None | Some("-") => None,
            Some(value) => Some(parse_bool(value)?),
        };
        let former_writer_healthy = match optional("former=")? {
            None | Some("-") => None,
            Some(value) => Some(parse_bool(value)?),
        };
        if fields.get(index).is_some() {
            return Err(StoreError::MalformedRecord);
        }
        Ok(Self {
            sequence,
            report: MemberReport {
                member_id,
                observed_at_ms,
                writer,
                writer_site_fence,
                writer_stop_confirmed,
                standby_ready,
                former_writer_healthy,
            },
        })
    }
}

/// The name of the durable membership record inside the store directory.
const MEMBERSHIP_FILE: &str = "membership";
/// The subdirectory holding one append-only journal per member.
const OBSERVATIONS_DIR: &str = "observations";
/// Suffixes of the observations entries this store recognizes: each
/// member's journal and compaction checkpoint, plus the temp files their
/// atomic rewrites pass through — a crash can leave either temp behind, so
/// it must not fail the next open. Any other entry is foreign.
const KNOWN_ENTRY_SUFFIXES: [&str; 4] =
    [".journal", ".checkpoint", ".journal.tmp", ".checkpoint.tmp"];
/// Records every member journal retains after compaction even when all of
/// them are stale: a bounded tail that keeps recent hysteresis and forensics
/// evidence for an operator reopening the store. Eight comfortably holds a
/// complete fence-then-promote replay per member — one healthy observation,
/// three failed checks, one fencing-evidence round, one post-promotion
/// observation and one restart observation.
const JOURNAL_RETAINED_FLOOR: usize = 8;
/// FNV-1a 64-bit offset basis and prime. Std-only (no new dependency) and
/// stable forever, which a durable file format needs; see [`fnv1a64`].
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Digest `bytes` into `seed` with 64-bit FNV-1a. This is a non-cryptographic
/// checksum used for tamper *evidence* — detecting torn writes, restores and
/// accidental modification — in kind with the store's otherwise structural
/// integrity rules; it is not a defense against an attacker able to rewrite
/// both the journal and its checkpoint, exactly as no unkeyed on-disk
/// content in this store is.
fn fnv1a64(seed: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(seed, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}

/// The per-member compaction checkpoint: one line next to the journal it
/// describes, recording what a journal rewrite dropped so the compacted
/// history stays tamper-evidenced and the retained journal stays bound to
/// its continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Checkpoint {
    /// The owning member identity; a checkpoint claiming another identity
    /// is spoofing and fails the load.
    member_id: String,
    /// The last sequence physically removed from the journal: the retained
    /// journal continues from `last_compacted_sequence + 1`.
    last_compacted_sequence: u64,
    /// The observation timestamp of the newest compacted record, kept for
    /// operator forensics (out-of-order timestamps mean it is not
    /// necessarily the last compacted record's timestamp).
    newest_compacted_at_ms: u64,
    /// Running FNV-1a chain over the encoded lines of every compacted
    /// record, seeded from the previous checkpoint's chain (or the offset
    /// basis for a first compaction), so successive compactions extend one
    /// anchor over the whole dropped history. Load cannot recompute it —
    /// the bytes are gone by design — so it is evidence for a future
    /// reconstruction from backups, not a load-time check. A crash between
    /// a journal rewrite and its checkpoint can leave one silent gap where
    /// the chain resumes from the previous checkpoint.
    prefix_digest: u64,
    /// Digest of the first retained record's encoded line, checked against
    /// the journal on load so a checkpoint from another journal (or a
    /// rewritten head) fails closed.
    head_digest: u64,
}

impl Checkpoint {
    /// Encode into the stable single-line checkpoint format
    /// (`v1 member=… seq=… at=… prefix=<16 hex> head=<16 hex>`). Only a
    /// checkpoint that actually compacted at least one record exists, so
    /// the sequence is at least one.
    fn encode(&self) -> Result<String, StoreError> {
        if !member_is_file_safe(&self.member_id) {
            return Err(StoreError::InvalidMembers(format!(
                "member {:?} is not a safe journal file name",
                self.member_id
            )));
        }
        if self.last_compacted_sequence == 0 {
            return Err(StoreError::InvalidMembers(
                "a checkpoint must compact at least sequence one".to_owned(),
            ));
        }
        Ok(format!(
            "v1 member={} seq={} at={} prefix={:016x} head={:016x}\n",
            self.member_id,
            self.last_compacted_sequence,
            self.newest_compacted_at_ms,
            self.prefix_digest,
            self.head_digest
        ))
    }
}

/// Parse a checkpoint produced by [`Checkpoint::encode`] for the member
/// whose file it is. Anything else — wrong version, missing, extra or
/// misordered fields, a zero sequence, malformed numbers or digests — is
/// corruption and fails closed.
fn decode_checkpoint(member: &str, content: &str) -> Result<Checkpoint, StoreError> {
    let corrupt = |detail: &str| StoreError::CheckpointCorrupt {
        member: member.to_owned(),
        detail: detail.to_owned(),
    };
    let Some(single_line) = content.strip_suffix('\n') else {
        return Err(corrupt("the checkpoint is torn: no final newline"));
    };
    if single_line.contains('\n') {
        return Err(corrupt("the checkpoint has more than one line"));
    }
    let mut fields = single_line.split_whitespace();
    if fields.next() != Some("v1") {
        return Err(corrupt("not a v1 checkpoint"));
    }
    let mut field = |prefix: &str| -> Result<&str, StoreError> {
        fields
            .next()
            .and_then(|field| field.strip_prefix(prefix))
            .ok_or_else(|| corrupt("a checkpoint field is missing or misordered"))
    };
    let member_id = field("member=")?.to_owned();
    if !member_is_file_safe(&member_id) {
        return Err(corrupt(
            "the member identity is not a safe journal file name",
        ));
    }
    let last_compacted_sequence = field("seq=")?
        .parse::<u64>()
        .map_err(|_| corrupt("the last-compacted sequence is not a number"))?;
    if last_compacted_sequence == 0 {
        return Err(corrupt("the last-compacted sequence must be at least one"));
    }
    let newest_compacted_at_ms = field("at=")?
        .parse::<u64>()
        .map_err(|_| corrupt("the newest compacted timestamp is not a number"))?;
    let digest = |raw: &str, name: &str| -> Result<u64, StoreError> {
        if raw.len() != 16 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(corrupt(&format!("the {name} digest is not 16 hex digits")));
        }
        u64::from_str_radix(raw, 16).map_err(|_| corrupt(&format!("the {name} digest is invalid")))
    };
    let prefix_digest = digest(field("prefix=")?, "prefix")?;
    let head_digest = digest(field("head=")?, "head")?;
    if fields.next().is_some() {
        return Err(corrupt("trailing fields after the head digest"));
    }
    Ok(Checkpoint {
        member_id,
        last_compacted_sequence,
        newest_compacted_at_ms,
        prefix_digest,
        head_digest,
    })
}

/// Encode the durable membership record (`v1 members=a,b,c`).
fn encode_membership(members: &[String]) -> Result<String, StoreError> {
    validate_members(members)?;
    Ok(format!("v1 members={}\n", members.join(",")))
}

/// Parse a membership record produced by [`encode_membership`]. A file that
/// is not exactly one well-formed line of three distinct safe member ids is
/// corruption and fails closed.
fn decode_membership(content: &str) -> Result<Vec<String>, StoreError> {
    let corrupt = |detail: &str| StoreError::MembershipCorrupt(detail.to_owned());
    let Some(single_line) = content.strip_suffix('\n') else {
        return Err(corrupt("the record is torn: no final newline"));
    };
    if single_line.contains('\n') {
        return Err(corrupt("the record has more than one line"));
    }
    let mut fields = single_line.split_whitespace();
    if fields.next() != Some("v1") {
        return Err(corrupt("not a v1 membership record"));
    }
    let Some(list) = fields
        .next()
        .and_then(|field| field.strip_prefix("members="))
    else {
        return Err(corrupt("the members field is missing"));
    };
    if fields.next().is_some() {
        return Err(corrupt("trailing fields after the members list"));
    }
    let members: Vec<String> = list.split(',').map(str::to_owned).collect();
    validate_members(&members).map_err(|error| corrupt(&error.to_string()))?;
    Ok(members)
}

/// Failures of the consensus store. Every variant is a fail-closed
/// condition: the store never serves possibly-corrupt evidence.
#[derive(Debug)]
pub enum StoreError {
    /// The configured membership is not exactly three distinct member ids
    /// safe enough to be journal file names.
    InvalidMembers(String),
    /// The durable membership record could not be decoded.
    MembershipCorrupt(String),
    /// The configured membership differs from the durable one — a quorum
    /// change mid-flight; reconfiguration needs a fresh store directory.
    MembershipMismatch {
        on_disk: Vec<String>,
        configured: Vec<String>,
    },
    /// Member journals exist but the membership record is gone.
    MembershipMissing,
    /// An observations entry belongs to no configured member.
    ForeignJournal(String),
    /// A journal line is not a record this version understands.
    MalformedRecord,
    /// A journal line failed to decode while loading that journal; the
    /// member and one-based line number locate the corruption.
    CorruptRecord { member: String, line: usize },
    /// The journal ends mid-record (no terminating newline).
    TruncatedTail { member: String },
    /// Record sequences are not contiguous from one: a deletion, reorder or
    /// interleaved concurrent appends.
    SequenceBroken {
        member: String,
        expected: u64,
        found: u64,
    },
    /// A record inside one member's journal claims another member identity.
    IdentitySpoof {
        journal_member: String,
        record_member: String,
    },
    /// The compaction checkpoint beside a member journal is torn or not a
    /// checkpoint this version understands.
    CheckpointCorrupt { member: String, detail: String },
    /// A checkpoint claims another member identity than the journal it
    /// sits beside.
    CheckpointIdentitySpoof {
        journal_member: String,
        checkpoint_member: String,
    },
    /// The checkpoint's last-compacted sequence disagrees with the journal's
    /// first record: the checkpoint claims records the journal still holds
    /// (or the journal is empty under a checkpoint), which a compaction
    /// never produces — only a journal restored over a newer checkpoint can.
    CheckpointDisagrees {
        member: String,
        checkpoint_last_compacted: u64,
        journal_first: u64,
    },
    /// The checkpoint's head digest does not anchor the retained journal's
    /// first record: the checkpoint belongs to another journal, or the
    /// retained head was rewritten.
    CheckpointHeadMismatch { member: String },
    /// The journal continues from a sequence above one but has no
    /// checkpoint: its head was lost with no evidence it was ever
    /// compacted. A journal starting at one is the legacy layout and needs
    /// no checkpoint.
    CheckpointMissing { member: String, journal_first: u64 },
    /// A report names a member outside the durable membership.
    UnknownMember(String),
    /// The member's next sequence number does not fit `u64`.
    SequenceExhausted,
    /// The store failed earlier and stays closed until re-opened.
    Failed,
    /// Filesystem failure.
    Io(io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::InvalidMembers(detail) => {
                write!(f, "invalid quorum membership: {detail}")
            }
            StoreError::MembershipCorrupt(detail) => {
                write!(f, "the durable membership record is corrupt: {detail}")
            }
            StoreError::MembershipMismatch {
                on_disk,
                configured,
            } => write!(
                f,
                "the durable membership {:?} does not match the configured membership {:?}; \
                 reconfigure onto a fresh store directory",
                on_disk, configured
            ),
            StoreError::MembershipMissing => {
                write!(
                    f,
                    "member journals exist but the membership record is missing"
                )
            }
            StoreError::ForeignJournal(name) => write!(
                f,
                "observations entry {name:?} belongs to no configured member"
            ),
            StoreError::MalformedRecord => {
                write!(f, "not a journal record this version understands")
            }
            StoreError::CorruptRecord { member, line } => {
                write!(f, "corrupt journal record in {member:?} at line {line}")
            }
            StoreError::TruncatedTail { member } => {
                write!(f, "the journal of {member:?} ends mid-record")
            }
            StoreError::SequenceBroken {
                member,
                expected,
                found,
            } => write!(
                f,
                "the journal of {member:?} has a broken sequence (expected {expected}, \
                 found {found}): deleted, reordered or concurrently appended records"
            ),
            StoreError::IdentitySpoof {
                journal_member,
                record_member,
            } => write!(
                f,
                "a record in the journal of {journal_member:?} claims identity {record_member:?}"
            ),
            StoreError::CheckpointCorrupt { member, detail } => write!(
                f,
                "the compaction checkpoint of {member:?} is corrupt: {detail}"
            ),
            StoreError::CheckpointIdentitySpoof {
                journal_member,
                checkpoint_member,
            } => write!(
                f,
                "the checkpoint beside the journal of {journal_member:?} claims identity \
                 {checkpoint_member:?}"
            ),
            StoreError::CheckpointDisagrees {
                member,
                checkpoint_last_compacted,
                journal_first,
            } => write!(
                f,
                "the checkpoint of {member:?} claims sequences through \
                 {checkpoint_last_compacted} compacted but the journal holds records from \
                 sequence {journal_first}: a journal restored over a newer checkpoint"
            ),
            StoreError::CheckpointHeadMismatch { member } => write!(
                f,
                "the checkpoint of {member:?} does not anchor the retained journal's first \
                 record"
            ),
            StoreError::CheckpointMissing {
                member,
                journal_first,
            } => write!(
                f,
                "the journal of {member:?} continues from sequence {journal_first} without a \
                 checkpoint"
            ),
            StoreError::UnknownMember(member) => {
                write!(f, "member {member:?} is outside the durable membership")
            }
            StoreError::SequenceExhausted => {
                write!(f, "the journal sequence space is exhausted")
            }
            StoreError::Failed => write!(
                f,
                "the consensus store failed earlier and fails closed until re-opened"
            ),
            StoreError::Io(error) => write!(f, "consensus store I/O failed: {error}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Whether a member identifier is safe as a journal file name component on
/// every supported platform: ASCII letters, digits, `-`, `_` and inner dots
/// only — no path separators, whitespace, Windows-reserved characters or
/// reserved device names, and no leading or trailing dot.
fn member_is_file_safe(member: &str) -> bool {
    if member.is_empty() || member.starts_with('.') || member.ends_with('.') {
        return false;
    }
    let safe_bytes = member
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.');
    if !safe_bytes {
        return false;
    }
    // Windows resolves a reserved device name even with an extension.
    let base = member.split('.').next().unwrap_or(member);
    let upper = base.to_ascii_uppercase();
    !matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Validate a configured membership: exactly [`REQUIRED_MEMBERS`] distinct
/// identifiers, each safe as a journal file name.
fn validate_members(members: &[String]) -> Result<(), StoreError> {
    if members.len() != REQUIRED_MEMBERS {
        return Err(StoreError::InvalidMembers(format!(
            "the quorum needs exactly {REQUIRED_MEMBERS} members"
        )));
    }
    for (index, member) in members.iter().enumerate() {
        if !member_is_file_safe(member) {
            return Err(StoreError::InvalidMembers(format!(
                "member {member:?} is not a safe journal file name"
            )));
        }
        if members[..index].contains(member) {
            return Err(StoreError::InvalidMembers(
                "member identifiers must be distinct".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Whether two membership lists describe the same member set.
fn same_membership(on_disk: &[String], configured: &[String]) -> bool {
    let mut on_disk = on_disk.to_vec();
    let mut configured = configured.to_vec();
    on_disk.sort();
    configured.sort();
    on_disk == configured
}

/// Whether an observation is fresh evidence at `now_ms`, with exactly the
/// decision model's window semantics.
fn is_fresh(observed_at_ms: u64, now_ms: u64, freshness_ms: u64) -> bool {
    observed_at_ms <= now_ms && now_ms - observed_at_ms <= freshness_ms
}

fn parse_bool(value: &str) -> Result<bool, StoreError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(StoreError::MalformedRecord),
    }
}

/// Refuse any observations entry that is not an artifact of a configured
/// member: a journal, a compaction checkpoint, or either one's atomic-write
/// temp file. A journal from a previous membership or a stray file must not
/// be mixed into this quorum's evidence.
fn scan_observations(observations: &Path, members: &[String]) -> Result<(), StoreError> {
    let entries = match fs::read_dir(observations) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(StoreError::Io(error)),
    };
    for entry in entries {
        let entry = entry.map_err(StoreError::Io)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_file = entry.file_type().map_err(StoreError::Io)?.is_file();
        let known = KNOWN_ENTRY_SUFFIXES.iter().any(|suffix| {
            is_file
                && name.ends_with(suffix)
                && name
                    .strip_suffix(suffix)
                    .is_some_and(|base| members.iter().any(|member| member == base))
        });
        if !known {
            return Err(StoreError::ForeignJournal(name));
        }
    }
    Ok(())
}

/// Whether the directory exists and holds at least one entry.
fn directory_has_entries(directory: &Path) -> Result<bool, StoreError> {
    match fs::read_dir(directory) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(StoreError::Io(error)),
    }
}

/// Load one member's journal: validate every record's identity, sequence
/// continuity and encoding, reconcile it with the compaction checkpoint when
/// one exists, compact the aged-out prefix (see [`compactable_prefix_len`]),
/// then hold the append handle. A missing journal (a member that never
/// reported under an existing membership) is created empty.
fn open_journal(
    observations: &Path,
    member: &str,
    observation_freshness_ms: u64,
) -> Result<MemberJournal, StoreError> {
    let journal_path = observations.join(format!("{member}.journal"));
    let content = match fs::read(&journal_path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&journal_path)
                .map_err(StoreError::Io)?;
            file.sync_all().map_err(StoreError::Io)?;
            Vec::new()
        }
        Err(error) => return Err(StoreError::Io(error)),
    };
    let checkpoint = match fs::read_to_string(observations.join(format!("{member}.checkpoint"))) {
        Ok(content) => Some(decode_checkpoint(member, &content)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(StoreError::Io(error)),
    };
    let mut records = Vec::new();
    // The first record's sequence anchors the journal's continuation; its
    // raw line is kept for the checkpoint's head-digest check.
    let mut first_sequence: Option<u64> = None;
    let mut first_line: Option<&[u8]> = None;
    if !content.is_empty() {
        if content.last() != Some(&b'\n') {
            return Err(StoreError::TruncatedTail {
                member: member.to_owned(),
            });
        }
        let lines = content[..content.len() - 1].split(|byte| *byte == b'\n');
        for (index, line) in lines.enumerate() {
            let line_number = index + 1;
            let record = JournalRecord::decode(std::str::from_utf8(line).map_err(|_| {
                StoreError::CorruptRecord {
                    member: member.to_owned(),
                    line: line_number,
                }
            })?)
            .map_err(|_| StoreError::CorruptRecord {
                member: member.to_owned(),
                line: line_number,
            })?;
            if record.report.member_id != member {
                return Err(StoreError::IdentitySpoof {
                    journal_member: member.to_owned(),
                    record_member: record.report.member_id,
                });
            }
            match first_sequence {
                None => {
                    if record.sequence == 0 {
                        return Err(StoreError::SequenceBroken {
                            member: member.to_owned(),
                            expected: 1,
                            found: 0,
                        });
                    }
                    first_sequence = Some(record.sequence);
                    first_line = Some(line);
                }
                Some(first) => {
                    let expected = first.saturating_add(index as u64);
                    if record.sequence != expected {
                        return Err(StoreError::SequenceBroken {
                            member: member.to_owned(),
                            expected,
                            found: record.sequence,
                        });
                    }
                }
            }
            records.push(record.report);
        }
    }
    // Reconcile the journal with its checkpoint. No checkpoint means the
    // legacy full journal, which must start at sequence one; an empty
    // journal likewise continues from one (reported as journal first zero
    // in the disagrees error, which no real journal can produce).
    let first_sequence = first_sequence.unwrap_or(1);
    if let Some(checkpoint) = &checkpoint {
        if checkpoint.member_id != member {
            return Err(StoreError::CheckpointIdentitySpoof {
                journal_member: member.to_owned(),
                checkpoint_member: checkpoint.member_id.clone(),
            });
        }
        if first_sequence <= checkpoint.last_compacted_sequence {
            // The checkpoint claims records the journal still holds — or the
            // journal is empty under a checkpoint: the only way either arises
            // is a journal restored over a newer checkpoint, because
            // compaction never empties a journal (the floor keeps a tail).
            return Err(StoreError::CheckpointDisagrees {
                member: member.to_owned(),
                checkpoint_last_compacted: checkpoint.last_compacted_sequence,
                journal_first: if records.is_empty() {
                    0
                } else {
                    first_sequence
                },
            });
        }
        if first_sequence == checkpoint.last_compacted_sequence + 1 {
            // The checkpoint anchors the retained journal's first record;
            // a journal (or checkpoint) from anywhere else fails closed.
            let Some(first_line) = first_line else {
                return Err(StoreError::CheckpointDisagrees {
                    member: member.to_owned(),
                    checkpoint_last_compacted: checkpoint.last_compacted_sequence,
                    journal_first: first_sequence,
                });
            };
            if fnv1a64(FNV_OFFSET_BASIS, first_line) != checkpoint.head_digest {
                return Err(StoreError::CheckpointHeadMismatch {
                    member: member.to_owned(),
                });
            }
        }
        // Otherwise the journal starts above the checkpoint's continuation:
        // the crash window of the compaction order (journal rewritten
        // durably, checkpoint rename still pending). The journal on disk is
        // the ground truth and loads; the head anchor covers a record the
        // rewrite dropped, so it cannot be checked.
    } else if first_sequence > 1 {
        return Err(StoreError::CheckpointMissing {
            member: member.to_owned(),
            journal_first: first_sequence,
        });
    }
    // The next sequence exists before anything is rewritten, so a journal
    // too far along to continue fails closed without touching the disk.
    let next_sequence = first_sequence
        .checked_add(
            u64::try_from(records.len())
                .ok()
                .ok_or(StoreError::SequenceExhausted)?,
        )
        .ok_or(StoreError::SequenceExhausted)?;
    let first_sequence = compact_journal(
        observations,
        member,
        first_sequence,
        &mut records,
        checkpoint.as_ref(),
        observation_freshness_ms,
    )?;
    let file = OpenOptions::new()
        .append(true)
        .open(&journal_path)
        .map_err(StoreError::Io)?;
    Ok(MemberJournal {
        file,
        first_sequence,
        next_sequence,
        records,
    })
}

/// How many leading records of a loaded journal compaction may drop: the
/// run of records that have aged out of the decision model's freshness
/// window, measured from the newest observation in that journal — the store
/// takes no clock of its own (every round injects `now_ms`, and open takes
/// none), and anchoring at the newest record is the deterministic,
/// conservative choice. The run stops at the first record inside the window,
/// and the [`JOURNAL_RETAINED_FLOOR`] tail records are never dropped, so an
/// all-stale journal still keeps its floor.
fn compactable_prefix_len(records: &[MemberReport], observation_freshness_ms: u64) -> usize {
    let Some(anchor) = records.iter().map(|report| report.observed_at_ms).max() else {
        return 0;
    };
    let mut compactable = 0;
    for report in records {
        if is_fresh(report.observed_at_ms, anchor, observation_freshness_ms) {
            break;
        }
        compactable += 1;
    }
    compactable.min(records.len().saturating_sub(JOURNAL_RETAINED_FLOOR))
}

/// Rewrite the member journal without its compactable prefix and write the
/// checkpoint naming what was dropped. Order is the crash-safety contract:
/// the new journal holding the retained tail is made durable (temp file,
/// fsync, atomic rename) *first*, and only then is the checkpoint replaced.
/// A crash in between leaves the rewritten journal beside the previous (or
/// no) checkpoint — a state load accepts as the ground truth — so a
/// checkpoint that runs ahead of its journal can never exist on disk;
/// `open_journal` treats one as corruption. The in-memory `records` lose the
/// compacted prefix and the new first sequence is returned.
fn compact_journal(
    observations: &Path,
    member: &str,
    first_sequence: u64,
    records: &mut Vec<MemberReport>,
    previous: Option<&Checkpoint>,
    observation_freshness_ms: u64,
) -> Result<u64, StoreError> {
    let compactable = compactable_prefix_len(records, observation_freshness_ms);
    if compactable == 0 {
        return Ok(first_sequence);
    }
    // The floor guarantees a retained tail, so the head anchor always has a
    // record to bind to.
    let mut chain = previous.map_or(FNV_OFFSET_BASIS, |checkpoint| checkpoint.prefix_digest);
    let mut newest_compacted_at_ms = 0;
    let mut head_digest = None;
    let mut retained = String::new();
    for (index, report) in records.iter().enumerate() {
        let line = JournalRecord {
            sequence: first_sequence + index as u64,
            report: report.clone(),
        }
        .encode()?;
        if index < compactable {
            chain = fnv1a64(chain, line.as_bytes());
            newest_compacted_at_ms = newest_compacted_at_ms.max(report.observed_at_ms);
        } else {
            if head_digest.is_none() {
                head_digest = Some(fnv1a64(FNV_OFFSET_BASIS, line.as_bytes()));
            }
            retained.push_str(&line);
            retained.push('\n');
        }
    }
    let checkpoint = Checkpoint {
        member_id: member.to_owned(),
        last_compacted_sequence: first_sequence + compactable as u64 - 1,
        newest_compacted_at_ms,
        prefix_digest: chain,
        head_digest: head_digest.ok_or(StoreError::SequenceExhausted)?,
    };
    // Journal first, checkpoint second: the exact order load recovers from.
    write_atomically(
        &observations.join(format!("{member}.journal.tmp")),
        &observations.join(format!("{member}.journal")),
        retained.as_bytes(),
    )?;
    write_atomically(
        &observations.join(format!("{member}.checkpoint.tmp")),
        &observations.join(format!("{member}.checkpoint")),
        checkpoint.encode()?.as_bytes(),
    )?;
    records.drain(..compactable);
    Ok(first_sequence + compactable as u64)
}

/// Write `bytes` to `destination` atomically: create the temp file (also
/// clearing any a previous crash left), write, flush and fsync, then rename
/// over the destination — so a crash at any point leaves either the old or
/// the new content, never a torn record.
fn write_atomically(temp: &Path, destination: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut file = File::create(temp).map_err(StoreError::Io)?;
    file.write_all(bytes).map_err(StoreError::Io)?;
    file.flush().map_err(StoreError::Io)?;
    file.sync_all().map_err(StoreError::Io)?;
    fs::rename(temp, destination).map_err(StoreError::Io)?;
    Ok(())
}

#[cfg(test)]
mod compaction_tests;

#[cfg(test)]
mod tests;
