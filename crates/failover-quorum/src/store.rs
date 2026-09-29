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
//! rotation or compaction (the whole journal is re-read on open), and any
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
    /// Sequence number the next append will take (`u64::MAX` is exhausted).
    next_sequence: u64,
    /// Reports in append order; sequence is the index plus one.
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
            journals.insert(member.clone(), open_journal(&observations, member)?);
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
            // Sequence numbers are the record index plus one, so records
            // after `cursor` start at index `cursor`.
            let skip = usize::try_from(cursor).unwrap_or(usize::MAX);
            for (index, report) in journal.records.iter().enumerate().skip(skip) {
                if is_fresh(report.observed_at_ms, now_ms, self.observation_freshness_ms) {
                    reports.push(report.clone());
                    last_served = u64::try_from(index)
                        .ok()
                        .and_then(|index| index.checked_add(1))
                        .unwrap_or(u64::MAX);
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

/// Refuse any observations entry that is not a journal file of a configured
/// member: a journal from a previous membership or a stray file must not be
/// mixed into this quorum's evidence.
fn scan_observations(observations: &Path, members: &[String]) -> Result<(), StoreError> {
    let entries = match fs::read_dir(observations) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(StoreError::Io(error)),
    };
    for entry in entries {
        let entry = entry.map_err(StoreError::Io)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_journal_file =
            entry.file_type().map_err(StoreError::Io)?.is_file() && name.ends_with(".journal");
        let known_member = name
            .strip_suffix(".journal")
            .is_some_and(|member| members.iter().any(|known| known == member));
        if !is_journal_file || !known_member {
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

/// Load one member's journal: validate every record's identity, sequence and
/// encoding, then hold the append handle. A missing journal (a member that
/// never reported under an existing membership) is created empty.
fn open_journal(observations: &Path, member: &str) -> Result<MemberJournal, StoreError> {
    let path = observations.join(format!("{member}.journal"));
    let content = match fs::read(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(StoreError::Io)?;
            file.sync_all().map_err(StoreError::Io)?;
            Vec::new()
        }
        Err(error) => return Err(StoreError::Io(error)),
    };
    let mut records = Vec::new();
    if !content.is_empty() {
        if content.last() != Some(&b'\n') {
            return Err(StoreError::TruncatedTail {
                member: member.to_owned(),
            });
        }
        let lines = content[..content.len() - 1].split(|byte| *byte == b'\n');
        for (index, line) in lines.enumerate() {
            let line_number = index + 1;
            let expected_sequence = line_number as u64;
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
            if record.sequence != expected_sequence {
                return Err(StoreError::SequenceBroken {
                    member: member.to_owned(),
                    expected: expected_sequence,
                    found: record.sequence,
                });
            }
            records.push(record.report);
        }
    }
    let file = OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(StoreError::Io)?;
    let next_sequence = u64::try_from(records.len())
        .ok()
        .and_then(|len| len.checked_add(1))
        .ok_or(StoreError::SequenceExhausted)?;
    Ok(MemberJournal {
        file,
        next_sequence,
        records,
    })
}

#[cfg(test)]
mod tests;
