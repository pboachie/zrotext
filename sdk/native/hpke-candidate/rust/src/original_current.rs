//! Authenticated current grant proof plus durable accepted-history fencing.
use crate::{
    journal::JournalError,
    manifest::{Manifest, RootTrust, enroll_root, verify_manifest},
    original_checkpoint::{OriginalReplyCheckpoint, OriginalReplySnapshot, accepted_manifest_at},
    original_http::{HttpError, OriginalHttp, Request},
    original_reply::{OriginalAuthority, OriginalScope, valid_scope},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

/// A verified snapshot, never permission to omit fresh checks around effects.
pub struct VerifiedOriginalCurrent {
    scope: OriginalScope,
    now: u64,
    expires: u64,
    manifest: Manifest,
}
impl VerifiedOriginalCurrent {
    pub fn authority(&self) -> OriginalAuthority<'_> {
        OriginalAuthority {
            scope: self.scope.clone(),
            revision: "1".into(),
            now: self.now,
            expires: self.expires,
            manifest: &self.manifest,
        }
    }
}
pub(super) struct State {
    pub(super) revision: u64,
    pub(super) last: u64,
    pub(super) failed: bool,
}
pub struct OriginalCurrentClient {
    pub(super) transport: OriginalHttp,
    pub(super) checkpoint: Arc<OriginalReplyCheckpoint>,
    pub(super) scope: OriginalScope,
    pub(super) root: RootTrust,
    pub(super) state: Mutex<State>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    version: u64,
    accepted_at_ms: u64,
    manifest_b64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    account_id: String,
    interval_id: String,
    device_id: String,
    line_id: String,
    connector_id: String,
    read_grant_id: String,
    reader_id: String,
    root_generation: u64,
    authority_revision: u64,
    expires_at_ms: u64,
    observed_at_ms: u64,
    current_manifest_version: u64,
    current_manifest_digest: String,
    manifest_chain: Vec<Entry>,
}
fn need(v: bool) -> Result<(), HttpError> {
    if v {
        Ok(())
    } else {
        Err(HttpError::Unavailable)
    }
}
fn positive(v: u64) -> bool {
    (1..=9007199254740991).contains(&v)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub(super) fn uuid(b: &[u8; 16]) -> String {
    let h = hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
pub(super) fn sample(state: &mut State, clock: &impl Fn() -> u64) -> Result<u64, HttpError> {
    let n = clock();
    need(positive(n) && n >= state.last)?;
    state.last = n;
    Ok(n)
}
impl OriginalCurrentClient {
    /// Checkpoint is mandatory and must already contain independently enrolled
    /// complete accepted history. This constructor cannot bootstrap from HTTP.
    pub fn new(
        transport: OriginalHttp,
        checkpoint: Arc<OriginalReplyCheckpoint>,
        pin: &[u8],
        fingerprint: &[u8],
        scope: OriginalScope,
        now: u64,
    ) -> Result<Self, HttpError> {
        let bad = HttpError::Unavailable;
        need(valid_scope(&scope) && positive(now))?;
        let root = enroll_root(pin, fingerprint).map_err(|_| bad)?;
        let saved = checkpoint.snapshot(&scope, now).map_err(|_| bad)?;
        let first = saved.history.first().ok_or(bad)?;
        verify_manifest(&first.raw, &root, None, 2, first.comparison).map_err(|_| bad)?;
        Ok(Self {
            transport,
            checkpoint,
            scope,
            root,
            state: Mutex::new(State {
                revision: saved.revision,
                last: now,
                failed: false,
            }),
        })
    }
    /// One HTTP request. An uncertain persistence outcome poisons this instance;
    /// explicit reconstruction from the existing checkpoint is required.
    pub fn current(
        &self,
        grant: &str,
        clock: impl Fn() -> u64,
    ) -> Result<VerifiedOriginalCurrent, HttpError> {
        let bad = HttpError::Unavailable;
        let mut state = self.state.try_lock().map_err(|_| bad)?;
        self.current_locked(grant, &clock, &mut state)
    }
    pub(super) fn current_locked(
        &self,
        grant: &str,
        clock: &impl Fn() -> u64,
        state: &mut State,
    ) -> Result<VerifiedOriginalCurrent, HttpError> {
        let bad = HttpError::Unavailable;
        need(!state.failed)?;
        let now = sample(state, clock)?;
        let saved = self.checkpoint.snapshot(&self.scope, now).map_err(|_| {
            state.failed = true;
            bad
        })?;
        if saved.revision != state.revision {
            state.failed = true;
            return Err(bad);
        }
        let latest = saved.history.last().ok_or(bad)?;
        let wire = self
            .transport
            .exchange(grant, latest.version, Request::Current)?;
        self.accept_proof(wire.json.get(), &saved, latest, clock, state)
    }
    pub(super) fn accept_proof(
        &self,
        raw: &str,
        saved: &OriginalReplySnapshot,
        baseline: &Manifest,
        clock: &impl Fn() -> u64,
        state: &mut State,
    ) -> Result<VerifiedOriginalCurrent, HttpError> {
        let bad = HttpError::Unavailable;
        let latest = saved.history.last().ok_or(bad)?;
        let p: Proof = serde_json::from_str(raw).map_err(|_| bad)?;
        let now = sample(state, clock)?;
        need(positive(p.observed_at_ms) && positive(p.expires_at_ms))?;
        let fresh = |n: u64| {
            n < p.expires_at_ms && n <= p.observed_at_ms + 30000 && p.observed_at_ms <= n + 30000
        };
        need(fresh(now))?;
        for (actual, expected) in [
            (&p.account_id, &self.scope.account),
            (&p.device_id, &self.scope.device),
            (&p.line_id, &self.scope.line),
            (&p.interval_id, &self.scope.interval),
            (&p.connector_id, &self.scope.connector),
            (&p.read_grant_id, &self.scope.read_grant),
        ] {
            need(*actual == uuid(expected))?
        }
        need(
            p.reader_id == hex(&self.scope.reader)
                && p.authority_revision == 1
                && (1..=32).contains(&p.manifest_chain.len()),
        )?;
        let mut staged = Vec::new();
        for (i, entry) in p.manifest_chain.iter().enumerate() {
            let previous = staged.last().unwrap_or(baseline);
            need(
                positive(entry.accepted_at_ms)
                    && entry.accepted_at_ms <= now + 30000
                    && positive(entry.version)
                    && entry.version
                        == if i == 0 {
                            baseline.version
                        } else {
                            previous.version + 1
                        },
            )?;
            need(entry.manifest_b64.len() <= 13004)?;
            let signed = STANDARD.decode(&entry.manifest_b64).map_err(|_| bad)?;
            need(signed.len() <= 9751 && STANDARD.encode(&signed) == entry.manifest_b64)?;
            let m = accepted_manifest_at(&signed, &self.root, Some(previous), entry.accepted_at_ms)
                .map_err(|_| bad)?;
            need(
                m.version == entry.version
                    && m.generation == latest.generation
                    && m.root == latest.root,
            )?;
            if m.version <= latest.version {
                need(
                    saved
                        .history
                        .iter()
                        .any(|cached| cached.version == m.version && cached.digest == m.digest),
                )?;
            }
            staged.push(m);
        }
        let current = staged.last().ok_or(bad)?;
        need(
            positive(p.current_manifest_version)
                && p.current_manifest_version == current.version
                && current.version >= latest.version
                && p.root_generation == latest.generation
                && p.current_manifest_digest == hex(&current.digest)
                && saved.history.len()
                    + staged.iter().filter(|m| m.version > latest.version).count()
                    <= 64,
        )?;
        let now = sample(state, clock)?;
        need(fresh(now))?;
        accepted_manifest_at(&current.raw, &self.root, Some(current), now).map_err(|_| bad)?;
        let history: Vec<_> = saved
            .history
            .iter()
            .chain(staged.iter().filter(|m| m.version > latest.version))
            .collect();
        let mut commit = |history: &[&Manifest],
                          revision: u64,
                          at: u64|
         -> Result<OriginalReplySnapshot, HttpError> {
            self.checkpoint
                .accept(&self.scope, history, revision, at, |m, floor| {
                    let n = sample(state, clock).map_err(|_| JournalError::Refused)?;
                    if n < floor || !fresh(n) {
                        return Err(JournalError::Refused);
                    }
                    accepted_manifest_at(&m.raw, &self.root, Some(m), n)
                        .map_err(|_| JournalError::Refused)?;
                    Ok(n)
                })
                .map_err(|_| bad)
        };
        // Copy before the closure borrows state during its locked freshness callback.
        let revision = saved.revision;
        let mut committed = match commit(&history, revision, now) {
            Ok(v) => v,
            Err(_) => {
                state.failed = true;
                return Err(bad);
            }
        };
        // A failure after the first commit must never leave an apparently reusable
        // stale in-memory revision. Preserve this flag until the full fence succeeds.
        state.failed = true;
        let after = sample(state, clock)?;
        need(after >= committed.comparison && fresh(after))?;
        let current = committed.history.last().ok_or(bad)?;
        accepted_manifest_at(&current.raw, &self.root, Some(current), after).map_err(|_| bad)?;
        if after > committed.comparison {
            let history: Vec<_> = committed.history.iter().collect();
            committed = self
                .checkpoint
                .accept(
                    &self.scope,
                    &history,
                    committed.revision,
                    after,
                    |m, floor| {
                        let n = sample(state, clock).map_err(|_| JournalError::Refused)?;
                        if n < floor || !fresh(n) {
                            return Err(JournalError::Refused);
                        }
                        accepted_manifest_at(&m.raw, &self.root, Some(m), n)
                            .map_err(|_| JournalError::Refused)?;
                        Ok(n)
                    },
                )
                .map_err(|_| bad)?;
        }
        state.revision = committed.revision;
        state.last = committed.comparison;
        state.failed = false;
        Ok(VerifiedOriginalCurrent {
            scope: self.scope.clone(),
            now: committed.comparison,
            expires: p.expires_at_ms,
            manifest: committed.history.pop().ok_or(bad)?,
        })
    }
}
