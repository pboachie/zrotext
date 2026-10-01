// SPDX-License-Identifier: AGPL-3.0-only
//! Server wiring for the independent-quorum failover executor and the
//! member-side reporting loop.
//!
//! [`ExecutorEnv::parse`] mirrors the `AlphaPolicy::parse` convention: a pure
//! function over raw environment values, so the default-off behavior stays
//! unit-testable. Disabled — the default — returns `Ok(None)` and reads no
//! further configuration, and [`spawn_failover_executor`] then spawns
//! nothing: zero behavior change while the flag is off.
//!
//! [`PgWriterAuthority`] is the PostgreSQL implementation of the
//! `zrotext_failover_quorum::executor::WriterAuthority` port. It keeps one
//! dedicated, long-lived connection to the writer database — opened under a
//! bounded connect ceiling and reopened, after a small randomized pause,
//! whenever an operation fails — on its own single-threaded runtime, because
//! the executor itself is synchronous and deliberately independent of the
//! main async runtime. Every operation waits under a generous ceiling: a
//! timeout is a failed operation like any transport or SQL error, and the
//! executor's idempotent replay turns it into a retry instead of a hang.
//!
//! The executor is a per-database singleton, guarded by a session-level
//! PostgreSQL advisory lock ([`EXECUTOR_ADVISORY_LOCK_KEY`]): every API
//! replica with the wiring enabled may spawn the executor thread, but the
//! authority's dedicated connection must acquire the lock when it opens —
//! and again after every reconnect, because the lock dies with its session
//! — so exactly one replica runs rounds against the journal row. A replica
//! that cannot acquire the lock stays dormant: every operation fails
//! closed without a connection (fail-closed — no lock means no authority
//! writes), the retry rides the check cadence, readiness is unaffected —
//! a dormant replica is an ordinary API replica — and each role change is
//! logged once, never per tick. Executor-host failover needs no lease
//! semantics: taking the previous owner's connection down releases the
//! lock, and a dormant replica acquires it on its next retry.
//!
//! Re-acquisition is not a resume. A replica that re-acquires the lock
//! after losing its connection must assume another executor ran in
//! between: everything it cached from its previous exclusive period —
//! controller phase, journal, pending intents — may describe a past the
//! database no longer reflects, and replaying it would act on stale state
//! (a stale promotion replay re-pauses dispatch and overwrites the durable
//! journal row). The port therefore latches every re-acquisition: the
//! operation that paid for the acquiring connection is failed closed, and
//! every later operation fails closed until the executor acknowledges the
//! reload — the `WriterAuthority::exclusivity_reacquired` check at the top
//! of each tick, which discards the cached state and restores from the
//! authority snapshot and the durable journal row (the database's current
//! truth) before anything runs again.
//!
//! The observation source is the durable consensus store
//! (`FAILOVER_QUORUM_STORE_DIR`): one membership record plus append-only
//! per-member journals, served through the decision model's freshness
//! window; a store that is corrupt, truncated or belongs to another
//! membership fails the executor closed at startup instead of serving
//! uncertain evidence (see `docs/MULTI-LOCATION.md`). Alongside the
//! executor thread, the member-side reporting loop records this member's
//! rounds into the same shared store (`FAILOVER_QUORUM_REPORT_MEMBER_ID`),
//! through the crate's sink adapter — the store stays the only writer of
//! its journals. Optional authenticated HTTPS adapters supply explicit inputs
//! and pinned member reports. Without adapter configuration, the source abstains.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zrotext_failover_quorum::decision::{FailoverConfig, Round, SiteFenceState};
use zrotext_failover_quorum::executor::{
    AuthoritySnapshot, FailoverExecutor, FenceOutcome, ObservationSource, PromoteOutcome,
    WriterAuthority,
};
use zrotext_failover_quorum::observe::{MemberObserver, ProbeFault, RoundProbes, WriterProbe};
use zrotext_failover_quorum::policy::QuorumPolicy;
use zrotext_failover_quorum::report::{ConsensusStoreSink, ProbeSource, ReportLoop, RoundOutcome};
use zrotext_failover_quorum::store::ConsensusStore;

/// Default `FAILOVER_QUORUM_CHECK_INTERVAL_MS`.
pub const DEFAULT_CHECK_INTERVAL_MS: u64 = 5_000;

/// Ceiling for opening — and reopening — the authority's dedicated
/// PostgreSQL connection: one bound around TCP, TLS and authentication
/// together. No `FAILOVER_QUORUM_*` wiring configures a connect budget
/// today, so rather than add configuration surface the port fixes a
/// generous constant; an operator's URL-level `connect_timeout`, when
/// present, still applies underneath and can only tighten it.
const CONNECT_CEILING: Duration = Duration::from_secs(10);

/// Ceiling for waiting on one writer-authority operation (snapshot read,
/// fence write, promote transaction, journal round-trip). The promote
/// transaction is a handful of small statements on locked singleton rows,
/// so 30 seconds comfortably exceeds any healthy worst case — including a
/// brief `FOR UPDATE` wait behind an operator's manual epoch bump — while
/// still turning a wedged server into a failed operation instead of an
/// executor blocked forever.
const OPERATION_CEILING: Duration = Duration::from_secs(30);

/// Upper bound of the randomized pause taken before a reconnect, so that
/// processes recovering from a shared writer bounce do not reconnect in
/// lockstep. Kept small next to the executor's check interval: it staggers
/// reconnect attempts, nothing more.
const RECONNECT_JITTER_CEILING: Duration = Duration::from_millis(250);

/// Key of the session-level PostgreSQL advisory lock that makes the
/// failover executor a per-database singleton. The value is the big-endian
/// ASCII of `ZROFAILO`, so it is self-describing when an operator inspects
/// `pg_locks`; it is otherwise arbitrary but must stay fixed forever;
/// changing it would let two executors that disagree on the key drive the
/// one `failover_controller_state` journal row again.
pub const EXECUTOR_ADVISORY_LOCK_KEY: i64 = 0x5A52_4F46_4149_4C4F;

/// The singleton-executor role of one [`PgWriterAuthority`] connection, as
/// the executor wiring observes it. The role is shared through a
/// [`SharedExecutorRole`] cell so the wiring loop can log role changes
/// without borrowing the authority the controller loop owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorRole {
    /// No lock attempt has completed on the current connection yet.
    Pending,
    /// The connection holds [`EXECUTOR_ADVISORY_LOCK_KEY`]: authority
    /// operations run.
    Active,
    /// Another replica's executor holds the lock: operations fail closed
    /// until a later attempt acquires it.
    Dormant,
}

impl ExecutorRole {
    /// The shared-cell encoding of the role.
    fn as_bits(self) -> u8 {
        match self {
            ExecutorRole::Pending => 0,
            ExecutorRole::Active => 1,
            ExecutorRole::Dormant => 2,
        }
    }

    /// The role for a shared-cell encoding; anything unexpected reads as
    /// [`ExecutorRole::Pending`], the claim-nothing default.
    fn from_bits(bits: u8) -> Self {
        match bits {
            1 => ExecutorRole::Active,
            2 => ExecutorRole::Dormant,
            _ => ExecutorRole::Pending,
        }
    }
}

/// The wiring loop's lock-free window onto the guard's role.
#[derive(Clone)]
struct SharedExecutorRole(Arc<AtomicU8>);

impl SharedExecutorRole {
    /// A cell that claims no role yet.
    fn new() -> Self {
        Self(Arc::new(AtomicU8::new(ExecutorRole::Pending.as_bits())))
    }

    /// The currently observed role.
    fn load(&self) -> ExecutorRole {
        ExecutorRole::from_bits(self.0.load(Ordering::Acquire))
    }

    /// Publish a role change to every holder of the cell.
    fn store(&self, role: ExecutorRole) {
        self.0.store(role.as_bits(), Ordering::Release);
    }
}

/// The guard's verdict for one arriving operation.
enum GuardDecision {
    /// Run the operation: the connection holds the lock, or a lock
    /// attempt is due now (the port attempts it while opening).
    Proceed,
    /// Fail the operation closed without touching the database: another
    /// replica holds the lock and the retry interval has not elapsed.
    Dormant,
    /// Fail the operation closed without touching the database: the lock
    /// was re-acquired and the owner has not yet acknowledged the reload
    /// (see [`SingletonExecutorGuard::take_reacquired`]). State cached
    /// from the previous exclusive period may be stale, so nothing may run
    /// until the executor reloads from the database.
    Stale,
}

/// What one `pg_try_advisory_lock` attempt means for the operation that
/// paid for the connection it ran on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockAttempt {
    /// Another replica holds the lock.
    Refused,
    /// This port's first acquisition: no earlier exclusive period exists,
    /// so nothing the owner could have cached is stale and the triggering
    /// operation may run.
    AcquiredFirst,
    /// A re-acquisition: a previous exclusive period ended with a lost
    /// connection, and another executor may have run in between. The
    /// triggering operation is failed closed — it may carry intent cached
    /// from that period — and the guard latches the re-acquisition so the
    /// owner reloads authoritative state before the next operation.
    AcquiredAgain,
}

/// Pure state machine behind the singleton-executor guard. The port
/// consults it before every operation and resolves it with the outcome of
/// `pg_try_advisory_lock` on each connection it opens, so the lock's
/// lifetime is exactly the connection's lifetime: a lost connection
/// demotes the role to [`ExecutorRole::Pending`] instead of assuming it,
/// and the next operation re-attempts the lock on the fresh connection.
/// A replica whose attempt fails stays [`ExecutorRole::Dormant`] — every
/// operation fails closed without a connection — until the retry interval
/// elapses, which bounds lock attempts regardless of how often operations
/// arrive.
struct SingletonExecutorGuard {
    retry_interval: Duration,
    next_attempt: Option<Instant>,
    role: SharedExecutorRole,
    /// Whether this port has completed an acquisition before, so a later
    /// acquisition can be told apart from the first: only a re-acquisition
    /// implies a previous exclusive period whose cached state may be stale.
    ever_acquired: bool,
    /// Latched on every re-acquisition and read-and-cleared by the owner
    /// through [`Self::take_reacquired`]: while set, every operation fails
    /// closed ([`GuardDecision::Stale`]) so nothing runs on the
    /// re-acquired lock until the owner reloaded authoritative state.
    reacquired: bool,
}

impl SingletonExecutorGuard {
    /// Build the guard and the role cell shared with the wiring loop.
    fn new(retry_interval: Duration) -> (Self, SharedExecutorRole) {
        let role = SharedExecutorRole::new();
        (
            Self {
                retry_interval,
                next_attempt: None,
                role: role.clone(),
                ever_acquired: false,
                reacquired: false,
            },
            role,
        )
    }

    /// The verdict for an operation arriving at `now`.
    fn poll(&mut self, now: Instant) -> GuardDecision {
        if self.reacquired {
            return GuardDecision::Stale;
        }
        if self.role.load() == ExecutorRole::Active {
            return GuardDecision::Proceed;
        }
        match self.next_attempt {
            Some(due) if now < due => GuardDecision::Dormant,
            _ => GuardDecision::Proceed,
        }
    }

    /// Record the outcome of one `pg_try_advisory_lock` attempt: an
    /// acquisition runs operations until the connection is lost; a refusal
    /// parks the guard dormant until the retry interval elapses, so at most
    /// one attempt is made per interval however often operations arrive.
    /// An acquisition after a previous exclusive period additionally
    /// latches [`Self::take_reacquired`] — a re-acquisition means another
    /// executor may have advanced the authority and journal in between, so
    /// the owner must reload before any of its cached state is acted on.
    fn resolved(&mut self, acquired: bool, now: Instant) -> LockAttempt {
        if acquired {
            let attempt = if self.ever_acquired {
                self.reacquired = true;
                LockAttempt::AcquiredAgain
            } else {
                LockAttempt::AcquiredFirst
            };
            self.ever_acquired = true;
            self.role.store(ExecutorRole::Active);
            self.next_attempt = None;
            attempt
        } else {
            self.role.store(ExecutorRole::Dormant);
            self.next_attempt = Some(now.checked_add(self.retry_interval).unwrap_or(now));
            LockAttempt::Refused
        }
    }

    /// Read-and-clear the re-acquisition signal. This is the owner's
    /// reload acknowledgment: the one call that consumes it belongs to the
    /// executor's reload step, and only after it may operations run again
    /// (see [`GuardDecision::Stale`]).
    fn take_reacquired(&mut self) -> bool {
        std::mem::take(&mut self.reacquired)
    }

    /// The connection holding the lock was discarded: the role is not
    /// assumed across connections, so the next operation re-attempts the
    /// lock on the fresh one. A dormant guard keeps its retry floor — an
    /// unrelated discard must not wake it early.
    fn connection_lost(&mut self) {
        if self.role.load() == ExecutorRole::Active {
            self.role.store(ExecutorRole::Pending);
            self.next_attempt = None;
        }
    }
}

/// Parsed `FAILOVER_QUORUM_*` wiring for the executor loop.
/// Parsed `FAILOVER_QUORUM_*` wiring for the executor loop and the
/// member-side reporting loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorEnv {
    config: FailoverConfig,
    check_interval_ms: u64,
    store_dir: PathBuf,
    probe_interval_ms: u64,
    probe_timeout_ms: u64,
    report_member_id: String,
}

impl ExecutorEnv {
    /// Parse the executor and reporting wiring. Every argument is the raw
    /// environment value; `None` means unset. `Ok(None)` means the module is
    /// disabled and the caller must not construct or spawn anything — while
    /// the flag is off nothing else is read, the store directory and the
    /// reporting variables included. Invalid values fail closed with an
    /// error instead of guessing. Nine arguments is the cost of parsing one
    /// strictly-validated variable per parameter; grouping them would let a
    /// caller pass partially-read environment state.
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        enabled: Option<&str>,
        members: Option<&str>,
        writer_site: Option<&str>,
        standby_site: Option<&str>,
        check_interval_ms: Option<&str>,
        store_dir: Option<&str>,
        probe_interval_ms: Option<&str>,
        probe_timeout_ms: Option<&str>,
        report_member_id: Option<&str>,
    ) -> Result<Option<Self>, String> {
        let policy = QuorumPolicy::parse(enabled, members)?;
        if !policy.enabled() {
            // Deliberately read nothing else while the flag is off.
            return Ok(None);
        }
        let writer_site_id = writer_site
            .filter(|site| !site.is_empty())
            .ok_or("FAILOVER_QUORUM_WRITER_SITE_ID is required when FAILOVER_QUORUM_ENABLED=true")?
            .to_owned();
        let standby_site_id = standby_site
            .filter(|site| !site.is_empty())
            .ok_or("FAILOVER_QUORUM_STANDBY_SITE_ID is required when FAILOVER_QUORUM_ENABLED=true")?
            .to_owned();
        let check_interval_ms = match check_interval_ms {
            None => DEFAULT_CHECK_INTERVAL_MS,
            Some(raw) => raw.parse::<u64>().map_err(|_| {
                "FAILOVER_QUORUM_CHECK_INTERVAL_MS must be a number of milliseconds".to_owned()
            })?,
        };
        if check_interval_ms == 0 {
            return Err("FAILOVER_QUORUM_CHECK_INTERVAL_MS must be greater than zero".to_owned());
        }
        let store_dir = store_dir
            .filter(|dir| !dir.is_empty())
            .ok_or("FAILOVER_QUORUM_STORE_DIR is required when FAILOVER_QUORUM_ENABLED=true")?
            .to_owned();
        // An operator-configured path, never a request-derived one; it must
        // still name one unambiguous location: absolute, with no `.` or `..`
        // component that could resolve somewhere other than it reads.
        // Segments are checked on the raw value (both separators), because
        // `Path::components` silently drops an interior `.`.
        let dot_segment = store_dir
            .split(['/', '\\'])
            .any(|segment| segment == "." || segment == "..");
        if !Path::new(&store_dir).is_absolute() || dot_segment {
            return Err(
                "FAILOVER_QUORUM_STORE_DIR must be an absolute path without . or .. components"
                    .to_owned(),
            );
        }
        let probe_interval_ms = match probe_interval_ms {
            // The reporting loop defaults to lockstep with the executor's
            // checks: one probe round per check round.
            None => check_interval_ms,
            Some(raw) => raw.parse::<u64>().map_err(|_| {
                "FAILOVER_QUORUM_PROBE_INTERVAL_MS must be a number of milliseconds".to_owned()
            })?,
        };
        if probe_interval_ms == 0 {
            return Err("FAILOVER_QUORUM_PROBE_INTERVAL_MS must be greater than zero".to_owned());
        }
        let probe_timeout_ms = probe_timeout_ms
            .filter(|raw| !raw.is_empty())
            .ok_or(
                "FAILOVER_QUORUM_PROBE_TIMEOUT_MS is required when FAILOVER_QUORUM_ENABLED=true",
            )?
            .parse::<u64>()
            .map_err(|_| {
                "FAILOVER_QUORUM_PROBE_TIMEOUT_MS must be a number of milliseconds".to_owned()
            })?;
        if probe_timeout_ms == 0 {
            return Err("FAILOVER_QUORUM_PROBE_TIMEOUT_MS must be greater than zero".to_owned());
        }
        let report_member_id = report_member_id
            .filter(|member| !member.is_empty())
            .ok_or(
                "FAILOVER_QUORUM_REPORT_MEMBER_ID is required when FAILOVER_QUORUM_ENABLED=true",
            )?
            .to_owned();
        if !policy.members().contains(&report_member_id) {
            return Err(
                "FAILOVER_QUORUM_REPORT_MEMBER_ID must be one of the configured \
                 FAILOVER_QUORUM_MEMBERS"
                    .to_owned(),
            );
        }
        let config =
            FailoverConfig::new(policy.members().to_vec(), writer_site_id, standby_site_id)?;
        Ok(Some(Self {
            config,
            check_interval_ms,
            store_dir: PathBuf::from(store_dir),
            probe_interval_ms,
            probe_timeout_ms,
            report_member_id,
        }))
    }

    /// The validated failover configuration.
    pub fn config(&self) -> &FailoverConfig {
        &self.config
    }

    /// The check-round interval.
    pub fn check_interval_ms(&self) -> u64 {
        self.check_interval_ms
    }

    /// The consensus store directory observations are journaled under.
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// The reporting loop's probe interval.
    pub fn probe_interval_ms(&self) -> u64 {
        self.probe_interval_ms
    }

    /// The timeout enforced by the optional production probe source.
    pub fn probe_timeout_ms(&self) -> u64 {
        self.probe_timeout_ms
    }

    /// The member identity this instance's reporting loop reports as.
    pub fn report_member_id(&self) -> &str {
        &self.report_member_id
    }
}

/// Failures of the PostgreSQL writer-authority port.
#[derive(Debug, thiserror::Error)]
pub enum PgAuthorityError {
    #[error("PostgreSQL connection failed: {0}")]
    Connect(#[from] zrotext_postgres_connection::ConnectError),
    #[error("PostgreSQL connection did not open within {0:?}")]
    ConnectTimedOut(Duration),
    #[error("writer authority operation failed: {0}")]
    Database(#[from] tokio_postgres::Error),
    #[error("writer authority operation did not finish within {0:?}")]
    OperationTimedOut(Duration),
    #[error(
        "another replica's executor holds the singleton advisory lock; this executor is dormant \
         and performs no authority writes"
    )]
    ExecutorDormant,
    #[error(
        "the singleton advisory lock was re-acquired for this connection; the operation fails \
         closed until the executor reloads authoritative state, because intent cached from the \
         previous exclusive period may be stale"
    )]
    ExecutorLockReacquired,
    #[error("deployment_authority.epoch is outside the executor's domain: {0}")]
    EpochOutOfRange(i64),
}

/// One boxed authority-operation future. The box is what lets an operation
/// borrow the dedicated client (`&mut`) while [`PgWriterAuthority::call`]
/// stays a single generic entry point; async closures would express this
/// natively but are not stable.
type BoxedOperation<'a, T> = Pin<Box<dyn Future<Output = Result<T, PgAuthorityError>> + 'a>>;

/// Outcome of opening the dedicated connection on a guarded port: the
/// connection is ready for the triggering operation, or the singleton lock
/// was (re-)acquired on it — see [`LockAttempt::AcquiredAgain`] for why the
/// triggering operation must then fail closed even though the connection
/// itself is healthy and retained.
enum OpenedConnection {
    /// The connection holds the lock (or the port has no guard): the
    /// triggering operation may run on it.
    Ready(tokio_postgres::Client),
    /// The lock was re-acquired on this connection, which is retained in
    /// the port: the triggering operation is failed closed instead of run.
    AcquiredOnOpen,
}

/// PostgreSQL implementation of the `WriterAuthority` port. One dedicated,
/// long-lived connection on a private single-threaded runtime: opened under
/// [`CONNECT_CEILING`], reused across operations, and discarded and reopened
/// (after a small random pause) whenever an operation fails, so the next
/// operation always starts from a known-good transport.
pub struct PgWriterAuthority {
    database_url: String,
    runtime: tokio::runtime::Runtime,
    /// The retained client handle: `None` until the first operation, and
    /// while a broken connection awaits its jittered reconnect.
    client: Option<tokio_postgres::Client>,
    /// The runtime task driving the retained client's socket.
    driver: Option<tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>>,
    /// Set by every failed operation and failed connect: the next operation
    /// first waits out a jittered pause and opens a fresh connection.
    reconnect_pending: bool,
    /// The advisory-lock key this instance contends on. Production always
    /// uses [`EXECUTOR_ADVISORY_LOCK_KEY`]; the test seam lets parallel
    /// PostgreSQL tests isolate from each other with unique keys, because
    /// advisory locks are per-database, not per-schema.
    lock_key: i64,
    /// The singleton-executor advisory-lock guard: `None` on a plain port,
    /// which never attempts the lock, and `Some` on an executor-guarded
    /// port, whose every connection must acquire the lock before its
    /// operations run.
    guard: Option<SingletonExecutorGuard>,
    /// Test seam: how many connections this instance has opened, so tests
    /// can assert the one-connection contract directly.
    #[cfg(test)]
    connections_opened: u32,
}

impl PgWriterAuthority {
    /// Build the port. Fails only when the local runtime cannot be created;
    /// the connection itself is opened lazily by the first operation.
    pub fn new(database_url: String) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("failover executor runtime: {error}"))?;
        Ok(Self {
            database_url,
            runtime,
            client: None,
            driver: None,
            reconnect_pending: false,
            lock_key: EXECUTOR_ADVISORY_LOCK_KEY,
            guard: None,
            #[cfg(test)]
            connections_opened: 0,
        })
    }

    /// Build the port guarded by the singleton-executor advisory lock: the
    /// port's dedicated connection must acquire
    /// `pg_try_advisory_lock(EXECUTOR_ADVISORY_LOCK_KEY)` when it opens —
    /// and again after every reconnect, because a session-level lock dies
    /// with its session — or the port stays dormant, failing every
    /// operation closed until a later attempt succeeds. `lock_retry_interval`
    /// paces dormant retries (the executor wiring passes its check
    /// interval, so lock retries ride the check rounds). The returned role
    /// cell is the wiring loop's window onto the guard for change logging.
    fn new_for_executor(
        database_url: String,
        lock_retry_interval: Duration,
    ) -> Result<(Self, SharedExecutorRole), String> {
        let mut port = Self::new(database_url)?;
        let (guard, role) = SingletonExecutorGuard::new(lock_retry_interval);
        port.guard = Some(guard);
        Ok((port, role))
    }

    /// Test seam: [`Self::new_for_executor`] with an explicit advisory-lock
    /// key. Production wiring always contends on
    /// [`EXECUTOR_ADVISORY_LOCK_KEY`]; parallel tests that share one CI
    /// database pass a unique key so their executors cannot fence each
    /// other across test boundaries (advisory locks are per-database, so
    /// schemas do not isolate them).
    #[cfg(test)]
    fn new_for_executor_with_lock_key(
        database_url: String,
        lock_retry_interval: Duration,
        lock_key: i64,
    ) -> Result<(Self, SharedExecutorRole), String> {
        let mut port = Self::new(database_url)?;
        let (guard, role) = SingletonExecutorGuard::new(lock_retry_interval);
        port.lock_key = lock_key;
        port.guard = Some(guard);
        Ok((port, role))
    }

    /// Run one operation on the dedicated connection under the production
    /// wait ceiling.
    fn call<T>(
        &mut self,
        operation: impl for<'a> FnOnce(&'a mut tokio_postgres::Client) -> BoxedOperation<'a, T>,
    ) -> Result<T, PgAuthorityError> {
        self.call_bounded(OPERATION_CEILING, operation)
    }

    /// [`Self::call`] with an explicit wait ceiling, so a test can prove the
    /// bound without waiting out [`OPERATION_CEILING`].
    fn call_bounded<T>(
        &mut self,
        ceiling: Duration,
        operation: impl for<'a> FnOnce(&'a mut tokio_postgres::Client) -> BoxedOperation<'a, T>,
    ) -> Result<T, PgAuthorityError> {
        // Dormancy and staleness are checked before anything else — a
        // dormant replica performs no authority writes and never even opens
        // a connection, and a re-acquired lock runs nothing until the owner
        // acknowledged the reload — and both fail closed without disturbing
        // the pending-reconnect state, which still applies once they end.
        if let Some(guard) = self.guard.as_mut() {
            match guard.poll(Instant::now()) {
                GuardDecision::Dormant => return Err(PgAuthorityError::ExecutorDormant),
                GuardDecision::Stale => return Err(PgAuthorityError::ExecutorLockReacquired),
                GuardDecision::Proceed => {}
            }
        }
        if self.reconnect_pending {
            // The previous failure left the connection unusable; discard it
            // and pause briefly (randomized) before touching the database
            // again, so recoveries from a shared writer bounce do not
            // reconnect in lockstep. The failed operation itself has already
            // returned its error; nothing is retried inside the port.
            self.discard_connection();
            self.reconnect_pending = false;
            std::thread::sleep(reconnect_jitter());
        }
        let mut client = match self.client.take() {
            Some(client) => client,
            None => match self.open_connection(CONNECT_CEILING)? {
                // The lock was re-acquired on the very connection this
                // operation paid for. The connection (and its lock) is
                // retained, but the operation does not run: it may carry
                // intent cached from the previous exclusive period, and the
                // guard now fails every operation closed until the executor
                // reloaded authoritative state from the database.
                OpenedConnection::AcquiredOnOpen => {
                    return Err(PgAuthorityError::ExecutorLockReacquired);
                }
                OpenedConnection::Ready(client) => client,
            },
        };
        // The client is lent to the operation only inside this block_on:
        // the port's runtime drives the operation and the socket together,
        // and the connection is never held across an await that is not the
        // port's own.
        let result = self
            .runtime
            .block_on(wait_bounded(ceiling, operation(&mut client)));
        match result {
            Ok(value) => {
                self.client = Some(client);
                Ok(value)
            }
            Err(error) => {
                // Any failure may have broken the socket — a timeout can
                // even have left it mid-response — so the connection is
                // discarded and the next operation reconnects. This
                // operation fails closed exactly as it would have on a
                // per-operation connection.
                self.discard_connection();
                self.reconnect_pending = true;
                Err(error)
            }
        }
    }

    /// Open the dedicated connection under `ceiling` and start its driver
    /// task. A failure still marks a jittered reconnect before the next
    /// operation, so even a connect attempt cannot hang the executor.
    fn open_connection(&mut self, ceiling: Duration) -> Result<OpenedConnection, PgAuthorityError> {
        let url = self.database_url.clone();
        let opened = self.runtime.block_on(async move {
            let connecting = zrotext_postgres_connection::connect(&url);
            match tokio::time::timeout(ceiling, connecting).await {
                Ok(connected) => {
                    let (client, connection) = connected?;
                    // The driver task lives on the port's own runtime and
                    // stays alive between operations; it ends — as before —
                    // when the last client handle goes away.
                    let driver = tokio::spawn(connection);
                    Ok((client, driver))
                }
                Err(_elapsed) => Err(PgAuthorityError::ConnectTimedOut(ceiling)),
            }
        });
        match opened {
            Ok((client, driver)) => {
                self.discard_connection();
                self.driver = Some(driver);
                #[cfg(test)]
                {
                    self.connections_opened = self.connections_opened.saturating_add(1);
                }
                match self.acquire_executor_lock(&client) {
                    Ok(LockAttempt::AcquiredFirst) => Ok(OpenedConnection::Ready(client)),
                    Ok(LockAttempt::AcquiredAgain) => {
                        // The re-acquired connection is kept — its lock is
                        // exactly what the executor needs — but the
                        // triggering operation is failed closed by the
                        // caller: it may carry intent cached from the
                        // previous exclusive period. No reconnect flag is
                        // set: the transport is healthy, and the guard's
                        // stale verdict already fails every operation
                        // closed until the reload is acknowledged.
                        self.client = Some(client);
                        Ok(OpenedConnection::AcquiredOnOpen)
                    }
                    Ok(LockAttempt::Refused) => {
                        // The connection is healthy but worthless without
                        // the lock: discard it and fail the operation
                        // closed. No reconnect flag is set — the transport
                        // did not fail, and the guard's retry floor already
                        // paces the next attempt.
                        self.discard_connection();
                        Err(PgAuthorityError::ExecutorDormant)
                    }
                    Err(error) => {
                        self.discard_connection();
                        self.reconnect_pending = true;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                self.reconnect_pending = true;
                Err(error)
            }
        }
    }

    /// Try to take the singleton-executor advisory lock on `client` under
    /// the connect ceiling and record the outcome in the guard. This is the
    /// seam where the lock and the authority meet: it runs on the very
    /// connection later operations ride, so the lock's lifetime is the
    /// connection's lifetime — the guard re-attempts it after every
    /// reconnect, and the executor role fails over with the connection,
    /// with no lease to renew. A re-acquisition (a previous exclusive
    /// period exists) additionally latches the reload signal the guard
    /// serves until the executor acknowledges it. A plain port (no guard)
    /// always proceeds.
    fn acquire_executor_lock(
        &mut self,
        client: &tokio_postgres::Client,
    ) -> Result<LockAttempt, PgAuthorityError> {
        let Some(guard) = self.guard.as_mut() else {
            return Ok(LockAttempt::AcquiredFirst);
        };
        let key = self.lock_key;
        let attempted = self.runtime.block_on(wait_bounded(CONNECT_CEILING, async {
            let row = client
                .query_one("SELECT pg_try_advisory_lock($1)", &[&key])
                .await?;
            Ok(row.get::<_, bool>(0))
        }));
        match attempted {
            Ok(acquired) => Ok(guard.resolved(acquired, Instant::now())),
            Err(error) => Err(error),
        }
    }

    /// Drop the retained connection and stop its driver task.
    fn discard_connection(&mut self) {
        self.client = None;
        if let Some(guard) = self.guard.as_mut() {
            // The lock died with the connection: the next operation must
            // re-attempt it on the fresh one instead of assuming the role.
            guard.connection_lost();
        }
        if let Some(driver) = self.driver.take() {
            // Abort rather than detach: a wedged socket must not outlive the
            // decision to discard it.
            driver.abort();
            // A current-thread runtime only runs inside `block_on`, so the
            // abort is otherwise processed — the dropped task closes the
            // socket, releasing the server-side backend and any advisory
            // lock it holds — at the next operation, not now. One yield
            // pumps the runtime immediately: a replica discarding its
            // connection, a dormant one above all, must not keep a backend
            // alive while it does nothing.
            self.runtime.block_on(tokio::task::yield_now());
        }
    }
}

/// Await one operation under its wait ceiling. A timeout is a *failed*
/// operation, not a retry trigger: the executor's decisions are idempotent —
/// pending ones replay through the durable journal, and the promote
/// transaction's epoch compare-and-set makes an interrupted promote (say, a
/// timeout after the commit was sent but before the reply was read) safe to
/// replay on a later tick, converging instead of double-applying.
async fn wait_bounded<T, Fut>(ceiling: Duration, operation: Fut) -> Result<T, PgAuthorityError>
where
    Fut: Future<Output = Result<T, PgAuthorityError>>,
{
    match tokio::time::timeout(ceiling, operation).await {
        Ok(result) => result,
        Err(_elapsed) => Err(PgAuthorityError::OperationTimedOut(ceiling)),
    }
}

/// A random reconnect pause in `[0, RECONNECT_JITTER_CEILING)`. Std-only
/// randomness: `RandomState` is seeded from the OS, so hashing the current
/// nanosecond through a fresh one draws unpredictably without a new
/// dependency.
fn reconnect_jitter() -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|moment| moment.subsec_nanos() as u64)
        .unwrap_or(0);
    let mut draw = RandomState::new().build_hasher();
    draw.write_u64(nanos);
    Duration::from_nanos(draw.finish() % RECONNECT_JITTER_CEILING.as_nanos() as u64)
}

impl WriterAuthority for PgWriterAuthority {
    type Error = PgAuthorityError;

    fn load_state(
        &mut self,
        writer_site: &str,
        standby_site: &str,
    ) -> Result<AuthoritySnapshot, Self::Error> {
        let writer_site = writer_site.to_owned();
        let standby_site = standby_site.to_owned();
        self.call(move |client| {
            Box::pin(async move {
                let row = client
                    .query_one(
                        "SELECT p.epoch, p.dispatch_enabled, wa.enabled, wa.draining, \
                         st.enabled, st.draining \
                         FROM deployment_authority p \
                         LEFT JOIN sites wa ON wa.site_id=$1 \
                         LEFT JOIN sites st ON st.site_id=$2 \
                         WHERE p.singleton=TRUE",
                        &[&writer_site, &standby_site],
                    )
                    .await?;
                let epoch: i64 = row.get(0);
                let epoch =
                    u64::try_from(epoch).map_err(|_| PgAuthorityError::EpochOutOfRange(epoch))?;
                let site = |enabled: Option<bool>, draining: Option<bool>| {
                    enabled
                        .zip(draining)
                        .map(|(enabled, draining)| SiteFenceState { enabled, draining })
                };
                let writer_enabled: Option<bool> = row.try_get(2).unwrap_or(None);
                let writer_draining: Option<bool> = row.try_get(3).unwrap_or(None);
                let standby_enabled: Option<bool> = row.try_get(4).unwrap_or(None);
                let standby_draining: Option<bool> = row.try_get(5).unwrap_or(None);
                Ok(AuthoritySnapshot {
                    epoch,
                    dispatch_enabled: row.get(1),
                    writer_site: site(writer_enabled, writer_draining),
                    standby_site: site(standby_enabled, standby_draining),
                })
            })
        })
    }

    fn fence_writer_site(&mut self, site_id: &str) -> Result<FenceOutcome, Self::Error> {
        let site_id = site_id.to_owned();
        self.call(move |client| {
            Box::pin(async move {
                let row = client
                    .query_opt(
                        "SELECT enabled, draining FROM sites WHERE site_id=$1",
                        &[&site_id],
                    )
                    .await?;
                let Some(row) = row else {
                    return Ok(FenceOutcome::SiteRowMissing);
                };
                let enabled: bool = row.get(0);
                let draining: bool = row.get(1);
                if !enabled || draining {
                    return Ok(FenceOutcome::AlreadyFenced);
                }
                client
                    .execute(
                        "UPDATE sites SET draining=TRUE WHERE site_id=$1",
                        &[&site_id],
                    )
                    .await?;
                Ok(FenceOutcome::Fenced)
            })
        })
    }

    fn promote_standby(
        &mut self,
        promoted_site: &str,
        fenced_writer_site: &str,
        new_epoch: u64,
    ) -> Result<PromoteOutcome, Self::Error> {
        let promoted_site = promoted_site.to_owned();
        let fenced_writer_site = fenced_writer_site.to_owned();
        let new_epoch_i64 =
            i64::try_from(new_epoch).map_err(|_| PgAuthorityError::EpochOutOfRange(i64::MAX))?;
        self.call(move |client| {
            Box::pin(async move {
                let transaction = client.transaction().await?;
                // Hold the authority row so a concurrent manual bump either
                // happens before this read or after our commit.
                let authority = transaction
                    .query_one(
                        "SELECT epoch FROM deployment_authority WHERE singleton=TRUE FOR UPDATE",
                        &[],
                    )
                    .await?;
                let current: i64 = authority.get(0);
                if current > new_epoch_i64 {
                    transaction.rollback().await?;
                    return Ok(PromoteOutcome::RefusedHigherEpoch {
                        current: u64::try_from(current)
                            .map_err(|_| PgAuthorityError::EpochOutOfRange(current))?,
                    });
                }
                // The promotion is conditional on the old writer's site row
                // still showing a fence, held against concurrent changes. The
                // checks run before the equal-epoch answer too: an external
                // same-epoch bump is only ever confirmed together with the
                // full promoted state, never with dispatch still enabled.
                let fenced = transaction
                    .query_opt(
                        "SELECT 1 FROM sites WHERE site_id=$1 AND (NOT enabled OR draining) \
                         FOR SHARE",
                        &[&fenced_writer_site],
                    )
                    .await?;
                if fenced.is_none() {
                    transaction.rollback().await?;
                    return Ok(PromoteOutcome::RefusedWriterUnfenced);
                }
                let promoted = transaction
                    .query_opt("SELECT 1 FROM sites WHERE site_id=$1", &[&promoted_site])
                    .await?;
                if promoted.is_none() {
                    transaction.rollback().await?;
                    return Ok(PromoteOutcome::SiteRowMissing);
                }
                transaction
                    .execute(
                        "UPDATE sites SET enabled=TRUE WHERE site_id=$1",
                        &[&promoted_site],
                    )
                    .await?;
                // At an equal epoch this write is the idempotent convergence:
                // the epoch stays put and dispatch is forced paused.
                transaction
                    .execute(
                        "UPDATE deployment_authority SET epoch=$1, dispatch_enabled=FALSE \
                         WHERE singleton=TRUE",
                        &[&new_epoch_i64],
                    )
                    .await?;
                transaction.commit().await?;
                Ok(if current == new_epoch_i64 {
                    PromoteOutcome::AlreadyAtEpoch
                } else {
                    PromoteOutcome::Promoted
                })
            })
        })
    }

    fn save_controller_state(&mut self, encoded: &str) -> Result<(), Self::Error> {
        let encoded = encoded.to_owned();
        self.call(move |client| {
            Box::pin(async move {
                client
                    .execute(
                        "INSERT INTO failover_controller_state (singleton, state) VALUES \
                         (TRUE, $1) ON CONFLICT (singleton) DO UPDATE \
                         SET state=EXCLUDED.state, updated_at=now()",
                        &[&encoded],
                    )
                    .await?;
                Ok(())
            })
        })
    }

    fn load_controller_state(&mut self) -> Result<Option<String>, Self::Error> {
        self.call(|client| {
            Box::pin(async move {
                let row = client
                    .query_opt(
                        "SELECT state FROM failover_controller_state WHERE singleton=TRUE",
                        &[],
                    )
                    .await?;
                Ok(row.map(|row| row.get(0)))
            })
        })
    }

    fn exclusivity_reacquired(&mut self) -> bool {
        self.guard
            .as_mut()
            .is_some_and(SingletonExecutorGuard::take_reacquired)
    }
}

/// Open the executor's consensus store. A store that cannot open — corrupt,
/// truncated, foreign membership, unwritable — fails the executor closed
/// rather than serving uncertain evidence: the failure is logged and
/// `healthy` is cleared so readiness reports it to operators until a restart
/// (or an operator repair of the directory and a restart).
fn open_consensus_store(env: &ExecutorEnv, healthy: &AtomicBool) -> Option<ConsensusStore> {
    match ConsensusStore::open(
        env.store_dir(),
        env.config().members().to_vec(),
        env.config().observation_freshness_ms(),
    ) {
        Ok(store) => Some(store),
        Err(error) => {
            healthy.store(false, Ordering::Release);
            eprintln!(
                "failover quorum executor: consensus store at {} failed to open: {error}; \
                 the executor is not running and readiness reports failover_executor_failed",
                env.store_dir().display()
            );
            None
        }
    }
}

/// The store handle shared by the executor thread (reads rounds) and the
/// reporting thread (appends reports): one [`ConsensusStore`], one lock, so
/// the store stays the only writer of its journals while both loops run.
type SharedStore = Arc<Mutex<ConsensusStore>>;

/// Serves executor rounds from the shared store with exactly the
/// [`zrotext_failover_quorum::store::StoreObservationSource`] semantics:
/// each collect serves only the fresh records appended since the last
/// record served per member (a high-water sequence), so a report counts in
/// at most one check round.
struct SharedStoreSource {
    store: SharedStore,
    served: HashMap<String, u64>,
}

impl SharedStoreSource {
    fn new(store: SharedStore) -> Self {
        Self {
            store,
            served: HashMap::new(),
        }
    }
}

impl ObservationSource for SharedStoreSource {
    fn collect(&mut self, now_ms: u64) -> Round {
        let store = self
            .store
            .lock()
            .expect("the consensus store mutex was poisoned");
        store.unserved_round(now_ms, &mut self.served)
    }
}

/// The deterministic placeholder behind the reporting loop's
/// `ProbeSource` seam: every probe is indeterminate, so the observer
/// abstains every round and the loop records nothing. No production probe
/// source exists in this build — a real one (writer epoch read, site fence,
/// watchdog stop confirmation, standby readiness, former-writer health,
/// bounded by `FAILOVER_QUORUM_PROBE_TIMEOUT_MS`) is deliberately deferred;
/// an abstaining member is the fail-closed stand-in, never fabricated
/// evidence.
struct AbstainingProbeSource;

impl ProbeSource for AbstainingProbeSource {
    fn probe(&mut self) -> RoundProbes {
        RoundProbes {
            writer: WriterProbe::Indeterminate,
            writer_site_fence: Err(ProbeFault::Indeterminate),
            writer_stop: Err(ProbeFault::Indeterminate),
            standby: Err(ProbeFault::Indeterminate),
            former_writer: Err(ProbeFault::Indeterminate),
        }
    }
}

/// Spawn the member-side reporting thread: one probe round per
/// `FAILOVER_QUORUM_PROBE_INTERVAL_MS`, formed by the crate's observer and
/// recorded through the store sink until `shutdown` is set (the same
/// graceful-drain flag the executor loop obeys). A sticky sink failure — the
/// loop fails closed for reporting and keeps probing — is logged once; it
/// does not clear `healthy`: a reporter that records nothing can only lose
/// quorum and hold (never fabricate evidence), so it stays a log-line
/// condition, cleared by a process restart.
fn spawn_failover_reporter(
    env: ExecutorEnv,
    store: SharedStore,
    shutdown: Arc<AtomicBool>,
    adapters: Option<crate::failover_adapters::Adapters>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("failover-quorum-reporter".to_owned())
        .spawn(move || {
            eprintln!(
                "failover quorum reporter running (reporting as {} every {}ms, {}ms probe \
                 timeout; authenticated adapters configured={})",
                env.report_member_id(),
                env.probe_interval_ms(),
                env.probe_timeout_ms(),
                adapters.is_some(),
            );
            let observer = MemberObserver::new(env.report_member_id())
                .expect("the report member id was validated at parse");
            if let Some(adapters) = adapters {
                let (probes, sink) = adapters.into_ports(store);
                run_reporting_loop(ReportLoop::new(observer, probes, sink), &env, &shutdown);
                return;
            }
            let mut reporting = ReportLoop::new(
                observer,
                AbstainingProbeSource,
                ConsensusStoreSink::new(store),
            );
            let interval = Duration::from_millis(env.probe_interval_ms());
            let mut failure_logged = false;
            loop {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                match reporting.run_round(now_ms()) {
                    RoundOutcome::SinkFailed if !failure_logged => {
                        eprintln!(
                            "failover quorum reporter: recording a report failed; reporting is \
                             fail-closed until the process restarts (probes continue, the \
                             executor can only lose quorum and hold)"
                        );
                        failure_logged = true;
                    }
                    _ => {}
                }
                std::thread::sleep(interval);
            }
        })
        .expect("spawn failover-quorum-reporter thread")
}

/// The threads of the enabled failover wiring: the executor loop applying
/// decisions, and the member-side reporter recording rounds into the same
/// store. Both stop at the shared drain flag.
pub struct FailoverExecutorThreads {
    pub executor: std::thread::JoinHandle<()>,
    pub reporter: std::thread::JoinHandle<()>,
}

/// One log line per executor-role change, `None` when the role has not
/// changed (or nothing has been observed yet): a dormant replica logs its
/// dormancy once — not once per retry — and an acquisition logs the running
/// banner exactly once per acquisition, takeover included.
fn role_change_log(
    previous: Option<ExecutorRole>,
    current: ExecutorRole,
    env: &ExecutorEnv,
) -> Option<String> {
    if previous == Some(current) || current == ExecutorRole::Pending {
        return None;
    }
    match current {
        ExecutorRole::Dormant => Some(format!(
            "failover quorum executor is dormant: another replica holds the singleton advisory \
             lock; no authority writes from this replica, retrying every {}ms",
            env.check_interval_ms()
        )),
        ExecutorRole::Active => Some(format!(
            "failover quorum executor acquired the singleton advisory lock and is running \
             ({} members, writer site {}, standby site {}, {}ms checks, store {}); the controller \
             uses only fresh authenticated observations",
            env.config().members().len(),
            env.config().writer_site_id(),
            env.config().standby_site_id(),
            env.check_interval_ms(),
            env.store_dir().display(),
        )),
        ExecutorRole::Pending => None,
    }
}
/// Spawn the failover executor and reporter threads. `None` env (the
/// default) spawns nothing at all and never touches `healthy`; `Some` runs
/// the controller loop and the reporting loop until `shutdown` is set or
/// the process exits. The executor is a per-database singleton: the
/// authority's dedicated connection must hold
/// [`EXECUTOR_ADVISORY_LOCK_KEY`], so a replica that loses the race stays
/// dormant — logging once, performing no authority writes, and leaving
/// readiness untouched, exactly like a replica without an executor — and
/// takes over when the previous owner's connection dies. One store
/// instance is shared by both loops; it is opened before any thread runs
/// so a directory that cannot serve this quorum clears `healthy` and
/// spawns nothing, and a writer-authority port that cannot be built
/// clears `healthy` from inside the executor thread. The handles are
/// intentionally detached-style: both loops are best-effort and never
/// block process exit.
pub fn spawn_failover_executor(
    env: Option<ExecutorEnv>,
    database_url: String,
    shutdown: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
) -> Option<FailoverExecutorThreads> {
    spawn_failover_executor_with_adapters(env, database_url, shutdown, healthy, None)
}

pub fn spawn_failover_executor_with_adapters(
    env: Option<ExecutorEnv>,
    database_url: String,
    shutdown: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    adapters: Option<crate::failover_adapters::Adapters>,
) -> Option<FailoverExecutorThreads> {
    let env = env?;
    let store = open_consensus_store(&env, &healthy)?;
    let store: SharedStore = Arc::new(Mutex::new(store));
    let reporter = spawn_failover_reporter(env.clone(), store.clone(), shutdown.clone(), adapters);
    let executor = std::thread::Builder::new()
        .name("failover-quorum-executor".to_owned())
        .spawn(move || {
            let (authority, role) = match PgWriterAuthority::new_for_executor(
                database_url,
                Duration::from_millis(env.check_interval_ms()),
            ) {
                Ok(pair) => pair,
                Err(error) => {
                    healthy.store(false, Ordering::Release);
                    eprintln!(
                        "failover quorum executor: {error}; the executor is not running and                          readiness reports failover_executor_failed"
                    );
                    return;
                }
            };
            let mut executor = FailoverExecutor::new(
                env.config().clone(),
                SharedStoreSource::new(store),
                authority,
            );
            let interval = Duration::from_millis(env.check_interval_ms());
            let mut last_status = None;
            let mut last_role = None;
            loop {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                executor.tick(now_ms());
                let status = executor.status().clone();
                if last_status.as_ref() != Some(&status) {
                    eprintln!("failover quorum executor status: {status:?}");
                    last_status = Some(status);
                }
                let current_role = role.load();
                if let Some(line) = role_change_log(last_role, current_role, &env) {
                    eprintln!("{line}");
                }
                last_role = Some(current_role);
                std::thread::sleep(interval);
            }
        })
        .expect("spawn failover-quorum-executor thread");
    Some(FailoverExecutorThreads { executor, reporter })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn run_reporting_loop<P: ProbeSource, S: zrotext_failover_quorum::report::ObservationSink>(
    mut reporting: ReportLoop<P, S>,
    env: &ExecutorEnv,
    shutdown: &AtomicBool,
) {
    let mut failure_logged = false;
    while !shutdown.load(Ordering::Acquire) {
        if reporting.run_round(now_ms()) == RoundOutcome::SinkFailed && !failure_logged {
            eprintln!("failover quorum reporter: recording failed; reporting holds until restart");
            failure_logged = true;
        }
        std::thread::sleep(Duration::from_millis(env.probe_interval_ms()));
    }
}

#[cfg(test)]
mod tests;
