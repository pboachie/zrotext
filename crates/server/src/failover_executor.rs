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
//! `zrotext_failover_quorum::executor::WriterAuthority` port. It opens one
//! dedicated connection per operation (the executor must survive writer
//! restarts and writer moves, and its call rate is one small query set per
//! tick) on its own single-threaded runtime, because the executor itself is
//! synchronous and deliberately independent of the main async runtime.
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
//! its journals. No production probe source exists in this build: the
//! deterministic placeholder behind the `ProbeSource` seam abstains every
//! round, so nothing is recorded in production and every round still holds
//! fail-closed until that probe lands (a documented follow-up).

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

    /// The probe timeout the (future) production probe source will enforce.
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
    #[error("writer authority operation failed: {0}")]
    Database(#[from] tokio_postgres::Error),
    #[error("deployment_authority.epoch is outside the executor's domain: {0}")]
    EpochOutOfRange(i64),
}

/// PostgreSQL implementation of the `WriterAuthority` port. One connection
/// per operation on a private single-threaded runtime.
pub struct PgWriterAuthority {
    database_url: String,
    runtime: tokio::runtime::Runtime,
}

impl PgWriterAuthority {
    /// Build the port. Fails only when the local runtime cannot be created.
    pub fn new(database_url: String) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("failover executor runtime: {error}"))?;
        Ok(Self {
            database_url,
            runtime,
        })
    }

    fn call<T, F, Fut>(&mut self, operation: F) -> Result<T, PgAuthorityError>
    where
        F: FnOnce(tokio_postgres::Client) -> Fut,
        Fut: Future<Output = Result<T, PgAuthorityError>>,
    {
        let url = self.database_url.clone();
        self.runtime.block_on(async move {
            let (client, connection) = zrotext_postgres_connection::connect(&url).await?;
            let driver = tokio::spawn(connection);
            // The client is consumed by the operation; when it drops, the
            // driver ends with a Closed error that does not matter here.
            let result = operation(client).await;
            let _ = driver.await;
            result
        })
    }
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
        self.call(move |client| async move {
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
    }

    fn fence_writer_site(&mut self, site_id: &str) -> Result<FenceOutcome, Self::Error> {
        let site_id = site_id.to_owned();
        self.call(move |client| async move {
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
        self.call(move |mut client| async move {
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
                    "SELECT 1 FROM sites WHERE site_id=$1 AND (NOT enabled OR draining) FOR SHARE",
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
    }

    fn save_controller_state(&mut self, encoded: &str) -> Result<(), Self::Error> {
        let encoded = encoded.to_owned();
        self.call(move |client| async move {
            client
                .execute(
                    "INSERT INTO failover_controller_state (singleton, state) VALUES (TRUE, $1) \
                     ON CONFLICT (singleton) DO UPDATE \
                     SET state=EXCLUDED.state, updated_at=now()",
                    &[&encoded],
                )
                .await?;
            Ok(())
        })
    }

    fn load_controller_state(&mut self) -> Result<Option<String>, Self::Error> {
        self.call(|client| async move {
            let row = client
                .query_opt(
                    "SELECT state FROM failover_controller_state WHERE singleton=TRUE",
                    &[],
                )
                .await?;
            Ok(row.map(|row| row.get(0)))
        })
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
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("failover-quorum-reporter".to_owned())
        .spawn(move || {
            eprintln!(
                "failover quorum reporter running (reporting as {} every {}ms, {}ms probe \
                 timeout; no production probe source in this build, so every round abstains \
                 and nothing is recorded)",
                env.report_member_id(),
                env.probe_interval_ms(),
                env.probe_timeout_ms(),
            );
            let observer = MemberObserver::new(env.report_member_id())
                .expect("the report member id was validated at parse");
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

/// Spawn the failover executor and reporter threads. `None` env (the
/// default) spawns nothing at all and never touches `healthy`; `Some` runs
/// the controller loop and the reporting loop until `shutdown` is set or
/// the process exits. If the wiring cannot start — the consensus store
/// cannot open (corrupt, foreign membership, unwritable) — `healthy` is
/// cleared and nothing is spawned, so the failure is visible to operators
/// through readiness rather than only as a log line; a writer-authority
/// port that cannot be built clears `healthy` from inside the executor
/// thread. The handles are intentionally detached-style: both loops are
/// best-effort and never block process exit.
pub fn spawn_failover_executor(
    env: Option<ExecutorEnv>,
    database_url: String,
    shutdown: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
) -> Option<FailoverExecutorThreads> {
    let env = env?;
    // One store instance is shared by both loops; it is opened here so a
    // directory that cannot serve this quorum fails before any thread runs.
    let store = open_consensus_store(&env, &healthy)?;
    let store: SharedStore = Arc::new(Mutex::new(store));
    let reporter = spawn_failover_reporter(env.clone(), store.clone(), shutdown.clone());
    let executor = std::thread::Builder::new()
        .name("failover-quorum-executor".to_owned())
        .spawn(move || {
            let authority = match PgWriterAuthority::new(database_url) {
                Ok(authority) => authority,
                Err(error) => {
                    healthy.store(false, Ordering::Release);
                    eprintln!(
                        "failover quorum executor: {error}; the executor is not running and \
                         readiness reports failover_executor_failed"
                    );
                    return;
                }
            };
            eprintln!(
                "failover quorum executor running ({} members, writer site {}, standby site {}, \
                 {}ms checks, store {}, reporter {} every {}ms); the reporter has no \
                 production probe source in this build, so the store stays empty and rounds hold",
                env.config().members().len(),
                env.config().writer_site_id(),
                env.config().standby_site_id(),
                env.check_interval_ms(),
                env.store_dir().display(),
                env.report_member_id(),
                env.probe_interval_ms(),
            );
            let mut executor = FailoverExecutor::new(
                env.config().clone(),
                SharedStoreSource::new(store),
                authority,
            );
            let interval = Duration::from_millis(env.check_interval_ms());
            let mut last_status = None;
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

#[cfg(test)]
mod tests;
