// SPDX-License-Identifier: AGPL-3.0-only
//! Server wiring for the independent-quorum failover executor.
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
//! window. No transport carries member reports into it in this build, so
//! the store stays empty and every round holds fail-closed; a store that is
//! corrupt, truncated or belongs to another membership fails the executor
//! closed at startup instead of serving uncertain evidence (see
//! `docs/MULTI-LOCATION.md`).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zrotext_failover_quorum::decision::{FailoverConfig, SiteFenceState};
use zrotext_failover_quorum::executor::{
    AuthoritySnapshot, FailoverExecutor, FenceOutcome, PromoteOutcome, WriterAuthority,
};
use zrotext_failover_quorum::policy::QuorumPolicy;
use zrotext_failover_quorum::store::{ConsensusStore, StoreObservationSource};

/// Default `FAILOVER_QUORUM_CHECK_INTERVAL_MS`.
pub const DEFAULT_CHECK_INTERVAL_MS: u64 = 5_000;

/// Parsed `FAILOVER_QUORUM_*` wiring for the executor loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorEnv {
    config: FailoverConfig,
    check_interval_ms: u64,
    store_dir: PathBuf,
}

impl ExecutorEnv {
    /// Parse the executor wiring. Every argument is the raw environment
    /// value; `None` means unset. `Ok(None)` means the module is disabled
    /// and the caller must not construct or spawn anything — while the flag
    /// is off nothing else is read, the store directory included. Invalid
    /// values fail closed with an error instead of guessing.
    pub fn parse(
        enabled: Option<&str>,
        members: Option<&str>,
        writer_site: Option<&str>,
        standby_site: Option<&str>,
        check_interval_ms: Option<&str>,
        store_dir: Option<&str>,
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
        let config =
            FailoverConfig::new(policy.members().to_vec(), writer_site_id, standby_site_id)?;
        Ok(Some(Self {
            config,
            check_interval_ms,
            store_dir: PathBuf::from(store_dir),
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

/// Spawn the failover executor thread. `None` env (the default) spawns
/// nothing at all and never touches `healthy`; `Some` runs the controller
/// loop until `shutdown` is set or the process exits. If the executor cannot
/// start — the writer-authority port or the consensus store fails — the
/// thread clears `healthy` before it exits, so the failure is visible to
/// operators through readiness rather than only as a log line. The handle
/// is intentionally detached-style: the loop is best-effort and never
/// blocks process exit.
pub fn spawn_failover_executor(
    env: Option<ExecutorEnv>,
    database_url: String,
    shutdown: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let env = env?;
    let handle = std::thread::Builder::new()
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
            let Some(store) = open_consensus_store(&env, &healthy) else {
                return;
            };
            eprintln!(
                "failover quorum executor running ({} members, writer site {}, standby site {}, \
                 {}ms checks, store {}); no transport reports into the store in this build, so \
                 rounds hold",
                env.config().members().len(),
                env.config().writer_site_id(),
                env.config().standby_site_id(),
                env.check_interval_ms(),
                env.store_dir().display(),
            );
            let mut executor = FailoverExecutor::new(
                env.config().clone(),
                StoreObservationSource::new(store),
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
    Some(handle)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
