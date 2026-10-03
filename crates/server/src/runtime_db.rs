// SPDX-License-Identifier: AGPL-3.0-only
//! Process-wide admission, reuse and PostgreSQL-side deadlines for runtime
//! connections.
//!
//! A fresh connection costs a TCP connect, a TLS handshake and SCRAM
//! authentication before the first query. Released clients are therefore
//! reset with `DISCARD ALL` and kept for reuse. A client that cannot be reset
//! promptly (a cancelled query still running, an open transaction block, a
//! closed socket) is closed instead of pooled.
use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::{Instant, MissedTickBehavior, interval_at, timeout, timeout_at},
};
use tokio_postgres::Client;

// Two default hubs use at most 80 connections, leaving room on a default
// 100-connection PostgreSQL server for migrations, inspection and recovery.
// Pooled idle sockets count against the same budgets as busy ones.
// Device slots bound concurrent database work, not connected phones: the
// stream admits 32 sessions and 32 handshakes without pinning their clients.
const REQUEST_SLOTS: usize = 16;
const DEVICE_SLOTS: usize = 16;
/// Worker-class sockets must cover the configured webhook lanes, the Stripe
/// reconciliation jobs and one socket per periodic worker; startup rejects
/// configurations that do not fit. Workers must still hold a socket only for
/// database phases, never across webhook, Stripe or SMTP network I/O.
pub const WORKER_SLOTS: usize = 8;
/// Idle sockets are closed after this long so a quiet hub returns its
/// connections to PostgreSQL.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// A quiet pool must inspect its sockets without waiting for another request.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/// Recycle sockets periodically to bound server-side memory growth and to
/// follow DNS or failover changes.
const MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);
const RESET_DEADLINE: Duration = Duration::from_secs(2);
const CONNECT_DEADLINE: Duration = Duration::from_secs(3);
const ADMISSION_WAIT: Duration = Duration::from_secs(2);
/// Bounds how long worker-class admission waits for the permit of an evicted
/// idle socket (freed once its driver observes the close), or for any socket
/// to be returned to the pool, before failing fast.
const EVICTION_WAIT: Duration = Duration::from_secs(1);
/// How long acquire prefers a same-class socket whose DISCARD ALL reset is
/// still in flight over opening a brand-new connection, when a permit is
/// otherwise free. Back-to-back checkouts (auth extractor then handler,
/// proof then claim) would otherwise grow the pool toward its cap while the
/// previous socket is milliseconds from reuse (issue #514).
const RESET_REUSE_WAIT: Duration = Duration::from_millis(50);

struct Idle {
    url: Arc<str>,
    client: Client,
    created: Instant,
    idle_since: Instant,
}

/// One admission class: a fixed socket budget plus the idle sockets it owns.
struct ClassPool {
    slots: Arc<Semaphore>,
    /// Request/device operations may wait briefly; background jobs fail fast
    /// after a shorter bounded wait.
    wait: bool,
    idle: Mutex<Vec<Idle>>,
    returned: Notify,
    /// Sockets whose drop has spawned a DISCARD ALL reset that has not yet
    /// returned them to the idle list (or closed them).
    resets_in_flight: AtomicUsize,
    sweep_started: AtomicBool,
}

impl ClassPool {
    fn new(slots: usize, wait: bool) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(Semaphore::new(slots)),
            wait,
            idle: Mutex::new(Vec::new()),
            returned: Notify::new(),
            resets_in_flight: AtomicUsize::new(0),
            sweep_started: AtomicBool::new(false),
        })
    }

    fn idle(&self) -> std::sync::MutexGuard<'_, Vec<Idle>> {
        // A panic while holding the lock cannot leave the Vec inconsistent.
        self.idle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Most recently used first, so surplus sockets age out under light load.
    /// Expired and closed sockets are dropped outside the lock.
    fn take(&self, url: &str) -> Option<(Client, Instant)> {
        let now = Instant::now();
        let (found, expired) = {
            let mut idle = self.idle();
            let expired = drain_expired(&mut idle, now);
            let found = idle
                .iter()
                .rposition(|entry| &*entry.url == url)
                .map(|index| idle.remove(index));
            (found, expired)
        };
        drop(expired);
        found.map(|entry| (entry.client, entry.created))
    }

    fn put(self: &Arc<Self>, url: Arc<str>, client: Client, created: Instant) {
        let now = Instant::now();
        let expired = {
            let mut idle = self.idle();
            let expired = drain_expired(&mut idle, now);
            idle.push(Idle {
                url,
                client,
                created,
                idle_since: now,
            });
            expired
        };
        drop(expired);
        self.returned.notify_waiters();
        self.ensure_sweeper();
    }

    fn sweep_idle(&self) {
        let expired = {
            let mut idle = self.idle();
            drain_expired(&mut idle, Instant::now())
        };
        // The connection driver releases its socket permit only after the
        // client is dropped. Never drop it while holding the pool mutex.
        drop(expired);
    }

    fn ensure_sweeper(self: &Arc<Self>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self
            .sweep_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let weak = Arc::downgrade(self);
        let registration = SweeperRegistration(weak.clone());
        let first_tick = Instant::now() + IDLE_SWEEP_INTERVAL;
        runtime.spawn(async move {
            let _registration = registration;
            let mut ticks = interval_at(first_tick, IDLE_SWEEP_INTERVAL);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                let Some(pool) = weak.upgrade() else {
                    break;
                };
                pool.sweep_idle();
            }
        });
    }

    /// Close one idle socket that belongs to a different database URL. Only
    /// tests and tools use more than one URL per process.
    fn evict_other(&self, url: &str) -> bool {
        let evicted = {
            let mut idle = self.idle();
            idle.iter()
                .position(|entry| &*entry.url != url)
                .map(|index| idle.remove(index))
        };
        evicted.is_some()
    }
}

/// Allows a pool to start a new sweeper if its Tokio runtime was shut down.
struct SweeperRegistration(Weak<ClassPool>);

impl Drop for SweeperRegistration {
    fn drop(&mut self) {
        if let Some(pool) = self.0.upgrade() {
            pool.sweep_started.store(false, Ordering::Release);
        }
    }
}

/// Balance reset accounting even if the runtime cancels an unpolled task.
struct ResetRegistration(Arc<ClassPool>);

impl ResetRegistration {
    fn new(pool: Arc<ClassPool>) -> Self {
        pool.resets_in_flight.fetch_add(1, Ordering::AcqRel);
        Self(pool)
    }
}

impl Drop for ResetRegistration {
    fn drop(&mut self) {
        self.0.resets_in_flight.fetch_sub(1, Ordering::AcqRel);
        self.0.returned.notify_waiters();
    }
}

fn drain_expired(idle: &mut Vec<Idle>, now: Instant) -> Vec<Idle> {
    let mut expired = Vec::new();
    let mut index = 0;
    while index < idle.len() {
        let entry = &idle[index];
        if entry.client.is_closed()
            || now.duration_since(entry.idle_since) >= IDLE_TIMEOUT
            || now.duration_since(entry.created) >= MAX_LIFETIME
        {
            expired.push(idle.swap_remove(index));
        } else {
            index += 1;
        }
    }
    expired
}

struct Pools {
    requests: Arc<ClassPool>,
    devices: Arc<ClassPool>,
    workers: Arc<ClassPool>,
}
impl Pools {
    fn new() -> Self {
        Self {
            requests: ClassPool::new(REQUEST_SLOTS, true),
            devices: ClassPool::new(DEVICE_SLOTS, true),
            workers: ClassPool::new(WORKER_SLOTS, false),
        }
    }
}
static POOLS: LazyLock<Pools> = LazyLock::new(Pools::new);

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("database capacity unavailable")]
    Capacity,
    #[error("database connection deadline exceeded")]
    Timeout,
    #[error("database connection unavailable")]
    Database(#[from] tokio_postgres::Error),
    #[error("database transport unavailable: {0}")]
    Transport(#[from] zrotext_postgres_connection::ConnectError),
}

/// A runtime PostgreSQL client. Dropping it returns the socket to its
/// admission class for reuse once session state has been reset.
pub struct PooledClient {
    client: Option<Client>,
    url: Arc<str>,
    created: Instant,
    pool: Arc<ClassPool>,
}

impl Deref for PooledClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        self.client.as_ref().expect("client present until drop")
    }
}
impl DerefMut for PooledClient {
    fn deref_mut(&mut self) -> &mut Client {
        self.client.as_mut().expect("client present until drop")
    }
}

impl Drop for PooledClient {
    fn drop(&mut self) {
        let Some(client) = self.client.take() else {
            return;
        };
        if client.is_closed() || self.created.elapsed() >= MAX_LIFETIME {
            return;
        }
        // Without a runtime there is nothing to reuse the socket with.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let pool = self.pool.clone();
        let url = self.url.clone();
        let created = self.created;
        let registration = ResetRegistration::new(pool.clone());
        runtime.spawn(async move {
            let _registration = registration;
            // DISCARD ALL runs after any statement still queued on this socket
            // and fails inside a transaction block. Either way an unready
            // socket is closed rather than handed to another caller. It also
            // restores the startup deadlines should anything have SET them.
            if matches!(
                timeout(RESET_DEADLINE, client.batch_execute("DISCARD ALL")).await,
                Ok(Ok(()))
            ) {
                // DISCARD ALL deallocates server-side statements, including
                // any cached type lookups.
                client.clear_type_cache();
                pool.put(url, client, created);
            }
        });
    }
}

#[cfg(test)]
pub(crate) fn diagnostic_connect_failure(stage: &'static str, error: &ConnectError) {
    if std::env::var("ZT_RUNTIME_DB_TEST_DIAGNOSTIC").as_deref() != Ok("1") {
        return;
    }
    let category = match error {
        ConnectError::Capacity => "capacity",
        ConnectError::Timeout => "connect_timeout",
        ConnectError::Database(_) => "pg_connect",
        ConnectError::Transport(_) => "transport",
    };
    eprintln!("fixture_database_failure stage={stage} category={category}");
}

#[cfg(test)]
pub(crate) fn diagnostic_auth_failure(
    stage: &'static str,
    error: &crate::http_auth::AuthHttpError,
) {
    if std::env::var("ZT_RUNTIME_DB_TEST_DIAGNOSTIC").as_deref() != Ok("1") {
        return;
    }
    let category = match error {
        crate::http_auth::AuthHttpError::Unavailable => "unavailable",
        crate::http_auth::AuthHttpError::Busy => "busy",
        _ => "other",
    };
    eprintln!("fixture_auth_failure stage={stage} category={category}");
}

#[cfg(test)]
pub(crate) fn diagnostic_query_failure(stage: &'static str, error: &tokio_postgres::Error) {
    if std::env::var("ZT_RUNTIME_DB_TEST_DIAGNOSTIC").as_deref() != Ok("1") {
        return;
    }
    let category = match error.code().map(|code| code.code()) {
        Some("55P03") => "lock_timeout",
        Some("57014") => "statement_timeout",
        Some("42P01" | "42703" | "42883") => "missing_schema",
        Some(code) if code.starts_with("23") => "constraint",
        Some(_) => "pg_other",
        None => "client",
    };
    eprintln!("fixture_query_failure stage={stage} category={category}");
}

pub async fn connect(url: &str) -> Result<PooledClient, ConnectError> {
    acquire(&POOLS.requests, url).await.inspect_err(|_error| {
        #[cfg(test)]
        diagnostic_connect_failure("requests", _error);
    })
}
pub async fn connect_device(url: &str) -> Result<PooledClient, ConnectError> {
    acquire(&POOLS.devices, url).await.inspect_err(|_error| {
        #[cfg(test)]
        diagnostic_connect_failure("devices", _error);
    })
}
pub async fn connect_worker(url: &str) -> Result<PooledClient, ConnectError> {
    acquire(&POOLS.workers, url).await.inspect_err(|_error| {
        #[cfg(test)]
        diagnostic_connect_failure("workers", _error);
    })
}

#[cfg(test)]
#[path = "runtime_db/reset_tests.rs"]
mod reset_tests;

/// Test-only: how many idle worker-class sockets exist for `url`. An entry in
/// the idle list is reusable by any worker acquire without a permit, so its
/// presence proves the previous holder released the socket.
#[cfg(test)]
pub(crate) fn worker_idle_sockets(url: &str) -> usize {
    POOLS
        .workers
        .idle()
        .iter()
        .filter(|entry| &*entry.url == url)
        .count()
}

async fn acquire(pool: &Arc<ClassPool>, url: &str) -> Result<PooledClient, ConnectError> {
    // Worker admission rejects faster than request admission, but both wait a
    // bounded window first: a socket released a moment ago is still completing
    // its DISCARD ALL reset with its permit held, and foreign-URL sockets can
    // be busy rather than idle.
    let deadline = Instant::now()
        + if pool.wait {
            ADMISSION_WAIT
        } else {
            EVICTION_WAIT
        };
    let url: Arc<str> = url.into();
    loop {
        // Register before checking so a socket returned in between wakes us.
        let returned = pool.returned.notified();
        tokio::pin!(returned);
        returned.as_mut().enable();
        if let Some((client, created)) = pool.take(&url) {
            return Ok(PooledClient {
                client: Some(client),
                url,
                created,
                pool: pool.clone(),
            });
        }
        // A same-class socket may be milliseconds from reuse: its drop is
        // still running DISCARD ALL. With a free permit we could open a new
        // connection immediately, but that grows the pool toward its cap for
        // no need, so briefly prefer the returning socket first (#514). The
        // preference is bounded by the admission deadline so a stream of
        // return notifications cannot spin a fail-fast class past its
        // ADMISSION_WAIT/EVICTION_WAIT budget.
        if pool.resets_in_flight.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
            let prefer_until = std::cmp::min(Instant::now() + RESET_REUSE_WAIT, deadline);
            tokio::select! {
                _ = &mut returned => {
                    continue;
                }
                _ = tokio::time::sleep_until(prefer_until) => {}
            }
        }
        if let Ok(permit) = pool.slots.clone().try_acquire_owned() {
            return open(pool, url, permit).await;
        }
        // HTTP and device socket admission already bound external callers.
        // Permit a brief, cancellable wait for bursts (including synchronized
        // heartbeats), for a free slot or a reset socket returned to the pool.
        // Worker jobs get the shorter window: a replacement whose predecessor
        // just released a socket must not fail admission while that socket is
        // milliseconds from reuse.
        pool.evict_other(&url);
        tokio::select! {
            permit = timeout_at(deadline, pool.slots.clone().acquire_owned()) => {
                let permit = permit
                    .map_err(|_| ConnectError::Capacity)?
                    .map_err(|_| ConnectError::Capacity)?;
                return open(pool, url, permit).await;
            }
            _ = returned => {}
        }
    }
}

async fn open(
    pool: &Arc<ClassPool>,
    url: Arc<str>,
    permit: OwnedSemaphorePermit,
) -> Result<PooledClient, ConnectError> {
    let mut config = zrotext_postgres_connection::parse_config(&url)?;
    // Preserve operator search_path options, but enforce deadlines last. These
    // start with the session and also apply after an HTTP future is cancelled.
    config.options(format!("{} -c statement_timeout=10000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=15000", config.get_options().unwrap_or_default()));
    let (client, connection) = timeout(
        CONNECT_DEADLINE,
        zrotext_postgres_connection::connect_config(config),
    )
    .await
    .map_err(|_| ConnectError::Timeout)??;
    tokio::spawn(async move {
        // A dropped request/client need not mean its query has stopped. Keep
        // the permit until the PostgreSQL driver actually releases the socket.
        let _permit = permit;
        // Connection errors contain deployment details; do not log them here.
        let _ = connection.await;
    });
    Ok(PooledClient {
        client: Some(client),
        url,
        created: Instant::now(),
        pool: pool.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn capacity_rejects_before_connecting() {
        let pool = ClassPool::new(0, false);
        assert!(matches!(
            acquire(&pool, "invalid").await,
            Err(ConnectError::Capacity)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn request_admission_waits_then_rejects() {
        let pool = ClassPool::new(0, true);
        let started = Instant::now();
        assert!(matches!(
            acquire(&pool, "invalid").await,
            Err(ConnectError::Capacity)
        ));
        assert_eq!(started.elapsed(), ADMISSION_WAIT);
    }

    // A worker job replacing a finished one must not fail admission while the
    // released socket's DISCARD ALL reset is still in flight: the permit is
    // held and the idle list is empty until the reset completes.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn worker_admission_waits_for_in_flight_socket_reset() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let pool = ClassPool::new(1, false);
        let client = acquire(&pool, &url).await.unwrap();
        client.query_one("SELECT 1", &[]).await.unwrap();
        drop(client);
        assert_eq!(pool.slots.available_permits(), 0);
        let replacement = timeout(EVICTION_WAIT + Duration::from_secs(1), acquire(&pool, &url))
            .await
            .expect("replacement admission resolves within the bounded window");
        let replacement = replacement.expect("imminent same-URL release is reused, not rejected");
        replacement.query_one("SELECT 1", &[]).await.unwrap();
    }

    // The reset preference must never spin a fail-fast class past its
    // admission deadline: a stream of return notifications (churn from other
    // waiters) restarts the preference loop, and without the deadline bound
    // the acquire would never reach the permit wait that enforces Capacity.
    #[tokio::test(start_paused = true)]
    async fn reset_preference_cannot_spin_past_the_admission_deadline() {
        let pool = ClassPool::new(1, false);
        // Hold the only permit and pretend a reset is in flight: take() finds
        // nothing, the preference would loop on notifications, and only the
        // deadline can end it. The URL never gets dialed: admission fails
        // before any connection attempt.
        let held = pool.slots.clone().acquire_owned().await.unwrap();
        pool.resets_in_flight.store(1, Ordering::SeqCst);
        let churn_pool = pool.clone();
        let churn = tokio::spawn(async move {
            loop {
                churn_pool.returned.notify_waiters();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        let outcome = tokio::time::timeout(
            EVICTION_WAIT * 3,
            acquire(&pool, "postgresql://127.0.0.1:1/never-dialed"),
        )
        .await;
        churn.abort();
        drop(held);
        let acquired = outcome.expect("acquire resolves instead of spinning on notifications");
        assert!(matches!(acquired, Err(ConnectError::Capacity)));
    }

    // Back-to-back checkouts on a class with free permits must still reuse
    // the socket whose DISCARD ALL reset is in flight instead of growing the
    // pool with a brand-new connection (issue #514).
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn immediate_recheckout_reuses_the_resetting_socket_with_permits_free() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let pool = ClassPool::new(2, true);
        let first = acquire(&pool, &url).await.unwrap();
        let pid: i32 = first
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        // The pool's second permit is free, so opening a new connection is
        // always possible; the re-checkout must still land on the same
        // backend once its reset completes.
        drop(first);
        let second = timeout(
            RESET_REUSE_WAIT + Duration::from_secs(2),
            acquire(&pool, &url),
        )
        .await
        .expect("re-checkout resolves within the bounded window")
        .unwrap();
        let reuse_pid: i32 = second
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            reuse_pid, pid,
            "the resetting socket must be reused, not replaced"
        );
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn released_socket_is_reset_and_reused_within_its_budget() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let pool = ClassPool::new(1, false);
        let client = acquire(&pool, &url).await.unwrap();
        let backend: i32 = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        client
            .batch_execute("SET statement_timeout = '250ms'")
            .await
            .unwrap();
        drop(client);
        // The only permit stays with the pooled socket.
        assert_eq!(pool.slots.available_permits(), 0);
        let client = timeout(Duration::from_secs(2), async {
            loop {
                match acquire(&pool, &url).await {
                    Ok(client) => break client,
                    Err(ConnectError::Capacity) => tokio::task::yield_now().await,
                    Err(error) => panic!("{error}"),
                }
            }
        })
        .await
        .unwrap();
        let row = client.query_one("SELECT pg_backend_pid(), current_setting('statement_timeout'), current_setting('lock_timeout'), current_setting('idle_in_transaction_session_timeout')", &[]).await.unwrap();
        assert_eq!(row.get::<_, i32>(0), backend);
        assert_eq!(row.get::<_, String>(1), "10s");
        assert_eq!(row.get::<_, String>(2), "3s");
        assert_eq!(row.get::<_, String>(3), "15s");
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn quiet_pool_sweep_closes_expired_socket_and_returns_permit() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let pool = ClassPool::new(1, false);
        let client = acquire(&pool, &url).await.unwrap();
        client.query_one("SELECT 1", &[]).await.unwrap();
        let returned = pool.returned.notified();
        tokio::pin!(returned);
        returned.as_mut().enable();
        drop(client);
        timeout(Duration::from_secs(3), returned).await.unwrap();
        assert_eq!(pool.idle().len(), 1);
        assert_eq!(pool.slots.available_permits(), 0);

        // No subsequent acquire or put can perform opportunistic eviction.
        // Advance Tokio's clock while the hub is otherwise quiet.
        tokio::time::pause();
        tokio::time::advance(IDLE_TIMEOUT + IDLE_SWEEP_INTERVAL + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(pool.idle().is_empty(), "quiet pool kept an expired socket");
        tokio::time::resume();

        timeout(Duration::from_secs(3), async {
            while pool.slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("socket driver did not return its permit after the sweep");
    }

    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
    async fn cancelled_query_retains_capacity_and_never_leaks_into_reuse() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let pool = ClassPool::new(1, false);
        let mut client = acquire(&pool, &url).await.unwrap();
        client
            .batch_execute("CREATE TEMP TABLE pooled_leak(id int)")
            .await
            .unwrap();
        let transaction = client.transaction().await.unwrap();
        assert!(
            timeout(
                Duration::from_millis(50),
                transaction.batch_execute("SELECT pg_sleep(1)")
            )
            .await
            .is_err()
        );
        drop(transaction);
        drop(client);
        // Still busy (or closed): capacity is not handed out twice.
        assert_eq!(pool.slots.available_permits(), 0);
        let client = timeout(Duration::from_secs(5), async {
            loop {
                match acquire(&pool, &url).await {
                    Ok(client) => break client,
                    Err(ConnectError::Capacity) => {
                        tokio::time::sleep(Duration::from_millis(20)).await
                    }
                    Err(error) => panic!("{error}"),
                }
            }
        })
        .await
        .unwrap();
        let leaked: bool = client
            .query_one("SELECT to_regclass('pg_temp.pooled_leak') IS NOT NULL", &[])
            .await
            .unwrap()
            .get(0);
        assert!(!leaked);
    }

    #[tokio::test]
    async fn device_capacity_does_not_consume_request_or_worker_reserve() {
        let pools = Pools::new();
        let devices = pools
            .devices
            .slots
            .clone()
            .acquire_many_owned(DEVICE_SLOTS as u32)
            .await
            .unwrap();
        assert!(matches!(
            acquire(&pools.devices, "invalid").await,
            Err(ConnectError::Capacity)
        ));
        assert!(matches!(
            acquire(&pools.requests, "invalid").await,
            Err(ConnectError::Transport(_))
        ));
        assert!(matches!(
            acquire(&pools.workers, "invalid").await,
            Err(ConnectError::Transport(_))
        ));
        drop(devices);
    }

    #[tokio::test]
    async fn unusable_url_is_a_configuration_error_not_an_outage() {
        let pool = ClassPool::new(1, false);
        let Err(error) = acquire(
            &pool,
            "postgres://u:<secret>@writer.example/zrotext?sslmode=verify-any",
        )
        .await
        else {
            panic!("an unsupported sslmode must not connect");
        };
        assert!(matches!(
            error,
            ConnectError::Transport(zrotext_postgres_connection::ConnectError::Configuration(_))
        ));
        let message = error.to_string();
        assert!(message.contains("sslmode"), "{message}");
        assert!(!message.contains("<secret>"));

        // Parse errors that would echo input text reach callers only as
        // fixed diagnostics.
        for url in [
            "host=writer.example password='zt-leak-marker dbname=zrotext",
            "postgres://u@writer.example/zrotext?%0Azt-leak-marker%0A=1",
        ] {
            let Err(error) = acquire(&pool, url).await else {
                panic!("{url:?} must not connect");
            };
            assert!(matches!(
                error,
                ConnectError::Transport(zrotext_postgres_connection::ConnectError::Configuration(
                    _
                ))
            ));
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains("zt-leak-marker"), "{url:?} leaked: {text:?}");
                assert!(!text.contains('\n'), "{url:?} injected a newline: {text:?}");
            }
        }
    }

    #[tokio::test]
    async fn tls_runtime_connection_is_encrypted() {
        let Ok(url) = std::env::var("ZT_POSTGRES_TLS_TEST_DATABASE_URL") else {
            return;
        };
        let client = connect(&url).await.unwrap();
        let encrypted: bool = client
            .query_one(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(encrypted);
    }
}
