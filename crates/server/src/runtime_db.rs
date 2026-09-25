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
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::{Instant, timeout, timeout_at},
};
use tokio_postgres::Client;

// Two default hubs use at most 72 connections, leaving room on a default
// 100-connection PostgreSQL server for migrations, inspection and recovery.
// Pooled idle sockets count against the same budgets as busy ones.
const REQUEST_SLOTS: usize = 16;
const DEVICE_SLOTS: usize = 16;
const WORKER_SLOTS: usize = 4;
/// Idle sockets are closed after this long so a quiet hub returns its
/// connections to PostgreSQL.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Recycle sockets periodically to bound server-side memory growth and to
/// follow DNS or failover changes.
const MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);
const RESET_DEADLINE: Duration = Duration::from_secs(2);
const CONNECT_DEADLINE: Duration = Duration::from_secs(3);
const REQUEST_ADMISSION_WAIT: Duration = Duration::from_secs(2);
/// Only used after evicting another database URL's idle socket, which frees a
/// permit as soon as its driver observes the close.
const EVICTION_WAIT: Duration = Duration::from_secs(1);

struct Idle {
    url: Arc<str>,
    client: Client,
    created: Instant,
    idle_since: Instant,
}

/// One admission class: a fixed socket budget plus the idle sockets it owns.
struct ClassPool {
    slots: Arc<Semaphore>,
    /// Request handlers may wait briefly; persistent sockets fail fast.
    wait: bool,
    idle: Mutex<Vec<Idle>>,
    returned: Notify,
}

impl ClassPool {
    fn new(slots: usize, wait: bool) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(Semaphore::new(slots)),
            wait,
            idle: Mutex::new(Vec::new()),
            returned: Notify::new(),
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

    fn put(&self, url: Arc<str>, client: Client, created: Instant) {
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
            devices: ClassPool::new(DEVICE_SLOTS, false),
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
        runtime.spawn(async move {
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

pub async fn connect(url: &str) -> Result<PooledClient, ConnectError> {
    acquire(&POOLS.requests, url).await
}
pub async fn connect_device(url: &str) -> Result<PooledClient, ConnectError> {
    acquire(&POOLS.devices, url).await
}
pub async fn connect_worker(url: &str) -> Result<PooledClient, ConnectError> {
    acquire(&POOLS.workers, url).await
}

async fn acquire(pool: &Arc<ClassPool>, url: &str) -> Result<PooledClient, ConnectError> {
    let deadline = Instant::now() + REQUEST_ADMISSION_WAIT;
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
        if let Ok(permit) = pool.slots.clone().try_acquire_owned() {
            return open(pool, url, permit).await;
        }
        if !pool.wait {
            if !pool.evict_other(&url) {
                return Err(ConnectError::Capacity);
            }
            let permit = timeout(EVICTION_WAIT, pool.slots.clone().acquire_owned())
                .await
                .map_err(|_| ConnectError::Capacity)?
                .map_err(|_| ConnectError::Capacity)?;
            return open(pool, url, permit).await;
        }
        // Request admission already bounds external handlers; permit a brief,
        // cancellable wait for normal bursts, for either a free slot or a
        // socket released back to the pool.
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
    let mut config: tokio_postgres::Config = url.parse()?;
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
        assert_eq!(started.elapsed(), REQUEST_ADMISSION_WAIT);
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
            Err(ConnectError::Database(_))
        ));
        assert!(matches!(
            acquire(&pools.workers, "invalid").await,
            Err(ConnectError::Database(_))
        ));
        drop(devices);
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
