// SPDX-License-Identifier: AGPL-3.0-only
//! Process-wide admission and PostgreSQL-side deadlines for runtime connections.
use std::{
    future::Future,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::{sync::Semaphore, time::timeout};
use tokio_postgres::{Client, NoTls};

// Two default hubs use at most 72 connections, leaving room on a default
// 100-connection PostgreSQL server for migrations, inspection and recovery.
#[derive(Clone, Copy)]
enum Class {
    Request,
    Device,
    Worker,
}
struct Budgets {
    requests: Arc<Semaphore>,
    devices: Arc<Semaphore>,
    workers: Arc<Semaphore>,
}
impl Budgets {
    fn new() -> Self {
        Self {
            requests: Arc::new(Semaphore::new(16)),
            devices: Arc::new(Semaphore::new(16)),
            workers: Arc::new(Semaphore::new(4)),
        }
    }
    fn slots(&self, class: Class) -> Arc<Semaphore> {
        match class {
            Class::Request => self.requests.clone(),
            Class::Device => self.devices.clone(),
            Class::Worker => self.workers.clone(),
        }
    }
}
static BUDGETS: LazyLock<Budgets> = LazyLock::new(Budgets::new);

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("database capacity unavailable")]
    Capacity,
    #[error("database connection deadline exceeded")]
    Timeout,
    #[error("database connection unavailable")]
    Database(#[from] tokio_postgres::Error),
}

pub async fn connect(
    url: &str,
) -> Result<
    (
        Client,
        impl Future<Output = Result<(), tokio_postgres::Error>> + Send + use<>,
    ),
    ConnectError,
> {
    connect_with_wait(url, BUDGETS.slots(Class::Request), true).await
}
pub async fn connect_device(
    url: &str,
) -> Result<
    (
        Client,
        impl Future<Output = Result<(), tokio_postgres::Error>> + Send + use<>,
    ),
    ConnectError,
> {
    connect_with(url, BUDGETS.slots(Class::Device)).await
}
pub async fn connect_worker(
    url: &str,
) -> Result<
    (
        Client,
        impl Future<Output = Result<(), tokio_postgres::Error>> + Send + use<>,
    ),
    ConnectError,
> {
    connect_with(url, BUDGETS.slots(Class::Worker)).await
}

async fn connect_with(
    url: &str,
    slots: Arc<Semaphore>,
) -> Result<
    (
        Client,
        impl Future<Output = Result<(), tokio_postgres::Error>> + Send + use<>,
    ),
    ConnectError,
> {
    connect_with_wait(url, slots, false).await
}

async fn connect_with_wait(
    url: &str,
    slots: Arc<Semaphore>,
    wait: bool,
) -> Result<
    (
        Client,
        impl Future<Output = Result<(), tokio_postgres::Error>> + Send + use<>,
    ),
    ConnectError,
> {
    // Request admission already bounds external handlers; permit a brief,
    // cancellable wait for normal bursts. Persistent sockets fail fast.
    let permit = if wait {
        timeout(Duration::from_secs(2), slots.acquire_owned())
            .await
            .map_err(|_| ConnectError::Capacity)?
            .map_err(|_| ConnectError::Capacity)?
    } else {
        slots
            .try_acquire_owned()
            .map_err(|_| ConnectError::Capacity)?
    };
    let mut config: tokio_postgres::Config = url.parse()?;
    // Preserve operator search_path options, but enforce deadlines last. These
    // start with the session and also apply after an HTTP future is cancelled.
    config.options(format!("{} -c statement_timeout=10000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=15000", config.get_options().unwrap_or_default()));
    let (client, connection) = timeout(Duration::from_secs(3), config.connect(NoTls))
        .await
        .map_err(|_| ConnectError::Timeout)??;
    Ok((client, async move {
        // A dropped request/client need not mean its query has stopped. Keep
        // the permit until the PostgreSQL driver actually releases the socket.
        let _permit = permit;
        connection.await
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn capacity_rejects_before_connecting() {
        let slots = Arc::new(Semaphore::new(0));
        assert!(matches!(
            connect_with("invalid", slots).await,
            Err(ConnectError::Capacity)
        ));
    }
    #[tokio::test]
    async fn cancelled_query_retains_capacity_until_driver_stops() {
        let Ok(url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let slots = Arc::new(Semaphore::new(1));
        let (client, connection) = connect_with(&url, slots.clone()).await.unwrap();
        let driver = tokio::spawn(connection);
        let row = client.query_one("SELECT current_setting('statement_timeout'), current_setting('lock_timeout'), current_setting('idle_in_transaction_session_timeout')", &[]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "10s");
        assert_eq!(row.get::<_, String>(1), "3s");
        assert_eq!(row.get::<_, String>(2), "15s");
        client
            .batch_execute("SET statement_timeout = '250ms'")
            .await
            .unwrap();
        assert!(
            timeout(
                Duration::from_millis(50),
                client.batch_execute("SELECT pg_sleep(10)")
            )
            .await
            .is_err()
        );
        drop(client);
        assert_eq!(slots.available_permits(), 0);
        assert!(matches!(
            connect_with(&url, slots.clone()).await,
            Err(ConnectError::Capacity)
        ));
        timeout(Duration::from_secs(2), driver)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(slots.available_permits(), 1);
        let (client, connection) = connect_with(&url, slots.clone()).await.unwrap();
        let driver = tokio::spawn(connection);
        assert_eq!(
            client
                .query_one("SELECT 1", &[])
                .await
                .unwrap()
                .get::<_, i32>(0),
            1
        );
        drop(client);
        driver.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn device_capacity_does_not_consume_request_or_worker_reserve() {
        let budgets = Budgets::new();
        let device_slots = budgets.slots(Class::Device);
        let request_slots = budgets.slots(Class::Request);
        let worker_slots = budgets.slots(Class::Worker);
        let devices = device_slots.clone().acquire_many_owned(16).await.unwrap();
        assert!(matches!(
            connect_with("invalid", device_slots).await,
            Err(ConnectError::Capacity)
        ));
        assert!(matches!(
            connect_with("invalid", request_slots).await,
            Err(ConnectError::Database(_))
        ));
        assert!(matches!(
            connect_with("invalid", worker_slots).await,
            Err(ConnectError::Database(_))
        ));
        drop(devices);
    }
}
