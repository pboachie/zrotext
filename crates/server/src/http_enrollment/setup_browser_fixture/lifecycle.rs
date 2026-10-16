// SPDX-License-Identifier: AGPL-3.0-only
use std::time::Duration;
use tokio::task::JoinHandle;

pub(super) async fn drive(
    mut server: JoinHandle<()>,
    mut consumer: Option<JoinHandle<()>>,
    limit: Duration,
) -> Result<(), &'static str> {
    let mut server_joined = false;
    let mut consumer_joined = consumer.is_none();
    let result = tokio::time::timeout(limit, async {
        if let Some(task) = consumer.as_mut() {
            let outcome = task.await;
            consumer_joined = true;
            outcome.map_err(|_| "HTTP consumer failed")?;
        }
        let outcome = (&mut server).await;
        server_joined = true;
        outcome.map_err(|_| "fixture server failed")
    })
    .await
    .unwrap_or(Err("fixture consumer/server deadline expired"));
    // A failed consumer never emits Finish. Stop and join every owned task
    // before the caller drops its exact disposable schema or reports failure.
    if !consumer_joined {
        let task = consumer.as_mut().unwrap();
        task.abort();
        let _ = task.await;
    }
    if !server_joined {
        server.abort();
        let _ = server.await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Stopped(Arc<AtomicBool>);
    impl Drop for Stopped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    fn pending() -> (JoinHandle<()>, Arc<AtomicBool>) {
        let stopped = Arc::new(AtomicBool::new(false));
        let guard = Stopped(stopped.clone());
        (
            tokio::spawn(async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            }),
            stopped,
        )
    }

    #[tokio::test]
    async fn consumer_failure_is_reported_after_owned_server_stops() {
        let (server, stopped) = pending();
        let consumer = tokio::spawn(async { panic!("synthetic consumer failure") });
        assert_eq!(
            drive(server, Some(consumer), Duration::from_secs(1)).await,
            Err("HTTP consumer failed")
        );
        assert!(stopped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn deadline_stops_and_joins_both_owned_tasks() {
        let (server, server_stopped) = pending();
        let (consumer, consumer_stopped) = pending();
        assert_eq!(
            drive(server, Some(consumer), Duration::from_millis(10)).await,
            Err("fixture consumer/server deadline expired")
        );
        assert!(server_stopped.load(Ordering::SeqCst));
        assert!(consumer_stopped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn external_mode_waits_for_server_without_an_automatic_consumer() {
        let (server, stopped) = pending();
        assert_eq!(
            drive(server, None, Duration::from_millis(10)).await,
            Err("fixture consumer/server deadline expired")
        );
        assert!(stopped.load(Ordering::SeqCst));
    }
}
