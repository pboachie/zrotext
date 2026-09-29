// SPDX-License-Identifier: AGPL-3.0-only
//! In-process producer-to-worker wakeups (issue #491). Queueing a webhook
//! delivery or an account mail row wakes the matching worker loop at once so
//! it does not wait out its fixed poll interval; the periodic tick remains
//! the fallback for rows queued by another process or missed wakeups.
//! `Notify` stores one permit when no worker is waiting, so a wakeup that
//! arrives between a worker's drain and its next wait is still observed.

use std::sync::OnceLock;
use tokio::sync::Notify;

static WEBHOOK_DELIVERY_CELL: OnceLock<Notify> = OnceLock::new();
static ACCOUNT_MAIL_CELL: OnceLock<Notify> = OnceLock::new();

/// The notify handle webhook delivery workers wait on besides their tick.
pub fn webhook_delivery() -> &'static Notify {
    WEBHOOK_DELIVERY_CELL.get_or_init(Notify::new)
}

/// The notify handle the account-mail worker waits on besides its tick.
pub fn account_mail() -> &'static Notify {
    ACCOUNT_MAIL_CELL.get_or_init(Notify::new)
}

/// A producer committed at least one claimable webhook delivery row.
pub fn webhook_delivery_queued() {
    wake(Queue::WebhookDelivery);
}

/// A producer committed at least one claimable account mail row
/// (verification, reset code or reset notice).
pub fn account_mail_queued() {
    wake(Queue::AccountMail);
}

/// The queue a producer woke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Queue {
    WebhookDelivery,
    AccountMail,
}

fn wake(queue: Queue) {
    #[cfg(test)]
    if OBSERVER.try_with(|observe| observe(queue)).is_ok() {
        return;
    }
    match queue {
        Queue::WebhookDelivery => webhook_delivery(),
        Queue::AccountMail => account_mail(),
    }
    .notify_one();
}

#[cfg(test)]
type Observer = std::sync::Arc<dyn Fn(Queue) + Send + Sync>;

/// Wakeups an observer saw: the queue and the row count at that instant.
#[cfg(test)]
type SeenWakes = std::sync::Arc<std::sync::Mutex<Vec<(Queue, i64)>>>;

#[cfg(test)]
tokio::task_local! {
    static OBSERVER: Observer;
}

/// Test-only: run `future` with its producers' wakeups routed to `observer`
/// instead of the process-wide notify handles. The test then sees exactly
/// its own wakeups; a parallel test's producer can neither satisfy nor
/// disturb it.
#[cfg(test)]
pub(crate) async fn observed<F: std::future::Future>(observer: Observer, future: F) -> F::Output {
    OBSERVER.scope(observer, future).await
}

/// Test-only observer that, at the instant of each wakeup, runs `count_sql`
/// on a separate database session and records the queue and the count.
/// A wakeup sent before the producer's commit cannot see the producer's rows,
/// so the recorded count pins the wake after the commit.
#[cfg(test)]
pub(crate) fn committed_rows_observer(
    database_url: String,
    count_sql: &'static str,
) -> (Observer, SeenWakes) {
    let seen: SeenWakes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    let observer: Observer = std::sync::Arc::new(move |queue| {
        let url = database_url.clone();
        // The producer's runtime is blocked inside this synchronous call, so
        // the check runs on its own thread and runtime.
        let count = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                        .await
                        .unwrap();
                    tokio::spawn(connection);
                    client
                        .query_one(count_sql, &[])
                        .await
                        .unwrap()
                        .get::<_, i64>(0)
                })
        })
        .join()
        .unwrap();
        record.lock().unwrap().push((queue, count));
    });
    (observer, seen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_permit_from_a_producer_survives_until_the_worker_waits() {
        // notify_one() with no waiter yet must not drop the wakeup: a worker
        // that reaches notified() afterwards still returns immediately.
        webhook_delivery_queued();
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            webhook_delivery().notified(),
        )
        .await
        .expect("stored permit wakes the worker without waiting");

        account_mail_queued();
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            account_mail().notified(),
        )
        .await
        .expect("stored permit wakes the worker without waiting");
    }
}
