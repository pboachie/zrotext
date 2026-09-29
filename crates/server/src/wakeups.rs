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
    webhook_delivery().notify_one();
}

/// A producer committed at least one claimable account mail row
/// (verification, reset code or reset notice).
pub fn account_mail_queued() {
    account_mail().notify_one();
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
