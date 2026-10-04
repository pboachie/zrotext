// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Notify, Semaphore};

/// Uses the existing billing worker budget. Observations cannot release a hold,
/// retry usage, charge, refund, or alter an entitlement.
pub async fn run_queue(
    database_url: String,
    worker: TestUsageReconciler,
    draining: Arc<AtomicBool>,
    notify: Arc<Notify>,
    permits: Arc<Semaphore>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(300));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut cursor: Option<(Uuid, i64, String)> = None;
    let mut invoice_cursor: Option<(Uuid, Uuid)> = None;
    let mut prefer_invoice = false;
    loop {
        if !wait_for_tick(&mut tick, &notify, &draining).await {
            break;
        }
        let Ok(_permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let mut db = match crate::runtime_db::connect(&database_url).await {
            Ok(db) => db,
            Err(_) => {
                eprintln!("TEST usage observation database unavailable");
                continue;
            }
        };
        prefer_invoice = !prefer_invoice;
        let result = if prefer_invoice {
            match observe_next_invoice(&mut db, &worker, &mut invoice_cursor, &draining).await {
                Ok(false) => observe_next(&mut db, &worker, &mut cursor, &draining).await,
                other => other,
            }
        } else {
            match observe_next(&mut db, &worker, &mut cursor, &draining).await {
                Ok(false) => {
                    observe_next_invoice(&mut db, &worker, &mut invoice_cursor, &draining).await
                }
                other => other,
            }
        };
        if result.is_err() {
            eprintln!("TEST usage observation pending review");
        }
    }
}

pub(super) async fn observe_next_invoice(
    db: &mut Database,
    worker: &TestUsageReconciler,
    cursor: &mut Option<(Uuid, Uuid)>,
    draining: &AtomicBool,
) -> Result<bool, Error> {
    let account = cursor.as_ref().map(|c| c.0);
    let period = cursor.as_ref().map(|c| c.1);
    let row=db.query_opt("SELECT p.account_id,p.id FROM billing_invoice_periods p WHERE ($1::uuid IS NULL OR (p.account_id,p.id)>($1,$2::uuid)) AND NOT EXISTS(SELECT 1 FROM billing_invoice_usage_observations o WHERE (o.account_id,o.period_id)=(p.account_id,p.id) AND o.observed_at>clock_timestamp()-interval '15 minutes') ORDER BY p.account_id,p.id LIMIT 1",&[&account,&period]).await?;
    let Some(row) = row else {
        *cursor = None;
        return Ok(false);
    };
    let account = row.get(0);
    let period = row.get(1);
    *cursor = Some((account, period));
    if draining.load(Ordering::SeqCst) {
        return Ok(false);
    }
    worker
        .reconcile_invoice_period(db, account, period, Uuid::new_v4())
        .await?;
    Ok(true)
}

pub(super) async fn observe_next(
    db: &mut Database,
    worker: &TestUsageReconciler,
    cursor: &mut Option<(Uuid, i64, String)>,
    draining: &AtomicBool,
) -> Result<bool, Error> {
    let after_account = cursor.as_ref().map(|c| c.0);
    let after_policy = cursor.as_ref().map(|c| c.1);
    let after_period = cursor.as_ref().map(|c| c.2.as_str());
    let row = db.query_opt("SELECT b.account_id,b.policy_version,b.period_start::text FROM billing_usage_bindings b         JOIN billing_usage_finalized f USING(account_id,message_id) JOIN billing_usage_test_policies p USING(account_id,policy_version)         WHERE p.mode='test' AND ($1::uuid IS NULL OR (b.account_id,b.policy_version,b.period_start::text)>($1,$2::bigint,$3::text))         AND NOT EXISTS(SELECT 1 FROM billing_usage_reconciliations r WHERE (r.account_id,r.policy_version,r.period_start)=(b.account_id,b.policy_version,b.period_start)             AND r.observed_at>clock_timestamp()-interval '15 minutes')         GROUP BY b.account_id,b.policy_version,b.period_start ORDER BY b.account_id,b.policy_version,b.period_start LIMIT 1",&[&after_account,&after_policy,&after_period]).await?;
    let Some(row) = row else {
        *cursor = None;
        return Ok(false);
    };
    let account = row.get(0);
    let policy = row.get(1);
    let period: String = row.get(2);
    *cursor = Some((account, policy, period.clone()));
    if draining.load(Ordering::SeqCst) {
        return Ok(false);
    }
    worker
        .reconcile_period(db, account, policy, &period, Uuid::new_v4())
        .await?;
    Ok(true)
}

async fn wait_for_tick(
    tick: &mut tokio::time::Interval,
    notify: &Notify,
    draining: &AtomicBool,
) -> bool {
    wait_registered(tick, notify, draining, || {}).await
}

async fn wait_registered(
    tick: &mut tokio::time::Interval,
    notify: &Notify,
    draining: &AtomicBool,
    before_select: impl FnOnce(),
) -> bool {
    let notified = notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    if draining.load(Ordering::SeqCst) {
        return false;
    }
    // The same registered waiter covers the atomic-check-to-select boundary.
    before_select();
    tokio::select! { _=tick.tick()=>{}, _=notified=>{} }
    !draining.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn drain_during_observation_does_not_wait_for_the_next_five_minute_tick() {
        let draining = AtomicBool::new(false);
        let notify = Notify::new();
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        assert!(wait_for_tick(&mut tick, &notify, &draining).await);
        // notify_waiters is deliberately delivered while observation owns the worker,
        // with no registered waiter. The persistent flag must independently stop it.
        draining.store(true, Ordering::SeqCst);
        notify.notify_waiters();
        let result = tokio::time::timeout(
            Duration::from_millis(1),
            wait_for_tick(&mut tick, &notify, &draining),
        )
        .await;
        assert!(!result.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn drain_between_flag_check_and_wait_is_observed_by_the_registered_waiter() {
        let draining = AtomicBool::new(false);
        let notify = Notify::new();
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.tick().await;
        let result = tokio::time::timeout(
            Duration::from_millis(1),
            wait_registered(&mut tick, &notify, &draining, || {
                draining.store(true, Ordering::SeqCst);
                notify.notify_waiters();
            }),
        )
        .await;
        assert!(!result.unwrap());
    }
}
