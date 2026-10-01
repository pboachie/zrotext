// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    super::{BillingError, SubscriptionSnapshot, TestQuotaPlan},
    model::{GRACE_MS, Observation},
};
use tokio_postgres::{GenericClient, Transaction};
use uuid::Uuid;

pub(super) async fn enabled<C: GenericClient + Sync>(
    db: &C,
    account: Uuid,
) -> Result<bool, BillingError> {
    let installed: bool = db
        .query_one(
            "SELECT to_regclass('billing_invoice_entitlements') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    if !installed {
        let policies: bool = db
            .query_one(
                "SELECT to_regclass('usage_quota_policies') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        if policies && db.query_opt("SELECT 1 FROM usage_quota_policies q WHERE account_id=$1 AND coalesce((to_jsonb(q)->>'invoice_bound_test')::boolean,false)", &[&account]).await?.is_some() {
            return Err(BillingError::InvalidEvent);
        }
        return Ok(false);
    }
    Ok(db.query_opt("SELECT coalesce((to_jsonb(q)->>'invoice_bound_test')::boolean,false) FROM usage_quota_policies q WHERE account_id=$1 AND metric='outbound_message'", &[&account]).await?
        .is_some_and(|r| r.get::<_, bool>(0)))
}

/// Runs inside the existing account -> customer -> reconciliation transaction.
/// Current provider observations never reset any period consumption counter.
pub(super) async fn apply(
    tx: &Transaction<'_>,
    account: Uuid,
    snapshot: &SubscriptionSnapshot,
    current: Option<&Observation>,
    plans: &[TestQuotaPlan],
    generation: i64,
) -> Result<(), BillingError> {
    if !enabled(tx, account).await? {
        return Ok(());
    }
    let now_ms: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    let prior = tx.query_opt("SELECT period_id,effective_limit FROM billing_invoice_entitlements WHERE account_id=$1 FOR UPDATE", &[&account]).await?;
    let previous_period: Option<Uuid> = prior.as_ref().and_then(|r| r.get(0));
    let previous_limit: i64 = prior.as_ref().map_or(0, |r| r.get(1));
    let mut period_id = None;
    let mut effective_limit = 0i64;
    let mut phase = "restricted";
    let mut grace_until = None;
    let mut cancel_at = None;
    if snapshot.status == "provider_deleted" {
        phase = "cancelled";
    } else {
        let current = current.ok_or(BillingError::InvalidEvent)?;
        if current.subscription.subscription_id != snapshot.subscription_id
            || current.subscription.customer_id != snapshot.customer_id
            || current.subscription.status != snapshot.status
            || current.subscription.price_id != snapshot.price_id
            || current.subscription.latest_invoice_id != snapshot.latest_invoice_id
        {
            return Err(BillingError::TenantConflict);
        }
        let recognized: bool = tx.query_one("SELECT recognized_price FROM billing_subscriptions WHERE stripe_subscription_id=$1 AND account_id=$2", &[&snapshot.subscription_id, &account]).await?.get(0);
        let limit = plans
            .iter()
            .filter(|_| recognized)
            .find(|p| snapshot.price_id.as_deref() == Some(p.price_id.as_str()))
            .map_or(0, |p| p.outbound_limit);
        cancel_at = current.cancel_at_ms;
        if current.cancel_at_period_end {
            cancel_at =
                Some(cancel_at.map_or(current.period.end_ms, |at| at.min(current.period.end_ms)));
        }
        let known = tx.query_opt("SELECT id,item_id FROM billing_invoice_periods WHERE account_id=$1 AND subscription_id=$2 AND start_ms=$3 AND end_ms=$4 FOR UPDATE",
            &[&account, &snapshot.subscription_id, &current.period.start_ms, &current.period.end_ms]).await?;
        if let Some(known) = known {
            if known.get::<_, String>(1) != current.item_id {
                return Err(BillingError::InvalidEvent);
            }
            period_id = Some(known.get::<_, Uuid>(0));
        } else if current.can_establish_period() && current.period.contains(now_ms) && limit > 0 {
            let conflicts: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM billing_invoice_periods WHERE account_id=$1 AND subscription_id=$2 AND (end_ms>$3 OR invoice_id=$4))",
                &[&account, &snapshot.subscription_id, &current.period.start_ms, &current.invoice_id]).await?.get(0);
            let count: i64 = tx
                .query_one(
                    "SELECT count(*) FROM billing_invoice_periods WHERE account_id=$1",
                    &[&account],
                )
                .await?
                .get(0);
            if !conflicts && count < 1000 {
                let id = Uuid::new_v4();
                tx.execute("INSERT INTO billing_invoice_periods(id,account_id,subscription_id,invoice_id,line_id,item_id,start_ms,end_ms,original_price_id,original_limit) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                    &[&id, &account, &snapshot.subscription_id, &current.invoice_id, &current.renewal_line_id.as_ref().ok_or(BillingError::InvalidEvent)?, &current.item_id, &current.period.start_ms, &current.period.end_ms, &snapshot.price_id, &limit]).await?;
                period_id = Some(id);
            }
        }
        // An old provider observation cannot replace a newer applied period,
        // even if an event delivery happened later in wall-clock order.
        if let Some(previous) = previous_period {
            let row = tx
                .query_one(
                    "SELECT start_ms FROM billing_invoice_periods WHERE account_id=$1 AND id=$2",
                    &[&account, &previous],
                )
                .await?;
            if row.get::<_, i64>(0) > current.period.start_ms {
                return Err(BillingError::InvalidEvent);
            }
        }
        if snapshot.status == "canceled" || cancel_at.is_some_and(|at| at <= now_ms) {
            phase = "cancelled";
        } else if period_id.is_some() && current.period.contains(now_ms) && limit > 0 {
            if snapshot.status == "active" && current.invoice_status == "paid" {
                phase = "active";
                effective_limit = limit;
            } else if snapshot.status == "past_due" {
                let anchor = tx.query_one("SELECT CASE WHEN payment_grace_invoice_id=latest_invoice_id THEN extract(epoch FROM payment_grace_started_at)::bigint END FROM billing_subscriptions WHERE stripe_subscription_id=$1 AND account_id=$2",
                    &[&snapshot.subscription_id, &account]).await?.get::<_, Option<i64>>(0);
                grace_until = anchor
                    .and_then(|s| s.checked_mul(1000))
                    .and_then(|s| s.checked_add(GRACE_MS));
                if grace_until.is_some_and(|until| now_ms < until) {
                    phase = "grace";
                    // An unpaid upgrade cannot enlarge the previous allowance.
                    effective_limit = limit.min(previous_limit);
                }
            }
        } else {
            phase = "review";
        }
    }
    let live_subscriptions: i64 = tx.query_one("SELECT count(*) FROM billing_subscriptions WHERE account_id=$1 AND stripe_status NOT IN ('canceled','incomplete_expired','provider_deleted')", &[&account]).await?.get(0);
    if live_subscriptions > 1 {
        phase = "review";
        effective_limit = 0;
    }
    let audits: i64 = tx
        .query_one(
            "SELECT count(*) FROM billing_invoice_audit WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    if audits >= 8192 {
        return Err(BillingError::InvalidEvent);
    }
    tx.execute("INSERT INTO billing_invoice_entitlements(account_id,subscription_id,customer_id,period_id,observed_invoice_id,effective_price_id,effective_limit,phase,grace_until_ms,cancel_at_ms,generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(account_id) DO UPDATE SET subscription_id=EXCLUDED.subscription_id,customer_id=EXCLUDED.customer_id,period_id=EXCLUDED.period_id,observed_invoice_id=EXCLUDED.observed_invoice_id,effective_price_id=EXCLUDED.effective_price_id,effective_limit=EXCLUDED.effective_limit,phase=EXCLUDED.phase,grace_until_ms=EXCLUDED.grace_until_ms,cancel_at_ms=EXCLUDED.cancel_at_ms,generation=EXCLUDED.generation,observed_at=clock_timestamp()",
        &[&account, &snapshot.subscription_id, &snapshot.customer_id, &period_id, &snapshot.latest_invoice_id, &snapshot.price_id, &effective_limit, &phase, &grace_until, &cancel_at, &generation]).await?;
    tx.execute("INSERT INTO billing_invoice_audit(account_id,generation,period_id,phase,effective_limit,observed_invoice_id) VALUES($1,$2,$3,$4,$5,$6)",
        &[&account, &generation, &period_id, &phase, &effective_limit, &snapshot.latest_invoice_id]).await?;
    Ok(())
}
