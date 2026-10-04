// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;

struct InvoiceScope {
    scope: Scope,
    identity: Vec<u8>,
}

async fn scope<C: GenericClient + Sync>(
    db: &C,
    account: Uuid,
    period: Uuid,
) -> Result<InvoiceScope, Error> {
    let retained:i64=db.query_one("SELECT count(*)::bigint FROM (SELECT 1 FROM billing_invoice_usage WHERE account_id=$1 AND period_id=$2 LIMIT 10001) bounded",&[&account,&period]).await?.get(0);
    if retained > 10000 {
        return refused();
    }
    // Exact immutable invoice identity, never the current subscription's guessed
    // month. A single committed attribution policy is required; active policy alone
    // cannot establish the original meter for an empty period.
    let rows = db.query(
        "SELECT i.subscription_id,i.invoice_id,i.start_ms,i.end_ms,i.original_price_id,p.policy_version,p.stripe_customer_id,p.meter_id,p.event_name,i.line_id,i.item_id \
         FROM billing_invoice_periods i JOIN billing_reconciliations r ON (r.account_id,r.stripe_subscription_id)=(i.account_id,i.subscription_id) \
         JOIN billing_customers c ON (c.account_id,c.stripe_customer_id)=(r.account_id,r.stripe_customer_id) \
         JOIN billing_usage_test_policies p ON (p.account_id,p.stripe_customer_id)=(c.account_id,c.stripe_customer_id) \
         WHERE i.account_id=$1 AND i.id=$2 AND p.mode='test' AND p.api_version='2025-07-30.basil' \
         AND EXISTS(SELECT 1 FROM billing_invoice_usage u JOIN billing_usage_bindings b USING(account_id,message_id) WHERE u.account_id=i.account_id AND u.period_id=i.id AND b.policy_version=p.policy_version) ORDER BY p.policy_version LIMIT 2",
        &[&account,&period]).await?;
    if rows.len() != 1 {
        return refused();
    }
    let r = &rows[0];
    let start_ms: i64 = r.get(2);
    let end_ms: i64 = r.get(3);
    // Stripe meter summaries use whole UTC seconds. Refuse truncation.
    if start_ms % 1000 != 0 || end_ms % 1000 != 0 {
        return refused();
    }
    let result = InvoiceScope {
        scope: Scope {
            account,
            policy: r.get(5),
            period: String::new(),
            customer: r.get(6),
            meter: r.get(7),
            event_name: r.get(8),
            start: start_ms / 1000,
            end: end_ms / 1000,
            invoice: Some(r.get(1)),
            subscription: Some(r.get(0)),
            invoice_binding: Some((r.get(4), r.get(9), r.get(10))),
        },
        identity: Vec::new(),
    };
    let incompatible:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM billing_invoice_usage u LEFT JOIN billing_usage_bindings b USING(account_id,message_id) LEFT JOIN billing_usage_test_policies p ON (p.account_id,p.policy_version)=(b.account_id,b.policy_version) WHERE u.account_id=$1 AND u.period_id=$2 AND (b.message_id IS NULL OR b.policy_version<>$3 OR p.stripe_customer_id<>$4 OR p.meter_id<>$5))",&[&account,&period,&result.scope.policy,&result.scope.customer,&result.scope.meter]).await?.get(0);
    if incompatible {
        return refused();
    }
    let identity = Sha256::digest(
        serde_json::to_vec(&(
            "ZT/invoice-observation/v1",
            account,
            period,
            &result.scope.subscription,
            &result.scope.invoice,
            start_ms,
            end_ms,
            &result.scope.invoice_binding,
            result.scope.policy,
            &result.scope.customer,
            &result.scope.meter,
            &result.scope.event_name,
        ))
        .map_err(|_| Error::Unavailable)?,
    )
    .to_vec();
    Ok(InvoiceScope { identity, ..result })
}

impl TestUsageReconciler {
    /// Observe the original invoice-period attribution. No remote I/O occurs
    /// inside the final transaction; equality creates no credit or admission.
    pub async fn reconcile_invoice_period(
        &self,
        db: &mut Database,
        account: Uuid,
        period: Uuid,
        snapshot: Uuid,
    ) -> Result<String, Error> {
        if account.is_nil() || period.is_nil() || snapshot.is_nil() {
            return refused();
        }
        let before = scope(db, account, period).await?;
        let (provider, invoice) =
            tokio::time::timeout(Duration::from_secs(20), self.observe(&before.scope))
                .await
                .map_err(|_| Error::Unavailable)??;
        let invoice = invoice.ok_or(Error::Unavailable)?;
        let tx = db.transaction().await?;
        // Match invoice reservation/store order: account before policy/customer
        // and period; period excludes concurrent liability/attribution writes.
        tx.query_opt(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&account],
        )
        .await?
        .ok_or(Error::Unavailable)?;
        tx.query_opt(
            "SELECT account_id FROM billing_customers WHERE account_id=$1 FOR SHARE",
            &[&account],
        )
        .await?
        .ok_or(Error::Unavailable)?;
        tx.query_opt("SELECT policy_version FROM billing_usage_test_policies WHERE account_id=$1 AND policy_version=$2 FOR SHARE",&[&account,&before.scope.policy]).await?.ok_or(Error::Unavailable)?;
        tx.query_opt("SELECT stripe_subscription_id FROM billing_reconciliations WHERE account_id=$1 AND stripe_subscription_id=$2 FOR SHARE",&[&account,&before.scope.subscription]).await?.ok_or(Error::Unavailable)?;
        let period_row=tx.query_opt("SELECT open_units FROM billing_invoice_periods WHERE account_id=$1 AND id=$2 FOR SHARE",&[&account,&period]).await?.ok_or(Error::Unavailable)?;
        let after = scope(&tx, account, period).await?;
        if before.identity != after.identity {
            return refused();
        }
        // Lock exact attributed rows before reading their evolving observations.
        tx.query("SELECT u.message_id FROM billing_invoice_usage u WHERE account_id=$1 AND period_id=$2 ORDER BY message_id FOR SHARE",&[&account,&period]).await?;
        tx.query("SELECT b.message_id FROM billing_usage_bindings b JOIN billing_invoice_usage u USING(account_id,message_id) WHERE u.account_id=$1 AND u.period_id=$2 ORDER BY b.message_id FOR SHARE OF b",&[&account,&period]).await?;
        tx.query("SELECT o.message_id FROM billing_usage_outbox o JOIN billing_invoice_usage u USING(account_id,message_id) WHERE u.account_id=$1 AND u.period_id=$2 ORDER BY o.message_id FOR SHARE OF o",&[&account,&period]).await?;
        let counts=tx.query_one("SELECT count(f.message_id)::bigint,(count(f.message_id) FILTER(WHERE o.acknowledged_at IS NOT NULL))::bigint,(count(*) FILTER(WHERE (f.message_id IS NULL AND NOT u.refunded) OR o.state IN ('pending','leased')))::bigint,(count(*) FILTER(WHERE f.message_id IS NOT NULL AND (o.message_id IS NULL OR o.state='review')))::bigint FROM billing_invoice_usage u LEFT JOIN billing_usage_finalized f USING(account_id,message_id) LEFT JOIN billing_usage_outbox o USING(account_id,message_id) WHERE u.account_id=$1 AND u.period_id=$2",&[&account,&period]).await?;
        let finalized: i64 = counts.get(0);
        let acknowledged: i64 = counts.get(1);
        let pending: i64 = counts.get(2);
        let review: i64 = counts.get(3);
        let open: i64 = period_row.get(0);
        let state = if review > 0 || provider != finalized || invoice != finalized {
            "diverged"
        } else if pending > 0 || open > 0 {
            "pending"
        } else {
            "observed_equal"
        };
        let digest = Sha256::digest(
            serde_json::to_vec(&(&after.identity, provider, invoice))
                .map_err(|_| Error::Unavailable)?,
        )
        .to_vec();
        if tx.query_one("SELECT NOT EXISTS(SELECT 1 FROM billing_invoice_usage_observations WHERE account_id=$1 AND snapshot_id=$2) AND (SELECT count(*) FROM billing_invoice_usage_observations WHERE account_id=$1)>=10000",&[&account,&snapshot]).await?.get::<_,bool>(0){return refused();}
        tx.execute("INSERT INTO billing_invoice_usage_observations(account_id,snapshot_id,period_id,policy_version,identity_digest,snapshot_digest,finalized_units,acknowledged_units,pending_units,review_units,open_units,provider_units,invoice_units,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(account_id,snapshot_id) DO NOTHING",&[&account,&snapshot,&period,&after.scope.policy,&after.identity,&digest,&finalized,&acknowledged,&pending,&review,&open,&provider,&invoice,&state]).await?;
        let saved=tx.query_one("SELECT snapshot_digest,state FROM billing_invoice_usage_observations WHERE account_id=$1 AND snapshot_id=$2",&[&account,&snapshot]).await?;
        if saved.get::<_, Vec<u8>>(0) != digest {
            return Err(Error::Usage(billable::UsageError::Conflict));
        }
        // Fresh identity after all potentially blocking writes, including replay.
        if scope(&tx, account, period).await?.identity != after.identity {
            return refused();
        }
        let result = saved.get(1);
        tx.commit().await?;
        Ok(result)
    }
}
