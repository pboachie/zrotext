// SPDX-License-Identifier: AGPL-3.0-only
//! TEST-only provider observations. Equality never grants entitlement or credit.
use reqwest::{Client, Url};
use serde_json::Value;
use std::time::Duration;
use tokio_postgres::Client as Database;
use uuid::Uuid;
use zrotext_delivery_store::billable::{self, ProviderObservation};

mod invoice_period;
pub(crate) mod lifecycle;
mod provider;
mod worker;
pub use worker::run_queue;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TEST usage observation unavailable")]
    Unavailable,
    #[error("TEST usage observation storage unavailable")]
    Database(#[from] tokio_postgres::Error),
    #[error("TEST usage observation refused")]
    Usage(#[from] billable::UsageError),
}

pub struct TestUsageReconciler {
    http: Client,
    key: zeroize::Zeroizing<String>,
    base: Url,
}

struct Scope {
    account: Uuid,
    policy: i64,
    period: String,
    customer: String,
    meter: String,
    event_name: String,
    start: i64,
    end: i64,
    invoice: Option<String>,
    subscription: Option<String>,
    invoice_binding: Option<(String, String, String)>,
}

impl TestUsageReconciler {
    pub fn configured(
        enabled: bool,
        billing_test: bool,
        key: Option<String>,
    ) -> Result<Option<Self>, &'static str> {
        if !enabled {
            return Ok(None);
        }
        if !billing_test {
            return Err("TEST usage reconciliation requires TEST billing");
        }
        let key = key.ok_or("TEST usage reconciliation credential unavailable")?;
        if !super::is_test_api_key(&key)
            || key.len() > 256
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("invalid TEST usage reconciliation credential");
        }
        let http = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .build()
            .map_err(|_| "invalid TEST usage reconciliation client")?;
        Ok(Some(Self {
            http,
            key: zeroize::Zeroizing::new(key),
            base: Url::parse("https://api.stripe.com/").expect("fixed HTTPS endpoint"),
        }))
    }

    /// Enabled startup refuses an unapplied observation schema before spawning.
    pub async fn validate_schema(&self, database: &Database) -> Result<(), Error> {
        database.query("SELECT period_id,policy_version,identity_digest,provider_units,invoice_units FROM billing_invoice_usage_observations LIMIT 0",&[]).await?;
        database.query("SELECT p.stripe_customer_id,p.meter_id,p.event_name,p.mode,p.api_version,            b.period_start,b.period_end,i.invoice_id,i.subscription_id,f.message_id,o.state,o.acknowledged_at,            r.observed_at,r.invoice_units FROM billing_usage_test_policies p            JOIN billing_usage_bindings b USING(account_id,policy_version)            JOIN billing_customers c USING(account_id)            JOIN billing_usage_finalized f USING(account_id,message_id)            JOIN billing_usage_outbox o USING(account_id,message_id)            LEFT JOIN billing_invoice_periods i USING(account_id)            LEFT JOIN billing_usage_reconciliations r USING(account_id,policy_version,period_start) LIMIT 0", &[]).await?;
        Ok(())
    }

    /// The process supplies identities; customer, meter and period come from
    /// committed bindings. No browser, webhook or model supplies quantities.
    pub async fn reconcile_period(
        &self,
        database: &mut Database,
        account: Uuid,
        policy: i64,
        period: &str,
        snapshot: Uuid,
    ) -> Result<String, Error> {
        if account.is_nil() || snapshot.is_nil() || policy <= 0 || period.len() != 10 {
            return Err(Error::Unavailable);
        }
        let row = database.query_opt(
            "SELECT p.stripe_customer_id,p.meter_id,p.event_name,b.period_start::text,\
             extract(epoch FROM (b.period_start::timestamp AT TIME ZONE 'UTC'))::bigint,\
             extract(epoch FROM (b.period_end::timestamp AT TIME ZONE 'UTC'))::bigint,\
             i.invoice_id,i.subscription_id FROM billing_usage_test_policies p \
             JOIN billing_customers c ON (c.account_id,c.stripe_customer_id)=(p.account_id,p.stripe_customer_id) \
             JOIN billing_usage_bindings b ON (b.account_id,b.policy_version)=(p.account_id,p.policy_version) \
             LEFT JOIN billing_invoice_periods i ON i.account_id=b.account_id \
             AND i.start_ms=extract(epoch FROM (b.period_start::timestamp AT TIME ZONE 'UTC'))::bigint*1000 \
             AND i.end_ms=extract(epoch FROM (b.period_end::timestamp AT TIME ZONE 'UTC'))::bigint*1000 \
             WHERE p.account_id=$1 AND p.policy_version=$2 AND b.period_start::text=$3 \
             AND p.mode='test' AND p.api_version='2025-07-30.basil' \
             GROUP BY p.stripe_customer_id,p.meter_id,p.event_name,b.period_start,b.period_end,i.invoice_id,i.subscription_id \
             ORDER BY i.invoice_id LIMIT 2",
            &[&account,&policy,&period],
        ).await?;
        let row = row.ok_or(Error::Unavailable)?;
        let scope = Scope {
            account,
            policy,
            period: row.get(3),
            customer: row.get(0),
            meter: row.get(1),
            event_name: row.get(2),
            start: row.get(4),
            end: row.get(5),
            invoice: row.get(6),
            subscription: row.get(7),
            invoice_binding: None,
        };
        let (provider_units, invoice_units) =
            tokio::time::timeout(Duration::from_secs(20), self.observe(&scope))
                .await
                .map_err(|_| Error::Unavailable)??;
        Ok(billable::reconcile(
            database,
            scope.account,
            &ProviderObservation {
                snapshot_id: snapshot,
                policy_version: scope.policy,
                period_start: scope.period,
                customer: scope.customer,
                meter: scope.meter,
                provider_units,
                invoice_units,
            },
        )
        .await?)
    }
}

fn identifier(value: &str, prefix: &str) -> bool {
    value.len() <= 256
        && value.strip_prefix(prefix).is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

fn refused<T>() -> Result<T, Error> {
    Err(Error::Unavailable)
}

#[cfg(test)]
mod tests;
