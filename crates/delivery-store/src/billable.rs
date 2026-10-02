// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted, default-off TEST usage forwarding candidate. Admission quotas
//! remain the existing reserve/refund ledger; provider acknowledgements are
//! not validation, invoice settlement, entitlement or permission to dispatch.

use sha2::{Digest, Sha256};
use std::{future::Future, time::Duration};
use tokio_postgres::Client;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("usage storage unavailable")]
    Database(#[from] tokio_postgres::Error),
    #[error("invalid usage reference")]
    InvalidInput,
    #[error("usage reference not found")]
    NotFound,
    #[error("usage identity conflict")]
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeterRequest {
    pub identifier: String,
    pub idempotency_key: String,
    pub event_name: String,
    pub customer_id: String,
    /// Original reservation reporting timestamp in UTC epoch seconds.
    pub timestamp: i64,
    pub units: i64,
    pub api_version: &'static str,
}

/// Trusted TEST transport boundary. Credentials and HTTP remain outside the
/// delivery transaction; an acknowledgement is not asynchronous validation.
pub trait TestMeterTransport {
    fn submit(&self, request: MeterRequest) -> impl Future<Output = MeterResponse> + Send;
}

#[derive(Debug, PartialEq, Eq)]
pub enum MeterResponse {
    Acknowledged {
        identifier: String,
        livemode: bool,
    },
    Http {
        status: u16,
        retry_after_seconds: u64,
    },
    Unknown,
    InvalidResponse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WorkResult {
    Disabled,
    Idle,
    Acknowledged,
    Deferred,
    Review,
    Stale,
}

#[derive(Default)]
pub struct TestUsageWorker {
    enabled: bool,
}

enum ClaimResult {
    Claim(Claim),
    Idle,
    Review,
}

#[derive(Clone)]
struct Claim {
    account: Uuid,
    message: Uuid,
    lease: Uuid,
    attempt: i32,
    request: MeterRequest,
}

impl TestUsageWorker {
    /// Explicit library opt-in for synthetic integration, never inherited from
    /// BILLING_ENABLED and never mounted or spawned by the server.
    pub fn test_candidate() -> Self {
        Self { enabled: true }
    }

    pub async fn run_one<T: TestMeterTransport>(
        &self,
        client: &mut Client,
        transport: &T,
    ) -> Result<WorkResult, UsageError> {
        if !self.enabled {
            return Ok(WorkResult::Disabled);
        }
        let claim = match claim_one(client).await? {
            ClaimResult::Claim(claim) => claim,
            ClaimResult::Idle => return Ok(WorkResult::Idle),
            ClaimResult::Review => return Ok(WorkResult::Review),
        };
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            transport.submit(claim.request.clone()),
        )
        .await
        .unwrap_or(MeterResponse::Unknown);
        finish(client, claim, response).await
    }
}

async fn claim_one(client: &mut Client) -> Result<ClaimResult, UsageError> {
    let tx = client.transaction().await?;
    // One current customer row serializes worker claims across replicas. Do
    // not keep a database socket/transaction locked during transport I/O.
    let account = tx
        .query_opt(
            "SELECT c.account_id FROM billing_customers c WHERE EXISTS (
            SELECT 1 FROM billing_usage_outbox o WHERE o.account_id=c.account_id
              AND o.state IN ('pending','leased') AND o.next_attempt_at<=clock_timestamp()
              AND (o.state='pending' OR o.lease_until<=clock_timestamp()))
          AND NOT EXISTS (SELECT 1 FROM billing_usage_outbox o WHERE o.account_id=c.account_id
              AND o.state='leased' AND o.lease_until>clock_timestamp())
         ORDER BY c.account_id FOR UPDATE OF c SKIP LOCKED LIMIT 1",
            &[],
        )
        .await?;
    let Some(account) = account else {
        return Ok(ClaimResult::Idle);
    };
    let account: Uuid = account.get(0);
    // A selector snapshot can precede acquiring the customer lock. Recheck
    // the single-flight fence in a fresh statement after that lock.
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM billing_usage_outbox WHERE account_id=$1 AND state='leased' AND lease_until>clock_timestamp())", &[&account]).await?.get::<_,bool>(0) {
        return Ok(ClaimResult::Idle);
    }
    let row = tx.query_opt(
        "SELECT o.message_id,o.identifier,o.attempts,p.event_name,p.stripe_customer_id,
            floor(extract(epoch FROM b.report_at))::bigint
         FROM billing_usage_outbox o JOIN billing_usage_bindings b USING(account_id,message_id)
         JOIN billing_usage_test_policies p USING(account_id,policy_version)
         JOIN billing_customers c USING(account_id)
         WHERE o.account_id=$1 AND o.state IN ('pending','leased')
           AND o.next_attempt_at<=clock_timestamp()
           AND (o.state='pending' OR o.lease_until<=clock_timestamp())
         ORDER BY o.next_attempt_at,o.message_id FOR UPDATE OF o FOR SHARE OF p SKIP LOCKED LIMIT 1",
        &[&account]).await?;
    let Some(row) = row else {
        return Ok(ClaimResult::Idle);
    };
    let message: Uuid = row.get(0);
    // Target-list expressions can precede a row-lock wait. Recompute the
    // reporting/retry clocks only after customer, outbox and policy locks.
    let reason = tx.query_one(
        "SELECT CASE WHEN NOT p.active OR p.mode<>'test' THEN 'disabled'
              WHEN p.stripe_customer_id<>c.stripe_customer_id THEN 'binding'
              WHEN EXISTS(SELECT 1 FROM billing_usage_meter_errors e WHERE e.account_id=p.account_id AND e.policy_version=p.policy_version) THEN 'meter_error'
              WHEN clock_timestamp()>=b.period_end::timestamp AT TIME ZONE 'UTC' THEN 'period_closed'
              WHEN b.report_at<clock_timestamp()-interval '35 days'
                OR b.report_at>clock_timestamp()+interval '5 minutes'
                OR b.report_at<b.period_start::timestamp AT TIME ZONE 'UTC'
                OR b.report_at>=b.period_end::timestamp AT TIME ZONE 'UTC'
                OR o.first_attempt_at<=clock_timestamp()-interval '23 hours' THEN 'window'
              WHEN o.attempts>=7 THEN 'attempt_limit' ELSE NULL END
         FROM billing_usage_outbox o JOIN billing_usage_bindings b USING(account_id,message_id)
         JOIN billing_usage_test_policies p USING(account_id,policy_version)
         JOIN billing_customers c USING(account_id) WHERE o.account_id=$1 AND o.message_id=$2",
        &[&account,&message]).await?.get::<_,Option<String>>(0);
    if let Some(reason) = reason {
        tx.execute(
            "UPDATE billing_usage_outbox SET state='review',lease_id=NULL,lease_until=NULL,
              error_class=$3 WHERE account_id=$1 AND message_id=$2",
            &[&account, &message, &reason],
        )
        .await?;
        tx.commit().await?;
        return Ok(ClaimResult::Review);
    }
    let lease = Uuid::new_v4();
    tx.execute(
        "UPDATE billing_usage_outbox SET state='leased',lease_id=$3,
          lease_until=clock_timestamp()+interval '15 seconds',attempts=attempts+1,
          first_attempt_at=COALESCE(first_attempt_at,clock_timestamp())
          WHERE account_id=$1 AND message_id=$2",
        &[&account, &message, &lease],
    )
    .await?;
    let identifier: String = row.get(1);
    let claim = Claim {
        account,
        message,
        lease,
        attempt: row.get::<_, i32>(2) + 1,
        request: MeterRequest {
            idempotency_key: identifier.clone(),
            identifier,
            event_name: row.get(3),
            customer_id: row.get(4),
            timestamp: row.get(5),
            units: 1,
            api_version: "2025-07-30.basil",
        },
    };
    tx.commit().await?;
    Ok(ClaimResult::Claim(claim))
}

fn disposition(response: MeterResponse, claim: &Claim) -> (&'static str, &'static str, u64) {
    match response {
        MeterResponse::Acknowledged {
            identifier,
            livemode,
        } if !livemode && identifier == claim.request.identifier => ("acknowledged", "", 0),
        MeterResponse::Acknowledged { .. } => ("review", "response", 0),
        MeterResponse::InvalidResponse => ("review", "response", 0),
        MeterResponse::Http {
            status: 429 | 500..=599,
            retry_after_seconds,
        } => retry_disposition(claim.attempt, "retry", retry_after_seconds),
        MeterResponse::Unknown => retry_disposition(claim.attempt, "unknown", 0),
        MeterResponse::Http { .. } => ("review", "permanent", 0),
    }
}

fn retry_disposition(
    attempt: i32,
    reason: &'static str,
    retry_after: u64,
) -> (&'static str, &'static str, u64) {
    if attempt >= 7 {
        return ("review", "attempt_limit", 0);
    }
    let seconds = if retry_after > 0 {
        retry_after.min(600)
    } else {
        (1u64 << attempt.clamp(1, 9)).min(600)
    };
    ("pending", reason, seconds)
}

async fn finish(
    client: &mut Client,
    claim: Claim,
    response: MeterResponse,
) -> Result<WorkResult, UsageError> {
    let tx = client.transaction().await?;
    // Acquire the exact current lease before reading any expiry predicate.
    let Some(row)=tx.query_opt("SELECT lease_until FROM billing_usage_outbox WHERE account_id=$1 AND message_id=$2 AND state='leased' AND lease_id=$3 FOR UPDATE",&[&claim.account,&claim.message,&claim.lease]).await? else {
        return Ok(WorkResult::Stale);
    };
    // SystemTime transports a DB timestamp; it is never compared to the host clock.
    let deadline: std::time::SystemTime = row.get(0);
    let (state, error, delay) = disposition(response, &claim);
    let delay = delay as i32;
    let changed = tx.execute(
        "UPDATE billing_usage_outbox SET state=$4,lease_id=NULL,lease_until=NULL,
            acknowledged_at=CASE WHEN $4='acknowledged' THEN clock_timestamp() ELSE acknowledged_at END,
            error_class=NULLIF($5,''),next_attempt_at=clock_timestamp()+($6::integer*interval '1 second')
         WHERE account_id=$1 AND message_id=$2 AND state='leased' AND lease_id=$3
           AND lease_until>clock_timestamp()", &[&claim.account,&claim.message,&claim.lease,&state,&error,&delay]).await?;
    // A trigger, constraint or other awaited write may outlive the lease.
    // Use the authoritative DB clock AFTER mutation and roll back a late result.
    if changed == 0
        || !tx
            .query_one("SELECT $1::timestamptz>clock_timestamp()", &[&deadline])
            .await?
            .get::<_, bool>(0)
    {
        return Ok(WorkResult::Stale);
    }
    tx.commit().await?;
    Ok(match state {
        "acknowledged" => WorkResult::Acknowledged,
        "pending" => WorkResult::Deferred,
        _ => WorkResult::Review,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUsage {
    pub finalized: i64,
    pub acknowledged: i64,
    pub pending: i64,
    pub review: i64,
}

/// Content-free local projection; never polls Stripe for quota or totals.
pub async fn local_usage(
    client: &Client,
    account: Uuid,
    period_start: &str,
) -> Result<LocalUsage, UsageError> {
    if !valid_period(period_start) {
        return Err(UsageError::InvalidInput);
    }
    let r = client
        .query_one(
            "SELECT count(*)::bigint,
            (count(*) FILTER (WHERE o.acknowledged_at IS NOT NULL))::bigint,
            (count(*) FILTER (WHERE o.state IN ('pending','leased')))::bigint,
            (count(*) FILTER (WHERE o.state='review'))::bigint
         FROM billing_usage_finalized f JOIN billing_usage_bindings b USING(account_id,message_id)
         JOIN billing_usage_outbox o USING(account_id,message_id)
         WHERE f.account_id=$1 AND b.period_start::text=$2",
            &[&account, &period_start],
        )
        .await?;
    Ok(LocalUsage {
        finalized: r.get(0),
        acknowledged: r.get(1),
        pending: r.get(2),
        review: r.get(3),
    })
}

fn valid_period(value: &str) -> bool {
    value.is_ascii()
        && value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.ends_with("-01")
        && value[..4].bytes().all(|b| b.is_ascii_digit())
        && value[5..7]
            .parse::<u8>()
            .is_ok_and(|month| (1..=12).contains(&month))
}

/// Trusted TEST provider snapshot comparison. This only appends observations;
/// matching totals do not validate individual events or grant entitlement.
#[derive(Debug, Clone)]
pub struct ProviderObservation {
    pub snapshot_id: Uuid,
    pub policy_version: i64,
    pub period_start: String,
    pub customer: String,
    pub meter: String,
    pub provider_units: i64,
    /// Optional independently attributed TEST invoice quantity. Absence
    /// remains pending; matching aggregates alone cannot settle an invoice.
    pub invoice_units: Option<i64>,
}

pub async fn reconcile(
    client: &mut Client,
    account: Uuid,
    observation: &ProviderObservation,
) -> Result<String, UsageError> {
    let snapshot_id = observation.snapshot_id;
    let policy_version = observation.policy_version;
    let period_start = observation.period_start.as_str();
    let customer = observation.customer.as_str();
    let meter = observation.meter.as_str();
    let provider_units = observation.provider_units;
    let invoice_units = observation.invoice_units;
    if !valid_period(period_start)
        || policy_version <= 0
        || provider_units < 0
        || invoice_units.is_some_and(|units| units < 0)
        || customer.len() > 100
        || meter.len() > 100
    {
        return Err(UsageError::InvalidInput);
    }
    let tx = client.transaction().await?;
    tx.query_opt(
        "SELECT 1 FROM billing_customers WHERE account_id=$1 FOR SHARE",
        &[&account],
    )
    .await?;
    if tx
        .query_opt(
            "SELECT 1 FROM billing_usage_test_policies p JOIN billing_customers c USING(account_id)
          WHERE p.account_id=$1 AND p.policy_version=$2 AND p.stripe_customer_id=$3
            AND c.stripe_customer_id=$3 AND p.meter_id=$4 AND p.mode='test' FOR SHARE OF p,c",
            &[&account, &policy_version, &customer, &meter],
        )
        .await?
        .is_none()
    {
        return Err(UsageError::NotFound);
    }
    let r = tx
        .query_one(
            "SELECT count(*)::bigint,
          (count(*) FILTER (WHERE o.acknowledged_at IS NOT NULL))::bigint,
          (count(*) FILTER (WHERE o.state IN ('pending','leased')))::bigint,
          (count(*) FILTER (WHERE o.state='review'))::bigint
          FROM billing_usage_finalized f JOIN billing_usage_bindings b USING(account_id,message_id)
          JOIN billing_usage_outbox o USING(account_id,message_id)
          WHERE f.account_id=$1 AND b.policy_version=$2 AND b.period_start::text=$3",
            &[&account, &policy_version, &period_start],
        )
        .await?;
    let finalized: i64 = r.get(0);
    let acknowledged: i64 = r.get(1);
    let pending: i64 = r.get(2);
    let review: i64 = r.get(3);
    let state = if review > 0
        || provider_units != finalized
        || invoice_units.is_some_and(|units| units != finalized)
    {
        "diverged"
    } else if pending > 0 || invoice_units.is_none() {
        "pending"
    } else {
        "observed_equal"
    };
    let digest = Sha256::digest(format!("ZT/usage-observation/v1\0{account}\0{snapshot_id}\0{policy_version}\0{period_start}\0{customer}\0{meter}\0{provider_units}\0{invoice_units:?}").as_bytes()).to_vec();
    tx.execute("INSERT INTO billing_usage_reconciliations(account_id,snapshot_id,policy_version,period_start,
          finalized_units,acknowledged_units,provider_units,pending_units,review_units,snapshot_digest,state,invoice_units)
          VALUES($1,$2,$3,$4::text::date,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(account_id,snapshot_id) DO NOTHING",
          &[&account,&snapshot_id,&policy_version,&period_start,&finalized,&acknowledged,&provider_units,&pending,&review,&digest,&state,&invoice_units]).await?;
    let saved = tx.query_one("SELECT snapshot_digest,state FROM billing_usage_reconciliations WHERE account_id=$1 AND snapshot_id=$2", &[&account,&snapshot_id]).await?;
    if saved.get::<_, Vec<u8>>(0) != digest {
        return Err(UsageError::Conflict);
    }
    let result = saved.get(1);
    tx.commit().await?;
    Ok(result)
}

/// Call only after raw signature verification and trusted TEST/meter/account
/// binding. A complete validation interval is retained; samples never imply a
/// complete set of rejected identifiers. No credit or re-send is inferred.
#[derive(Debug, Clone)]
pub struct MeterErrorObservation {
    pub event_id: String,
    pub meter_id: String,
    pub body_digest: [u8; 32],
    /// Exact UTC epoch milliseconds from the provider validation interval.
    pub validation_start: i64,
    /// Exact UTC epoch milliseconds; never rounded to a guessed second.
    pub validation_end: i64,
}

pub async fn record_meter_error(
    client: &mut Client,
    account: Uuid,
    policy_version: i64,
    observation: &MeterErrorObservation,
) -> Result<bool, UsageError> {
    let event_id = observation.event_id.as_str();
    let meter_id = observation.meter_id.as_str();
    let body_digest = &observation.body_digest;
    let validation_start = observation.validation_start;
    let validation_end = observation.validation_end;
    if !event_id.starts_with("evt_")
        || event_id.len() > 100
        || event_id.len() < 5
        || !event_id[4..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || validation_start < 0
        || validation_end < validation_start
        || validation_end > 253402300799999
        || policy_version <= 0
    {
        return Err(UsageError::InvalidInput);
    }
    let tx = client.transaction().await?;
    tx.query_opt(
        "SELECT 1 FROM billing_customers WHERE account_id=$1 FOR SHARE",
        &[&account],
    )
    .await?;
    if tx
        .query_opt(
            "SELECT 1 FROM billing_usage_test_policies p JOIN billing_customers c USING(account_id)
          WHERE p.account_id=$1 AND p.policy_version=$2 AND p.mode='test' AND p.meter_id=$3
            AND p.stripe_customer_id=c.stripe_customer_id FOR SHARE OF p,c",
            &[&account, &policy_version, &meter_id],
        )
        .await?
        .is_none()
    {
        return Err(UsageError::NotFound);
    }
    tx.execute("INSERT INTO billing_usage_meter_error_receipts(event_id,meter_id,body_digest,validation_start,validation_end)
          VALUES($1,$2,$3,to_timestamp($4::double precision/1000),to_timestamp($5::double precision/1000)) ON CONFLICT(event_id) DO NOTHING",
          &[&event_id,&meter_id,&&body_digest[..],&(validation_start as f64),&(validation_end as f64)]).await?;
    let receipt=tx.query_one("SELECT meter_id,body_digest,(extract(epoch FROM validation_start)*1000)::bigint,(extract(epoch FROM validation_end)*1000)::bigint
          FROM billing_usage_meter_error_receipts WHERE event_id=$1", &[&event_id]).await?;
    if receipt.get::<_, String>(0) != meter_id
        || receipt.get::<_, Vec<u8>>(1) != body_digest.as_slice()
        || receipt.get::<_, i64>(2) != validation_start
        || receipt.get::<_, i64>(3) != validation_end
    {
        return Err(UsageError::Conflict);
    }
    let inserted=tx.execute("INSERT INTO billing_usage_meter_errors(event_id,account_id,policy_version,body_digest,validation_start,validation_end)
          VALUES($1,$2,$3,$4,to_timestamp($5::double precision/1000),to_timestamp($6::double precision/1000)) ON CONFLICT(account_id,policy_version,event_id) DO NOTHING",
          &[&event_id,&account,&policy_version,&&body_digest[..],&(validation_start as f64),&(validation_end as f64)]).await?;
    if inserted > 0 {
        // Error samples and validation timestamps cannot reliably attribute
        // every asynchronous rejection. Pause the entire affected meter policy.
        // Bound this eager batch; the durable policy error fences later claims.
        tx.execute("UPDATE billing_usage_outbox o SET state='review',lease_id=NULL,lease_until=NULL,error_class='meter_error'
          WHERE (o.account_id,o.message_id) IN (SELECT x.account_id,x.message_id FROM billing_usage_outbox x
            JOIN billing_usage_bindings b USING(account_id,message_id) WHERE b.account_id=$1 AND b.policy_version=$2
            ORDER BY x.message_id LIMIT 1000)", &[&account,&policy_version]).await?;
    }
    tx.commit().await?;
    Ok(inserted > 0)
}

#[cfg(test)]
mod tests;
