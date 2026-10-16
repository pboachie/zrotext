// SPDX-License-Identifier: AGPL-3.0-only
use super::{Error, Runtime, marker_error, provider, repository as db};
use crate::billing::hosted::{
    namespace::Scope,
    policy::{FailureEvidence, Observation, SubscriptionStatus},
    store::{self, ReadClaim},
};
use uuid::Uuid;

struct Job {
    account: Uuid,
    customer: String,
    generation: i64,
    token: Uuid,
    scope: Option<Scope>,
    read: Option<ReadClaim>,
    recovery: i64,
}
async fn claim(r: &Runtime) -> Result<Option<Job>, Error> {
    let mut conn = crate::runtime_db::connect_worker(&r.auth.database_url)
        .await
        .map_err(|_| Error::Database)?;
    let tx = conn.transaction().await?;
    // Candidates are observations, not locks; acquire namespace/account before
    // queue/projection so owner mutations and admissions use one lock order.
    let candidate=tx.query_opt("SELECT c.account_id FROM hosted_billing_customers c JOIN accounts a ON a.id=c.account_id AND a.disabled_at IS NULL WHERE c.namespace_id=$1 AND c.customer_id IS NOT NULL AND c.lease_until<=floor(extract(epoch FROM clock_timestamp())) AND c.next_attempt_at<=floor(extract(epoch FROM clock_timestamp())) ORDER BY c.next_attempt_at,c.account_id LIMIT 1",&[&db::ns(r)]).await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let account = candidate.get(0);
    db::lock(&tx, r, account).await?;
    db::require_no_global_review(&tx, r).await?;
    let Some(c) = db::customer(&tx, r, account, false).await? else {
        return Ok(None);
    };
    let token = Uuid::new_v4();
    let now = db::now(&tx).await?;
    let row=tx.query_opt("UPDATE hosted_billing_customers SET queue_generation=queue_generation+1,lease_token=$3,lease_until=$4 WHERE namespace_id=$1 AND account_id=$2 AND lease_until<=$5 AND next_attempt_at<=$5 RETURNING queue_generation,recovery_at",&[&db::ns(r),&account,&token,&(now+90),&now]).await?;
    let Some(row) = row else { return Ok(None) };
    let scope=tx.query_opt("SELECT customer_id,subscription_id FROM hosted_billing_projections WHERE namespace_id=$1 AND account_id=$2",&[&db::ns(r),&account]).await?.map(|p|Scope::new(r.options.namespace.clone(),account.into_bytes(),&p.get::<_,String>(0),&p.get::<_,String>(1)).map_err(|_|Error::Identity)).transpose()?;
    let read = if let Some(scope) = &scope {
        Some(
            store::claim_read(&tx, &r.gate, scope)
                .await
                .map_err(marker_error)?,
        )
    } else {
        None
    };
    let job = Job {
        account,
        customer: c.id.ok_or(Error::Identity)?,
        generation: row.get(0),
        token,
        scope,
        read,
        recovery: row.get(1),
    };
    tx.commit().await?;
    Ok(Some(job))
}
pub(super) async fn run_one(r: &Runtime) -> Result<bool, Error> {
    let Some(job) = claim(r).await? else {
        return Ok(false);
    };
    match observe(r, &job).await {
        Ok(()) => Ok(true),
        Err(e) => {
            let _ = retry(r, &job).await;
            Err(e)
        }
    }
}
async fn retry(r: &Runtime, j: &Job) -> Result<(), Error> {
    let mut conn = db::connect(r).await?;
    let tx = conn.transaction().await?;
    db::lock(&tx, r, j.account).await?;
    tx.execute("UPDATE hosted_billing_customers SET lease_token=NULL,lease_until=0,next_attempt_at=floor(extract(epoch FROM clock_timestamp()))+30 WHERE namespace_id=$1 AND account_id=$2 AND lease_token=$3",&[&db::ns(r),&j.account,&j.token]).await?;
    // No projection, grace deadline, hold or processed generation is changed.
    tx.commit().await?;
    Ok(())
}
async fn observe(r: &Runtime, j: &Job) -> Result<(), Error> {
    let list = r.provider.subscriptions(&r.options, &j.customer).await?;
    let _catalog = r.provider.catalog_current(&r.options).await?;
    let current = j
        .scope
        .as_ref()
        .and_then(|scope| list.current.iter().find(|s| s.id == scope.subscription()));
    if let Some(s) = current
        && list.complete
        && list.current.len() == 1
        && !s.invoice.is_empty()
    {
        let invoice = r.provider.invoice(&r.options, &s.invoice).await?;
        provider::validate_invoice(&invoice, &r.options, &j.customer, s)?;
    }
    let mut conn = db::connect(r).await?;
    let tx = conn.transaction().await?;
    db::lock(&tx, r, j.account).await?;
    db::require_no_global_review(&tx, r).await?;
    let c = db::customer(&tx, r, j.account, false)
        .await?
        .ok_or(Error::Identity)?;
    let valid=tx.query_opt("SELECT 1 FROM hosted_billing_customers WHERE namespace_id=$1 AND account_id=$2 AND lease_token=$3 AND queue_generation=$4 AND lease_until>floor(extract(epoch FROM clock_timestamp())) FOR UPDATE",&[&db::ns(r),&j.account,&j.token,&j.generation]).await?.is_some();
    if !valid || c.id.as_deref() != Some(&j.customer) {
        return Err(Error::Pending);
    }
    let now = db::now(&tx).await?;
    let mut reason = "pending";
    if let (Some(scope), Some(read)) = (&j.scope, &j.read) {
        let selected = current;
        let status = selected.map_or(SubscriptionStatus::Canceled, |s| s.status);
        let failure = if let Some(s) = selected
            && s.status == SubscriptionStatus::PastDue
        {
            tx.query_opt("SELECT least(occurred_at,received_at) FROM hosted_billing_events WHERE namespace_id=$1 AND account_id=$2 AND invoice_id=$3 AND event_type='invoice.payment_failed' AND state IN ('queued','processed') AND occurred_at>$4 ORDER BY least(occurred_at,received_at) LIMIT 1",&[&db::ns(r),&j.account,&s.invoice,&j.recovery]).await?.map(|row|FailureEvidence{scope:scope.clone(),invoice:s.invoice.clone(),occurred_at:row.get(0)})
        } else {
            None
        };
        let o = Observation {
            scope: scope.clone(),
            policy_revision: r.options.policy_revision,
            generation: read.generation(),
            complete: list.complete,
            nonterminal_subscriptions: list.current.len() as u64,
            status,
            price: selected.map_or(String::new(), |s| s.price.clone()),
            invoice: selected.map_or(String::new(), |s| s.invoice.clone()),
            period_start: selected.map_or(0, |s| s.start),
            period_end: selected.map_or(0, |s| s.end),
            revalidate_at: now + provider::LEASE_SECONDS,
            failure,
        };
        let projection = store::commit_observation(&tx, &r.gate, scope, read, &o, &r.options.plan)
            .await
            .map_err(marker_error)?;
        reason = match projection.phase() {
            super::super::policy::Phase::Active => "active",
            super::super::policy::Phase::Grace => "grace",
            super::super::policy::Phase::Restricted => "restricted",
            super::super::policy::Phase::Terminal => "terminal",
            _ => "pending",
        };
        if reason == "active" {
            tx.execute("UPDATE hosted_billing_customers SET recovery_at=$3 WHERE namespace_id=$1 AND account_id=$2",&[&db::ns(r),&j.account,&now]).await?;
        }
        // A complete list proves that the old immutable subscription is
        // terminal. Archive it before installing a new scope on a later read.
        if list.complete && current.is_none() && list.current.len() == 1 {
            tx.execute("INSERT INTO hosted_billing_history(namespace_id,account_id,subscription_id,customer_id,retired_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",&[&db::ns(r),&j.account,&scope.subscription(),&j.customer,&now]).await?;
            tx.execute("DELETE FROM hosted_billing_projections WHERE namespace_id=$1 AND account_id=$2 AND phase='terminal'",&[&db::ns(r),&j.account]).await?;
            install(&tx, r, j, &list.current[0].id, now).await?;
            reason = "scope_changed";
        }
    } else if list.complete && list.current.len() == 1 {
        install(&tx, r, j, &list.current[0].id, now).await?;
        reason = "scope_created";
    } else if list.complete && list.current.is_empty() {
        reason = "terminal";
    }
    let needs_read = matches!(reason, "scope_created" | "scope_changed" | "pending");
    tx.execute("UPDATE hosted_billing_customers SET processed_generation=$4,lease_token=NULL,lease_until=0,next_attempt_at=$5,last_observation_complete=$6,last_nonterminal_count=$7 WHERE namespace_id=$1 AND account_id=$2 AND lease_token=$3 AND queue_generation=$4",&[&db::ns(r),&j.account,&j.token,&j.generation,&(now+if needs_read{5}else{60}),&list.complete,&(list.current.len() as i64)]).await?;
    if !needs_read {
        tx.execute("UPDATE hosted_billing_events SET state='processed' WHERE namespace_id=$1 AND account_id=$2 AND state='queued'",&[&db::ns(r),&j.account]).await?;
    }
    db::audit(&tx, r, j.account, j.generation, reason).await?;
    // The namespace/account locks remain held; database time and marker are
    // checked again after the last write and immediately before commit.
    db::lock(&tx, r, j.account).await?;
    if db::now(&tx).await? >= now + provider::LEASE_SECONDS {
        return Err(Error::Pending);
    }
    tx.commit().await?;
    Ok(())
}
async fn install(
    tx: &tokio_postgres::Transaction<'_>,
    r: &Runtime,
    j: &Job,
    subscription: &str,
    now: i64,
) -> Result<(), Error> {
    if tx
        .query_opt(
            "SELECT 1 FROM hosted_billing_history WHERE namespace_id=$1 AND subscription_id=$2",
            &[&db::ns(r), &subscription],
        )
        .await?
        .is_some()
    {
        return Err(Error::Conflict);
    }
    tx.execute("INSERT INTO hosted_billing_projections(namespace_id,account_id,customer_id,subscription_id,policy_revision,dirty_generation,processed_generation,per_read_sequence,payment_hold,review_required,phase,outbound_limit,device_limit,issued_at,valid_until) SELECT namespace_id,account_id,customer_id,$3,$4,0,0,0,payment_hold,review_required,'pending',0,0,$5,$5 FROM hosted_billing_customers WHERE namespace_id=$1 AND account_id=$2",&[&db::ns(r),&j.account,&subscription,&(r.options.policy_revision as i64),&now]).await?;
    Ok(())
}
