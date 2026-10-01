// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

pub(super) struct Scope {
    pub kind: String,
    pub id: Uuid,
}
impl Scope {
    pub fn new(kind: &str, id: Uuid) -> Self {
        Self {
            kind: kind.into(),
            id,
        }
    }
}

pub(super) struct Budget {
    pub id: Uuid,
    pub kind: String,
    pub version: i64,
    pub start: i64,
    pub end: i64,
    pub soft: i64,
    pub hard: i64,
}
impl Budget {
    pub fn require_period(&self, now: i64) -> Result<(), Error> {
        if now < self.start || now >= self.end {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}

pub(super) async fn now(tx: &Transaction<'_>) -> Result<i64, Error> {
    Ok(tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0))
}

pub(super) async fn deployment(tx: &Transaction<'_>, id: Option<Uuid>) -> Result<Budget, Error> {
    let row = tx.query_opt("SELECT id,version,period_start_ms,period_end_ms,soft_units,hard_units FROM exposure_deployment_budgets WHERE ($1::uuid IS NULL AND enabled) OR id=$1 FOR UPDATE",
        &[&id]).await?.ok_or(Error::Unavailable)?;
    Ok(Budget {
        id: row.get(0),
        kind: String::new(),
        version: row.get(1),
        start: row.get(2),
        end: row.get(3),
        soft: row.get(4),
        hard: row.get(5),
    })
}

pub(super) async fn lock_customer(tx: &Transaction<'_>, account: Uuid) -> Result<(), Error> {
    let bound = tx
        .query_opt(
            "SELECT account_id FROM billing_customers WHERE account_id=$1 FOR SHARE",
            &[&account],
        )
        .await?
        .is_some();
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account],
    )
    .await?
    .ok_or(Error::Unavailable)?;
    if !bound
        && tx
            .query_opt(
                "SELECT account_id FROM billing_customers WHERE account_id=$1",
                &[&account],
            )
            .await?
            .is_some()
    {
        // A new binding won the FK race. Do not reverse customer/account locks.
        return Err(Error::Unavailable);
    }
    Ok(())
}

pub(super) async fn entitlement(tx: &Transaction<'_>, account: Uuid) -> Result<(), Error> {
    let billed = tx
        .query_opt(
            "SELECT account_id FROM billing_customers WHERE account_id=$1",
            &[&account],
        )
        .await?
        .is_some();
    if !billed {
        return Ok(());
    }
    // Reuse the existing TEST projection and payment-risk/grace ledgers;
    // provider summaries and prompts cannot manufacture current entitlement.
    let guards = tx.query_one("SELECT EXISTS(SELECT 1 FROM billing_risk_events WHERE account_id=$1 AND state IN ('queued','held','needs_review') FOR SHARE), \
        (SELECT count(*) FROM (SELECT 1 FROM billing_reconciliations WHERE account_id=$1 FOR SHARE) all_recon), \
        (SELECT count(*) FROM (SELECT 1 FROM billing_reconciliations WHERE account_id=$1 AND dirty_generation=processed_generation FOR SHARE) clean_recon), \
        (SELECT count(*) FROM (SELECT 1 FROM billing_subscriptions WHERE account_id=$1 AND stripe_status='past_due' FOR SHARE) overdue), \
        (SELECT source FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message' FOR SHARE), \
        (SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message' FOR SHARE)", &[&account]).await?;
    if guards.get::<_, bool>(0)
        || guards.get::<_, i64>(1) == 0
        || guards.get::<_, i64>(1) != guards.get::<_, i64>(2)
        || guards.get::<_, Option<String>>(4).as_deref() != Some("stripe_test")
        || guards.get::<_, Option<i64>>(5).unwrap_or(0) <= 0
    {
        return Err(Error::Unavailable);
    }
    if guards.get::<_,i64>(3)>0 && tx.query_opt("SELECT 1 FROM billing_subscriptions WHERE account_id=$1 AND stripe_status='past_due' AND (payment_grace_started_at IS NULL OR payment_grace_invoice_id IS DISTINCT FROM latest_invoice_id OR payment_grace_started_at+interval '7 days'<=clock_timestamp()) LIMIT 1", &[&account]).await?.is_some() {
        return Err(Error::Unavailable);
    }
    Ok(())
}

pub(super) struct Policy {
    pub operation: String,
    pub version: i64,
    pub input_limit: i64,
    pub output_limit: i64,
    pub input_rate: i64,
    pub output_rate: i64,
    pub fixed_units: i64,
    pub maximum_outstanding: i32,
}
pub(super) async fn route(
    tx: &Transaction<'_>,
    account: Uuid,
    id: Uuid,
    deployment: Uuid,
) -> Result<Policy, Error> {
    let row=tx.query_opt("SELECT operation,version,input_limit,output_limit,input_rate,output_rate,fixed_units,maximum_outstanding FROM exposure_route_policies WHERE account_id=$1 AND id=$2 AND deployment_id=$3 AND enabled FOR SHARE",
        &[&account,&id,&deployment]).await?.ok_or(Error::Unavailable)?;
    Ok(Policy {
        operation: row.get(0),
        version: row.get(1),
        input_limit: row.get(2),
        output_limit: row.get(3),
        input_rate: row.get(4),
        output_rate: row.get(5),
        fixed_units: row.get(6),
        maximum_outstanding: row.get(7),
    })
}

pub(super) struct Prior {
    pub id: Uuid,
    pub route: Uuid,
    pub reservation: Reservation,
}
pub(super) async fn prior(
    tx: &Transaction<'_>,
    account: Uuid,
    key: ActionKey,
    operation: &str,
) -> Result<Option<Prior>, Error> {
    let row=tx.query_opt("SELECT id,route_policy_id,binding_digest,maximum_units,state FROM exposure_reservations WHERE account_id=$1 AND action_id=$2 AND revision=$3 AND operation=$4 FOR UPDATE",
        &[&account,&key.action_id,&key.revision,&operation]).await?;
    row.map(|row| {
        if row.get::<_, Vec<u8>>(2) != key.binding_digest {
            return Err(Error::Conflict);
        }
        let id = row.get(0);
        Ok(Prior {
            id,
            route: row.get(1),
            reservation: Reservation {
                id,
                maximum_units: row.get(3),
                soft_warning: false,
                state: row.get(4),
                created: false,
            },
        })
    })
    .transpose()
}

pub(super) async fn scope(
    tx: &Transaction<'_>,
    account: Uuid,
    scope: Scope,
) -> Result<Budget, Error> {
    let row=tx.query_opt("SELECT version,period_start_ms,period_end_ms,soft_units,hard_units FROM exposure_scope_budgets WHERE account_id=$1 AND scope_kind=$2 AND scope_id=$3 AND enabled FOR UPDATE",
        &[&account,&scope.kind,&scope.id]).await?.ok_or(Error::Unavailable)?;
    Ok(Budget {
        id: scope.id,
        kind: scope.kind,
        version: row.get(0),
        start: row.get(1),
        end: row.get(2),
        soft: row.get(3),
        hard: row.get(4),
    })
}

pub(super) async fn scope_outstanding(
    tx: &Transaction<'_>,
    account: Uuid,
    b: &Budget,
) -> Result<i64, Error> {
    Ok(tx.query_one("SELECT COALESCE(sum(outstanding_units),0)::bigint FROM exposure_scope_budgets WHERE account_id=$1 AND scope_kind=$2 AND scope_id=$3",&[&account,&b.kind,&b.id]).await?.get(0))
}
pub(super) async fn scope_finalized(
    tx: &Transaction<'_>,
    account: Uuid,
    b: &Budget,
) -> Result<i64, Error> {
    Ok(tx.query_one("SELECT COALESCE(sum(finalized_units),0)::bigint FROM exposure_scope_budgets WHERE account_id=$1 AND scope_kind=$2 AND scope_id=$3 AND period_start_ms=$4 AND period_end_ms=$5",&[&account,&b.kind,&b.id,&b.start,&b.end]).await?.get(0))
}
pub(super) async fn check_deployment(
    tx: &Transaction<'_>,
    b: &Budget,
    maximum: ExposureUnits,
    now: i64,
) -> Result<bool, Error> {
    b.require_period(now)?;
    let row=tx.query_one("SELECT COALESCE(sum(outstanding_units),0)::bigint,COALESCE(sum(finalized_units) FILTER(WHERE period_start_ms=$1 AND period_end_ms=$2),0)::bigint FROM exposure_deployment_budgets",&[&b.start,&b.end]).await?;
    Ok(projected_liability(row.get(1), row.get(0), maximum, b.hard)? >= b.soft)
}
pub(super) async fn debit_scope(
    tx: &Transaction<'_>,
    account: Uuid,
    reservation: Uuid,
    b: &Budget,
    maximum: i64,
) -> Result<(), Error> {
    tx.execute("UPDATE exposure_scope_budgets SET outstanding_units=outstanding_units+$5 WHERE account_id=$1 AND scope_kind=$2 AND scope_id=$3 AND version=$4",&[&account,&b.kind,&b.id,&b.version,&maximum]).await?;
    tx.execute("INSERT INTO exposure_reservation_scopes(account_id,reservation_id,scope_kind,scope_id,version) VALUES($1,$2,$3,$4,$5)",&[&account,&reservation,&b.kind,&b.id,&b.version]).await?;
    Ok(())
}

pub(super) async fn bound_scopes(
    tx: &Transaction<'_>,
    account: Uuid,
    reservation: Uuid,
) -> Result<Vec<Budget>, Error> {
    let rows=tx.query("SELECT b.scope_kind,b.scope_id,b.version,b.period_start_ms,b.period_end_ms,b.soft_units,b.hard_units FROM exposure_reservation_scopes s JOIN exposure_scope_budgets b USING(account_id,scope_kind,scope_id,version) WHERE s.account_id=$1 AND s.reservation_id=$2 ORDER BY b.scope_kind,b.scope_id,b.version FOR UPDATE OF b",&[&account,&reservation]).await?;
    if rows.len() != 6 {
        return Err(Error::Unavailable);
    }
    Ok(rows
        .into_iter()
        .map(|row| Budget {
            kind: row.get(0),
            id: row.get(1),
            version: row.get(2),
            start: row.get(3),
            end: row.get(4),
            soft: row.get(5),
            hard: row.get(6),
        })
        .collect())
}
pub(super) async fn require_live_policies(
    tx: &Transaction<'_>,
    account: Uuid,
    route: Uuid,
    deployment: &Budget,
    budgets: &[Budget],
) -> Result<(), Error> {
    let now = now(tx).await?;
    deployment.require_period(now)?;
    tx.query_opt(
        "SELECT 1 FROM exposure_deployment_budgets WHERE id=$1 AND version=$2 AND enabled",
        &[&deployment.id, &deployment.version],
    )
    .await?
    .ok_or(Error::Unavailable)?;
    tx.query_opt("SELECT 1 FROM exposure_route_policies WHERE account_id=$1 AND id=$2 AND deployment_id=$3 AND enabled",&[&account,&route,&deployment.id]).await?.ok_or(Error::Unavailable)?;
    for b in budgets {
        b.require_period(now)?;
        tx.query_opt("SELECT 1 FROM exposure_scope_budgets WHERE account_id=$1 AND scope_kind=$2 AND scope_id=$3 AND version=$4 AND enabled",&[&account,&b.kind,&b.id,&b.version]).await?.ok_or(Error::Unavailable)?;
    }
    entitlement(tx, account).await
}

pub(super) async fn settle(
    client: &mut Client,
    intent: &TestIntent,
    outcome: TestOutcome,
) -> Result<bool, Error> {
    let tx = client.transaction().await?;
    let deployment_id: Uuid = tx
        .query_opt(
            "SELECT deployment_id FROM exposure_reservations WHERE account_id=$1 AND id=$2",
            &[&intent.account, &intent.reservation],
        )
        .await?
        .ok_or(Error::Unavailable)?
        .get(0);
    deployment(&tx, Some(deployment_id)).await?;
    let row=tx.query_opt("SELECT maximum_units,state,lease_id,actual_units,result_digest FROM exposure_reservations WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&intent.account,&intent.reservation]).await?.ok_or(Error::Unavailable)?;
    if row.get::<_, Option<Uuid>>(2) != Some(intent.nonce) {
        return Err(Error::Conflict);
    }
    let state: String = row.get(1);
    let maximum: i64 = row.get(0);
    let (actual, digest, terminal) = match outcome {
        TestOutcome::Unknown => {
            if matches!(state.as_str(), "settled" | "released") {
                return Ok(false);
            }
            tx.execute(
                "UPDATE exposure_reservations SET state='unknown' WHERE account_id=$1 AND id=$2",
                &[&intent.account, &intent.reservation],
            )
            .await?;
            tx.commit().await?;
            return Ok(true);
        }
        TestOutcome::Completed {
            actual_units,
            digest,
        } => (actual_units, digest, "settled"),
        TestOutcome::VerifiedNotStarted { digest } => (0, digest, "released"),
    };
    if actual < 0 || actual > maximum {
        return Err(Error::Conflict);
    }
    if matches!(state.as_str(), "settled" | "released") {
        if state != terminal
            || row.get::<_, Option<i64>>(3) != Some(actual)
            || row.get::<_, Option<Vec<u8>>>(4).as_deref() != Some(&digest[..])
        {
            return Err(Error::Conflict);
        }
        return Ok(false);
    }
    if !matches!(state.as_str(), "executing" | "unknown" | "review") {
        return Err(Error::Conflict);
    }
    let scopes = bound_scopes(&tx, intent.account, intent.reservation).await?;
    for b in scopes {
        let changed=tx.execute("UPDATE exposure_scope_budgets SET outstanding_units=outstanding_units-$5,finalized_units=finalized_units+$6 WHERE account_id=$1 AND scope_kind=$2 AND scope_id=$3 AND version=$4 AND outstanding_units>=$5",&[&intent.account,&b.kind,&b.id,&b.version,&maximum,&actual]).await?;
        if changed != 1 {
            return Err(Error::Conflict);
        }
    }
    if tx.execute("UPDATE exposure_deployment_budgets SET outstanding_units=outstanding_units-$2,finalized_units=finalized_units+$3 WHERE id=$1 AND outstanding_units>=$2",&[&deployment_id,&maximum,&actual]).await?!=1 {return Err(Error::Conflict);}
    tx.execute("UPDATE exposure_reservations SET state=$3,actual_units=$4,result_digest=$5 WHERE account_id=$1 AND id=$2",&[&intent.account,&intent.reservation,&terminal,&actual,&&digest[..]]).await?;
    tx.commit().await?;
    Ok(true)
}
