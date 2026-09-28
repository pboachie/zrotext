// SPDX-License-Identifier: AGPL-3.0-only
//! Quota-only usage-limit plans. A plan is a named monthly outbound-message
//! limit an operator defines in server configuration and assigns to an
//! account. Plans carry no price, currency, provider pointer or entitlement
//! beyond the limit itself; anything commercial is a founder decision and is
//! deliberately absent. This slice is disabled by default: without
//! `USAGE_LIMITS_ENABLED=true` no policy is projected and admission stays
//! unmetered for accounts without a billing-customer binding.

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum UsagePlanError {
    #[error("runtime database unavailable")]
    RuntimeDatabase(#[from] crate::runtime_db::ConnectError),
    #[error("usage-limit plan storage unavailable: {0}")]
    Database(#[from] tokio_postgres::Error),
    #[error("usage-limit plan schema is missing; apply migration 050 first")]
    SchemaMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageLimitPlan {
    pub plan_key: String,
    pub outbound_limit: i64,
}

fn valid_plan_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    let body_ok = || {
        bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    };
    !bytes.is_empty()
        && bytes.len() <= 32
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && body_ok()
}

/// Parse `USAGE_LIMIT_PLANS`: comma-separated `plan_key:outbound_limit`
/// entries. Limits are positive monthly outbound-message units. An empty
/// value is an empty catalog; nothing here encodes a product default.
pub fn parse_usage_limit_plans(value: &str) -> Result<Vec<UsageLimitPlan>, &'static str> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut plans = Vec::new();
    for entry in value.split(',') {
        let mut fields = entry.trim().split(':');
        let (key, limit) = match (fields.next(), fields.next(), fields.next()) {
            (Some(key), Some(limit), None) => (key, limit),
            _ => return Err("invalid usage-limit plan"),
        };
        if !valid_plan_key(key) {
            return Err("invalid usage-limit plan");
        }
        let outbound_limit: i64 = limit.parse().map_err(|_| "invalid usage-limit plan")?;
        if outbound_limit <= 0 {
            return Err("invalid usage-limit plan");
        }
        if plans
            .iter()
            .any(|plan: &UsageLimitPlan| plan.plan_key == key)
        {
            return Err("invalid usage-limit plan");
        }
        plans.push(UsageLimitPlan {
            plan_key: key.to_owned(),
            outbound_limit,
        });
    }
    Ok(plans)
}

/// Hash the effective plan catalog, independent of entry order. The catalog
/// contains no secrets, so unlike the Stripe test fingerprint no key material
/// is mixed in.
pub fn usage_plan_configuration_fingerprint(plans: &[UsageLimitPlan]) -> [u8; 32] {
    let mut plans = plans.to_vec();
    plans.sort_by(|left, right| left.plan_key.cmp(&right.plan_key));
    let mut hash = Sha256::new();
    hash.update(b"usage-plan-catalog-v1\0");
    for plan in plans {
        hash.update((plan.plan_key.len() as u64).to_be_bytes());
        hash.update(plan.plan_key.as_bytes());
        hash.update(plan.outbound_limit.to_be_bytes());
    }
    hash.finalize().into()
}

/// Project operator-assigned plans into the shared quota tables at startup.
///
/// * Disabled: every `usage_plan` policy is reset to zero (audited) and the
///   catalog marker is cleared, mirroring the Stripe test reset. Admission
///   only changes for deployments that had projected policies.
/// * Enabled with an unchanged catalog fingerprint: a no-op, so ordinary
///   restarts and rolling starts keep projections.
/// * Enabled with a new fingerprint: every assignment is reprojected. An
///   assignment whose plan key left the catalog projects zero
///   (`plan_removed`); a policy without an assignment row projects zero
///   (`assignment_removed`); an assignment on an account with a billing
///   customer binding is skipped (`skipped_billed`) because a bound tenant's
///   quota is owned by Stripe reconciliation and must not be overwritten.
///
/// Assignments take effect on the next startup or catalog change; there is no
/// request-time write path into quota policy.
pub async fn apply_usage_plan_assignments(
    database_url: &str,
    enabled: bool,
    plans: &[UsageLimitPlan],
) -> Result<(), UsagePlanError> {
    let mut db = crate::runtime_db::connect_worker(database_url).await?;
    let schema_ready: bool = db
        .query_one(
            "SELECT to_regclass('usage_plan_assignments') IS NOT NULL \
             AND to_regclass('usage_plan_audit') IS NOT NULL \
             AND to_regclass('usage_plan_config') IS NOT NULL \
             AND COALESCE((SELECT pg_get_constraintdef(c.oid) LIKE '%usage_plan%' \
                 FROM pg_constraint c \
                 WHERE c.conrelid='usage_quota_policies'::regclass \
                   AND c.conname='usage_quota_policies_source_check'), false)",
            &[],
        )
        .await?
        .get(0);
    if !schema_ready {
        // A pre-050 database keeps its current behavior while the feature is
        // off; enabling requires the schema.
        return if enabled {
            Err(UsagePlanError::SchemaMissing)
        } else {
            Ok(())
        };
    }
    let fingerprint = usage_plan_configuration_fingerprint(plans);
    let tx = db.transaction().await?;
    // Serialize rolling starts on one database lock, as the test billing
    // reset does, so two instances cannot interleave projections.
    tx.query_one("SELECT pg_advisory_xact_lock(139026)", &[])
        .await?;
    if !enabled {
        clear_usage_plan_policies(&tx).await?;
        tx.execute("DELETE FROM usage_plan_config WHERE singleton=true", &[])
            .await?;
        tx.commit().await?;
        return Ok(());
    }
    let current = tx
        .query_opt(
            "SELECT configuration_sha256 FROM usage_plan_config WHERE singleton=true",
            &[],
        )
        .await?;
    if current.is_some_and(|row| row.get::<_, Vec<u8>>(0) == fingerprint) {
        tx.commit().await?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO usage_plan_config(singleton,configuration_sha256) VALUES(true,$1) \
         ON CONFLICT(singleton) DO UPDATE SET configuration_sha256=EXCLUDED.configuration_sha256, \
         updated_at=clock_timestamp()",
        &[&fingerprint.as_slice()],
    )
    .await?;
    let assignments = tx
        .query(
            "SELECT account_id,plan_key FROM usage_plan_assignments ORDER BY account_id FOR UPDATE",
            &[],
        )
        .await?;
    for row in assignments {
        let account_id: Uuid = row.get(0);
        let plan_key: String = row.get(1);
        let billed = tx
            .query_opt(
                "SELECT 1 FROM billing_customers WHERE account_id=$1",
                &[&account_id],
            )
            .await?
            .is_some();
        if billed {
            // A bound tenant's quota policy belongs to Stripe reconciliation;
            // an operator plan must not shadow or overwrite it.
            tx.execute(
                "INSERT INTO usage_plan_audit(account_id,plan_key,previous_limit_units,limit_units,reason) \
                 SELECT $1,$2,p.limit_units,p.limit_units,'skipped_billed' \
                 FROM usage_quota_policies p WHERE p.account_id=$1 AND p.metric='outbound_message'",
                &[&account_id, &plan_key],
            )
            .await?;
            continue;
        }
        let limit = plans
            .iter()
            .find(|plan| plan.plan_key == plan_key)
            .map(|plan| plan.outbound_limit)
            .unwrap_or(0);
        let cause = if limit == 0 {
            ProjectionCause::PlanRemoved
        } else {
            ProjectionCause::Plan
        };
        project_policy(&tx, account_id, Some(&plan_key), limit, cause).await?;
    }
    // A policy can outlive its assignment row (operator deleted it). Reset it
    // so removal is enforced on the next catalog change or restart, not never.
    let orphans = tx
        .query(
            "SELECT p.account_id,p.limit_units FROM usage_quota_policies p \
             WHERE p.metric='outbound_message' AND p.source='usage_plan' \
               AND NOT EXISTS (SELECT 1 FROM usage_plan_assignments a WHERE a.account_id=p.account_id) \
             ORDER BY p.account_id FOR UPDATE",
            &[],
        )
        .await?;
    for row in orphans {
        let account_id: Uuid = row.get(0);
        if row.get::<_, i64>(1) == 0 {
            continue;
        }
        project_policy(&tx, account_id, None, 0, ProjectionCause::AssignmentRemoved).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Why a policy projection happened; selects the durable audit reason.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProjectionCause {
    Plan,
    PlanRemoved,
    AssignmentRemoved,
}

async fn clear_usage_plan_policies(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), UsagePlanError> {
    tx.execute(
        "INSERT INTO usage_plan_audit(account_id,plan_key,previous_limit_units,limit_units,reason) \
         SELECT account_id,NULL,limit_units,0,'disabled' FROM usage_quota_policies \
         WHERE metric='outbound_message' AND source='usage_plan' AND limit_units<>0",
        &[],
    )
    .await?;
    tx.execute(
        "UPDATE usage_quota_policies SET limit_units=0,updated_at=now() \
         WHERE metric='outbound_message' AND source='usage_plan' AND limit_units<>0",
        &[],
    )
    .await?;
    tx.execute(
        "UPDATE usage_periods u SET limit_units=0 FROM usage_quota_policies p \
         WHERE u.account_id=p.account_id AND u.metric='outbound_message' \
           AND p.metric='outbound_message' AND p.source='usage_plan' \
           AND u.period_start=date_trunc('month',transaction_timestamp() AT TIME ZONE 'UTC')::date",
        &[],
    )
    .await?;
    Ok(())
}

/// Upsert one account's policy and current-period limit, auditing only real
/// changes. A lower limit never removes existing reservations, matching the
/// Stripe test projection.
async fn project_policy(
    tx: &tokio_postgres::Transaction<'_>,
    account_id: Uuid,
    plan_key: Option<&str>,
    limit: i64,
    cause: ProjectionCause,
) -> Result<(), UsagePlanError> {
    let previous = tx
        .query_opt(
            "SELECT limit_units,source FROM usage_quota_policies \
             WHERE account_id=$1 AND metric='outbound_message' FOR UPDATE",
            &[&account_id],
        )
        .await?;
    let changed = previous
        .as_ref()
        .is_none_or(|row| row.get::<_, i64>(0) != limit || row.get::<_, String>(1) != "usage_plan");
    if !changed {
        return Ok(());
    }
    let reason = match cause {
        ProjectionCause::PlanRemoved => "plan_removed",
        ProjectionCause::AssignmentRemoved => "assignment_removed",
        ProjectionCause::Plan if previous.is_none() => "assigned",
        ProjectionCause::Plan => "reprojected",
    };
    tx.execute(
        "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) \
         VALUES($1,'outbound_message',$2,'usage_plan') \
         ON CONFLICT(account_id,metric) DO UPDATE SET limit_units=EXCLUDED.limit_units, \
         source='usage_plan',updated_at=now()",
        &[&account_id, &limit],
    )
    .await?;
    tx.execute(
        "UPDATE usage_periods SET limit_units=$2 WHERE account_id=$1 AND metric='outbound_message' \
         AND period_start=date_trunc('month',transaction_timestamp() AT TIME ZONE 'UTC')::date",
        &[&account_id, &limit],
    )
    .await?;
    let prior: Option<i64> = previous.map(|row| row.get(0));
    tx.execute(
        "INSERT INTO usage_plan_audit(account_id,plan_key,previous_limit_units,limit_units,reason) \
         VALUES($1,$2,$3,$4,$5)",
        &[&account_id, &plan_key, &prior, &limit, &reason],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
