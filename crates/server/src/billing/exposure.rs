// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted TEST exposure candidate. A receipt neither authorizes content
//! access nor starts an external call; provider/model adapters remain absent.

use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{
        ConversationError,
        context::decisions::{self, ActionKey},
    },
    sealed_manifest_store::outbound::lock_current,
};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
use zrotext_delivery_store::exposure::{ExposureError, ExposureUnits, projected_liability};

mod store;
use store::Scope;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TEST exposure candidate is unavailable")]
    Unavailable,
    #[error("exposure identity conflicts with prior reservation")]
    Conflict,
    #[error("current action authority unavailable")]
    Authority(#[from] ConversationError),
    #[error("exposure policy refuses the request")]
    Policy(#[from] ExposureError),
    #[error("exposure storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}

#[derive(Default)]
pub struct TestExposure {
    enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub id: Uuid,
    pub maximum_units: i64,
    pub soft_warning: bool,
    pub state: String,
    pub created: bool,
}

/// Non-deserializable process-local proof of the first synthetic intent. No
/// retry can mint another intent for this action, even after lease expiration.
pub struct TestIntent {
    account: Uuid,
    reservation: Uuid,
    nonce: Uuid,
}

/// Supplied only by a trusted in-process synthetic adapter, not an HTTP body.
/// Production terminal evidence and reconciliation adapters are unavailable.
pub enum TestOutcome {
    Completed { actual_units: i64, digest: [u8; 32] },
    VerifiedNotStarted { digest: [u8; 32] },
    Unknown,
}

impl TestExposure {
    pub fn synthetic_candidate() -> Self {
        Self { enabled: true }
    }

    fn require_enabled(&self) -> Result<(), Error> {
        if !self.enabled {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub async fn reserve(
        &self,
        client: &mut Client,
        owner: &SessionPrincipal,
        action: ActionKey,
        route_policy: Uuid,
        reservation_id: Uuid,
    ) -> Result<Reservation, Error> {
        self.require_enabled()?;
        if route_policy.is_nil() || reservation_id.is_nil() {
            return Err(Error::Unavailable);
        }
        let tx = client.transaction().await?;
        // Global serialization precedes root/customer/account/action locks.
        // Settlement follows deployment -> sorted scope rows without taking
        // an account or root lock, so it cannot invert authority lock order.
        let deployment = store::deployment(&tx, None).await?;
        let _root = lock_current(&tx, owner.tenant.account_id())
            .await
            .map_err(|_| Error::Unavailable)?;
        store::lock_customer(&tx, owner.tenant.account_id()).await?;
        let mut permit = decisions::lock_approved(&tx, owner, action).await?;
        let account = permit.key().account_id;
        store::entitlement(&tx, account).await?;
        let policy = store::route(&tx, account, route_policy, deployment.id).await?;
        if let Some(prior) = store::prior(&tx, account, action, &policy.operation).await? {
            if prior.route != route_policy || prior.id != reservation_id {
                return Err(Error::Conflict);
            }
            permit.recheck().await?;
            drop(permit);
            drop(_root);
            tx.commit().await?;
            return Ok(prior.reservation);
        }
        let maximum = ExposureUnits::model_maximum(
            policy.input_limit,
            policy.output_limit,
            policy.input_rate,
            policy.output_rate,
            policy.fixed_units,
        )?;
        let active: i64 = tx.query_one(
            "SELECT count(*) FROM exposure_reservations WHERE account_id=$1 AND state NOT IN ('settled','released')",
            &[&account]).await?.get(0);
        if active >= i64::from(policy.maximum_outstanding) {
            return Err(Error::Unavailable);
        }
        let device: Uuid = tx
            .query_one(
                "SELECT device_id FROM workflow_contexts WHERE account_id=$1 AND id=$2",
                &[&account, &permit.context_id()],
            )
            .await?
            .get(0);
        let scopes = [
            Scope::new("campaign", permit.routine_id()),
            Scope::new("device", device),
            Scope::new("route", route_policy),
            Scope::new("tenant", account),
            Scope::new("turn", action.action_id),
            Scope::new("workflow", permit.context_id()),
        ];
        let mut budgets = Vec::with_capacity(scopes.len());
        for scope in scopes {
            budgets.push(store::scope(&tx, account, scope).await?);
        }
        let now = store::now(&tx).await?;
        let mut warning = store::check_deployment(&tx, &deployment, maximum, now).await?;
        for budget in &budgets {
            let outstanding = store::scope_outstanding(&tx, account, budget).await?;
            let finalized = store::scope_finalized(&tx, account, budget).await?;
            budget.require_period(now)?;
            let projected = projected_liability(finalized, outstanding, maximum, budget.hard)?;
            warning |= projected >= budget.soft;
        }
        tx.execute(
            "INSERT INTO exposure_reservations(account_id,id,action_id,revision,binding_digest,route_policy_id,operation,policy_version,deployment_id,device_id,workflow_id,routine_id,routine_generation,owner_user_id,owner_session_id,maximum_units,original_period_start_ms,original_period_end_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
            &[&account,&reservation_id,&action.action_id,&action.revision,&&action.binding_digest[..],
              &route_policy,&policy.operation,&policy.version,&deployment.id,&device,&permit.context_id(),
              &permit.routine_id(),&permit.routine_generation(),&permit.actor_user_id(),&permit.actor_session_id(),
              &maximum.get(),&deployment.start,&deployment.end]).await?;
        for budget in &budgets {
            store::debit_scope(&tx, account, reservation_id, budget, maximum.get()).await?;
        }
        tx.execute("UPDATE exposure_deployment_budgets SET outstanding_units=outstanding_units+$2 WHERE id=$1",
            &[&deployment.id,&maximum.get()]).await?;
        // Waiting for any dimension lock cannot reuse cached consent, owner
        // session, action expiry or routine generation from initial admission.
        permit.recheck().await?;
        store::require_live_policies(&tx, account, route_policy, &deployment, &budgets).await?;
        permit.recheck().await?;
        let final_now = store::now(&tx).await?;
        deployment.require_period(final_now)?;
        for budget in &budgets {
            budget.require_period(final_now)?;
        }
        drop(permit);
        drop(_root);
        tx.commit().await?;
        Ok(Reservation {
            id: reservation_id,
            maximum_units: maximum.get(),
            soft_warning: warning,
            state: "reserved".into(),
            created: true,
        })
    }

    pub async fn first_test_intent(
        &self,
        client: &mut Client,
        owner: &SessionPrincipal,
        action: ActionKey,
        reservation: Uuid,
    ) -> Result<TestIntent, Error> {
        self.require_enabled()?;
        let tx = client.transaction().await?;
        let deployment_id: Uuid = tx
            .query_opt(
                "SELECT deployment_id FROM exposure_reservations WHERE account_id=$1 AND id=$2",
                &[&owner.tenant.account_id(), &reservation],
            )
            .await?
            .ok_or(Error::Unavailable)?
            .get(0);
        let deployment = store::deployment(&tx, Some(deployment_id)).await?;
        let _root = lock_current(&tx, owner.tenant.account_id())
            .await
            .map_err(|_| Error::Unavailable)?;
        store::lock_customer(&tx, owner.tenant.account_id()).await?;
        let mut permit = decisions::lock_approved(&tx, owner, action).await?;
        store::entitlement(&tx, action.account_id).await?;
        let row = tx.query_opt(
            "SELECT action_id,revision,binding_digest,route_policy_id,state FROM exposure_reservations WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&action.account_id,&reservation]).await?.ok_or(Error::Unavailable)?;
        if row.get::<_, Uuid>(0) != action.action_id
            || row.get::<_, i64>(1) != action.revision
            || row.get::<_, Vec<u8>>(2) != action.binding_digest
            || row.get::<_, String>(4) != "reserved"
        {
            return Err(Error::Conflict);
        }
        let route: Uuid = row.get(3);
        store::route(&tx, action.account_id, route, deployment.id).await?;
        let budgets = store::bound_scopes(&tx, action.account_id, reservation).await?;
        store::require_live_policies(&tx, action.account_id, route, &deployment, &budgets).await?;
        permit.recheck().await?;
        let now = store::now(&tx).await?;
        deployment.require_period(now)?;
        if now
            < permit
                .descriptor()
                .not_before
                .checked_mul(1000)
                .ok_or(Error::Unavailable)?
        {
            return Err(Error::Unavailable);
        }
        let nonce = Uuid::new_v4();
        let until = now
            .checked_add(15_000)
            .ok_or(Error::Unavailable)?
            .min(permit.expires_at_ms());
        if until <= now {
            return Err(Error::Unavailable);
        }
        tx.execute("UPDATE exposure_reservations SET state='executing',lease_id=$3,lease_until_ms=$4 WHERE account_id=$1 AND id=$2",
            &[&action.account_id,&reservation,&nonce,&until]).await?;
        permit.recheck().await?;
        store::require_live_policies(&tx, action.account_id, route, &deployment, &budgets).await?;
        permit.recheck().await?;
        if store::now(&tx).await? >= until {
            return Err(Error::Unavailable);
        }
        drop(permit);
        drop(_root);
        tx.commit().await?;
        Ok(TestIntent {
            account: action.account_id,
            reservation,
            nonce,
        })
    }

    /// Settlement remains usable after action/session expiry: it accounts for
    /// an already-started effect and never grants new work or restores quota.
    pub async fn settle_test(
        &self,
        client: &mut Client,
        intent: &TestIntent,
        outcome: TestOutcome,
    ) -> Result<bool, Error> {
        self.require_enabled()?;
        store::settle(client, intent, outcome).await
    }
}

#[cfg(test)]
mod tests;
