// SPDX-License-Identifier: AGPL-3.0-only
//! Composition with the existing invoice-attributed TEST usage ledger.
//! ROOT retains the caller transaction, manifest/auth checks and enqueue. Every
//! error requires rollback. No provider read, commit, new usage ledger or LIVE
//! reinterpretation occurs here. Prepare after manifest and before account;
//! check immediately before writes and again after all waits before commit.
use super::{
    Refusal,
    namespace::{Gate, Mode, Scope},
    policy::{self, Phase, Purpose},
    store::{self, StoreError},
};
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Locked immutable namespace-to-ledger provenance. Never browser supplied.
pub struct Prepared<'tx, 'connection> {
    scope: Scope,
    tx: &'tx Transaction<'connection>,
}

impl Prepared<'_, '_> {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

fn pending() -> StoreError {
    StoreError::Refused(Refusal::Pending)
}

/// This bridge supports only the existing explicitly TEST invoice ledger.
/// Missing installation/binding refuses; installation never creates a binding.
pub async fn prepare<'tx, 'connection>(
    tx: &'tx Transaction<'connection>,
    gate: &Gate,
    authenticated_account: Uuid,
) -> Result<Prepared<'tx, 'connection>, StoreError> {
    let namespace = gate.marker()?.namespace.clone();
    if namespace.mode() != Mode::Test {
        return Err(StoreError::Refused(Refusal::NamespaceMismatch));
    }
    store::bound_waits(tx).await?;
    let installed:bool=tx.query_one(
        "SELECT to_regprocedure('current_billing_invoice_period(uuid)') IS NOT NULL AND to_regprocedure('reserve_billing_invoice_unit(uuid,uuid)') IS NOT NULL AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='usage_ledger'::regclass AND tgname='billing_invoice_ledger' AND tgenabled IN ('O','A') AND tgfoid=to_regprocedure('apply_billing_invoice_ledger()')) AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='messages'::regclass AND tgname='billing_invoice_liability' AND tgenabled IN ('O','A') AND tgfoid=to_regprocedure('close_billing_invoice_liability()')) AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='hosted_billing_namespaces'::regclass AND tgname='hosted_namespace_identity_immutable' AND tgenabled IN ('O','A') AND tgfoid=to_regprocedure('hosted_namespace_identity_immutable()')) AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='hosted_billing_projections'::regclass AND tgname='hosted_projection_identity_immutable' AND tgenabled IN ('O','A') AND tgfoid=to_regprocedure('hosted_projection_identity_immutable()')) AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='hosted_billing_projections'::regclass AND tgname='hosted_projection_risk_invalidates' AND tgenabled IN ('O','A') AND tgfoid=to_regprocedure('hosted_projection_risk_invalidates()')) AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='hosted_billing_ledger_bindings'::regclass AND tgname='hosted_ledger_binding_immutable' AND tgenabled IN ('O','A') AND tgfoid=to_regprocedure('hosted_ledger_binding_immutable()'))",
        &[],
    ).await.map_err(|_|StoreError::Unavailable)?.get(0);
    if !installed {
        return Err(pending());
    }
    let namespace_id = Uuid::from_bytes(namespace.id());
    let read = tx.query_opt(
        "SELECT left(customer_id,129),left(subscription_id,129) FROM hosted_billing_ledger_bindings WHERE account_id=$1 AND namespace_id=$2 AND ledger_mode='test'",
        &[&authenticated_account,&namespace_id],
    ).await.map_err(|_|StoreError::Unavailable)?.ok_or_else(pending)?;
    let customer: String = read.try_get(0).map_err(|_| StoreError::MalformedState)?;
    let subscription: String = read.try_get(1).map_err(|_| StoreError::MalformedState)?;
    let scope = Scope::new(
        namespace,
        authenticated_account.into_bytes(),
        &customer,
        &subscription,
    )?;
    store::lock_marker(tx, gate, &scope).await?;
    if tx.query_opt(
        "SELECT 1 FROM hosted_billing_ledger_bindings WHERE account_id=$1 AND namespace_id=$2 AND customer_id=$3 AND subscription_id=$4 AND ledger_mode='test' FOR SHARE",
        &[&authenticated_account,&namespace_id,&customer,&subscription],
    ).await.map_err(|_|StoreError::Unavailable)?.is_none() { return Err(pending()); }
    // Match legacy ingress's customer-before-account order. No projection lock
    // until the caller has obtained its canonical account lock below.
    if tx.query_opt(
        "SELECT 1 FROM billing_customers WHERE account_id=$1 AND stripe_customer_id=$2 FOR SHARE",
        &[&authenticated_account,&customer],
    ).await.map_err(|_|StoreError::Unavailable)?.is_none() { return Err(pending()); }
    Ok(Prepared { scope, tx })
}

async fn locked_projection(
    tx: &Transaction<'_>,
    gate: &Gate,
    prepared: &Prepared<'_, '_>,
) -> Result<store::LockedState, StoreError> {
    if !std::ptr::eq(tx, prepared.tx) {
        return Err(pending());
    }
    let account = Uuid::from_bytes(prepared.scope.owner());
    // Reuses the caller's canonical account lock; also makes direct adapter
    // calls serialize quota/device races rather than trusting a claimed lock.
    if tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
            &[&account],
        )
        .await
        .map_err(|_| StoreError::Unavailable)?
        .is_none()
    {
        return Err(pending());
    }
    store::load_locked(tx, gate, &prepared.scope).await
}

/// `after_enqueue` requires the existing ledger's original attribution for this
/// message. Exact replay is also recorded, never reserved in a new period.
pub async fn outbound(
    tx: &Transaction<'_>,
    gate: &Gate,
    prepared: &Prepared<'_, '_>,
    message: Uuid,
    after_enqueue: bool,
) -> Result<(), StoreError> {
    let loaded = locked_projection(tx, gate, prepared).await?;
    let projection = loaded.projection.as_ref().ok_or_else(pending)?;
    let account = Uuid::from_bytes(prepared.scope.owner());
    // Existing current-period predicate verifies TEST source, current invoice,
    // reconciler generation, subscription identity/status, risk and deadlines.
    // Take account -> entitlement -> period locks, matching the ledger trigger.
    let row = tx.query_opt(
        "SELECT p.id,p.start_ms,p.end_ms,e.observed_invoice_id,e.effective_price_id,e.effective_limit,e.phase FROM billing_invoice_entitlements e JOIN billing_invoice_periods p ON (p.account_id,p.id)=(e.account_id,e.period_id) WHERE e.account_id=$1 AND e.customer_id=$2 AND e.subscription_id=$3 AND e.mode='test' FOR UPDATE OF e,p",
        &[&account,&prepared.scope.customer(),&prepared.scope.subscription()],
    ).await.map_err(|_|StoreError::Unavailable)?.ok_or_else(pending)?;
    let period: Uuid = row.try_get(0).map_err(|_| StoreError::MalformedState)?;
    let start: i64 = row.try_get(1).map_err(|_| StoreError::MalformedState)?;
    let end: i64 = row.try_get(2).map_err(|_| StoreError::MalformedState)?;
    let invoice: Option<String> = row.try_get(3).map_err(|_| StoreError::MalformedState)?;
    let price: Option<String> = row.try_get(4).map_err(|_| StoreError::MalformedState)?;
    let limit: i64 = row.try_get(5).map_err(|_| StoreError::MalformedState)?;
    let phase: String = row.try_get(6).map_err(|_| StoreError::MalformedState)?;
    if projection.period_start().checked_mul(1000) != Some(start)
        || projection.period_end().checked_mul(1000) != Some(end)
        || invoice.as_deref() != Some(projection.invoice())
        || price.as_deref() != Some(projection.price())
        || u64::try_from(limit).ok() != Some(projection.outbound_limit())
        || !matches!(
            (projection.phase(), phase.as_str()),
            (Phase::Active, "active") | (Phase::Grace, "grace")
        )
    {
        return Err(pending());
    }
    // Match reserve_billing_invoice_unit: lock current period only. Earlier
    // open liabilities can only decrease while account/entitlement locks stop
    // reservations and renewal. Locking every historical period would invert
    // batched refund lock order. One bounded aggregate retains conservative
    // prior liability without returning an unbounded row collection.
    let counter = tx.query_one(
        "SELECT p.reserved_units-p.refunded_units+(SELECT coalesce(sum(old.open_units),0)::bigint FROM billing_invoice_periods old WHERE old.account_id=$1 AND old.id<>$2) FROM billing_invoice_periods p WHERE p.account_id=$1 AND p.id=$2",
        &[&account,&period],
    ).await.map_err(|_|StoreError::Unavailable)?;
    let consumed = u64::try_from(
        counter
            .try_get::<_, i64>(0)
            .map_err(|_| StoreError::MalformedState)?,
    )
    .map_err(|_| StoreError::MalformedState)?;
    let recorded=tx.query_opt(
        "SELECT 1 FROM billing_invoice_usage u JOIN billing_invoice_periods p ON (p.account_id,p.id)=(u.account_id,u.period_id) JOIN usage_ledger l ON (l.account_id,l.message_id)=(u.account_id,u.message_id) WHERE u.account_id=$1 AND u.message_id=$2 AND p.subscription_id=$3 AND l.entry_kind='reserve' AND l.units=1",
        &[&account,&message,&prepared.scope.subscription()],
    ).await.map_err(|_|StoreError::Unavailable)?.is_some();
    if after_enqueue && !recorded {
        return Err(pending());
    }
    // Missing attribution for an existing message cannot be reinterpreted as a
    // free replay (or gain a new-period reservation).
    if !recorded
        && tx
            .query_opt(
                "SELECT 1 FROM messages WHERE account_id=$1 AND id=$2",
                &[&account, &message],
            )
            .await
            .map_err(|_| StoreError::Unavailable)?
            .is_some()
    {
        return Err(pending());
    }
    let purpose = if recorded {
        Purpose::OutboundRecorded { consumed }
    } else {
        Purpose::Outbound { units: 1, consumed }
    };
    store::admit_locked(tx, gate, &prepared.scope, purpose).await?;
    final_current_invoice(tx, prepared).await
}

async fn final_current_invoice(
    tx: &Transaction<'_>,
    prepared: &Prepared<'_, '_>,
) -> Result<(), StoreError> {
    let account = Uuid::from_bytes(prepared.scope.owner());
    let namespace = Uuid::from_bytes(prepared.scope.namespace().id());
    // One final statement checks both independent authority deadlines AFTER
    // preceding waits. Checking invoice and hosted lease in separate roundtrips
    // would let the latter expire while the former was being checked.
    if tx.query_opt(
        "SELECT 1 FROM current_billing_invoice_period($1) w JOIN billing_invoice_entitlements e ON e.account_id=$1 AND e.period_id=w.period_id JOIN hosted_billing_projections h ON h.account_id=$1 AND h.namespace_id=$2 WHERE e.mode='test' AND e.customer_id=h.customer_id AND e.subscription_id=h.subscription_id AND e.observed_invoice_id=h.invoice_id AND e.effective_price_id=h.price_id AND e.effective_limit=h.outbound_limit AND ((e.phase='active' AND h.phase='active') OR (e.phase='grace' AND h.phase='grace')) AND w.start_ms=h.period_start*1000 AND w.end_ms=h.period_end*1000 AND NOT h.payment_hold AND NOT h.review_required AND h.dirty_generation=h.processed_generation AND h.issued_at<=floor(extract(epoch FROM clock_timestamp()))::bigint AND h.valid_until>floor(extract(epoch FROM clock_timestamp()))::bigint",
        &[&account,&namespace],
    ).await.map_err(|_|StoreError::Unavailable)?.is_none(){return Err(pending());}
    Ok(())
}

/// Device count comes from the existing account-serialized devices table.
/// A final check proves the newly inserted device instead of counting it twice.
pub async fn device(
    tx: &Transaction<'_>,
    gate: &Gate,
    prepared: &Prepared<'_, '_>,
    recorded_device: Option<Uuid>,
) -> Result<(), StoreError> {
    let loaded = locked_projection(tx, gate, prepared).await?;
    let account = Uuid::from_bytes(prepared.scope.owner());
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM devices WHERE account_id=$1 AND revoked_at IS NULL",
            &[&account],
        )
        .await
        .map_err(|_| StoreError::Unavailable)?
        .get(0);
    let active_devices = u64::try_from(count).map_err(|_| StoreError::MalformedState)?;
    let purpose = if let Some(device) = recorded_device {
        if tx
            .query_opt(
                "SELECT 1 FROM devices WHERE account_id=$1 AND id=$2 AND revoked_at IS NULL",
                &[&account, &device],
            )
            .await
            .map_err(|_| StoreError::Unavailable)?
            .is_none()
        {
            return Err(pending());
        }
        Purpose::DeviceRecorded { active_devices }
    } else {
        Purpose::EnrollDevice { active_devices }
    };
    policy::admit(
        gate,
        &loaded.marker,
        &prepared.scope,
        loaded.fence,
        loaded.projection.as_ref(),
        purpose,
        loaded.now,
    )?;
    store::admit_locked(tx, gate, &prepared.scope, purpose).await?;
    // Devices consume the same paid service: a legacy risk/cancel/grace change
    // must refuse even before its separate hosted projection has been dirtied.
    final_current_invoice(tx, prepared).await
}
