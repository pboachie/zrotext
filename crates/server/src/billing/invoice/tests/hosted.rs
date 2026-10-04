// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise the bridge against the real migration chain and invoice triggers.
use super::Case;
use crate::billing::hosted::{
    admission,
    namespace::{Gate, Marker, Mode, Namespace, ProviderIdentity, Scope},
    policy::{Observation, Plan, SubscriptionStatus},
    store,
};
use tokio_postgres::Transaction;
use uuid::Uuid;

async fn installed() -> (Case, Gate, Scope) {
    installed_horizon(3600).await
}

async fn installed_horizon(horizon: i64) -> (Case, Gate, Scope) {
    let mut case = Case::new().await;
    case.end = case.start + 60 + horizon;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.db
        .batch_execute(include_str!("../../hosted/store_fixture.sql"))
        .await
        .unwrap();
    case.db
        .batch_execute(include_str!("../../hosted/admission_fixture.sql"))
        .await
        .unwrap();
    let namespace =
        Namespace::new(Uuid::new_v4().into_bytes(), Mode::Test, "acct_fixture").unwrap();
    let marker = Marker {
        namespace: namespace.clone(),
        policy_revision: 1,
        enabled: true,
    };
    let gate = Gate::verify(
        true,
        &namespace,
        1,
        &marker,
        &ProviderIdentity {
            mode: Mode::Test,
            provider_account: "acct_fixture".into(),
        },
    )
    .unwrap();
    let scope = Scope::new(
        namespace,
        case.account.into_bytes(),
        "cus_invoice1",
        "sub_invoice1",
    )
    .unwrap();
    let ns = Uuid::from_bytes(scope.namespace().id());
    case.db
        .execute(
            "INSERT INTO hosted_billing_namespaces VALUES($1,'test','acct_fixture',1,true,true)",
            &[&ns],
        )
        .await
        .unwrap();
    case.db.execute("INSERT INTO hosted_billing_projections(namespace_id,account_id,customer_id,subscription_id,policy_revision,dirty_generation,processed_generation,per_read_sequence,payment_hold,review_required,phase,outbound_limit,device_limit,issued_at,valid_until) VALUES($1,$2,'cus_invoice1','sub_invoice1',1,0,0,0,false,false,'pending',0,0,0,0)",&[&ns,&case.account]).await.unwrap();
    case.db.execute("INSERT INTO hosted_billing_ledger_bindings VALUES($1,$2,'cus_invoice1','sub_invoice1','test')",&[&case.account,&ns]).await.unwrap();
    let tx = case.db.transaction().await.unwrap();
    let claim = store::claim_read(&tx, &gate, &scope).await.unwrap();
    tx.commit().await.unwrap();
    let tx = case.db.transaction().await.unwrap();
    let observation = Observation {
        scope: scope.clone(),
        policy_revision: 1,
        generation: claim.generation(),
        complete: true,
        nonterminal_subscriptions: 1,
        status: SubscriptionStatus::Active,
        price: "price_invoice1".into(),
        invoice: "in_invoice1".into(),
        period_start: case.start,
        period_end: case.end,
        revalidate_at: case.end,
        failure: None,
    };
    store::commit_observation(
        &tx,
        &gate,
        &scope,
        &claim,
        &observation,
        &Plan::new("price_invoice1", 2, 2, 0).unwrap(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (case, gate, scope)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted invoice schema"]
async fn hosted_wrong_transaction_live_and_partial_ledger_installation_refuse() {
    let (mut case, gate, _) = installed().await;
    let mut other = case.connect().await;
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    let unrelated = other.transaction().await.unwrap();
    assert!(
        admission::outbound(&unrelated, &gate, &prepared, Uuid::new_v4(), false)
            .await
            .is_err()
    );
    unrelated.rollback().await.unwrap();
    let namespace =
        Namespace::new(Uuid::new_v4().into_bytes(), Mode::Live, "acct_fixture").unwrap();
    let marker = Marker {
        namespace: namespace.clone(),
        policy_revision: 1,
        enabled: true,
    };
    let live = Gate::verify(
        true,
        &namespace,
        1,
        &marker,
        &ProviderIdentity {
            mode: Mode::Live,
            provider_account: "acct_fixture".into(),
        },
    )
    .unwrap();
    assert!(admission::prepare(&tx, &live, case.account).await.is_err());
    drop(prepared);
    tx.rollback().await.unwrap();
    case.db
        .batch_execute("ALTER TABLE usage_ledger DISABLE TRIGGER billing_invoice_ledger")
        .await
        .unwrap();
    let tx = case.db.transaction().await.unwrap();
    assert!(admission::prepare(&tx, &gate, case.account).await.is_err());
    tx.rollback().await.unwrap();
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted invoice schema"]
async fn hosted_final_expiry_and_legacy_risk_rollback_message_and_device() {
    let (mut case, gate, _) = installed().await;
    let id = Uuid::new_v4();
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    admission::outbound(&tx, &gate, &prepared, id, false)
        .await
        .unwrap();
    write_existing_ledger(&tx, case.account, case.device, id).await;
    tx.execute("UPDATE hosted_billing_projections SET valid_until=floor(extract(epoch FROM clock_timestamp()))::bigint+1",&[]).await.unwrap();
    tx.query_one("SELECT 1 FROM pg_sleep(2)", &[])
        .await
        .unwrap();
    assert!(
        admission::outbound(&tx, &gate, &prepared, id, true)
            .await
            .is_err()
    );
    drop(prepared);
    tx.rollback().await.unwrap();
    assert_eq!(
        case.db
            .query_one("SELECT count(*) FROM usage_ledger", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    // Legacy cancellation precedes a new hosted current observation. It must
    // invalidate both operation types immediately through the original gate.
    case.db.execute("UPDATE billing_invoice_entitlements SET cancel_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint",&[]).await.unwrap();
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    assert!(
        admission::device(&tx, &gate, &prepared, None)
            .await
            .is_err()
    );
    assert!(
        admission::outbound(&tx, &gate, &prepared, id, false)
            .await
            .is_err()
    );
    drop(prepared);
    tx.rollback().await.unwrap();
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted invoice schema"]
async fn concurrent_hosted_attempts_serialize_the_last_existing_invoice_unit() {
    let (mut case, gate, _) = installed().await;
    case.send("prior hosted unit").await.unwrap();
    let mut other = case.connect().await;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let account = case.account;
    let device = case.device;
    let left_gate = gate.clone();
    let right_gate = gate.clone();
    let left = async {
        let tx = case.db.transaction().await.unwrap();
        let prepared = admission::prepare(&tx, &left_gate, account).await.unwrap();
        if admission::outbound(&tx, &left_gate, &prepared, first, false)
            .await
            .is_err()
        {
            drop(prepared);
            tx.rollback().await.unwrap();
            return false;
        }
        write_existing_ledger(&tx, account, device, first).await;
        admission::outbound(&tx, &left_gate, &prepared, first, true)
            .await
            .unwrap();
        drop(prepared);
        tx.commit().await.unwrap();
        true
    };
    let right = async {
        let tx = other.transaction().await.unwrap();
        let prepared = admission::prepare(&tx, &right_gate, account).await.unwrap();
        if admission::outbound(&tx, &right_gate, &prepared, second, false)
            .await
            .is_err()
        {
            drop(prepared);
            tx.rollback().await.unwrap();
            return false;
        }
        write_existing_ledger(&tx, account, device, second).await;
        admission::outbound(&tx, &right_gate, &prepared, second, true)
            .await
            .unwrap();
        drop(prepared);
        tx.commit().await.unwrap();
        true
    };
    let (a, b) = tokio::join!(left, right);
    assert_ne!(a, b);
    assert_eq!(
        case.db
            .query_one("SELECT reserved_units FROM billing_invoice_periods", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    assert_eq!(
        case.db
            .query_one("SELECT count(*) FROM usage_ledger", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted invoice schema"]
async fn hosted_renewal_retains_original_attribution_and_unresolved_carry() {
    let (mut case, gate, scope) = installed_horizon(30).await;
    let old = case
        .send("old unresolved hosted invoice")
        .await
        .unwrap()
        .message_id;
    let original: Uuid = case
        .db
        .query_one(
            "SELECT period_id FROM billing_invoice_usage WHERE message_id=$1",
            &[&old],
        )
        .await
        .unwrap()
        .get(0);
    case.db.query_one("SELECT 1 FROM pg_sleep(GREATEST(0.0,($1::bigint-extract(epoch FROM clock_timestamp()))::double precision+0.05))",&[&case.end]).await.unwrap();
    case.start = case.end;
    case.end += 3600;
    let paid = case.observation_for_price(
        "active",
        "paid",
        "subscription_cycle",
        "price_invoice1",
        "in_invoice2",
    );
    case.observe(&paid).await.unwrap();
    let tx = case.db.transaction().await.unwrap();
    let claim = store::claim_read(&tx, &gate, &scope).await.unwrap();
    tx.commit().await.unwrap();
    let tx = case.db.transaction().await.unwrap();
    let observation = Observation {
        scope: scope.clone(),
        policy_revision: 1,
        generation: claim.generation(),
        complete: true,
        nonterminal_subscriptions: 1,
        status: SubscriptionStatus::Active,
        price: "price_invoice1".into(),
        invoice: "in_invoice2".into(),
        period_start: case.start,
        period_end: case.end,
        revalidate_at: case.end,
        failure: None,
    };
    store::commit_observation(
        &tx,
        &gate,
        &scope,
        &claim,
        &observation,
        &Plan::new("price_invoice1", 2, 2, 0).unwrap(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let current = Uuid::new_v4();
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    admission::outbound(&tx, &gate, &prepared, current, false)
        .await
        .unwrap();
    write_existing_ledger(&tx, case.account, case.device, current).await;
    admission::outbound(&tx, &gate, &prepared, current, true)
        .await
        .unwrap();
    // One current reservation plus one old unresolved liability reaches cap.
    assert!(
        admission::outbound(&tx, &gate, &prepared, Uuid::new_v4(), false)
            .await
            .is_err()
    );
    admission::outbound(&tx, &gate, &prepared, old, true)
        .await
        .unwrap();
    drop(prepared);
    tx.commit().await.unwrap();
    assert_eq!(
        case.db
            .query_one(
                "SELECT period_id FROM billing_invoice_usage WHERE message_id=$1",
                &[&old]
            )
            .await
            .unwrap()
            .get::<_, Uuid>(0),
        original
    );
    // Original reservation, not the new invoice, receives the one-time refund.
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    assert!(
        zrotext_delivery_store::cancel_in_transaction(&tx, case.account, old)
            .await
            .unwrap()
    );
    assert!(matches!(
        zrotext_delivery_store::cancel_in_transaction(&tx, case.account, old).await,
        Err(zrotext_delivery_store::StoreError::InvalidTransition)
    ));
    admission::outbound(&tx, &gate, &prepared, Uuid::new_v4(), false)
        .await
        .unwrap();
    drop(prepared);
    tx.commit().await.unwrap();
    assert_eq!(
        case.db
            .query_one(
                "SELECT refunded_units FROM billing_invoice_periods WHERE id=$1",
                &[&original]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted invoice schema"]
async fn hosted_lease_expiring_during_actual_invoice_lock_wait_refuses() {
    let (case, gate, _) = installed().await;
    // All connection startup precedes the original bounded lease. The test
    // must witness the actual period lock wait, then cross that SAME deadline.
    let mut worker = case.connect().await;
    let mut blocker = case.connect().await;
    let pid: i32 = worker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocked = blocker.transaction().await.unwrap();
    blocked
        .query_one(
            "SELECT id FROM billing_invoice_periods WHERE account_id=$1 FOR UPDATE",
            &[&case.account],
        )
        .await
        .unwrap();
    let deadline:i64=case.db.query_one("UPDATE hosted_billing_projections SET valid_until=floor(extract(epoch FROM clock_timestamp()))::bigint+2 RETURNING valid_until",&[]).await.unwrap().get(0);
    let account = case.account;
    let attempt = tokio::spawn(async move {
        let tx = worker.transaction().await.unwrap();
        let prepared = admission::prepare(&tx, &gate, account).await.unwrap();
        let result = admission::outbound(&tx, &gate, &prepared, Uuid::new_v4(), false).await;
        drop(prepared);
        tx.rollback().await.unwrap();
        result
    });
    tokio::time::timeout(std::time::Duration::from_secs(2),async{
        loop{
            let waiting:bool=case.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE '%billing_invoice_entitlements%')",&[&pid]).await.unwrap().get(0);
            if waiting{break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("admission must reach the actual current-invoice lock wait");
    case.db.query_one("SELECT 1 FROM pg_sleep(GREATEST(0.0,($1::bigint-extract(epoch FROM clock_timestamp()))::double precision+0.02))",&[&deadline]).await.unwrap();
    blocked.commit().await.unwrap();
    assert!(matches!(
        attempt.await.unwrap(),
        Err(store::StoreError::Refused(
            crate::billing::hosted::Refusal::Pending
        ))
    ));
    assert_eq!(
        case.db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.cleanup().await;
}

async fn write_existing_ledger(tx: &Transaction<'_>, account: Uuid, device: Uuid, id: Uuid) {
    // Same real ledger and triggers as enqueue. Synthetic transport has no
    // cryptographic authority claim; cryptographic caller validation is separate.
    tx.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+'||'1'||repeat('0',8)||'1',decode(repeat('00',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('01',32),'hex'),'queued',clock_timestamp()+interval '1 hour')",&[&id,&account,&device]).await.unwrap();
    tx.execute("INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units,reserved_units) SELECT $1,'outbound_message',date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')::date,(date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')+interval '1 month')::date,2,1 ON CONFLICT(account_id,metric,period_start) DO UPDATE SET reserved_units=usage_periods.reserved_units+1",&[&account]).await.unwrap();
    tx.execute("INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) SELECT $1,$2,'outbound_message',date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')::date,'reserve',1",&[&account,&id]).await.unwrap();
    tx.execute(
        "INSERT INTO dispatch_jobs(account_id,message_id,device_id) VALUES($1,$2,$3)",
        &[&account, &id, &device],
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted invoice schema"]
async fn hosted_invoice_last_unit_replay_and_rollback_share_existing_ledger() {
    let (mut case, gate, _) = installed().await;
    let first = Uuid::new_v4();
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    admission::outbound(&tx, &gate, &prepared, first, false)
        .await
        .unwrap();
    write_existing_ledger(&tx, case.account, case.device, first).await;
    admission::outbound(&tx, &gate, &prepared, first, true)
        .await
        .unwrap();
    drop(prepared);
    tx.rollback().await.unwrap();
    assert_eq!(
        case.db
            .query_one("SELECT count(*) FROM usage_ledger", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    for id in [first, Uuid::new_v4()] {
        let tx = case.db.transaction().await.unwrap();
        let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
        admission::outbound(&tx, &gate, &prepared, id, false)
            .await
            .unwrap();
        write_existing_ledger(&tx, case.account, case.device, id).await;
        admission::outbound(&tx, &gate, &prepared, id, true)
            .await
            .unwrap();
        drop(prepared);
        tx.commit().await.unwrap();
    }
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    admission::outbound(&tx, &gate, &prepared, first, false)
        .await
        .unwrap();
    admission::outbound(&tx, &gate, &prepared, first, true)
        .await
        .unwrap();
    assert!(
        admission::outbound(&tx, &gate, &prepared, Uuid::new_v4(), false)
            .await
            .is_err()
    );
    drop(prepared);
    tx.rollback().await.unwrap();
    assert_eq!(
        case.db
            .query_one("SELECT reserved_units FROM billing_invoice_periods", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    assert_eq!(
        case.db
            .query_one("SELECT count(*) FROM dispatch_jobs", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted invoice schema"]
async fn hosted_binding_and_projection_period_mismatch_refuse_before_writes() {
    let (mut case, gate, _) = installed().await;
    let tx = case.db.transaction().await.unwrap();
    assert!(
        admission::prepare(&tx, &gate, Uuid::new_v4())
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert!(
        case.db
            .execute(
                "UPDATE hosted_billing_ledger_bindings SET customer_id='cus_other'",
                &[]
            )
            .await
            .is_err()
    );
    case.db
        .execute(
            "UPDATE hosted_billing_projections SET invoice_id='in_other'",
            &[],
        )
        .await
        .unwrap();
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    assert!(
        admission::outbound(&tx, &gate, &prepared, Uuid::new_v4(), false)
            .await
            .is_err()
    );
    drop(prepared);
    tx.rollback().await.unwrap();
    assert_eq!(
        case.db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted invoice schema"]
async fn hosted_device_last_slot_and_final_hold_refuse_atomically() {
    let (mut case, gate, _) = installed().await;
    let tx = case.db.transaction().await.unwrap();
    let prepared = admission::prepare(&tx, &gate, case.account).await.unwrap();
    admission::device(&tx, &gate, &prepared, None)
        .await
        .unwrap();
    let added = Uuid::new_v4();
    tx.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic hosted device')",
        &[&added, &case.account],
    )
    .await
    .unwrap();
    admission::device(&tx, &gate, &prepared, Some(added))
        .await
        .unwrap();
    assert!(
        admission::device(&tx, &gate, &prepared, None)
            .await
            .is_err()
    );
    tx.execute(
        "UPDATE hosted_billing_projections SET payment_hold=true",
        &[],
    )
    .await
    .unwrap();
    assert!(
        admission::device(&tx, &gate, &prepared, Some(added))
            .await
            .is_err()
    );
    drop(prepared);
    tx.rollback().await.unwrap();
    assert_eq!(
        case.db
            .query_one("SELECT count(*) FROM devices", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    case.cleanup().await;
}
