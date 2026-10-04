// SPDX-License-Identifier: AGPL-3.0-only
//! Test-only composition for an existing manifest fixture account. No runtime
//! mount, provider request, auth replacement, or substitute ledger schema.
use super::{CurrentInvoice, model};
use crate::billing::hosted::{
    namespace::{Gate, Marker, Mode, Namespace, ProviderIdentity, Scope},
    policy::{Observation, Plan, SubscriptionStatus},
    store,
};
use crate::billing::{self, IngestResult, TestQuotaPlan};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use tokio_postgres::Client;
use uuid::Uuid;

/// The caller supplies its existing account in a unique disposable manifest
/// schema. Only billing is installed; account/device/session/key rows survive.
/// Synthetic limits are fixture inputs, never approved commercial plan facts.
pub(crate) async fn install_for_existing_account(
    db: &mut Client,
    account: Uuid,
    outbound_limit: u64,
    device_limit: u64,
) -> (Gate, Scope) {
    let schema: String = db
        .query_one("SELECT current_schema()", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        schema.starts_with("manifest_authority_"),
        "requires a disposable manifest fixture schema"
    );
    assert!(outbound_limit > 0 && device_limit > 0);
    let outbound_i64 = i64::try_from(outbound_limit).unwrap();
    let device_i64 = i64::try_from(device_limit).unwrap();
    assert!(
        db.query_opt("SELECT 1 FROM accounts WHERE id=$1", &[&account])
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        db.query_opt(
            "SELECT 1 FROM billing_customers WHERE account_id=$1",
            &[&account]
        )
        .await
        .unwrap()
        .is_none(),
        "fixture account must have no prior provider binding"
    );
    let installed: bool = db
        .query_one(
            "SELECT to_regprocedure('current_billing_invoice_period(uuid)') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    if !installed {
        db.batch_execute(include_str!(
            "../../../../../deploy/compose/migrations/081_invoice_bound_test_billing.sql"
        ))
        .await
        .unwrap();
    }
    let suffix = account.simple();
    let customer = format!("cus_hosted{suffix}");
    let subscription = format!("sub_hosted{suffix}");
    let invoice_id = format!("in_hosted{suffix}");
    let item = format!("si_hosted{suffix}");
    let line = format!("il_hosted{suffix}");
    let price = "price_hostedfixture";
    billing::bind_customer(db, account, &customer)
        .await
        .unwrap();
    // A fresh fixture account must not silently replace existing quota policy.
    db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units,source,invoice_bound_test) VALUES($1,'outbound_message',0,'stripe_test',true)", &[&account]).await.unwrap();
    let now: i64 = db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let start = now - 60;
    let end = now + 3600;
    let snapshot = json!({"id":subscription,"object":"subscription","livemode":false,
        "customer":customer,"status":"active","latest_invoice":invoice_id,
        "cancel_at":null,"cancel_at_period_end":false,
        "items":{"object":"list","has_more":false,"data":[{"id":item,"quantity":1,
            "price":{"id":price},"current_period_start":start,"current_period_end":end}]}});
    let invoice = json!({"id":invoice_id,"object":"invoice","livemode":false,
        "customer":customer,"status":"paid","billing_reason":"subscription_cycle",
        "parent":{"type":"subscription_details","subscription_details":{"subscription":subscription}},
        "lines":{"object":"list","has_more":false,"data":[{"id":line,
            "parent":{"type":"subscription_item_details","subscription_item_details":{"subscription_item":item,"proration":false}},
            "period":{"start":start,"end":end},"pricing":{"price_details":{"price":price}}}]}});
    let proof = CurrentInvoice {
        observation: model::parse(
            &serde_json::to_vec(&snapshot).unwrap(),
            &serde_json::to_vec(&invoice).unwrap(),
        )
        .unwrap(),
    };
    let event = json!({"id":format!("evt_hosted{suffix}"),"object":"event","livemode":false,
        "type":"customer.subscription.updated","data":{"object":{"id":subscription,"customer":customer}}});
    let body = serde_json::to_vec(&event).unwrap();
    let secret = format!("whsec_{}", Uuid::new_v4().simple());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(&body);
    let signature = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let verified = billing::verify_event(
        &body,
        &format!("t=1750000000,v1={signature}"),
        &secret,
        1_750_000_000,
    )
    .unwrap();
    assert_eq!(
        billing::ingest(db, &verified).await.unwrap(),
        IngestResult::Queued
    );
    billing::reconcile_with_invoice(
        db,
        account,
        proof.subscription(),
        &[price.into()],
        &[TestQuotaPlan {
            price_id: price.into(),
            outbound_limit: outbound_i64,
            device_limit: Some(device_i64),
        }],
        1,
        Some(&proof),
    )
    .await
    .unwrap();
    db.batch_execute(include_str!("../hosted/store_fixture.sql"))
        .await
        .unwrap();
    db.batch_execute(include_str!("../hosted/admission_fixture.sql"))
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
    let scope = Scope::new(namespace, account.into_bytes(), &customer, &subscription).unwrap();
    let ns = Uuid::from_bytes(scope.namespace().id());
    db.execute(
        "INSERT INTO hosted_billing_namespaces VALUES($1,'test','acct_fixture',1,true,true)",
        &[&ns],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO hosted_billing_projections(namespace_id,account_id,customer_id,subscription_id,policy_revision,dirty_generation,processed_generation,per_read_sequence,payment_hold,review_required,phase,outbound_limit,device_limit,issued_at,valid_until) VALUES($1,$2,$3,$4,1,0,0,0,false,false,'pending',0,0,0,0)", &[&ns,&account,&customer,&subscription]).await.unwrap();
    db.execute(
        "INSERT INTO hosted_billing_ledger_bindings VALUES($1,$2,$3,$4,'test')",
        &[&account, &ns, &customer, &subscription],
    )
    .await
    .unwrap();
    let tx = db.transaction().await.unwrap();
    let claim = store::claim_read(&tx, &gate, &scope).await.unwrap();
    tx.commit().await.unwrap();
    let tx = db.transaction().await.unwrap();
    store::commit_observation(
        &tx,
        &gate,
        &scope,
        &claim,
        &Observation {
            scope: scope.clone(),
            policy_revision: 1,
            generation: claim.generation(),
            complete: true,
            nonterminal_subscriptions: 1,
            status: SubscriptionStatus::Active,
            price: price.into(),
            invoice: invoice_id,
            period_start: start,
            period_end: end,
            revalidate_at: end,
            failure: None,
        },
        &Plan::new(price, outbound_limit, device_limit, 0).unwrap(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (gate, scope)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated existing manifest fixture"]
async fn existing_manifest_fixture_installs_real_hosted_invoice_without_replacing_authority() {
    let mut fixture = crate::sealed_manifest_store::tests::Fixture::new().await;
    let account = fixture.account;
    let device = fixture.device;
    let (gate, scope) = install_for_existing_account(&mut fixture.db, account, 2, 2).await;
    assert_eq!(scope.owner(), account.into_bytes());
    let tx = fixture.db.transaction().await.unwrap();
    let prepared = crate::billing::hosted::admission::prepare(&tx, &gate, account)
        .await
        .unwrap();
    crate::billing::hosted::admission::device(&tx, &gate, &prepared, None)
        .await
        .unwrap();
    crate::billing::hosted::admission::outbound(&tx, &gate, &prepared, Uuid::new_v4(), false)
        .await
        .unwrap();
    drop(prepared);
    tx.rollback().await.unwrap();
    assert!(
        fixture
            .db
            .query_opt(
                "SELECT 1 FROM devices WHERE id=$1 AND account_id=$2",
                &[&device, &account]
            )
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fixture
            .db
            .query_one("SELECT count(*) FROM accounts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    fixture.cleanup().await;
}
