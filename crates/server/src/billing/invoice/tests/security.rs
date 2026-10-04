// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn signed_foreign_account_or_api_context_is_durable_unsupported_without_entitlement_effects()
{
    let mut case = Case::new().await;
    for (index, field, value) in [
        (1, "account", json!("acct_foreignfixture")),
        (2, "context", json!("acct_foreignfixture")),
        (3, "api_version", json!("unsupported-fixture-version")),
    ] {
        let mut payload = json!({"id":format!("evt_context{index}"),"object":"event","livemode":false,
            "api_version":billing::risk::STRIPE_API_VERSION,"type":"invoice.paid",
            "data":{"object":{"id":"in_invoice1","customer":&case.customer,"parent":{"subscription_details":{"subscription":"sub_invoice1"}}}}});
        payload[field] = value;
        let body = serde_json::to_vec(&payload).unwrap();
        let secret = format!("whsec_{}", Uuid::new_v4().simple());
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(b"1750000000.");
        mac.update(&body);
        let digest = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let header = format!("t=1750000000,v1={digest}");
        let verified = billing::verify_event(&body, &header, &secret, 1_750_000_000).unwrap();
        assert_eq!(
            billing::ingest(&mut case.db, &verified).await.unwrap(),
            IngestResult::Unsupported
        );
        assert_eq!(
            billing::ingest(&mut case.db, &verified).await.unwrap(),
            IngestResult::Duplicate
        );
        let mut altered = body.clone();
        altered.push(b' ');
        assert!(
            billing::verify_event(&altered, &header, &secret, 1_750_000_000).is_err(),
            "verification binds raw bytes before JSON parsing"
        );
    }
    let row=case.db.query_one("SELECT (SELECT count(*) FROM billing_events),(SELECT count(*) FROM billing_reconciliations),(SELECT count(*) FROM billing_invoice_periods),(SELECT count(*) FROM billing_invoice_entitlements)",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 3);
    for col in 1..4 {
        assert_eq!(row.get::<_, i64>(col), 0);
    }
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn current_invoice_customer_substitution_rolls_back_without_new_period_authority() {
    let mut case = Case::new().await;
    let mut foreign = case.observation("active", "paid", "subscription_cycle");
    foreign.observation.subscription.customer_id = "cus_foreignfixture".into();
    assert!(case.observe(&foreign).await.is_err());
    let count: i64 = case
        .db
        .query_one("SELECT count(*) FROM billing_invoice_periods", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    let limit: i64 = case
        .db
        .query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
            &[&case.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(limit, 0);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn invoice_period_foreign_tenant_subscription_is_rejected_by_the_database_boundary() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    let foreign = Uuid::new_v4();
    case.db
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&foreign])
        .await
        .unwrap();
    let error=case.db.execute("INSERT INTO billing_invoice_periods(id,account_id,subscription_id,invoice_id,line_id,item_id,start_ms,end_ms,original_price_id,original_limit) VALUES($1,$2,'sub_invoice1','in_foreignperiod','il_foreignperiod','si_invoice1',$3,$4,'price_invoice1',2)", &[&Uuid::new_v4(),&foreign,&(case.start*1000),&(case.end*1000)]).await.unwrap_err();
    assert_eq!(error.code().unwrap().code(), "23503");
    case.cleanup().await;
}
