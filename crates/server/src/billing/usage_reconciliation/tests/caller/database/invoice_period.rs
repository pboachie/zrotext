// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
mod lifecycle;
mod replay;
const START: i64 = 1705276800;
const END: i64 = 1707955200;

async fn anchored(f: &Fixture) -> Uuid {
    anchored_state(f, true).await
}

async fn anchored_state(f: &Fixture, terminal: bool) -> Uuid {
    seed(
        &f.db,
        f.account,
        f.device,
        "cus_Synthetic",
        "mtr_Synthetic",
        false,
    )
    .await;
    f.db.execute("INSERT INTO billing_reconciliations(account_id,stripe_customer_id,stripe_subscription_id,processed_generation) VALUES($1,'cus_Synthetic','sub_Synthetic',1)",&[&f.account]).await.unwrap();
    let period = Uuid::new_v4();
    f.db.execute("INSERT INTO billing_invoice_periods(id,account_id,subscription_id,invoice_id,line_id,item_id,start_ms,end_ms,original_price_id,original_limit,reserved_units) VALUES($1,$2,'sub_Synthetic','in_Synthetic','il_Synthetic','si_Synthetic',$3,$4,'price_Synthetic',100,1)",&[&period,&f.account,&(START*1000),&(END*1000)]).await.unwrap();
    let message: Uuid =
        f.db.query_one(
            "SELECT message_id FROM billing_usage_finalized WHERE account_id=$1",
            &[&f.account],
        )
        .await
        .unwrap()
        .get(0);
    f.db.execute("INSERT INTO billing_invoice_usage(account_id,message_id,period_id,terminal) VALUES($1,$2,$3,$4)",&[&f.account,&message,&period,&terminal]).await.unwrap();
    period
}

async fn message(f: &Fixture, month: &str, period: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    let bytes = id.as_bytes().repeat(2);
    f.db.execute("INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units,reserved_units) VALUES($1,'outbound_message',$2::text::date,($2::text::date+interval '1 month')::date,100,1) ON CONFLICT(account_id,metric,period_start) DO NOTHING",&[&f.account,&month]).await.unwrap();
    f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,$4,$5,'synthetic_alpha',$6,$5,'submitted',clock_timestamp()+interval '1 day')",&[&id,&f.account,&f.device,&format!("+{}{}","1555","1234567"),&bytes,&b"synthetic only".as_slice()]).await.unwrap();
    f.db.execute("INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) VALUES($1,$2,'outbound_message',$3::text::date,'reserve',1)",&[&f.account,&id,&month]).await.unwrap();
    f.db.execute("INSERT INTO billing_usage_finalized(account_id,message_id,success_event_id,success_attempt_id) VALUES($1,$2,$3,$4)",&[&f.account,&id,&Uuid::new_v4(),&Uuid::new_v4()]).await.unwrap();
    f.db.execute("INSERT INTO billing_usage_outbox(account_id,message_id,identifier,state,acknowledged_at) VALUES($1,$2,$3,'acknowledged',clock_timestamp())",&[&f.account,&id,&format!("zt-usage-v1-{}{}",id.simple(),id.simple())]).await.unwrap();
    if let Some(period) = period {
        f.db.execute("UPDATE billing_invoice_periods SET reserved_units=reserved_units+1 WHERE account_id=$1 AND id=$2",&[&f.account,&period]).await.unwrap();
        f.db.execute("INSERT INTO billing_invoice_usage(account_id,message_id,period_id,terminal) VALUES($1,$2,$3,true)",&[&f.account,&id,&period]).await.unwrap();
    }
    id
}

fn responses(quantity: i64) -> Vec<Reply> {
    let mut usage = line("il_Synthetic", quantity);
    usage["period"] = json!({"start":START,"end":END});
    usage["parent"]["subscription_item_details"]["subscription_item"] = json!("si_Synthetic");
    let invoice = invoice(vec![usage], false);
    let mut aggregate = summary(quantity);
    aggregate["data"][0]["start_time"] = json!(START);
    aggregate["data"][0]["end_time"] = json!(END);
    vec![
        reply("/v1/billing/meters/mtr_Synthetic", meter()),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            aggregate.clone(),
        ),
        reply("/v1/invoices/in_Synthetic", invoice.clone()),
        reply("/v1/prices/price_Synthetic", price()),
        reply("/v1/invoices/in_Synthetic", invoice),
        reply(
            "/v1/billing/meters/mtr_Synthetic/event_summaries",
            aggregate,
        ),
    ]
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine invoice attribution and synthetic TLS"]
async fn crossing_calendar_invoice_observation_excludes_other_month_messages_and_replays_once() {
    let mut f = invoice_fixture().await;
    let period = anchored(&f).await;
    message(&f, "2024-02-01", Some(period)).await;
    message(&f, "2024-01-01", None).await;
    let snapshot = Uuid::new_v4();
    let before = authority_snapshot(&f.db, f.account).await;
    for _ in 0..2 {
        let (worker, server) = tls(responses(2)).await;
        assert_eq!(
            worker
                .reconcile_invoice_period(&mut f.db, f.account, period, snapshot)
                .await
                .unwrap(),
            "observed_equal"
        );
        let paths = server.await.unwrap();
        assert_eq!(paths.len(), 6);
        assert!(paths[1].contains(&format!("start_time={START}")));
        assert!(paths[1].contains(&format!("end_time={END}")));
        assert_eq!(authority_snapshot(&f.db, f.account).await, before);
    }
    let r=f.db.query_one("SELECT finalized_units,acknowledged_units,provider_units,invoice_units,(SELECT count(*) FROM billing_invoice_usage_observations) FROM billing_invoice_usage_observations",&[]).await.unwrap();
    assert_eq!(
        (
            r.get::<_, i64>(0),
            r.get::<_, i64>(1),
            r.get::<_, i64>(2),
            r.get::<_, i64>(3),
            r.get::<_, i64>(4)
        ),
        (2, 2, 2, 2, 1)
    );
    // API replay recovers the exact committed snapshot; changing provider
    // observations under that identity conflicts, never replaces or credits it.
    let (worker, server) = tls(responses(3)).await;
    assert!(matches!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, snapshot)
            .await,
        Err(Error::Usage(billable::UsageError::Conflict))
    ));
    assert_eq!(server.await.unwrap().len(), 6);
    assert!(
        f.db.execute(
            "UPDATE billing_invoice_usage_observations SET provider_units=0",
            &[]
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine invoice attribution, no external requests"]
async fn foreign_period_and_mixed_meter_attribution_refuse_before_http() {
    let mut f = invoice_fixture().await;
    let period = anchored(&f).await;
    let (worker, server) = tls(vec![]).await;
    assert!(
        worker
            .reconcile_invoice_period(&mut f.db, Uuid::new_v4(), period, Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(server.await.unwrap().is_empty());
    f.db.execute(
        "UPDATE billing_usage_test_policies SET active=false WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    f.db.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name,active) VALUES($1,2,'cus_Synthetic','mtr_Other','other_submit',true)",&[&f.account]).await.unwrap();
    message(&f, "2024-02-01", Some(period)).await;
    let (worker, server) = tls(vec![]).await;
    assert!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(server.await.unwrap().is_empty());
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM billing_invoice_usage_observations",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; invoice unknown liability and receipt rollback"]
async fn unknown_invoice_liability_stays_pending_and_failed_receipt_cannot_change_accounting() {
    let mut f = invoice_fixture().await;
    let period = anchored_state(&f, false).await;
    f.db.execute(
        "DELETE FROM billing_usage_outbox WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    f.db.execute(
        "DELETE FROM billing_usage_finalized WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    f.db.execute(
        "UPDATE billing_invoice_periods SET open_units=1 WHERE account_id=$1 AND id=$2",
        &[&f.account, &period],
    )
    .await
    .unwrap();
    let before = authority_snapshot(&f.db, f.account).await;
    let snapshot = Uuid::new_v4();
    f.db.batch_execute("CREATE FUNCTION reject_invoice_observation_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic observation failure'; END $$; CREATE TRIGGER reject_invoice_observation_fixture BEFORE INSERT ON billing_invoice_usage_observations FOR EACH ROW EXECUTE FUNCTION reject_invoice_observation_fixture()").await.unwrap();
    let (worker, server) = tls(responses(0)).await;
    assert!(matches!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, snapshot)
            .await,
        Err(Error::Database(_))
    ));
    assert_eq!(server.await.unwrap().len(), 6);
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM billing_invoice_usage_observations",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(authority_snapshot(&f.db, f.account).await, before);
    f.db.batch_execute("DROP TRIGGER reject_invoice_observation_fixture ON billing_invoice_usage_observations; DROP FUNCTION reject_invoice_observation_fixture()").await.unwrap();
    let (worker, server) = tls(responses(0)).await;
    assert_eq!(
        worker
            .reconcile_invoice_period(&mut f.db, f.account, period, snapshot)
            .await
            .unwrap(),
        "pending"
    );
    assert_eq!(server.await.unwrap().len(), 6);
    let r=f.db.query_one("SELECT finalized_units,pending_units,open_units,provider_units,invoice_units FROM billing_invoice_usage_observations",&[]).await.unwrap();
    assert_eq!(
        (
            r.get::<_, i64>(0),
            r.get::<_, i64>(1),
            r.get::<_, i64>(2),
            r.get::<_, i64>(3),
            r.get::<_, i64>(4)
        ),
        (0, 1, 1, 0, 0)
    );
    assert_eq!(authority_snapshot(&f.db, f.account).await, before);
    f.cleanup().await;
}
