// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{DeliveryStore, NewMessage, RadioEvent, now_ms};
use zrotext_domain::Evidence;

fn candidate(attempt: i32) -> Claim {
    Claim {
        account: Uuid::new_v4(),
        message: Uuid::new_v4(),
        lease: Uuid::new_v4(),
        attempt,
        request: MeterRequest {
            identifier: "synthetic-id".into(),
            idempotency_key: "synthetic-id".into(),
            event_name: "synthetic_execution".into(),
            customer_id: "cus_Synthetic".into(),
            timestamp: 1,
            units: 1,
            api_version: "2025-07-30.basil",
        },
    }
}

#[test]
fn acknowledgements_require_exact_identity_and_test_mode() {
    let c = candidate(1);
    assert_eq!(
        disposition(
            MeterResponse::Acknowledged {
                identifier: c.request.identifier.clone(),
                livemode: false
            },
            &c
        )
        .0,
        "acknowledged"
    );
    for response in [
        MeterResponse::Acknowledged {
            identifier: "different".into(),
            livemode: false,
        },
        MeterResponse::Acknowledged {
            identifier: c.request.identifier.clone(),
            livemode: true,
        },
    ] {
        assert_eq!(disposition(response, &c), ("review", "response", 0));
    }
}

#[test]
fn unknown_and_transient_responses_have_bounded_retries() {
    for response in [
        MeterResponse::Unknown,
        MeterResponse::Http {
            status: 429,
            retry_after_seconds: u64::MAX,
        },
        MeterResponse::Http {
            status: 503,
            retry_after_seconds: 0,
        },
    ] {
        let result = disposition(response, &candidate(1));
        assert_eq!(result.0, "pending");
        assert!((1..=600).contains(&result.2));
    }
    assert_eq!(
        disposition(MeterResponse::Unknown, &candidate(7)),
        ("review", "attempt_limit", 0)
    );
    assert_eq!(
        disposition(
            MeterResponse::Http {
                status: 400,
                retry_after_seconds: 0
            },
            &candidate(1)
        ),
        ("review", "permanent", 0)
    );
}

#[test]
fn periods_reject_non_ascii_and_non_month_boundaries() {
    for value in [
        "2026-00-01",
        "2026-13-01",
        "2026-01-02",
        "2026-é-01",
        "",
        "2026-01-01extra",
    ] {
        assert!(!valid_period(value));
    }
    assert!(valid_period("2026-01-01"));
    assert!(!TestUsageWorker::default().enabled);
}

struct Db {
    client: Client,
    schema: String,
    account: Uuid,
    device: Uuid,
    customer: String,
}
impl Db {
    async fn new() -> Self {
        let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL").unwrap();
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        let schema = format!("billable_test_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        crate::tests::apply_test_migrations(&client).await;
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let customer = format!("cus_Synthetic{}", account.simple());
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
                &[&device, &account],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
                &[&account, &customer],
            )
            .await
            .unwrap();
        let subscription = format!("sub_Synthetic{}", account.simple());
        client.execute("INSERT INTO billing_reconciliations(account_id,stripe_customer_id,stripe_subscription_id,processed_generation) VALUES($1,$2,$3,1)",&[&account,&customer,&subscription]).await.unwrap();
        client.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',100,'stripe_test')",&[&account]).await.unwrap();
        client.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name,active) VALUES($1,1,$2,'mtr_Synthetic','synthetic_execution',true)",&[&account,&customer]).await.unwrap();
        client
            .batch_execute("UPDATE deployment_authority SET dispatch_enabled=true")
            .await
            .unwrap();
        Self {
            client,
            schema,
            account,
            device,
            customer,
        }
    }
    async fn submit(&mut self, segments: i32) -> (Uuid, RadioEvent) {
        self.submit_at(segments, None).await
    }
    async fn submit_at(&mut self, segments: i32, at: Option<i64>) -> (Uuid, RadioEvent) {
        let account = self.account;
        let device = self.device;
        let id = Uuid::new_v4();
        let key = id.to_string();
        let mut store = DeliveryStore::new(&mut self.client);
        let input = NewMessage {
            account_id: account,
            device_id: device,
            client_message_id: id,
            idempotency_key: &key,
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic only",
            expires_at_ms: now_ms() + 60_000,
        };
        if let Some(at) = at {
            store.accept_metered_at(input, at).await.unwrap();
        } else {
            store.accept_metered(input).await.unwrap();
        }
        let session = store
            .connect_session(account, device, "test", "test", 60)
            .await
            .unwrap();
        let claim = store
            .claim_due_for_device("test", account, device)
            .await
            .unwrap()
            .unwrap();
        let attempt = Uuid::new_v4();
        store.issue_grant(&claim, &session, attempt).await.unwrap();
        let event = RadioEvent {
            event_id: Uuid::new_v4(),
            account_id: account,
            device_id: device,
            message_id: id,
            attempt_id: attempt,
            evidence: Evidence::DurableSubmitIntent,
            observed_at_ms: now_ms(),
            segment_index: None,
            segment_count: None,
        };
        store.record_radio_event(event).await.unwrap();
        for index in 0..segments {
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    evidence: Evidence::SentCallbackOk,
                    segment_index: Some(index),
                    segment_count: Some(segments),
                    ..event
                })
                .await
                .unwrap();
        }
        (id, event)
    }
    async fn close(self) {
        self.client
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {} CASCADE",
                self.schema
            ))
            .await
            .unwrap();
    }
    async fn period(&self) -> String {
        self.client
            .query_one(
                "SELECT date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')::date::text",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn all_segment_success_creates_one_unit_and_duplicate_callback_cannot_charge_again() {
    let mut db = Db::new().await;
    let (message, event) = db.submit(2).await;
    let period = db.period().await;
    assert_eq!(
        local_usage(&db.client, db.account, &period).await.unwrap(),
        LocalUsage {
            finalized: 1,
            acknowledged: 0,
            pending: 1,
            review: 0
        }
    );
    assert_eq!(
        local_usage(&db.client, Uuid::new_v4(), &period)
            .await
            .unwrap()
            .finalized,
        0
    );
    let duplicate=db.client.query_one("SELECT id FROM message_events WHERE message_id=$1 AND evidence_code='sent_callback_ok' AND segment_index=1",&[&message]).await.unwrap().get(0);
    DeliveryStore::new(&mut db.client)
        .record_radio_event(RadioEvent {
            event_id: duplicate,
            evidence: Evidence::SentCallbackOk,
            segment_index: Some(1),
            segment_count: Some(2),
            ..event
        })
        .await
        .unwrap();
    assert_eq!(
        local_usage(&db.client, db.account, &period)
            .await
            .unwrap()
            .finalized,
        1
    );
    assert!(
        db.client
            .execute(
                "UPDATE billing_usage_finalized SET units=2 WHERE account_id=$1",
                &[&db.account]
            )
            .await
            .is_err()
    );
    let reserves: i64 = db
        .client
        .query_one(
            "SELECT sum(units)::bigint FROM usage_ledger WHERE account_id=$1",
            &[&db.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(reserves, 1);
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn response_loss_reuses_identity_and_async_error_preserves_acknowledgement() {
    let mut db = Db::new().await;
    db.submit(1).await;
    let ClaimResult::Claim(first) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    let id = first.request.identifier.clone();
    assert_eq!(id, first.request.idempotency_key);
    assert_eq!(
        finish(&db.client, first, MeterResponse::Unknown)
            .await
            .unwrap(),
        WorkResult::Deferred
    );
    db.client
        .batch_execute("UPDATE billing_usage_outbox SET next_attempt_at=clock_timestamp()")
        .await
        .unwrap();
    let ClaimResult::Claim(second) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing retry")
    };
    assert_eq!(second.request.identifier, id);
    assert_eq!(
        finish(
            &db.client,
            second,
            MeterResponse::Acknowledged {
                identifier: id,
                livemode: false
            }
        )
        .await
        .unwrap(),
        WorkResult::Acknowledged
    );
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Idle
    ));
    let obs = MeterErrorObservation {
        event_id: "evt_SyntheticError".into(),
        meter_id: "mtr_Synthetic".into(),
        body_digest: [3; 32],
        validation_start: 1,
        validation_end: 2,
    };
    assert!(
        record_meter_error(&mut db.client, db.account, 1, &obs)
            .await
            .unwrap()
    );
    assert!(
        !record_meter_error(&mut db.client, db.account, 1, &obs)
            .await
            .unwrap()
    );
    let period = db.period().await;
    assert_eq!(
        local_usage(&db.client, db.account, &period).await.unwrap(),
        LocalUsage {
            finalized: 1,
            acknowledged: 1,
            pending: 0,
            review: 1
        }
    );
    let observation = ProviderObservation {
        snapshot_id: Uuid::new_v4(),
        policy_version: 1,
        period_start: period,
        customer: db.customer.clone(),
        meter: "mtr_Synthetic".into(),
        provider_units: 1,
        invoice_units: Some(1),
    };
    assert_eq!(
        reconcile(&mut db.client, db.account, &observation)
            .await
            .unwrap(),
        "diverged"
    );
    let changed = ProviderObservation {
        provider_units: 2,
        ..observation
    };
    assert!(matches!(
        reconcile(&mut db.client, db.account, &changed).await,
        Err(UsageError::Conflict)
    ));
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn crashed_lease_is_reclaimed_without_new_identity_and_stale_completion_cannot_ack() {
    let mut db = Db::new().await;
    db.submit(1).await;
    let ClaimResult::Claim(first) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    let id = first.request.identifier.clone();
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Idle
    ));
    db.client
        .batch_execute(
            "UPDATE billing_usage_outbox SET lease_until=clock_timestamp()-interval '1 second'",
        )
        .await
        .unwrap();
    assert_eq!(
        finish(
            &db.client,
            first.clone(),
            MeterResponse::Acknowledged {
                identifier: id.clone(),
                livemode: false
            }
        )
        .await
        .unwrap(),
        WorkResult::Stale
    );
    let ClaimResult::Claim(second) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing reclaimed claim")
    };
    assert_eq!(second.request.identifier, id);
    assert_ne!(second.lease, first.lease);
    assert_eq!(
        finish(
            &db.client,
            first,
            MeterResponse::Acknowledged {
                identifier: id.clone(),
                livemode: false
            }
        )
        .await
        .unwrap(),
        WorkResult::Stale
    );
    assert_eq!(
        finish(
            &db.client,
            second,
            MeterResponse::Http {
                status: 400,
                retry_after_seconds: 0
            }
        )
        .await
        .unwrap(),
        WorkResult::Review
    );
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Idle
    ));
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn success_outbox_failure_rolls_back_callback_and_default_off_cannot_call_transport() {
    let mut db = Db::new().await;
    let (message, event) = db.submit(0).await;
    db.client.batch_execute("CREATE FUNCTION reject_usage_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic crash before commit'; END $$; CREATE TRIGGER reject_usage_test BEFORE INSERT ON billing_usage_outbox FOR EACH ROW EXECUTE FUNCTION reject_usage_test()").await.unwrap();
    let callback = RadioEvent {
        event_id: Uuid::new_v4(),
        evidence: Evidence::SentCallbackOk,
        segment_index: Some(0),
        segment_count: Some(1),
        ..event
    };
    assert!(
        DeliveryStore::new(&mut db.client)
            .record_radio_event(callback)
            .await
            .is_err()
    );
    let state: String = db
        .client
        .query_one("SELECT state FROM messages WHERE id=$1", &[&message])
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "submitting");
    assert_eq!(
        local_usage(&db.client, db.account, &db.period().await)
            .await
            .unwrap()
            .finalized,
        0
    );
    db.client.batch_execute("DROP TRIGGER reject_usage_test ON billing_usage_outbox; DROP FUNCTION reject_usage_test()").await.unwrap();
    DeliveryStore::new(&mut db.client)
        .record_radio_event(callback)
        .await
        .unwrap();
    struct PanicTransport;
    impl TestMeterTransport for PanicTransport {
        async fn submit(&self, _: MeterRequest) -> MeterResponse {
            panic!("default-off worker called provider")
        }
    }
    assert_eq!(
        TestUsageWorker::default()
            .run_one(&mut db.client, &PanicTransport)
            .await
            .unwrap(),
        WorkResult::Disabled
    );
    assert_eq!(
        local_usage(&db.client, db.account, &db.period().await)
            .await
            .unwrap()
            .finalized,
        1
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn invalidated_policy_and_error_customer_pointer_cannot_forward_or_reconcile() {
    let mut db = Db::new().await;
    db.submit(1).await;
    let observation = ProviderObservation {
        snapshot_id: Uuid::new_v4(),
        policy_version: 1,
        period_start: db.period().await,
        customer: "cus_Foreign".into(),
        meter: "mtr_Synthetic".into(),
        provider_units: 1,
        invoice_units: Some(1),
    };
    assert!(matches!(
        reconcile(&mut db.client, db.account, &observation).await,
        Err(UsageError::NotFound)
    ));
    let error = MeterErrorObservation {
        event_id: "evt_ForeignPointer".into(),
        meter_id: "mtr_Foreign".into(),
        body_digest: [4; 32],
        validation_start: 1,
        validation_end: 2,
    };
    assert!(matches!(
        record_meter_error(&mut db.client, db.account, 1, &error).await,
        Err(UsageError::NotFound)
    ));
    db.client
        .batch_execute("UPDATE billing_usage_test_policies SET active=false")
        .await
        .unwrap();
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Review
    ));
    assert_eq!(
        local_usage(&db.client, db.account, &db.period().await)
            .await
            .unwrap()
            .review,
        1
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn concurrent_workers_serialize_customer_and_retry_deadline_requires_review() {
    let mut db = Db::new().await;
    db.submit(1).await;
    db.submit(1).await;
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL").unwrap();
    let (mut second, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    second
        .batch_execute(&format!("SET search_path TO {}", db.schema))
        .await
        .unwrap();
    let (a, b) = tokio::join!(claim_one(&mut db.client), claim_one(&mut second));
    let winner = match (a.unwrap(), b.unwrap()) {
        (ClaimResult::Claim(c), ClaimResult::Idle) | (ClaimResult::Idle, ClaimResult::Claim(c)) => {
            c
        }
        _ => panic!("customer had simultaneous leases"),
    };
    assert_eq!(
        finish(
            &db.client,
            winner,
            MeterResponse::Http {
                status: 429,
                retry_after_seconds: 1
            }
        )
        .await
        .unwrap(),
        WorkResult::Deferred
    );
    // Simulate a queued historical first attempt without editing immutable
    // provenance: only a never-attempted row may acquire its first clock.
    db.client.batch_execute("UPDATE billing_usage_outbox SET first_attempt_at=clock_timestamp()-interval '24 hours' WHERE attempts=0").await.unwrap();
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Review
    ));
    let state = db
        .client
        .query_one(
            "SELECT error_class FROM billing_usage_outbox WHERE state='review'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    assert_eq!(state, "window");
    drop(second);
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn closed_original_period_is_reviewed_without_moving_usage_to_current_month() {
    let mut db = Db::new().await;
    let at=db.client.query_one("SELECT (extract(epoch FROM (date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')-interval '1 day') AT TIME ZONE 'UTC')*1000)::bigint",&[]).await.unwrap().get::<_,i64>(0);
    db.submit_at(1, Some(at)).await;
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Review
    ));
    let row=db.client.query_one("SELECT b.period_start::text,o.error_class FROM billing_usage_bindings b JOIN billing_usage_outbox o USING(account_id,message_id)",&[]).await.unwrap();
    let old = row.get::<_, String>(0);
    assert_ne!(old, db.period().await);
    assert_eq!(row.get::<_, String>(1), "period_closed");
    assert_eq!(
        local_usage(&db.client, db.account, &old)
            .await
            .unwrap()
            .review,
        1
    );
    assert_eq!(
        local_usage(&db.client, db.account, &db.period().await)
            .await
            .unwrap()
            .finalized,
        0
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn failed_execution_and_default_policy_do_not_finalize_billable_usage() {
    let mut db = Db::new().await;
    let (_, event) = db.submit(0).await;
    DeliveryStore::new(&mut db.client)
        .record_radio_event(RadioEvent {
            event_id: Uuid::new_v4(),
            evidence: Evidence::SentCallbackFailed,
            segment_index: Some(0),
            segment_count: Some(1),
            ..event
        })
        .await
        .unwrap();
    assert_eq!(
        local_usage(&db.client, db.account, &db.period().await)
            .await
            .unwrap()
            .finalized,
        0
    );
    db.client
        .batch_execute("UPDATE billing_usage_test_policies SET active=false")
        .await
        .unwrap();
    db.submit(1).await;
    assert_eq!(
        local_usage(&db.client, db.account, &db.period().await)
            .await
            .unwrap()
            .finalized,
        0
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn missing_invoice_stays_pending_and_changed_invoice_snapshot_conflicts() {
    let mut db = Db::new().await;
    db.submit(1).await;
    let ClaimResult::Claim(claim) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    let identifier = claim.request.identifier.clone();
    finish(
        &db.client,
        claim,
        MeterResponse::Acknowledged {
            identifier,
            livemode: false,
        },
    )
    .await
    .unwrap();
    let missing = ProviderObservation {
        snapshot_id: Uuid::new_v4(),
        policy_version: 1,
        period_start: db.period().await,
        customer: db.customer.clone(),
        meter: "mtr_Synthetic".into(),
        provider_units: 1,
        invoice_units: None,
    };
    assert_eq!(
        reconcile(&mut db.client, db.account, &missing)
            .await
            .unwrap(),
        "pending"
    );
    let changed = ProviderObservation {
        invoice_units: Some(1),
        ..missing.clone()
    };
    assert!(matches!(
        reconcile(&mut db.client, db.account, &changed).await,
        Err(UsageError::Conflict)
    ));
    let matched = ProviderObservation {
        snapshot_id: Uuid::new_v4(),
        ..changed
    };
    assert_eq!(
        reconcile(&mut db.client, db.account, &matched)
            .await
            .unwrap(),
        "observed_equal"
    );
    let divergent = ProviderObservation {
        snapshot_id: Uuid::new_v4(),
        invoice_units: Some(2),
        ..matched
    };
    assert_eq!(
        reconcile(&mut db.client, db.account, &divergent)
            .await
            .unwrap(),
        "diverged"
    );
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn shared_meter_error_is_once_bound_and_erasure_keeps_only_remaining_tenant_mappings() {
    let mut db = Db::new().await;
    let other = Uuid::new_v4();
    db.client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&other])
        .await
        .unwrap();
    db.client.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_SyntheticOther')",&[&other]).await.unwrap();
    db.client.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name,active) VALUES($1,1,'cus_SyntheticOther','mtr_Synthetic','synthetic_execution',true)",&[&other]).await.unwrap();
    let error = MeterErrorObservation {
        event_id: "evt_test_SharedMeter".into(),
        meter_id: "mtr_Synthetic".into(),
        body_digest: [5; 32],
        validation_start: 1_234,
        validation_end: 5_678,
    };
    assert!(
        record_meter_error(&mut db.client, db.account, 1, &error)
            .await
            .unwrap()
    );
    assert!(
        record_meter_error(&mut db.client, other, 1, &error)
            .await
            .unwrap()
    );
    let changed = MeterErrorObservation {
        body_digest: [6; 32],
        ..error.clone()
    };
    assert!(matches!(
        record_meter_error(&mut db.client, other, 1, &changed).await,
        Err(UsageError::Conflict)
    ));
    db.client
        .execute(
            "DELETE FROM billing_reconciliations WHERE account_id=$1",
            &[&db.account],
        )
        .await
        .unwrap();
    db.client
        .execute(
            "DELETE FROM billing_customers WHERE account_id=$1",
            &[&db.account],
        )
        .await
        .unwrap();
    assert_eq!(
        db.client
            .query_one(
                "SELECT count(*)::bigint FROM billing_usage_meter_error_receipts",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        db.client
            .query_one(
                "SELECT count(*)::bigint FROM billing_usage_meter_errors WHERE account_id=$1",
                &[&db.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    db.client
        .execute(
            "DELETE FROM billing_customers WHERE account_id=$1",
            &[&other],
        )
        .await
        .unwrap();
    assert_eq!(
        db.client
            .query_one(
                "SELECT count(*)::bigint FROM billing_usage_meter_error_receipts",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    db.close().await;
}
