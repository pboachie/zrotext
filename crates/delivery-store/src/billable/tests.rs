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
        MeterResponse::InvalidResponse,
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
    current: Option<crate::test_database::Fixture>,
    runtime_driver: Option<crate::test_database::Driver>,
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
        crate::tests::apply_legacy_isolated_test_migrations(&client).await;
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
            current: None,
            runtime_driver: None,
            client,
            schema,
            account,
            device,
            customer,
        }
    }
    async fn for_store() -> Self {
        let fixture = crate::test_database::Fixture::for_store().await;
        let client = &fixture.owner;
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
        let (client, driver) = fixture.another_runtime().await;
        Self {
            client,
            current: Some(fixture),
            runtime_driver: Some(driver),
            schema: String::from("public"),
            account,
            device,
            customer,
        }
    }
    // Controlled WORKER PROJECTION input only. These owner-DML rows are not
    // evidence of Store admission, callback, native/HMAC or provider success.
    async fn seed_fractional_worker_input(&mut self) -> (Uuid, std::time::SystemTime, String) {
        let account = self.account;
        let device = self.device;
        let customer = self.customer.clone();
        let message = Uuid::new_v4();
        let synthetic_event = Uuid::new_v4();
        let synthetic_attempt = Uuid::new_v4();
        let identifier = format!(
            "zt-usage-v1-{}",
            Sha256::digest(message.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let fixture = self.current.as_mut().unwrap();
        let tx = fixture.owner.transaction().await.unwrap();
        let absent: bool = tx.query_one(
            "SELECT NOT EXISTS(SELECT FROM messages WHERE account_id=$1 AND id=$2) AND NOT EXISTS(SELECT FROM usage_ledger WHERE account_id=$1 AND message_id=$2) AND NOT EXISTS(SELECT FROM billing_usage_bindings WHERE account_id=$1 AND message_id=$2) AND NOT EXISTS(SELECT FROM billing_usage_finalized WHERE account_id=$1 AND message_id=$2) AND NOT EXISTS(SELECT FROM billing_usage_outbox WHERE account_id=$1 AND message_id=$2) AND NOT EXISTS(SELECT FROM usage_periods WHERE account_id=$1)",
            &[&account, &message],
        ).await.unwrap().get(0);
        assert!(
            absent,
            "the projection input has no prior reservation or history"
        );
        let policy: bool = tx.query_one(
            "SELECT EXISTS(SELECT FROM usage_quota_policies q JOIN billing_usage_test_policies p USING(account_id) JOIN billing_customers c USING(account_id) WHERE q.account_id=$1 AND q.metric='outbound_message' AND q.limit_units=100 AND q.source='stripe_test' AND NOT q.invoice_bound_test AND p.policy_version=1 AND p.active AND p.mode='test' AND p.stripe_customer_id=$2 AND c.stripe_customer_id=$2)",
            &[&account, &customer],
        ).await.unwrap().get(0);
        assert!(policy);
        let seed: std::time::SystemTime = tx
            .query_one(
                "SELECT date_trunc('second',transaction_timestamp())+interval '900 milliseconds'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(tx.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'submitted',transaction_timestamp()+interval '1 hour')",
            &[&message, &account, &device, &vec![5u8; 32], &b"synthetic worker projection".as_slice(), &vec![7u8; 32]],
        ).await.unwrap(), 1);
        assert_eq!(tx.execute(
            "INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units,reserved_units,refunded_units) VALUES($1,'outbound_message',date_trunc('month',$2::timestamptz AT TIME ZONE 'UTC')::date,(date_trunc('month',$2::timestamptz AT TIME ZONE 'UTC')+interval '1 month')::date,100,1,0)",
            &[&account, &seed],
        ).await.unwrap(), 1);
        // The actual unchanged capture trigger creates the immutable binding.
        assert_eq!(tx.execute(
            "INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units,created_at) SELECT $1,$2,'outbound_message',period_start,'reserve',1,$3::timestamptz FROM usage_periods WHERE account_id=$1 AND metric='outbound_message'",
            &[&account, &message, &seed],
        ).await.unwrap(), 1);
        let captured = tx.query_one(
            "SELECT l.created_at,b.report_at,b.policy_version=1 AND b.period_start=u.period_start AND b.period_end=u.period_end AND u.limit_units=100 AND u.reserved_units=1 AND u.refunded_units=0,(SELECT count(*) FROM usage_ledger WHERE account_id=$1 AND message_id=$2),(SELECT count(*) FROM billing_usage_bindings WHERE account_id=$1 AND message_id=$2) FROM usage_ledger l JOIN billing_usage_bindings b USING(account_id,message_id) JOIN usage_periods u ON u.account_id=l.account_id AND u.metric=l.metric AND u.period_start=l.period_start WHERE l.account_id=$1 AND l.message_id=$2 AND l.entry_kind='reserve'",
            &[&account, &message],
        ).await.unwrap();
        assert_eq!(captured.get::<_, std::time::SystemTime>(0), seed);
        assert_eq!(captured.get::<_, std::time::SystemTime>(1), seed);
        assert!(captured.get::<_, bool>(2));
        assert_eq!(captured.get::<_, i64>(3), 1);
        assert_eq!(captured.get::<_, i64>(4), 1);
        assert_eq!(
            seed.duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_micros(),
            900_000
        );
        // Inert synthetic worker identity inputs, not accepted event/attempt
        // rows or a claim that the production finalizer generated this outbox.
        assert_eq!(tx.execute(
            "INSERT INTO billing_usage_finalized(account_id,message_id,success_event_id,success_attempt_id) VALUES($1,$2,$3,$4)",
            &[&account, &message, &synthetic_event, &synthetic_attempt],
        ).await.unwrap(), 1);
        assert_eq!(tx.execute(
            "INSERT INTO billing_usage_outbox(account_id,message_id,identifier) VALUES($1,$2,$3)",
            &[&account, &message, &identifier],
        ).await.unwrap(), 1);
        tx.commit().await.unwrap();
        fixture.verify().await;
        crate::hosted_runtime_identity::require(&self.client)
            .await
            .unwrap();
        (message, seed, identifier)
    }
    fn owner(&self) -> &Client {
        self.current
            .as_ref()
            .map_or(&self.client, |fixture| &fixture.owner)
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
        if let Some(fixture) = self.current {
            crate::test_database::Fixture::close_connection(
                self.client,
                self.runtime_driver.unwrap(),
            )
            .await;
            fixture.finish().await;
            return;
        }
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
    let mut db = Db::for_store().await;
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
    let duplicate=db.owner().query_one("SELECT id FROM message_events WHERE message_id=$1 AND evidence_code='sent_callback_ok' AND segment_index=1",&[&message]).await.unwrap().get(0);
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
        db.owner()
            .execute(
                "UPDATE billing_usage_finalized SET units=2 WHERE account_id=$1",
                &[&db.account]
            )
            .await
            .is_err()
    );
    let reserves: i64 = db
        .owner()
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
    let mut db = Db::for_store().await;
    db.submit(1).await;
    let ClaimResult::Claim(first) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    let id = first.request.identifier.clone();
    assert_eq!(id, first.request.idempotency_key);
    assert_eq!(
        finish(&mut db.client, first, MeterResponse::Unknown)
            .await
            .unwrap(),
        WorkResult::Deferred
    );
    db.owner()
        .batch_execute("UPDATE billing_usage_outbox SET next_attempt_at=clock_timestamp()")
        .await
        .unwrap();
    let ClaimResult::Claim(second) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing retry")
    };
    assert_eq!(second.request.identifier, id);
    assert_eq!(
        finish(
            &mut db.client,
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
    let mut db = Db::for_store().await;
    db.submit(1).await;
    let ClaimResult::Claim(first) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    let id = first.request.identifier.clone();
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Idle
    ));
    db.owner()
        .batch_execute(
            "UPDATE billing_usage_outbox SET lease_until=clock_timestamp()-interval '1 second'",
        )
        .await
        .unwrap();
    assert_eq!(
        finish(
            &mut db.client,
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
            &mut db.client,
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
            &mut db.client,
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
    let mut db = Db::for_store().await;
    let (message, event) = db.submit(0).await;
    let callback = RadioEvent {
        event_id: Uuid::new_v4(),
        evidence: Evidence::SentCallbackOk,
        segment_index: Some(0),
        segment_count: Some(1),
        ..event
    };
    crate::hosted_runtime_identity::require(&db.client)
        .await
        .unwrap();
    let config = db.current.as_ref().unwrap().config.clone();
    let mut worker = crate::test_database::RuntimeConnection::connect(&config).await;
    let pid: i32 = worker
        .client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let cancel = worker.client.cancel_token();
    let lock = db
        .current
        .as_mut()
        .unwrap()
        .owner
        .transaction()
        .await
        .unwrap();
    lock.batch_execute("LOCK TABLE public.billing_usage_outbox IN SHARE MODE")
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        let result = DeliveryStore::new(&mut worker.client)
            .record_radio_event(callback)
            .await;
        worker.finish().await;
        result
    });
    let mut reached = false;
    for _ in 0..500 {
        reached = lock.query_one(
            "SELECT EXISTS(SELECT FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation='public.billing_usage_outbox'::regclass AND mode='RowExclusiveLock' AND NOT granted)",
            &[&pid],
        ).await.unwrap().get(0);
        if reached || task.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The one cancellation also drains a missed-target failure; only the exact
    // lock witness below permits this test to claim the intended fault.
    cancel.cancel_query(tokio_postgres::NoTls).await.unwrap();
    let result = task.await.unwrap();
    lock.rollback().await.unwrap();
    assert!(
        reached,
        "callback reached the exact outbox INSERT table-lock request"
    );
    let Err(crate::StoreError::Database(error)) = result else {
        panic!("expected database query cancellation at outbox write")
    };
    assert_eq!(
        error.code(),
        Some(&tokio_postgres::error::SqlState::QUERY_CANCELED)
    );
    crate::hosted_runtime_identity::require(&db.client)
        .await
        .unwrap();
    db.current.as_ref().unwrap().verify().await;
    let absent: bool = db.owner().query_one(
        "SELECT NOT EXISTS(SELECT FROM message_events WHERE id=$1) AND NOT EXISTS(SELECT FROM billing_usage_finalized WHERE account_id=$2 AND message_id=$3) AND NOT EXISTS(SELECT FROM billing_usage_outbox WHERE account_id=$2 AND message_id=$3)",
        &[&callback.event_id, &db.account, &message],
    ).await.unwrap().get(0);
    assert!(
        absent,
        "cancelled callback/finalization/outbox writes all rolled back"
    );
    let state: String = db
        .owner()
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
    let mut db = Db::for_store().await;
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
    db.owner()
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
    let mut db = Db::for_store().await;
    db.submit(1).await;
    db.submit(1).await;
    let mut second =
        crate::test_database::RuntimeConnection::connect(&db.current.as_ref().unwrap().config)
            .await;
    let (a, b) = tokio::join!(claim_one(&mut db.client), claim_one(&mut second.client));
    let winner = match (a.unwrap(), b.unwrap()) {
        (ClaimResult::Claim(c), ClaimResult::Idle) | (ClaimResult::Idle, ClaimResult::Claim(c)) => {
            c
        }
        _ => panic!("customer had simultaneous leases"),
    };
    assert_eq!(
        finish(
            &mut db.client,
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
    db.owner().batch_execute("UPDATE billing_usage_outbox SET first_attempt_at=clock_timestamp()-interval '24 hours' WHERE attempts=0").await.unwrap();
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Review
    ));
    let state = db
        .owner()
        .query_one(
            "SELECT error_class FROM billing_usage_outbox WHERE state='review'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    assert_eq!(state, "window");
    second.finish().await;
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn closed_original_period_is_reviewed_without_moving_usage_to_current_month() {
    let mut db = Db::for_store().await;
    let at=db.owner().query_one("SELECT (extract(epoch FROM (date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')-interval '1 day') AT TIME ZONE 'UTC')*1000)::bigint",&[]).await.unwrap().get::<_,i64>(0);
    db.submit_at(1, Some(at)).await;
    assert!(matches!(
        claim_one(&mut db.client).await.unwrap(),
        ClaimResult::Review
    ));
    let row=db.owner().query_one("SELECT b.period_start::text,o.error_class FROM billing_usage_bindings b JOIN billing_usage_outbox o USING(account_id,message_id)",&[]).await.unwrap();
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
    let mut db = Db::for_store().await;
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
    db.owner()
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
    let mut db = Db::for_store().await;
    db.submit(1).await;
    let ClaimResult::Claim(claim) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    let identifier = claim.request.identifier.clone();
    finish(
        &mut db.client,
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

async fn probe_connection(schema: &str) -> Client {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL").unwrap();
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    client
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn completion_waiting_for_outbox_lock_cannot_acknowledge_after_lease_expiry() {
    let mut db = Db::for_store().await;
    db.submit(1).await;
    let ClaimResult::Claim(claim) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    // Connection setup is outside the deliberately short lease window; the
    // observed row-lock wait below must still start while that lease is live.
    let mut holder =
        crate::test_database::RuntimeConnection::connect(&db.current.as_ref().unwrap().config)
            .await;
    let mut worker =
        crate::test_database::RuntimeConnection::connect(&db.current.as_ref().unwrap().config)
            .await;
    let pid: i32 = worker
        .client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    db.owner()
        .batch_execute(
            "UPDATE billing_usage_outbox SET lease_until=clock_timestamp()+interval '5 seconds'",
        )
        .await
        .unwrap();
    let lock = holder.client.transaction().await.unwrap();
    lock.query_one("SELECT 1 FROM billing_usage_outbox FOR UPDATE", &[])
        .await
        .unwrap();
    let identifier = claim.request.identifier.clone();
    let lease = claim.lease;
    let task = tokio::spawn(async move {
        let result = finish(
            &mut worker.client,
            claim,
            MeterResponse::Acknowledged {
                identifier,
                livemode: false,
            },
        )
        .await
        .unwrap();
        worker.finish().await;
        result
    });
    let mut blocked = false;
    for _ in 0..250 {
        blocked = lock
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)",
                &[&pid],
            )
            .await
            .unwrap()
            .get(0);
        if blocked {
            break;
        }
        assert!(
            !task.is_finished(),
            "worker must actually wait on the held outbox row"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(blocked, "completion reached the row-lock boundary");
    assert!(
        lock.query_one(
            "SELECT lease_until>clock_timestamp() FROM billing_usage_outbox",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0),
        "lease was live when completion blocked"
    );
    lock.query_one("SELECT pg_sleep(GREATEST(extract(epoch FROM (lease_until-clock_timestamp())),0)::double precision+0.1) FROM billing_usage_outbox",&[]).await.unwrap();
    lock.commit().await.unwrap();
    holder.finish().await;
    assert_eq!(task.await.unwrap(), WorkResult::Stale);
    let row = db
        .owner()
        .query_one(
            "SELECT state,acknowledged_at IS NULL,lease_id FROM billing_usage_outbox",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "leased");
    assert!(row.get::<_, bool>(1));
    assert_eq!(row.get::<_, Uuid>(2), lease);
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider calls"]
async fn concurrent_last_tenant_mapping_erasure_removes_the_shared_error_receipt() {
    let mut db = Db::new().await;
    let other = Uuid::new_v4();
    db.client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&other])
        .await
        .unwrap();
    db.client.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_SyntheticConcurrent')",&[&other]).await.unwrap();
    db.client.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name,active) VALUES($1,1,'cus_SyntheticConcurrent','mtr_Synthetic','synthetic_execution',true)",&[&other]).await.unwrap();
    let event = MeterErrorObservation {
        event_id: "evt_SyntheticConcurrent".into(),
        meter_id: "mtr_Synthetic".into(),
        body_digest: [9; 32],
        validation_start: 1000,
        validation_end: 2000,
    };
    record_meter_error(&mut db.client, db.account, 1, &event)
        .await
        .unwrap();
    record_meter_error(&mut db.client, other, 1, &event)
        .await
        .unwrap();
    let worker = probe_connection(&db.schema).await;
    let pid: i32 = worker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let first = db.client.transaction().await.unwrap();
    first
        .execute(
            "DELETE FROM billing_usage_meter_errors WHERE account_id=$1",
            &[&db.account],
        )
        .await
        .unwrap();
    let second = tokio::spawn(async move {
        worker
            .execute(
                "DELETE FROM billing_usage_meter_errors WHERE account_id=$1",
                &[&other],
            )
            .await
            .unwrap()
    });
    let mut reached = false;
    for _ in 0..250 {
        reached = second.is_finished()
            || first
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)",
                    &[&pid],
                )
                .await
                .unwrap()
                .get::<_, bool>(0);
        if reached {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        reached,
        "second tenant erasure reached cleanup or completed before first commit"
    );
    first.commit().await.unwrap();
    assert_eq!(second.await.unwrap(), 1);
    assert_eq!(
        db.client
            .query_one(
                "SELECT count(*)::bigint FROM billing_usage_meter_errors",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
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

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn completion_stalled_during_the_write_rolls_back_expired_acknowledgement() {
    let mut db = Db::for_store().await;
    db.submit(1).await;
    let ClaimResult::Claim(claim) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    let lease = claim.lease;
    let identifier = claim.request.identifier.clone();
    let mut proxy = crate::tests::test_wire::Proxy::with_update_completion_gate(
        &db.current.as_ref().unwrap().config,
    )
    .await;
    db.owner()
        .batch_execute(
            "UPDATE billing_usage_outbox SET lease_until=clock_timestamp()+interval '5 seconds'",
        )
        .await
        .unwrap();
    let result = finish(
        &mut proxy.client,
        claim,
        MeterResponse::Acknowledged {
            identifier,
            livemode: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        proxy.completed_update_count(),
        1,
        "completion reached an actual UPDATE 1 before the six-second response hold"
    );
    proxy.finish_gated().await;
    crate::hosted_runtime_identity::require(&db.client)
        .await
        .unwrap();
    assert_eq!(result, WorkResult::Stale);
    let row = db
        .owner()
        .query_one(
            "SELECT state,acknowledged_at IS NULL,lease_id FROM billing_usage_outbox",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "leased");
    assert!(row.get::<_, bool>(1));
    assert_eq!(row.get::<_, Uuid>(2), lease);
    db.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; isolated schema, no provider or radio calls"]
async fn report_timestamp_preserves_the_original_utc_second_without_rounding_forward() {
    let mut db = Db::for_store().await;
    let (message, _) = db.submit(1).await;
    let row = db.owner().query_one(
        "SELECT l.created_at,b.report_at,o.identifier FROM usage_ledger l JOIN billing_usage_bindings b USING(account_id,message_id) JOIN billing_usage_outbox o USING(account_id,message_id) WHERE l.account_id=$1 AND l.message_id=$2 AND l.entry_kind='reserve'",
        &[&db.account, &message],
    ).await.unwrap();
    let created_at: std::time::SystemTime = row.get(0);
    assert_eq!(created_at, row.get::<_, std::time::SystemTime>(1));
    let identifier: String = row.get(2);
    let expected = i64::try_from(
        created_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let ClaimResult::Claim(claim) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing claim")
    };
    assert_eq!(claim.message, message);
    assert_eq!(claim.request.identifier, identifier);
    assert_eq!(
        claim.request.timestamp, expected,
        "provider timestamp must never move the reservation into a later UTC second"
    );
    db.close().await;
}

/// Explicit synthetic worker input, separate from genuine Store capture above.
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; real public schema, synthetic worker input only"]
async fn worker_projection_preserves_fractional_reservation_second() {
    let mut db = Db::for_store().await;
    let (message, original, identifier) = db.seed_fractional_worker_input().await;
    let duration = original.duration_since(std::time::UNIX_EPOCH).unwrap();
    assert_eq!(duration.subsec_micros(), 900_000);
    let expected = i64::try_from(duration.as_secs()).unwrap();
    let ClaimResult::Claim(claim) = claim_one(&mut db.client).await.unwrap() else {
        panic!("missing synthetic worker projection claim")
    };
    assert_eq!(claim.account, db.account);
    assert_eq!(claim.message, message);
    assert_eq!(claim.request.identifier, identifier);
    assert_eq!(claim.request.idempotency_key, identifier);
    assert_eq!(claim.request.customer_id, db.customer);
    assert_eq!(claim.request.event_name, "synthetic_execution");
    assert_eq!(claim.request.units, 1);
    assert_eq!(claim.request.timestamp, expected);
    assert_ne!(claim.request.timestamp, expected + 1);
    let retained = db.owner().query_one(
        "SELECT l.created_at,b.report_at,o.identifier,b.policy_version FROM usage_ledger l JOIN billing_usage_bindings b USING(account_id,message_id) JOIN billing_usage_outbox o USING(account_id,message_id) WHERE l.account_id=$1 AND l.message_id=$2 AND l.entry_kind='reserve'",
        &[&db.account, &message],
    ).await.unwrap();
    assert_eq!(retained.get::<_, std::time::SystemTime>(0), original);
    assert_eq!(retained.get::<_, std::time::SystemTime>(1), original);
    assert_eq!(retained.get::<_, String>(2), identifier);
    assert_eq!(retained.get::<_, i64>(3), 1);
    db.close().await;
}
