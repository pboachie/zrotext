use super::*;
use std::env;
use tokio_postgres::NoTls;
use zrotext_delivery_store::{DeliveryStore, NewMessage, StoreError};

const BODY: &[u8] = br#"{"id":"evt_fixture1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_fixture1","object":"subscription","customer":"cus_fixture1","status":"active"}}}"#;

// Random per-process webhook secrets keep reusable signing keys out of source
// while staying stable for every signature a test process derives.
fn random_webhook_secret() -> String {
    let hex = rand::random::<[u8; 16]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("whsec_{hex}")
}

fn secret() -> &'static str {
    static SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SECRET.get_or_init(random_webhook_secret)
}

fn body_v1() -> String {
    let mut mac = HmacSha256::new_from_slice(secret().as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(BODY);
    signed_header(1_750_000_000, mac)
        .split_once(",v1=")
        .unwrap()
        .1
        .to_owned()
}

fn header() -> String {
    format!("t=1750000000,v0=0000,v1={}", body_v1())
}

#[test]
fn api_key_gate_accepts_only_test_secret_or_restricted_keys() {
    assert!(is_test_api_key("sk_test_fixture123456"));
    assert!(is_test_api_key("rk_test_fixture123456"));
    for key in [
        "sk_live_fixture123456",
        "rk_live_fixture123456",
        "pk_test_fixture123456",
        "rk_test_",
        "sk_test_",
    ] {
        assert!(!is_test_api_key(key));
    }
}

#[test]
fn quota_configuration_fingerprint_tracks_effective_mapping() {
    let prices = vec!["price_a".into(), "price_b".into()];
    let plans = vec![
        TestQuotaPlan {
            price_id: "price_a".into(),
            outbound_limit: 100,
            device_limit: Some(2),
        },
        TestQuotaPlan {
            price_id: "price_b".into(),
            outbound_limit: 200,
            device_limit: Some(4),
        },
    ];
    let original = quota_configuration_fingerprint(&prices, &plans, "rk_test_fixture123456");
    let mut reordered_prices = prices.clone();
    reordered_prices.reverse();
    let mut reordered_plans = plans.clone();
    reordered_plans.reverse();
    assert_eq!(
        original,
        quota_configuration_fingerprint(
            &reordered_prices,
            &reordered_plans,
            "rk_test_fixture123456"
        )
    );
    reordered_plans[0].outbound_limit += 1;
    assert_ne!(
        original,
        quota_configuration_fingerprint(&prices, &reordered_plans, "rk_test_fixture123456")
    );
    assert_ne!(
        original,
        quota_configuration_fingerprint(&prices, &plans, "rk_test_fixture654321")
    );
}

fn signed_header(timestamp: i64, mac: HmacSha256) -> String {
    let digest = mac.finalize().into_bytes();
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("t={timestamp},v1={hex}")
}

#[test]
fn stripe_signature_uses_exact_raw_body_and_recency() {
    let event = verify_event(BODY, &header(), secret(), 1_750_000_000).unwrap();
    assert_eq!(event.event_id, "evt_fixture1");
    assert_eq!(event.customer_id.as_deref(), Some("cus_fixture1"));
    assert_eq!(event.subscription_id.as_deref(), Some("sub_fixture1"));
    assert!(verify_event(BODY, &header(), secret(), 1_750_000_300).is_ok());
    assert!(verify_event(BODY, &header(), secret(), 1_750_000_301).is_err());
    assert!(verify_event(BODY, &header(), secret(), 1_749_999_699).is_err());
    assert!(
        verify_event(
            BODY,
            &format!("t=1750000000,v0={}", body_v1()),
            secret(),
            1_750_000_000
        )
        .is_err()
    );
    assert!(
        verify_event(
            BODY,
            &format!("t=1750000000,t=1750000000,v1={}", body_v1()),
            secret(),
            1_750_000_000
        )
        .is_err()
    );
    let mut edited = BODY.to_vec();
    edited.push(b' ');
    assert!(verify_event(&edited, &header(), secret(), 1_750_000_000).is_err());
    assert!(verify_event(BODY, &header(), &random_webhook_secret(), 1_750_000_000).is_err());
}

#[test]
fn test_mode_rejects_live_event_even_with_valid_signature() {
    let mut body = BODY.to_vec();
    let at = body
        .windows(5)
        .position(|window| window == b"false")
        .unwrap();
    body.splice(at..at + 5, b"true".iter().copied());
    let mut mac = HmacSha256::new_from_slice(secret().as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(&body);
    let signed = signed_header(1_750_000_000, mac);
    assert!(matches!(
        verify_event(&body, &signed, secret(), 1_750_000_000),
        Err(BillingError::InvalidEvent)
    ));
}

#[test]
fn test_mode_checkout_completion_accepts_stripe_test_id_shape() {
    let body = br#"{"id":"evt_checkout1","object":"event","livemode":false,"type":"checkout.session.completed","data":{"object":{"id":"cs_test_fixture1","customer":"cus_fixture1","subscription":"sub_fixture1"}}}"#;
    let mut mac = HmacSha256::new_from_slice(secret().as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(body);
    let signature = signed_header(1_750_000_000, mac);
    let event = verify_event(body, &signature, secret(), 1_750_000_000).unwrap();
    assert_eq!(event.object_id.as_deref(), Some("cs_test_fixture1"));
    assert_eq!(event.customer_id.as_deref(), Some("cus_fixture1"));
}

#[test]
fn test_quota_plan_config_is_explicit_and_bounded() {
    let prices = vec!["price_basic1".to_owned(), "price_plus1".to_owned()];
    assert_eq!(
        parse_test_quota_plans("price_basic1:2,price_plus1:10", &prices).unwrap(),
        vec![
            TestQuotaPlan {
                price_id: prices[0].clone(),
                outbound_limit: 2,
                device_limit: None,
            },
            TestQuotaPlan {
                price_id: prices[1].clone(),
                outbound_limit: 10,
                device_limit: None,
            },
        ]
    );
    assert_eq!(
        parse_test_quota_plans("price_basic1:2:1,price_plus1:10:3", &prices)
            .unwrap()
            .iter()
            .map(|plan| plan.device_limit)
            .collect::<Vec<_>>(),
        vec![Some(1), Some(3)]
    );
    for invalid in [
        "price_unknown1:2",
        "price_basic1:0",
        "price_basic1:-1",
        "price_basic1:2,price_basic1:3",
        "price_basic1:18446744073709551616",
        "price_basic1:x",
        "price_basic1:2:-1",
        "price_basic1:2:1:4",
        "price_basic1:2:1,price_plus1:10",
    ] {
        assert!(parse_test_quota_plans(invalid, &prices).is_err());
    }
}

fn signed_test_event(body: &[u8]) -> VerifiedEvent {
    let mut mac = HmacSha256::new_from_slice(secret().as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(body);
    let signature = signed_header(1_750_000_000, mac);
    verify_event(body, &signature, secret(), 1_750_000_000).unwrap()
}

#[test]
fn verified_test_payment_risk_shapes_are_strict() {
    let refund = signed_test_event(br#"{"id":"evt_riskrefund1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_risk1","object":"refund","charge":"ch_risk1"}}}"#);
    assert_eq!(refund.risk_charge_id.as_deref(), Some("ch_risk1"));
    let unsupported = signed_test_event(br#"{"id":"evt_riskrefund2","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_risk2","object":"refund","charge":null}}}"#);
    assert!(unsupported.risk_charge_id.is_none());
    assert!(unsupported.unsupported);
    assert!(unsupported.risk_review_required);
    let payment_intent_only = signed_test_event(br#"{"id":"evt_riskrefundpi1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_riskpi1","object":"refund","charge":null,"payment_intent":"pi_riskpi1"}}}"#);
    assert_eq!(
        payment_intent_only.risk_payment_intent_id.as_deref(),
        Some("pi_riskpi1")
    );
    assert!(!payment_intent_only.unsupported);
    let zero = br#"{"id":"evt_riskzero1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"ch_risk1","object":"charge","customer":"cus_risk1","amount_refunded":0}}}"#;
    let mut mac = HmacSha256::new_from_slice(secret().as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(zero);
    let signature = signed_header(1_750_000_000, mac);
    let zero_event = verify_event(zero, &signature, secret(), 1_750_000_000).unwrap();
    assert!(zero_event.unsupported);
    assert!(zero_event.risk_review_required);
    assert_eq!(zero_event.risk_charge_id.as_deref(), Some("ch_risk1"));
}

#[test]
fn noncard_py_charges_carry_verified_risk_and_block_metered_sends() {
    // Non-card payment methods (SEPA Direct Debit, ACH, Bacs) surface as
    // PaymentIntent-scoped `py_` charges on refunds and disputes.
    let refund = signed_test_event(br#"{"id":"evt_riskpyrefund1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_pyrefund1","object":"refund","charge":"py_risk1"}}}"#);
    assert_eq!(refund.risk_charge_id.as_deref(), Some("py_risk1"));
    let refunded = signed_test_event(br#"{"id":"evt_riskpyrefunded1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"py_risk1","object":"charge","customer":"cus_risk1","amount_refunded":50}}}"#);
    assert_eq!(refunded.risk_charge_id.as_deref(), Some("py_risk1"));
    assert_eq!(refunded.customer_id.as_deref(), Some("cus_risk1"));
    let dispute = signed_test_event(br#"{"id":"evt_riskpydispute1","object":"event","livemode":false,"type":"charge.dispute.created","data":{"object":{"id":"du_pydispute1","object":"dispute","charge":"py_risk1"}}}"#);
    assert_eq!(dispute.risk_charge_id.as_deref(), Some("py_risk1"));
    for unknown in ["ca_risk1", "ch_", "py_", "py_risk-1", "ch_risk1 py_risk1"] {
        let body = format!(
            "{{\"id\":\"evt_riskunknown1\",\"object\":\"event\",\"livemode\":false,\"type\":\"refund.created\",\"data\":{{\"object\":{{\"id\":\"re_unknown1\",\"object\":\"refund\",\"charge\":\"{unknown}\"}}}}}}"
        );
        let event = signed_test_event(body.as_bytes());
        assert!(event.risk_charge_id.is_none());
        assert!(event.unsupported, "charge {unknown} must not act");
        assert!(event.risk_review_required);
    }
}

#[test]
fn signed_but_unexpected_shapes_are_recorded_as_unsupported() {
    // A payment-mode Checkout completion has no subscription pointer.
    let payment_mode = signed_test_event(br#"{"id":"evt_unsupported1","object":"event","livemode":false,"type":"checkout.session.completed","data":{"object":{"id":"cs_test_unsupported1","customer":"cus_unsupported1","subscription":null}}}"#);
    assert!(payment_mode.unsupported);
    assert!(payment_mode.object_id.is_none());
    assert!(payment_mode.customer_id.is_none());
    let missing_failure_time = signed_test_event(br#"{"id":"evt_unsupportedtime1","object":"event","livemode":false,"type":"invoice.payment_failed","data":{"object":{"id":"in_unsupportedtime1","customer":"cus_unsupported1","subscription":"sub_unsupported1"}}}"#);
    assert!(missing_failure_time.unsupported);
    assert!(missing_failure_time.subscription_id.is_none());
    assert!(missing_failure_time.customer_id.is_none());
    // Envelope problems on a correctly signed body stay hard failures.
    let live = br#"{"id":"evt_unsupported2","object":"event","livemode":true,"type":"checkout.session.completed","data":{"object":{"id":"cs_test_unsupported2","customer":"cus_unsupported1","subscription":"sub_unsupported1"}}}"#;
    let mut mac = HmacSha256::new_from_slice(secret().as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(live);
    let signature = signed_header(1_750_000_000, mac);
    assert!(matches!(
        verify_event(live, &signature, secret(), 1_750_000_000),
        Err(BillingError::InvalidEvent)
    ));
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn failed_payment_and_late_paid_event_follow_current_test_subscription() {
    let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_lifecycle_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
        include_str!("../../../../deploy/compose/migrations/019_line_activation_contract.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'billing fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    bind_customer(&mut db, account, "cus_lifecycle1")
        .await
        .unwrap();
    let prices = vec!["price_lifecycle1".into(), "price_lifecycle2".into()];
    let plans = parse_test_quota_plans("price_lifecycle1:2,price_lifecycle2:1", &prices).unwrap();
    let active = worker::parse_subscription(br#"{"id":"sub_lifecycle1","object":"subscription","livemode":false,"customer":"cus_lifecycle1","status":"active","items":{"object":"list","has_more":false,"data":[{"price":{"id":"price_lifecycle1"}}]}}"#).unwrap();
    let past_due = worker::parse_subscription(br#"{"id":"sub_lifecycle1","object":"subscription","livemode":false,"customer":"cus_lifecycle1","status":"past_due","latest_invoice":"in_lifecyclefailed1","items":{"object":"list","has_more":false,"data":[{"price":{"id":"price_lifecycle1"}}]}}"#).unwrap();
    let downgraded = worker::parse_subscription(br#"{"id":"sub_lifecycle1","object":"subscription","livemode":false,"customer":"cus_lifecycle1","status":"active","items":{"object":"list","has_more":false,"data":[{"price":{"id":"price_lifecycle2"}}]}}"#).unwrap();
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + 3_600_000;
    let send = |id: Uuid, key: &'static str| NewMessage {
        account_id: account,
        device_id: device,
        client_message_id: id,
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"synthetic billing fixture",
        expires_at_ms: expiry,
    };

    // These are locally signed virtual Stripe TEST fixtures. Only the
    // subscription snapshots, as parsed from a provider response, project
    // entitlements; invoice event payloads merely dirty the queue.
    let paid = signed_test_event(br#"{"id":"evt_lifecyclepaid1","object":"event","livemode":false,"type":"invoice.paid","data":{"object":{"id":"in_lifecyclepaid1","customer":"cus_lifecycle1","subscription":"sub_lifecycle1"}}}"#);
    assert_eq!(ingest(&mut db, &paid).await.unwrap(), IngestResult::Queued);
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 1)
        .await
        .unwrap();
    let first = Uuid::new_v4();
    assert!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(first, "first"))
            .await
            .unwrap()
            .created
    );
    // Model an active provider read before the later failed attempt.
    db.execute(
            "UPDATE billing_subscriptions SET last_non_past_due_at=now()-interval '2 minutes' WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap();

    // The nested subscription pointer covers the newer Invoice shape.
    let failure_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 60;
    let failed_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_lifecyclefailed1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": failure_created,
            "data": {"object": {"id": "in_lifecyclefailed1", "customer": "cus_lifecycle1", "parent": {"subscription_details": {"subscription": "sub_lifecycle1"}}}}
        })).unwrap();
    let failed = signed_test_event(&failed_body);
    assert_eq!(
        ingest(&mut db, &failed).await.unwrap(),
        IngestResult::Queued
    );
    assert_eq!(
        ingest(&mut db, &failed).await.unwrap(),
        IngestResult::Duplicate
    );
    let generation: i64 = db.query_one(
            "SELECT dirty_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
    assert_eq!(
        generation, 2,
        "duplicate delivery must not queue a second read"
    );
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(Uuid::new_v4(), "pending-failure"))
            .await,
        Err(StoreError::QuotaNotConfigured)
    ));
    reconcile_snapshot_with_quotas(&mut db, account, &past_due, &prices, &plans, 2)
        .await
        .unwrap();
    let grace_start: i64 = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
    assert_eq!(grace_start, failure_created);
    let grace_message = Uuid::new_v4();
    assert!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(grace_message, "within-grace"))
            .await
            .unwrap()
            .created
    );
    assert!(
        DeliveryStore::new(&mut db)
            .cancel(account, grace_message)
            .await
            .unwrap()
    );
    // This contender begins before expiry but waits on the account lock
    // until afterward. Admission must use the post-wait DB clock.
    db.execute(
            "UPDATE billing_subscriptions SET payment_grace_started_at=clock_timestamp()-interval '7 days'+interval '1 second' WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap();
    let (mut locker, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let lock = locker.transaction().await.unwrap();
    lock.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
        &[&account],
    )
    .await
    .unwrap();
    let contender_url = scoped_url.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let contender = tokio::spawn(async move {
        let (mut client, connection) = tokio_postgres::connect(&contender_url, NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        started_tx.send(()).unwrap();
        DeliveryStore::new(&mut client)
            .accept_metered(NewMessage {
                account_id: account,
                device_id: device,
                client_message_id: Uuid::new_v4(),
                idempotency_key: "after-lock-expiry",
                recipient_e164: "+15551234567",
                synthetic_payload: b"synthetic billing fixture",
                expires_at_ms: expiry,
            })
            .await
    });
    started_rx.await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
    lock.commit().await.unwrap();
    assert!(matches!(
        contender.await.unwrap(),
        Err(StoreError::QuotaExceeded)
    ));
    db.execute(
            "UPDATE billing_subscriptions SET payment_grace_started_at=transaction_timestamp()-interval '7 days 1 second' WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap();
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(Uuid::new_v4(), "after-grace"))
            .await,
        Err(StoreError::QuotaExceeded)
    ));
    assert!(
        !DeliveryStore::new(&mut db)
            .accept_metered(send(first, "first"))
            .await
            .unwrap()
            .created
    );

    // A delayed paid webhook must read the current past_due state. Its
    // old invoice payload cannot restore an allowance by itself.
    let late_paid = signed_test_event(br#"{"id":"evt_lifecyclelate1","object":"event","livemode":false,"type":"invoice.paid","data":{"object":{"id":"in_lifecycleold1","customer":"cus_lifecycle1","subscription":"sub_lifecycle1"}}}"#);
    assert_eq!(
        ingest(&mut db, &late_paid).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &past_due, &prices, &plans, 3)
        .await
        .unwrap();
    let row = db.query_one(
            "SELECT p.limit_units,u.reserved_units,u.refunded_units FROM usage_quota_policies p JOIN usage_periods u USING(account_id,metric) WHERE p.account_id=$1",
            &[&account],
        ).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (0, 2, 1)
    );
    let replayed_start: i64 = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
    assert!(replayed_start < grace_start);

    let recovered = signed_test_event(br#"{"id":"evt_lifecyclerecovered1","object":"event","livemode":false,"type":"invoice.paid","data":{"object":{"id":"in_lifecyclerecovered1","customer":"cus_lifecycle1","subscription":"sub_lifecycle1"}}}"#);
    assert_eq!(
        ingest(&mut db, &recovered).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 4)
        .await
        .unwrap();
    let cleared: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
    assert!(cleared);
    assert!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(Uuid::new_v4(), "recovered"))
            .await
            .unwrap()
            .created
    );

    // A delayed failure for the recovered invoice reads the current
    // active subscription and cannot reopen its old grace interval.
    let stale_failure_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_lifecyclestalefailed1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": failure_created,
            "data": {"object": {"id": "in_lifecyclefailed1", "customer": "cus_lifecycle1", "subscription": "sub_lifecycle1"}}
        })).unwrap();
    let stale_failure = signed_test_event(&stale_failure_body);
    assert_eq!(
        ingest(&mut db, &stale_failure).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 5)
        .await
        .unwrap();
    let cleared: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
    assert!(cleared);

    // The old failure is for a different invoice and cannot grant grace
    // when the current provider snapshot becomes past_due again.
    let next_past_due = SubscriptionSnapshot {
        latest_invoice_id: Some("in_lifecyclenew1".into()),
        ..past_due.clone()
    };
    let next_update = signed_test_event(br#"{"id":"evt_lifecyclenextdue1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_lifecycle1","customer":"cus_lifecycle1"}}}"#);
    assert_eq!(
        ingest(&mut db, &next_update).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &next_past_due, &prices, &plans, 6)
        .await
        .unwrap();
    let no_grace: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap().get(0);
    assert!(no_grace);
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(Uuid::new_v4(), "unmatched-invoice"))
            .await,
        Err(StoreError::QuotaExceeded)
    ));

    // A matching signed failure starts a new interval. A future provider
    // timestamp is capped at database receipt time before persistence.
    let future_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 3_600;
    let next_failure_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_lifecyclenewfailed1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": future_created,
            "data": {"object": {"id": "in_lifecyclenew1", "customer": "cus_lifecycle1", "subscription": "sub_lifecycle1"}}
        })).unwrap();
    let next_failure = signed_test_event(&next_failure_body);
    assert_eq!(
        ingest(&mut db, &next_failure).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &next_past_due, &prices, &plans, 7)
        .await
        .unwrap();
    let clock = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint,extract(epoch FROM transaction_timestamp())::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_lifecycle1'",
            &[],
        ).await.unwrap();
    let new_start: i64 = clock.get(0);
    let observed_now: i64 = clock.get(1);
    assert!((observed_now - 5..=observed_now).contains(&new_start));
    assert!(new_start < future_created);
    let new_limit: i64 = db.query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        ).await.unwrap().get(0);
    assert_eq!(new_limit, 2);
    let next_recovered = signed_test_event(br#"{"id":"evt_lifecyclenewpaid1","object":"event","livemode":false,"type":"invoice.paid","data":{"object":{"id":"in_lifecyclenew1","customer":"cus_lifecycle1","subscription":"sub_lifecycle1"}}}"#);
    assert_eq!(
        ingest(&mut db, &next_recovered).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 8)
        .await
        .unwrap();

    let downgrade = signed_test_event(br#"{"id":"evt_lifecycledowngrade1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_lifecycle1","customer":"cus_lifecycle1"}}}"#);
    assert_eq!(
        ingest(&mut db, &downgrade).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &downgraded, &prices, &plans, 9)
        .await
        .unwrap();
    let row = db.query_one(
            "SELECT p.limit_units,u.limit_units,u.reserved_units,u.refunded_units FROM usage_quota_policies p JOIN usage_periods u USING(account_id,metric) WHERE p.account_id=$1",
            &[&account],
        ).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
            row.get::<_, i64>(3)
        ),
        (1, 1, 3, 1),
        "downgrade preserves existing reservations"
    );
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(Uuid::new_v4(), "after-downgrade"))
            .await,
        Err(StoreError::QuotaExceeded)
    ));
    let audit = db.query(
            "SELECT reconciliation_generation,previous_limit_units,limit_units,reason FROM billing_quota_audit WHERE account_id=$1 ORDER BY id",
            &[&account],
        ).await.unwrap();
    assert_eq!(
        audit.len(),
        6,
        "duplicate and late events must not add policy changes"
    );
    assert_eq!(
        (
            audit[1].get::<_, i64>(0),
            audit[1].get::<_, i64>(2),
            audit[1].get::<_, String>(3)
        ),
        (3, 0, "inactive".into())
    );
    assert_eq!(
        (
            audit[5].get::<_, i64>(0),
            audit[5].get::<_, i64>(1),
            audit[5].get::<_, i64>(2)
        ),
        (9, 2, 1)
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn delayed_failure_keeps_last_active_boundary_and_recovery_excludes_old_cycle() {
    let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_delayed_grace_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let account = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    bind_customer(&mut db, account, "cus_delayedgrace1")
        .await
        .unwrap();
    let prices = vec!["price_delayedgrace1".into()];
    let plans = parse_test_quota_plans("price_delayedgrace1:3", &prices).unwrap();
    let active = SubscriptionSnapshot {
        subscription_id: "sub_delayedgrace1".into(),
        customer_id: "cus_delayedgrace1".into(),
        status: "active".into(),
        price_id: Some("price_delayedgrace1".into()),
        latest_invoice_id: None,
    };
    let past_due = SubscriptionSnapshot {
        status: "past_due".into(),
        latest_invoice_id: Some("in_delayedgrace1".into()),
        ..active.clone()
    };
    let update = |id: &str| {
        signed_test_event(
            &serde_json::to_vec(&serde_json::json!({
                "id": id,
                "object": "event",
                "livemode": false,
                "type": "customer.subscription.updated",
                "data": {"object": {"id": "sub_delayedgrace1", "customer": "cus_delayedgrace1"}}
            }))
            .unwrap(),
        )
    };
    assert_eq!(
        ingest(&mut db, &update("evt_delayedactive1"))
            .await
            .unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 1)
        .await
        .unwrap();
    db.execute(
            "UPDATE billing_subscriptions SET last_non_past_due_at=now()-interval '1 hour' WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap();
    assert_eq!(
        ingest(&mut db, &update("evt_delayedpastdue1"))
            .await
            .unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &past_due, &prices, &plans, 2)
        .await
        .unwrap();
    let no_anchor: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap().get(0);
    assert!(no_anchor);

    // Delivery arrives more than five minutes after its signed creation.
    // Repeated past_due reads must not move the last active boundary.
    let delayed_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 600;
    let failed_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayedfailure1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": delayed_created,
            "data": {"object": {"id": "in_delayedgrace1", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
    let delayed = signed_test_event(&failed_body);
    assert_eq!(
        ingest(&mut db, &delayed).await.unwrap(),
        IngestResult::Queued
    );
    assert_eq!(
        ingest(&mut db, &delayed).await.unwrap(),
        IngestResult::Duplicate
    );
    reconcile_snapshot_with_quotas(&mut db, account, &past_due, &prices, &plans, 3)
        .await
        .unwrap();
    let started: i64 = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap().get(0);
    assert_eq!(started, delayed_created);
    let limit: i64 = db.query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        ).await.unwrap().get(0);
    assert_eq!(limit, 3);

    // A newer current invoice invalidates the old binding immediately.
    // A matching failure can rebind without extending the first deadline.
    let swapped = SubscriptionSnapshot {
        latest_invoice_id: Some("in_delayedgrace2".into()),
        ..past_due.clone()
    };
    assert_eq!(
        ingest(&mut db, &update("evt_delayedswap1")).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 4)
        .await
        .unwrap();
    let mismatch = db.query_one(
            "SELECT payment_grace_invoice_id,latest_invoice_id,extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap();
    assert_eq!(mismatch.get::<_, String>(0), "in_delayedgrace1");
    assert_eq!(mismatch.get::<_, String>(1), "in_delayedgrace2");
    assert_eq!(mismatch.get::<_, i64>(2), started);
    let blocked_limit: i64 = db.query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        ).await.unwrap().get(0);
    assert_eq!(blocked_limit, 0);
    let swapped_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 30;
    let swapped_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayedswapfailed1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": swapped_created,
            "data": {"object": {"id": "in_delayedgrace2", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
    assert_eq!(
        ingest(&mut db, &signed_test_event(&swapped_body))
            .await
            .unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 5)
        .await
        .unwrap();
    let rebound = db.query_one(
            "SELECT payment_grace_invoice_id,extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap();
    assert_eq!(rebound.get::<_, String>(0), "in_delayedgrace2");
    assert_eq!(rebound.get::<_, i64>(1), started);
    let restored_limit: i64 = db.query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message'",
            &[&account],
        ).await.unwrap().get(0);
    assert_eq!(restored_limit, 3);

    // This failure was created and received before recovery, but lies
    // within five minutes. It cannot be reused after recovery.
    let near_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 60;
    let near_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayednear1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": near_created,
            "data": {"object": {"id": "in_delayedgrace2", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
    assert_eq!(
        ingest(&mut db, &signed_test_event(&near_body))
            .await
            .unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 6)
        .await
        .unwrap();

    assert_eq!(
        ingest(&mut db, &update("evt_delayedrecovery1"))
            .await
            .unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 7)
        .await
        .unwrap();
    let stale_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayedstale1",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": near_created,
            "data": {"object": {"id": "in_delayedgrace2", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
    assert_eq!(
        ingest(&mut db, &signed_test_event(&stale_body))
            .await
            .unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 8)
        .await
        .unwrap();
    db.execute(
            "UPDATE billing_subscriptions SET last_non_past_due_at=now()-interval '2 seconds' WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap();
    assert_eq!(
        ingest(&mut db, &update("evt_delayedpastdue2"))
            .await
            .unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 9)
        .await
        .unwrap();
    let no_replay: bool = db.query_one(
            "SELECT payment_grace_started_at IS NULL FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap().get(0);
    assert!(
        no_replay,
        "the prior cycle's failed invoice must not restart grace"
    );

    let fresh_created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let fresh_body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_delayedfailure2",
            "object": "event",
            "livemode": false,
            "type": "invoice.payment_failed",
            "created": fresh_created,
            "data": {"object": {"id": "in_delayedgrace2", "customer": "cus_delayedgrace1", "subscription": "sub_delayedgrace1"}}
        })).unwrap();
    assert_eq!(
        ingest(&mut db, &signed_test_event(&fresh_body))
            .await
            .unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(&mut db, account, &swapped, &prices, &plans, 10)
        .await
        .unwrap();
    let restarted: i64 = db.query_one(
            "SELECT extract(epoch FROM payment_grace_started_at)::bigint FROM billing_subscriptions WHERE stripe_subscription_id='sub_delayedgrace1'",
            &[],
        ).await.unwrap().get(0);
    assert!(restarted > started);
    assert!((fresh_created - 1..=fresh_created).contains(&restarted));
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn reconciliation_locks_customer_before_queue_row_without_blocking_account_fk() {
    let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_lock_order_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut blocker_db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let (mut reconcile_db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let (probe, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        probe.batch_execute(sql).await.unwrap();
    }
    let account = Uuid::new_v4();
    probe
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    probe.execute(
            "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_lockorder1')",
            &[&account],
        ).await.unwrap();
    probe.execute(
            "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES('sub_lockorder1',$1,'cus_lockorder1')",
            &[&account],
        ).await.unwrap();
    let reconcile_pid: i32 = reconcile_db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = blocker_db.transaction().await.unwrap();
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    blocker
        .query_one(
            "SELECT account_id FROM billing_customers WHERE account_id=$1 FOR UPDATE",
            &[&account],
        )
        .await
        .unwrap();

    let task = tokio::spawn(async move {
        reconcile_snapshot(
            &mut reconcile_db,
            account,
            &SubscriptionSnapshot {
                subscription_id: "sub_lockorder1".into(),
                customer_id: "cus_lockorder1".into(),
                status: "active".into(),
                price_id: None,
                latest_invoice_id: None,
            },
            &[],
            1,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blockers: Vec<i32> = setup
                .query_one("SELECT pg_blocking_pids($1)", &[&reconcile_pid])
                .await
                .unwrap()
                .get(0);
            if blockers.contains(&blocker_pid) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reconciliation must wait on the held customer row");

    // Both probes succeed only if reconciliation holds neither the old
    // account UPDATE lock nor the queue row before the customer lock.
    probe
        .query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR KEY SHARE NOWAIT",
            &[&account],
        )
        .await
        .unwrap();
    probe.query_one(
            "SELECT stripe_subscription_id FROM billing_reconciliations WHERE stripe_subscription_id='sub_lockorder1' FOR UPDATE NOWAIT",
            &[],
        ).await.unwrap();
    // The recovery boundary must be recorded after the blocked lock is
    // released. transaction_timestamp() would still be the earlier start
    // of the reconciliation transaction here.
    let released_after: f64 = probe
        .query_one(
            "SELECT extract(epoch FROM clock_timestamp())::double precision",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    blocker.commit().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .expect("reconciliation should resume")
        .unwrap()
        .unwrap();
    let processed: i64 = probe.query_one(
            "SELECT processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_lockorder1'",
            &[],
        ).await.unwrap().get(0);
    assert_eq!(processed, 1);
    let status: String = probe.query_one(
            "SELECT stripe_status FROM billing_subscriptions WHERE stripe_subscription_id='sub_lockorder1'",
            &[],
        ).await.unwrap().get(0);
    assert_eq!(status, "active");
    let recovery_boundary: f64 = probe
            .query_one(
                "SELECT extract(epoch FROM last_non_past_due_at)::double precision FROM billing_subscriptions WHERE stripe_subscription_id='sub_lockorder1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    assert!(recovery_boundary >= released_after);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn verified_refund_and_dispute_hold_active_metered_accounts() {
    let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_hold_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1),($2)", &[&a, &b])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'phone a'),($3,$4,'phone b')",
        &[&device_a, &a, &device_b, &b],
    )
    .await
    .unwrap();
    bind_customer(&mut db, a, "cus_holda1").await.unwrap();
    bind_customer(&mut db, b, "cus_holdb1").await.unwrap();
    let prices = vec!["price_hold1".to_owned()];
    let plans = parse_test_quota_plans("price_hold1:10", &prices).unwrap();
    for (event_id, account, customer, subscription) in [
        ("evt_holda1", a, "cus_holda1", "sub_holda1"),
        ("evt_holdb1", b, "cus_holdb1", "sub_holdb1"),
    ] {
        let event = signed_test_event(
                format!("{{\"id\":\"{event_id}\",\"object\":\"event\",\"livemode\":false,\"type\":\"customer.subscription.updated\",\"data\":{{\"object\":{{\"id\":\"{subscription}\",\"customer\":\"{customer}\"}}}}}}")
                    .as_bytes(),
            );
        assert_eq!(ingest(&mut db, &event).await.unwrap(), IngestResult::Queued);
        reconcile_snapshot_with_quotas(
            &mut db,
            account,
            &SubscriptionSnapshot {
                subscription_id: subscription.into(),
                customer_id: customer.into(),
                status: "active".into(),
                price_id: Some("price_hold1".into()),
                latest_invoice_id: None,
            },
            &prices,
            &plans,
            1,
        )
        .await
        .unwrap();
    }
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + 3_600_000;
    let send = |account_id: Uuid, device_id: Uuid, id: Uuid, key: &'static str| NewMessage {
        account_id,
        device_id,
        client_message_id: id,
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"synthetic test",
        expires_at_ms: expiry,
    };
    let first = Uuid::new_v4();
    assert!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(a, device_a, first, "a-first"))
            .await
            .unwrap()
            .created
    );

    let refund = signed_test_event(br#"{"id":"evt_refund1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"ch_refund1","object":"charge","customer":"cus_holda1","amount_refunded":50}}}"#);
    assert_eq!(refund.risk_charge_id.as_deref(), Some("ch_refund1"));
    assert_eq!(
        ingest(&mut db, &refund).await.unwrap(),
        IngestResult::Queued
    );
    assert_eq!(
        ingest(&mut db, &refund).await.unwrap(),
        IngestResult::Duplicate
    );
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(a, device_a, Uuid::new_v4(), "a-pending"))
            .await,
        Err(StoreError::PaymentHold)
    ));
    // The other tenant still has its own active allowance.
    assert!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(b, device_b, Uuid::new_v4(), "b-before"))
            .await
            .unwrap()
            .created
    );
    assert!(matches!(
        risk::apply_hold(
            &mut db,
            "evt_refund1",
            "ch_refund1",
            None,
            "cus_holdb1",
            "sub_holdb1",
            "refund"
        )
        .await,
        Err(BillingError::TenantConflict)
    ));
    risk::bind_charge_customer(&mut db, "evt_refund1", "cus_holda1")
        .await
        .unwrap();
    risk::apply_hold(
        &mut db,
        "evt_refund1",
        "ch_refund1",
        None,
        "cus_holda1",
        "sub_holda1",
        "refund",
    )
    .await
    .unwrap();
    risk::apply_hold(
        &mut db,
        "evt_refund1",
        "ch_refund1",
        None,
        "cus_holda1",
        "sub_holda1",
        "refund",
    )
    .await
    .unwrap();
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM billing_payment_holds WHERE account_id=$1",
            &[&a],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    let active_a = SubscriptionSnapshot {
        subscription_id: "sub_holda1".into(),
        customer_id: "cus_holda1".into(),
        status: "active".into(),
        price_id: Some("price_hold1".into()),
        latest_invoice_id: None,
    };
    reconcile_snapshot_with_quotas(&mut db, a, &active_a, &prices, &plans, 2)
        .await
        .unwrap();
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(a, device_a, Uuid::new_v4(), "a-still-held"))
            .await,
        Err(StoreError::PaymentHold)
    ));
    assert!(
        !DeliveryStore::new(&mut db)
            .accept_metered(send(a, device_a, first, "a-first"))
            .await
            .unwrap()
            .created
    );

    // A closed dispute received first cannot clear or suppress a later
    // creation event. The creation event carries no customer until the
    // current Charge is fetched and bound by the worker.
    let closed = signed_test_event(br#"{"id":"evt_disputeclosed1","object":"event","livemode":false,"type":"charge.dispute.closed","data":{"object":{"id":"du_holdb1","object":"dispute","charge":"ch_dispute1"}}}"#);
    assert_eq!(
        ingest(&mut db, &closed).await.unwrap(),
        IngestResult::Ignored
    );
    let dispute = signed_test_event(br#"{"id":"evt_dispute1","object":"event","livemode":false,"type":"charge.dispute.created","data":{"object":{"id":"du_holdb1","object":"dispute","charge":"ch_dispute1"}}}"#);
    assert_eq!(
        ingest(&mut db, &dispute).await.unwrap(),
        IngestResult::Unbound
    );
    assert!(
        risk::bind_charge_customer(&mut db, "evt_dispute1", "cus_holdb1")
            .await
            .unwrap()
    );
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(b, device_b, Uuid::new_v4(), "b-pending"))
            .await,
        Err(StoreError::PaymentHold)
    ));
    risk::apply_hold(
        &mut db,
        "evt_dispute1",
        "ch_dispute1",
        None,
        "cus_holdb1",
        "sub_holdb1",
        "dispute",
    )
    .await
    .unwrap();
    let count: i64 = db
        .query_one("SELECT count(*) FROM billing_payment_holds", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2);
    let late = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&late])
        .await
        .unwrap();
    let unbound = signed_test_event(br#"{"id":"evt_disputelate1","object":"event","livemode":false,"type":"charge.dispute.created","data":{"object":{"id":"du_late1","object":"dispute","charge":"ch_late1"}}}"#);
    assert_eq!(
        ingest(&mut db, &unbound).await.unwrap(),
        IngestResult::Unbound
    );
    assert!(
        !risk::bind_charge_customer(&mut db, "evt_disputelate1", "cus_late1")
            .await
            .unwrap()
    );
    db.execute(
            "UPDATE billing_risk_events SET state='needs_review',failed_attempts=10 WHERE stripe_event_id='evt_disputelate1'",
            &[],
        )
        .await
        .unwrap();
    bind_customer(&mut db, late, "cus_late1").await.unwrap();
    let late_risk = db
            .query_one(
                "SELECT r.account_id,r.state,e.stripe_customer_id FROM billing_risk_events r JOIN billing_events e USING(stripe_event_id) WHERE r.stripe_event_id='evt_disputelate1'",
                &[],
            )
            .await
            .unwrap();
    assert_eq!(late_risk.get::<_, Option<Uuid>>(0), Some(late));
    assert_eq!(late_risk.get::<_, String>(1), "needs_review");
    assert_eq!(
        late_risk.get::<_, Option<String>>(2).as_deref(),
        Some("cus_late1")
    );
    let live = br#"{"id":"evt_live1","object":"event","livemode":true,"type":"charge.refunded","data":{"object":{"id":"ch_live1","object":"charge","customer":"cus_holda1","amount_refunded":50}}}"#;
    let mut mac = HmacSha256::new_from_slice(secret().as_bytes()).unwrap();
    mac.update(b"1750000000.");
    mac.update(live);
    let signed = signed_header(1_750_000_000, mac);
    assert!(matches!(
        verify_event(live, &signed, secret(), 1_750_000_000),
        Err(BillingError::InvalidEvent)
    ));
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn noncard_py_refunds_and_disputes_hold_metered_accounts() {
    let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = format!("billing_py_hold_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'py charge fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    bind_customer(&mut db, account, "cus_pyhold1")
        .await
        .unwrap();
    let prices = vec!["price_pyhold1".to_owned()];
    let plans = parse_test_quota_plans("price_pyhold1:5", &prices).unwrap();
    let update = signed_test_event(br#"{"id":"evt_pyholdsub1","object":"event","livemode":false,"type":"customer.subscription.updated","data":{"object":{"id":"sub_pyhold1","customer":"cus_pyhold1"}}}"#);
    assert_eq!(
        ingest(&mut db, &update).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot_with_quotas(
        &mut db,
        account,
        &SubscriptionSnapshot {
            subscription_id: "sub_pyhold1".into(),
            customer_id: "cus_pyhold1".into(),
            status: "active".into(),
            price_id: Some("price_pyhold1".into()),
            latest_invoice_id: None,
        },
        &prices,
        &plans,
        1,
    )
    .await
    .unwrap();
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + 3_600_000;
    let send = |id: Uuid, key: &'static str| NewMessage {
        account_id: account,
        device_id: device,
        client_message_id: id,
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"synthetic billing fixture",
        expires_at_ms: expiry,
    };
    assert!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(Uuid::new_v4(), "py-before"))
            .await
            .unwrap()
            .created
    );

    // Non-card payment methods (SEPA Direct Debit, ACH, Bacs) surface as
    // PaymentIntent-scoped py_ charges on refunds and disputes.
    let refunded = signed_test_event(br#"{"id":"evt_pyrefund1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"py_refund1","object":"charge","customer":"cus_pyhold1","amount_refunded":50}}}"#);
    assert_eq!(refunded.risk_charge_id.as_deref(), Some("py_refund1"));
    assert_eq!(
        ingest(&mut db, &refunded).await.unwrap(),
        IngestResult::Queued
    );
    assert!(matches!(
        DeliveryStore::new(&mut db)
            .accept_metered(send(Uuid::new_v4(), "py-pending"))
            .await,
        Err(StoreError::PaymentHold)
    ));
    risk::bind_charge_customer(&mut db, "evt_pyrefund1", "cus_pyhold1")
        .await
        .unwrap();
    risk::apply_hold(
        &mut db,
        "evt_pyrefund1",
        "py_refund1",
        None,
        "cus_pyhold1",
        "sub_pyhold1",
        "refund",
    )
    .await
    .unwrap();
    let held_charge: String = db
            .query_one(
                "SELECT stripe_charge_id FROM billing_payment_holds WHERE stripe_event_id='evt_pyrefund1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(held_charge, "py_refund1");

    // Stripe permits Refund.charge=null. The signed PaymentIntent pointer
    // enters the risk queue; a separately validated Charges Read supplies
    // the Charge used for tenant and invoice attribution.
    let pi_refund = signed_test_event(br#"{"id":"evt_pyrefundpi1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_pyrefundpi1","object":"refund","charge":null,"payment_intent":"pi_pyrefundpi1"}}}"#);
    assert_eq!(
        ingest(&mut db, &pi_refund).await.unwrap(),
        IngestResult::Unbound
    );
    let risk = db
            .query_one(
                "SELECT stripe_charge_id,stripe_payment_intent_id,state FROM billing_risk_events WHERE stripe_event_id='evt_pyrefundpi1'",
                &[],
            )
            .await
            .unwrap();
    assert!(risk.get::<_, Option<String>>(0).is_none());
    assert_eq!(
        risk.get::<_, Option<String>>(1).as_deref(),
        Some("pi_pyrefundpi1")
    );
    assert_eq!(risk.get::<_, String>(2), "queued");
    assert!(
        risk::bind_charge_customer(&mut db, "evt_pyrefundpi1", "cus_pyhold1")
            .await
            .unwrap()
    );
    assert!(matches!(
        risk::apply_hold(
            &mut db,
            "evt_pyrefundpi1",
            "py_wrong1",
            Some("pi_wrong1"),
            "cus_pyhold1",
            "sub_pyhold1",
            "refund"
        )
        .await,
        Err(BillingError::TenantConflict)
    ));
    risk::apply_hold(
        &mut db,
        "evt_pyrefundpi1",
        "py_refundpi1",
        Some("pi_pyrefundpi1"),
        "cus_pyhold1",
        "sub_pyhold1",
        "refund",
    )
    .await
    .unwrap();
    let resolved: String = db
            .query_one(
                "SELECT stripe_charge_id FROM billing_payment_holds WHERE stripe_event_id='evt_pyrefundpi1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(resolved, "py_refundpi1");

    let refund_created = signed_test_event(br#"{"id":"evt_pyrefundre1","object":"event","livemode":false,"type":"refund.created","data":{"object":{"id":"re_pyrefund1","object":"refund","charge":"py_refund2"}}}"#);
    assert_eq!(refund_created.risk_charge_id.as_deref(), Some("py_refund2"));
    assert_eq!(
        ingest(&mut db, &refund_created).await.unwrap(),
        IngestResult::Unbound
    );
    let dispute = signed_test_event(br#"{"id":"evt_pydispute1","object":"event","livemode":false,"type":"charge.dispute.created","data":{"object":{"id":"du_pydispute1","object":"dispute","charge":"py_dispute1"}}}"#);
    assert_eq!(dispute.risk_charge_id.as_deref(), Some("py_dispute1"));
    assert_eq!(
        ingest(&mut db, &dispute).await.unwrap(),
        IngestResult::Unbound
    );
    assert!(
        risk::bind_charge_customer(&mut db, "evt_pydispute1", "cus_pyhold1")
            .await
            .unwrap()
    );
    risk::apply_hold(
        &mut db,
        "evt_pydispute1",
        "py_dispute1",
        None,
        "cus_pyhold1",
        "sub_pyhold1",
        "dispute",
    )
    .await
    .unwrap();
    let holds: i64 = db
        .query_one("SELECT count(*) FROM billing_payment_holds", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(holds, 3);

    // A correctly signed event this build does not act on — a payment-mode
    // Checkout completion — is acknowledged and durably recorded, and a
    // redelivery is a duplicate rather than a conflict.
    let payment_mode = signed_test_event(br#"{"id":"evt_pyunsupported1","object":"event","livemode":false,"type":"checkout.session.completed","data":{"object":{"id":"cs_test_pyunsupported1","customer":"cus_pyhold1","subscription":null}}}"#);
    assert_eq!(
        ingest(&mut db, &payment_mode).await.unwrap(),
        IngestResult::Unsupported
    );
    let row = db
            .query_one(
                "SELECT disposition,stripe_customer_id,stripe_subscription_id FROM billing_events WHERE stripe_event_id='evt_pyunsupported1'",
                &[],
            )
            .await
            .unwrap();
    assert_eq!(row.get::<_, String>(0), "unsupported");
    assert!(row.get::<_, Option<String>>(1).is_none());
    assert!(row.get::<_, Option<String>>(2).is_none());
    assert_eq!(
        ingest(&mut db, &payment_mode).await.unwrap(),
        IngestResult::Duplicate
    );
    let queued: i64 = db
            .query_one(
                "SELECT count(*) FROM billing_reconciliations WHERE stripe_subscription_id='sub_pyhold1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(queued, 1);
    let before_generation: i64 = db
            .query_one(
                "SELECT dirty_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_pyhold1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    let unsupported_failure = signed_test_event(br#"{"id":"evt_pyunsupportedtime1","object":"event","livemode":false,"type":"invoice.payment_failed","data":{"object":{"id":"in_pyunsupported1","customer":"cus_pyhold1","subscription":"sub_pyhold1"}}}"#);
    assert_eq!(
        ingest(&mut db, &unsupported_failure).await.unwrap(),
        IngestResult::Unsupported
    );
    let after_generation: i64 = db
            .query_one(
                "SELECT dirty_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_pyhold1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(after_generation, before_generation);
    let review = signed_test_event(br#"{"id":"evt_pyreview1","object":"event","livemode":false,"type":"charge.refunded","data":{"object":{"id":"py_review1","object":"charge","customer":"cus_pyhold1","amount_refunded":0}}}"#);
    assert_eq!(
        ingest(&mut db, &review).await.unwrap(),
        IngestResult::Unsupported
    );
    let review_row = db
            .query_one(
                "SELECT state,account_id FROM billing_risk_events WHERE stripe_event_id='evt_pyreview1'",
                &[],
            )
            .await
            .unwrap();
    assert_eq!(review_row.get::<_, String>(0), "needs_review");
    assert_eq!(review_row.get::<_, Option<Uuid>>(1), Some(account));
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn reconciled_test_subscription_controls_metered_reservations() {
    let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_quota_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let account = Uuid::new_v4();
    let other = Uuid::new_v4();
    let device = Uuid::new_v4();
    db.execute(
        "INSERT INTO accounts(id) VALUES($1),($2)",
        &[&account, &other],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'test phone')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',99)", &[&account]).await.unwrap();
    bind_customer(&mut db, account, "cus_entitlement1")
        .await
        .unwrap();
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
        + 3_600_000;
    let first = Uuid::new_v4();
    let send = |message_id: Uuid, key: &'static str| NewMessage {
        account_id: account,
        client_message_id: message_id,
        device_id: device,
        idempotency_key: key,
        recipient_e164: "+15551234567",
        synthetic_payload: b"synthetic test",
        expires_at_ms: expiry,
    };
    {
        let mut store = DeliveryStore::new(&mut db);
        assert!(matches!(
            store.accept_metered(send(first, "first")).await,
            Err(StoreError::QuotaNotConfigured)
        ));
    }
    let event = VerifiedEvent {
        event_id: "evt_entitlement1".into(),
        event_type: "customer.subscription.updated".into(),
        object_id: Some("sub_entitlement1".into()),
        customer_id: Some("cus_entitlement1".into()),
        subscription_id: Some("sub_entitlement1".into()),
        risk_charge_id: None,
        risk_payment_intent_id: None,
        payment_failed_at_unix: None,
        body_sha256: [1; 32],
        unsupported: false,
        risk_review_required: false,
    };
    assert_eq!(ingest(&mut db, &event).await.unwrap(), IngestResult::Queued);
    let plans = parse_test_quota_plans(
        "price_basic1:2,price_plus1:1",
        &["price_basic1".into(), "price_plus1".into()],
    )
    .unwrap();
    let prices = vec!["price_basic1".into(), "price_plus1".into()];
    let active = SubscriptionSnapshot {
        subscription_id: "sub_entitlement1".into(),
        customer_id: "cus_entitlement1".into(),
        status: "active".into(),
        price_id: Some("price_basic1".into()),
        latest_invoice_id: None,
    };
    reconcile_snapshot_with_quotas(&mut db, other, &active, &prices, &plans, 1)
        .await
        .expect_err("wrong tenant");
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 1)
        .await
        .unwrap();
    assert_eq!(
        ingest(&mut db, &event).await.unwrap(),
        IngestResult::Duplicate
    );
    let second = Uuid::new_v4();
    {
        let mut store = DeliveryStore::new(&mut db);
        assert!(
            store
                .accept_metered(send(first, "first"))
                .await
                .unwrap()
                .created
        );
        assert!(
            !store
                .accept_metered(send(first, "first"))
                .await
                .unwrap()
                .created
        );
        assert!(
            store
                .accept_metered(send(second, "second"))
                .await
                .unwrap()
                .created
        );
        assert!(matches!(
            store.accept_metered(send(Uuid::new_v4(), "third")).await,
            Err(StoreError::QuotaExceeded)
        ));
    }
    reset_test_quotas_on_start(&scoped_url, true, false, Some(&[1; 32]))
        .await
        .unwrap();
    {
        let mut store = DeliveryStore::new(&mut db);
        assert!(matches!(
            store
                .accept_metered(send(Uuid::new_v4(), "after-restart"))
                .await,
            Err(StoreError::QuotaNotConfigured)
        ));
    }
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 2)
        .await
        .unwrap();
    let mut next = event.clone();
    next.event_id = "evt_entitlement2".into();
    assert_eq!(ingest(&mut db, &next).await.unwrap(), IngestResult::Queued);
    {
        let mut store = DeliveryStore::new(&mut db);
        assert!(matches!(
            store.accept_metered(send(Uuid::new_v4(), "pending")).await,
            Err(StoreError::QuotaNotConfigured)
        ));
    }
    let downgraded = SubscriptionSnapshot {
        price_id: Some("price_plus1".into()),
        ..active.clone()
    };
    reconcile_snapshot_with_quotas(&mut db, account, &downgraded, &prices, &plans, 3)
        .await
        .unwrap();
    let row = db.query_one("SELECT p.limit_units,p.source,u.limit_units,u.reserved_units FROM usage_quota_policies p JOIN usage_periods u USING(account_id,metric) WHERE p.account_id=$1", &[&account]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, String>(1),
            row.get::<_, i64>(2),
            row.get::<_, i64>(3)
        ),
        (1, "stripe_test".into(), 1, 2)
    );
    next.event_id = "evt_entitlement3".into();
    assert_eq!(ingest(&mut db, &next).await.unwrap(), IngestResult::Queued);
    let canceled = SubscriptionSnapshot {
        status: "canceled".into(),
        ..downgraded.clone()
    };
    reconcile_snapshot_with_quotas(&mut db, account, &canceled, &prices, &plans, 4)
        .await
        .unwrap();
    reconcile_snapshot_with_quotas(&mut db, account, &active, &prices, &plans, 3)
        .await
        .unwrap();
    let row = db
        .query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    {
        let mut store = DeliveryStore::new(&mut db);
        assert!(matches!(
            store
                .accept_metered(send(Uuid::new_v4(), "after-cancel"))
                .await,
            Err(StoreError::QuotaExceeded)
        ));
        assert!(
            !store
                .accept_metered(send(first, "first"))
                .await
                .unwrap()
                .created
        );
    }
    let mut generation = 4;
    for (event_id, snapshot, expected_limit) in [
        (
            "evt_entitlement4",
            SubscriptionSnapshot {
                status: "past_due".into(),
                ..active.clone()
            },
            0_i64,
        ),
        (
            "evt_entitlement5",
            SubscriptionSnapshot {
                price_id: Some("price_unknown1".into()),
                ..active.clone()
            },
            0_i64,
        ),
        ("evt_entitlement6", active.clone(), 2_i64),
    ] {
        next.event_id = event_id.into();
        assert_eq!(ingest(&mut db, &next).await.unwrap(), IngestResult::Queued);
        generation += 1;
        reconcile_snapshot_with_quotas(&mut db, account, &snapshot, &prices, &plans, generation)
            .await
            .unwrap();
        let row = db
            .query_one(
                "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), expected_limit);
    }
    let mut another = event.clone();
    another.event_id = "evt_entitlement7".into();
    another.subscription_id = Some("sub_entitlement2".into());
    another.object_id = another.subscription_id.clone();
    assert_eq!(
        ingest(&mut db, &another).await.unwrap(),
        IngestResult::Queued
    );
    let second_active = SubscriptionSnapshot {
        subscription_id: "sub_entitlement2".into(),
        ..active.clone()
    };
    reconcile_snapshot_with_quotas(&mut db, account, &second_active, &prices, &plans, 1)
        .await
        .unwrap();
    let row = db
        .query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, i64>(0),
        0,
        "two active subscriptions are ambiguous"
    );
    another.event_id = "evt_entitlement8".into();
    assert_eq!(
        ingest(&mut db, &another).await.unwrap(),
        IngestResult::Queued
    );
    let second_canceled = SubscriptionSnapshot {
        status: "canceled".into(),
        ..second_active
    };
    reconcile_snapshot_with_quotas(&mut db, account, &second_canceled, &prices, &plans, 2)
        .await
        .unwrap();
    let row = db
        .query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 2);
    let row = db
        .query_one(
            "SELECT count(*) FROM billing_quota_audit WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 8);
    db.execute("UPDATE billing_reconciliations SET dirty_generation=dirty_generation+1,state='needs_review',failed_attempts=10,last_failure_class='authorization' WHERE stripe_subscription_id='sub_entitlement1'", &[]).await.unwrap();
    db.execute("UPDATE billing_reconciliations SET state='needs_review',failed_attempts=10,last_failure_class='authorization' WHERE stripe_subscription_id='sub_entitlement2'", &[]).await.unwrap();
    db.execute("INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) VALUES('evt_ConfigRisk1','charge.refunded',$1,$2,'queued')", &[&account, &vec![0u8; 32]]).await.unwrap();
    db.execute("INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,state,account_id,failed_attempts,last_failure_class) VALUES('evt_ConfigRisk1','ch_ConfigRisk1','refund','needs_review',$1,10,'authorization')", &[&account]).await.unwrap();
    let before = db.query("SELECT stripe_subscription_id,dirty_generation,processed_generation FROM billing_reconciliations WHERE account_id=$1 ORDER BY stripe_subscription_id", &[&account]).await.unwrap();
    reset_test_quotas_on_start(&scoped_url, true, false, Some(&[1; 32]))
        .await
        .unwrap();
    let unchanged = db.query("SELECT stripe_subscription_id,dirty_generation,processed_generation FROM billing_reconciliations WHERE account_id=$1 ORDER BY stripe_subscription_id", &[&account]).await.unwrap();
    for (old, new) in before.iter().zip(&unchanged) {
        assert_eq!(old.get::<_, i64>(1), new.get::<_, i64>(1));
        assert_eq!(old.get::<_, i64>(2), new.get::<_, i64>(2));
    }
    let preserved: i64 = db
        .query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(preserved, 2, "same config must preserve active quota");
    let review = db.query_one("SELECT state,failed_attempts,last_failure_class FROM billing_reconciliations WHERE stripe_subscription_id='sub_entitlement2'", &[]).await.unwrap();
    assert_eq!(review.get::<_, String>(0), "needs_review");
    assert_eq!(review.get::<_, i32>(1), 10);
    assert_eq!(
        review.get::<_, Option<String>>(2).as_deref(),
        Some("authorization")
    );
    let unchanged_risk = db.query_one("SELECT state,failed_attempts FROM billing_risk_events WHERE stripe_event_id='evt_ConfigRisk1'", &[]).await.unwrap();
    assert_eq!(unchanged_risk.get::<_, String>(0), "needs_review");
    assert_eq!(unchanged_risk.get::<_, i32>(1), 10);
    reset_test_quotas_on_start(&scoped_url, true, false, Some(&[2; 32]))
        .await
        .unwrap();
    let changed = db.query("SELECT stripe_subscription_id,dirty_generation,processed_generation FROM billing_reconciliations WHERE account_id=$1 ORDER BY stripe_subscription_id", &[&account]).await.unwrap();
    for (old, new) in before.iter().zip(&changed) {
        let subscription: String = new.get(0);
        let expected = old.get::<_, i64>(1) + i64::from(subscription != "sub_entitlement2");
        assert_eq!(
            new.get::<_, i64>(1),
            expected,
            "terminal subscription must not be redirtied"
        );
    }
    let terminal_review = db.query_one("SELECT state,failed_attempts,last_failure_class FROM billing_reconciliations WHERE stripe_subscription_id='sub_entitlement2'", &[]).await.unwrap();
    assert_eq!(terminal_review.get::<_, String>(0), "needs_review");
    assert_eq!(terminal_review.get::<_, i32>(1), 10);
    assert_eq!(
        terminal_review.get::<_, Option<String>>(2).as_deref(),
        Some("authorization")
    );
    let risk_review = db.query_one("SELECT state,failed_attempts,last_failure_class FROM billing_risk_events WHERE stripe_event_id='evt_ConfigRisk1'", &[]).await.unwrap();
    assert_eq!(risk_review.get::<_, String>(0), "queued");
    assert_eq!(risk_review.get::<_, i32>(1), 0);
    assert_eq!(risk_review.get::<_, Option<String>>(2), None);
    let active_review = db.query_one("SELECT state,failed_attempts,last_failure_class FROM billing_reconciliations WHERE stripe_subscription_id='sub_entitlement1'", &[]).await.unwrap();
    assert_eq!(active_review.get::<_, String>(0), "queued");
    assert_eq!(active_review.get::<_, i32>(1), 0);
    assert_eq!(active_review.get::<_, Option<String>>(2), None);
    // A rolling upgrade can temporarily have entitlement migration 010
    // without risk migration 011. Disabling billing still clears its old
    // allowance, while enabling billing requires both schemas.
    db.batch_execute(
        "DROP TABLE billing_risk_review_actions,billing_payment_holds,billing_risk_events",
    )
    .await
    .unwrap();
    assert!(
        reset_test_quotas_on_start(&scoped_url, true, false, Some(&[1; 32]))
            .await
            .is_err()
    );
    reset_test_quotas_on_start(&scoped_url, false, false, None)
        .await
        .unwrap();
    let limit: i64 = db
        .query_one(
            "SELECT limit_units FROM usage_quota_policies WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(limit, 0);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn dedupe_tenant_binding_and_stale_reconciliation() {
    let base_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let database_url = format!("{base_url}?options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1),($2)", &[&a, &b])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_fixture2')",
        &[&b],
    )
    .await
    .unwrap();
    let event = verify_event(BODY, &header(), secret(), 1_750_000_000).unwrap();
    assert_eq!(
        ingest(&mut db, &event).await.unwrap(),
        IngestResult::Unbound
    );
    bind_customer(&mut db, a, "cus_fixture1").await.unwrap();
    assert!(matches!(
        bind_customer(&mut db, b, "cus_fixture1").await,
        Err(BillingError::TenantConflict)
    ));
    assert_eq!(
        ingest(&mut db, &event).await.unwrap(),
        IngestResult::Duplicate
    );
    let mut changed_body = event.clone();
    changed_body.body_sha256[0] ^= 1;
    assert!(matches!(
        ingest(&mut db, &changed_body).await,
        Err(BillingError::EventConflict)
    ));
    let row = db.query_one("SELECT dirty_generation,processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (1, 0));
    assert_eq!(
        worker::claim(&mut db).await.unwrap(),
        Some((a, "sub_fixture1".into(), "cus_fixture1".into(), 1))
    );
    assert!(worker::claim(&mut db).await.unwrap().is_none());
    let mut newer = event.clone();
    newer.event_id = "evt_fixture2".into();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(16));
    let mut replays = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let event = newer.clone();
        let url = database_url.clone();
        let barrier = barrier.clone();
        replays.spawn(async move {
            let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            barrier.wait().await;
            ingest(&mut client, &event).await.unwrap()
        });
    }
    let mut queued = 0;
    let mut duplicate = 0;
    while let Some(result) = replays.join_next().await {
        match result.unwrap() {
            IngestResult::Queued => queued += 1,
            IngestResult::Duplicate => duplicate += 1,
            other => panic!("unexpected replay disposition: {other:?}"),
        }
    }
    assert_eq!((queued, duplicate), (1, 15));
    let active = SubscriptionSnapshot {
        subscription_id: "sub_fixture1".into(),
        customer_id: "cus_fixture1".into(),
        status: "active".into(),
        price_id: Some("price_known1".into()),
        latest_invoice_id: None,
    };
    let prices = vec!["price_known1".into()];
    reconcile_snapshot(&mut db, a, &active, &prices, 1)
        .await
        .unwrap();
    let row = db.query_one("SELECT dirty_generation,processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (2, 1));
    let canceled = SubscriptionSnapshot {
        status: "canceled".into(),
        ..active.clone()
    };
    reconcile_snapshot(&mut db, a, &canceled, &prices, 2)
        .await
        .unwrap();
    reconcile_snapshot(&mut db, a, &active, &prices, 1)
        .await
        .unwrap();
    let row = db.query_one("SELECT stripe_status,recognized_price FROM billing_subscriptions WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "canceled");
    assert!(row.get::<_, bool>(1));
    let mut late_old_event = event.clone();
    late_old_event.event_id = "evt_fixture4".into();
    assert_eq!(
        ingest(&mut db, &late_old_event).await.unwrap(),
        IngestResult::Queued
    );
    reconcile_snapshot(&mut db, a, &canceled, &prices, 3)
        .await
        .unwrap();
    let row = db.query_one("SELECT stripe_status FROM billing_subscriptions WHERE stripe_subscription_id='sub_fixture1'", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "canceled");
    let wrong_customer = SubscriptionSnapshot {
        customer_id: "cus_fixture2".into(),
        ..active
    };
    assert!(matches!(
        reconcile_snapshot(&mut db, a, &wrong_customer, &prices, 2).await,
        Err(BillingError::TenantConflict)
    ));
    let mut cross = newer;
    cross.event_id = "evt_fixture3".into();
    cross.customer_id = Some("cus_fixture2".into());
    assert_eq!(
        ingest(&mut db, &cross).await.unwrap(),
        IngestResult::Conflict
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "reads two real Stripe test events and reconciles their current subscriptions; run explicitly"]
async fn real_stripe_test_events_reconcile_current_state() {
    let database_url = env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set a disposable PostgreSQL test database URL");
    let secret_key = env::var("ZT_STRIPE_TEST_SECRET_KEY")
        .expect("set a Stripe test secret in the process environment");
    let price_id = env::var("ZT_STRIPE_TEST_PRICE_ID").expect("set the test price ID");
    let cases = [
        (
            env::var("ZT_STRIPE_TEST_PAID_EVENT_ID").expect("set the paid event ID"),
            env::var("ZT_STRIPE_TEST_PAID_CUSTOMER_ID").expect("set the paid test customer ID"),
            "invoice.paid",
            "canceled",
        ),
        (
            env::var("ZT_STRIPE_TEST_FAILED_EVENT_ID").expect("set the failed event ID"),
            env::var("ZT_STRIPE_TEST_FAILED_CUSTOMER_ID").expect("set the failed test customer ID"),
            "invoice.payment_failed",
            "incomplete_expired",
        ),
    ];
    assert!(is_test_api_key(&secret_key));
    valid_id(&price_id, "price_").unwrap();
    let (setup, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_real_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if database_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{database_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&scoped_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let http = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let signing_secret = &random_webhook_secret();
    for (event_id, customer_id, expected_type, _) in &cases {
        valid_id(event_id, "evt_").unwrap();
        valid_id(customer_id, "cus_").unwrap();
        let account_id = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
            .await
            .unwrap();
        bind_customer(&mut db, account_id, customer_id)
            .await
            .unwrap();
        let response = http
            .get(format!("https://api.stripe.com/v1/events/{event_id}"))
            .bearer_auth(&secret_key)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let body = response.bytes().await.unwrap();
        assert!(body.len() <= MAX_BODY);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes()).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(&body);
        let signature = signed_header(timestamp, mac);
        let event = verify_event(&body, &signature, signing_secret, timestamp).unwrap();
        assert_eq!(event.event_type, *expected_type);
        assert_eq!(event.customer_id.as_deref(), Some(customer_id.as_str()));
        assert!(event.subscription_id.is_some());
        assert_eq!(ingest(&mut db, &event).await.unwrap(), IngestResult::Queued);
        assert_eq!(
            ingest(&mut db, &event).await.unwrap(),
            IngestResult::Duplicate
        );
    }
    let worker = worker::StripeTestWorker::new(secret_key, vec![price_id]).unwrap();
    assert!(worker.reconcile_one(&scoped_url).await.unwrap());
    assert!(worker.reconcile_one(&scoped_url).await.unwrap());
    assert!(!worker.reconcile_one(&scoped_url).await.unwrap());
    for (_, customer_id, _, expected_status) in &cases {
        let row = db
                .query_one(
                    "SELECT stripe_status,recognized_price FROM billing_subscriptions WHERE stripe_customer_id=$1",
                    &[customer_id],
                )
                .await
                .unwrap();
        assert_eq!(row.get::<_, String>(0), *expected_status);
        assert!(row.get::<_, bool>(1));
    }
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
