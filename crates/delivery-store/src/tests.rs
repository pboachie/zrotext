use super::*;

// Keep the admission fixtures on the complete, reviewed schema. SQL is
// embedded at build time so tests never execute files discovered at runtime.
const TEST_MIGRATIONS: [(&str, &str); 39] = [
    (
        "001_foundation.sql",
        include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
    ),
    (
        "002_auth.sql",
        include_str!("../../../deploy/compose/migrations/002_auth.sql"),
    ),
    (
        "003_delivery.sql",
        include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
    ),
    (
        "004_enrollment.sql",
        include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
    ),
    (
        "005_verification_outbox.sql",
        include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
    ),
    (
        "006_usage_metering.sql",
        include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
    ),
    (
        "007_inbound_webhook_foundation.sql",
        include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
    ),
    (
        "008_stripe_billing_foundation.sql",
        include_str!("../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
    ),
    (
        "009_webhook_manual_replay.sql",
        include_str!("../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
    ),
    (
        "010_billing_test_entitlement.sql",
        include_str!("../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
    ),
    (
        "011_billing_payment_holds.sql",
        include_str!("../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
    ),
    (
        "012_auth_abuse_limits.sql",
        include_str!("../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
    ),
    (
        "013_owner_mfa.sql",
        include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
    ),
    (
        "014_owner_mfa_failure_budget.sql",
        include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
    ),
    (
        "015_webhook_kek_commitments.sql",
        include_str!("../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
    ),
    (
        "016_auth_abuse_atomic.sql",
        include_str!("../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ),
    (
        "017_billing_device_caps.sql",
        include_str!("../../../deploy/compose/migrations/017_billing_device_caps.sql"),
    ),
    (
        "018_sealed_inbound_identity.sql",
        include_str!("../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
    ),
    (
        "019_line_activation_contract.sql",
        include_str!("../../../deploy/compose/migrations/019_line_activation_contract.sql"),
    ),
    (
        "020_enrollment_retention_indexes.sql",
        include_str!("../../../deploy/compose/migrations/020_enrollment_retention_indexes.sql"),
    ),
    (
        "021_billing_payment_grace.sql",
        include_str!("../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
    ),
    (
        "022_pending_owner_expiry.sql",
        include_str!("../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
    ),
    (
        "023_billing_py_charge_and_unsupported.sql",
        include_str!(
            "../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
    ),
    (
        "024_billing_risk_operator_review.sql",
        include_str!("../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
    ),
    (
        "025_account_recovery.sql",
        include_str!("../../../deploy/compose/migrations/025_account_recovery.sql"),
    ),
    (
        "026_data_retention.sql",
        include_str!("../../../deploy/compose/migrations/026_data_retention.sql"),
    ),
    (
        "027_billing_test_config.sql",
        include_str!("../../../deploy/compose/migrations/027_billing_test_config.sql"),
    ),
    (
        "028_billing_provider_failures.sql",
        include_str!("../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
    ),
    (
        "029_webhook_dispatch_fairness.sql",
        include_str!("../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
    ),
    (
        "030_terminal_dispatch_jobs.sql",
        include_str!("../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
    ),
    (
        "031_recipient_suppression.sql",
        include_str!("../../../deploy/compose/migrations/031_recipient_suppression.sql"),
    ),
    (
        "032_line_opt_out_events.sql",
        include_str!("../../../deploy/compose/migrations/032_line_opt_out_events.sql"),
    ),
    (
        "033_sms_line_binding_scope.sql",
        include_str!("../../../deploy/compose/migrations/033_sms_line_binding_scope.sql"),
    ),
    (
        "034_delivery_sweep_index.sql",
        include_str!("../../../deploy/compose/migrations/034_delivery_sweep_index.sql"),
    ),
    (
        "035_sms_owner_key_ceremony.sql",
        include_str!("../../../deploy/compose/migrations/035_sms_owner_key_ceremony.sql"),
    ),
    (
        "036_owner_opt_out_holds.sql",
        include_str!("../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
    ),
    (
        "037_sms_line_activation_exchange.sql",
        include_str!("../../../deploy/compose/migrations/037_sms_line_activation_exchange.sql"),
    ),
    (
        "038_owner_opt_out_hold_guards.sql",
        include_str!("../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
    ),
    (
        "039_inbound_device_clock_offset.sql",
        include_str!("../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ),
];

async fn apply_test_migrations(client: &Client) {
    for (name, migration) in TEST_MIGRATIONS {
        if name == "034_delivery_sweep_index.sql" {
            // Mirror the migrator's autocommit preparation before the
            // numbered, checksummed validation file.
            client
                .batch_execute(
                    "CREATE INDEX CONCURRENTLY messages_in_flight_updated \
                     ON messages(updated_at,id) \
                     WHERE state IN ('claimed','submitting','submitted')",
                )
                .await
                .unwrap();
        }
        client.batch_execute(migration).await.unwrap();
    }
}

#[test]
fn admission_fixture_tracks_numbered_migrations() {
    let migrations_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut discovered = std::fs::read_dir(migrations_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sql"))
        .collect::<Vec<_>>();
    discovered.sort();
    let embedded = TEST_MIGRATIONS
        .iter()
        .map(|(name, _)| name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(discovered, embedded, "update the embedded migration list");
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn released_attempt_cannot_change_a_new_grant() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("stale_attempt_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();
    client
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let mut store = DeliveryStore::new(&mut client);
    store
        .accept(NewMessage {
            account_id,
            device_id,
            client_message_id: message_id,
            idempotency_key: "stale-attempt",
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic regression",
            expires_at_ms: now_ms() + 60_000,
        })
        .await
        .unwrap();
    let session = store
        .connect_session(account_id, device_id, "test", "test", 60)
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("test", account_id, device_id)
        .await
        .unwrap()
        .unwrap();
    let attempt_id = Uuid::new_v4();
    store
        .issue_grant(&claim, &session, attempt_id)
        .await
        .unwrap();
    let event = |evidence| RadioEvent {
        event_id: Uuid::new_v4(),
        account_id,
        device_id,
        message_id,
        attempt_id,
        evidence,
        observed_at_ms: now_ms(),
        segment_index: None,
        segment_count: None,
    };
    let intent = event(Evidence::DurableSubmitIntent);
    store.record_radio_event(intent).await.unwrap();
    let proof = event(Evidence::ProvenNoSubmit);
    store.record_radio_event(proof).await.unwrap();
    let claim = store
        .claim_due_for_device("test", account_id, device_id)
        .await
        .unwrap()
        .unwrap();
    let fresh_attempt = Uuid::new_v4();
    store
        .issue_grant(&claim, &session, fresh_attempt)
        .await
        .unwrap();
    // Exact receipts remain replayable without applying their state again.
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        MessageState::Submitting
    );
    assert_eq!(
        store.record_radio_event(proof).await.unwrap(),
        MessageState::Queued
    );
    for evidence in [Evidence::DurableSubmitIntent, Evidence::CallbackConflict] {
        assert!(matches!(
            store.record_radio_event(event(evidence)).await,
            Err(StoreError::StaleFence)
        ));
    }
    assert_eq!(
        store
            .status(account_id, message_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Claimed
    );
    store
        .record_radio_event(RadioEvent {
            attempt_id: fresh_attempt,
            ..event(Evidence::DurableSubmitIntent)
        })
        .await
        .unwrap();
    for evidence in [Evidence::SentCallbackOk, Evidence::SentCallbackFailed] {
        assert!(matches!(
            store
                .record_radio_event(RadioEvent {
                    segment_index: Some(0),
                    segment_count: Some(1),
                    ..event(evidence)
                })
                .await,
            Err(StoreError::StaleFence)
        ));
    }
    assert_eq!(
        store
            .status(account_id, message_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Submitting
    );
    store
        .record_radio_event(RadioEvent {
            attempt_id: fresh_attempt,
            segment_index: Some(0),
            segment_count: Some(1),
            ..event(Evidence::SentCallbackOk)
        })
        .await
        .unwrap();
    for evidence in [Evidence::DeliveryCallbackOk, Evidence::DeliveryTimeout] {
        assert!(matches!(
            store.record_radio_event(event(evidence)).await,
            Err(StoreError::StaleFence)
        ));
    }
    assert_eq!(
        store
            .status(account_id, message_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Submitted
    );
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn expired_message_replay_keeps_identity_without_new_dispatch() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("expired_replay_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    let expiry = now_ms() + 5_000;
    let input = || NewMessage {
        account_id: account,
        client_message_id: message,
        device_id: device,
        idempotency_key: "expired-replay",
        recipient_e164: "+15551234567",
        synthetic_payload: b"test only",
        expires_at_ms: expiry,
    };
    assert!(
        DeliveryStore::new(&mut client)
            .accept(input())
            .await
            .unwrap()
            .created
    );
    tokio::time::sleep(std::time::Duration::from_millis(
        (expiry - now_ms() + 10).max(0) as u64,
    ))
    .await;
    let replay = DeliveryStore::new(&mut client)
        .accept(input())
        .await
        .unwrap();
    assert_eq!(replay.message_id, message);
    assert!(!replay.created);
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                synthetic_payload: b"changed",
                ..input()
            })
            .await,
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                client_message_id: Uuid::new_v4(),
                idempotency_key: "expired-new",
                ..input()
            })
            .await,
        Err(StoreError::InvalidInput)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                idempotency_key: "expired-new-same-id",
                ..input()
            })
            .await,
        Err(StoreError::InvalidInput)
    ));
    for table in ["messages", "dispatch_jobs", "idempotency_keys"] {
        let count: i64 = client
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "{table} changed after expired retry");
    }
    client.execute(
            "UPDATE idempotency_keys SET expires_at=now()-interval '1 second' WHERE account_id=$1 AND key='expired-replay'",
            &[&account],
        ).await.unwrap();
    let replacement_id = Uuid::new_v4();
    let replacement = DeliveryStore::with_idempotency_days(&mut client, 1)
        .accept(NewMessage {
            client_message_id: replacement_id,
            synthetic_payload: b"new request after key expiry",
            expires_at_ms: now_ms() + 60_000,
            ..input()
        })
        .await
        .unwrap();
    assert!(replacement.created);
    assert_eq!(replacement.message_id, replacement_id);
    let row = client.query_one(
            "SELECT message_id,expires_at>now()+interval '23 hours' AND expires_at<now()+interval '25 hours' \
             FROM idempotency_keys WHERE account_id=$1 AND key='expired-replay'",
            &[&account],
        ).await.unwrap();
    assert_eq!(row.get::<_, Uuid>(0), replacement_id);
    assert!(row.get::<_, bool>(1));
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn exact_alpha_replay_survives_customer_binding_without_new_work() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("alpha_replay_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let expiry = now_ms() + 300_000;
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    let input = || NewMessage {
        account_id: account,
        client_message_id: message,
        device_id: device,
        idempotency_key: "before-binding",
        recipient_e164: "+15551234567",
        synthetic_payload: b"fixture",
        expires_at_ms: expiry,
    };
    assert!(
        DeliveryStore::new(&mut client)
            .accept_alpha(input(), false)
            .await
            .unwrap()
            .created
    );
    client
        .execute(
            "INSERT INTO billing_customers(account_id,stripe_customer_id) \
                 VALUES($1,'cus_alphareplayfixture')",
            &[&account],
        )
        .await
        .unwrap();
    for billing_enabled in [false, true] {
        let replay = DeliveryStore::new(&mut client)
            .accept_alpha(input(), billing_enabled)
            .await
            .unwrap();
        assert_eq!(replay.message_id, message);
        assert!(!replay.created);
    }
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    synthetic_payload: b"changed",
                    ..input()
                },
                false,
            )
            .await,
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    idempotency_key: "alternate-key",
                    ..input()
                },
                false,
            )
            .await,
        Err(StoreError::MessageIdConflict | StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    client_message_id: Uuid::new_v4(),
                    idempotency_key: "new-work",
                    ..input()
                },
                false,
            )
            .await,
        Err(StoreError::QuotaNotConfigured)
    ));
    for table in ["messages", "dispatch_jobs", "idempotency_keys"] {
        let count: i64 = client
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "{table} count changed after replay");
    }
    let reservations: i64 = client
        .query_one(
            "SELECT count(*) FROM usage_ledger WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(reservations, 0);
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn parallel_acceptance_respects_pending_queue_capacity() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("delivery_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    // Apply the complete numbered schema, including accept-time metering.
    apply_test_migrations(&client).await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'queue phone')",
            &[&device, &account],
        )
        .await
        .unwrap();

    // Independent connections represent competing API instances. Only one
    // account-row lock holder can count and insert at a time.
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..32 {
        let url = url.clone();
        let schema = schema.clone();
        tasks.spawn(async move {
            let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            client
                .batch_execute(&format!("SET search_path TO {schema}"))
                .await
                .unwrap();
            let id = Uuid::new_v4();
            let key = format!("parallel-{index}");
            let result = DeliveryStore::new(&mut client)
                .accept(NewMessage {
                    account_id: account,
                    client_message_id: id,
                    device_id: device,
                    idempotency_key: &key,
                    recipient_e164: "+15551234567",
                    synthetic_payload: b"test only",
                    expires_at_ms: now_ms() + 300_000,
                })
                .await;
            match result {
                Ok(outcome) => {
                    assert!(outcome.created);
                    Some((id, key))
                }
                Err(StoreError::QueueFull) => None,
                Err(error) => panic!("unexpected admission result: {error}"),
            }
        });
    }
    let mut accepted = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Some(item) = result.unwrap() {
            accepted.push(item);
        }
    }
    assert_eq!(accepted.len(), MAX_PENDING_PER_DEVICE as usize);
    let rows: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM messages WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, MAX_PENDING_PER_DEVICE);
    // An exact replay still succeeds while the queue is full.
    let (id, key) = &accepted[0];
    let (mut replay_client, replay_connection) =
        tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
    tokio::spawn(async move { replay_connection.await.unwrap() });
    replay_client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    // The original request deadline is read from its committed row so
    // the digest is identical to the first acceptance.
    let expiry: i64 = replay_client
        .query_one(
            "SELECT (extract(epoch FROM expires_at)*1000)::bigint FROM messages WHERE id=$1",
            &[id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !DeliveryStore::new(&mut replay_client)
            .accept(NewMessage {
                account_id: account,
                client_message_id: *id,
                device_id: device,
                idempotency_key: key,
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap()
            .created
    );

    // Fill other phones to the tenant-wide limit. A new device cannot
    // bypass account admission, and cancellation returns one slot.
    for ordinal in 0..7 {
        let another_device = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'queue phone')",
                &[&another_device, &account],
            )
            .await
            .unwrap();
        for slot in 0..MAX_PENDING_PER_DEVICE {
            let key = format!("account-{ordinal}-{slot}");
            DeliveryStore::new(&mut replay_client)
                .accept(NewMessage {
                    account_id: account,
                    client_message_id: Uuid::new_v4(),
                    device_id: another_device,
                    idempotency_key: &key,
                    recipient_e164: "+15551234567",
                    synthetic_payload: b"test only",
                    expires_at_ms: now_ms() + 300_000,
                })
                .await
                .unwrap();
        }
    }
    let extra_device = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'queue phone')",
            &[&extra_device, &account],
        )
        .await
        .unwrap();
    let extra_id = Uuid::new_v4();
    let extra = || NewMessage {
        account_id: account,
        client_message_id: extra_id,
        device_id: extra_device,
        idempotency_key: "account-full",
        recipient_e164: "+15551234567",
        synthetic_payload: b"test only",
        expires_at_ms: now_ms() + 300_000,
    };
    assert!(matches!(
        DeliveryStore::new(&mut replay_client).accept(extra()).await,
        Err(StoreError::QueueFull)
    ));
    assert!(
        DeliveryStore::new(&mut replay_client)
            .cancel(account, *id)
            .await
            .unwrap()
    );
    assert!(
        DeliveryStore::new(&mut replay_client)
            .accept(extra())
            .await
            .unwrap()
            .created
    );
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_fences_unknown_and_tenant_idempotency() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("delivery_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;

    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    for id in [account, other_account] {
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&id])
            .await
            .unwrap();
    }
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'test phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE deployment_authority SET dispatch_enabled=TRUE WHERE singleton=TRUE",
            &[],
        )
        .await
        .unwrap();

    let message = Uuid::new_v4();
    let expiry = now_ms() + 3_600_000;
    let input = || NewMessage {
        account_id: account,
        client_message_id: message,
        device_id: device,
        idempotency_key: "one",
        recipient_e164: "+15551234567",
        synthetic_payload: b"test only",
        expires_at_ms: expiry,
    };
    {
        let mut store = DeliveryStore::new(&mut client);
        assert!(store.accept(input()).await.unwrap().created);
        assert!(!store.accept(input()).await.unwrap().created);
        assert_eq!(
            store.status(account, message).await.unwrap().unwrap().state,
            MessageState::Queued
        );
        assert!(
            store
                .status(other_account, message)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store
                .accept(NewMessage {
                    synthetic_payload: b"changed",
                    ..input()
                })
                .await,
            Err(StoreError::IdempotencyConflict)
        ));
        assert!(matches!(
            store
                .accept(NewMessage {
                    idempotency_key: "different-key",
                    ..input()
                })
                .await,
            Err(StoreError::MessageIdConflict)
        ));
        assert!(matches!(
            store
                .connect_session(other_account, device, "a", "hub", 60)
                .await,
            Err(StoreError::NotFound)
        ));
        let session = store
            .connect_session(account, device, "a", "hub", 60)
            .await
            .unwrap();
        let (mut blocker, blocker_connection) =
            tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .unwrap();
        tokio::spawn(async move { blocker_connection.await.unwrap() });
        blocker
            .batch_execute(&format!("SET search_path TO {schema}"))
            .await
            .unwrap();
        let locked = blocker.transaction().await.unwrap();
        locked
            .query_one(
                "SELECT message_id FROM dispatch_jobs WHERE message_id=$1 FOR UPDATE",
                &[&message],
            )
            .await
            .unwrap();
        assert!(store.claim_due("blocked-worker").await.unwrap().is_none());
        locked.rollback().await.unwrap();
        let claim = store.claim_due("worker-a").await.unwrap().unwrap();
        assert_eq!(claim.message_id, message);
        let attempt = Uuid::new_v4();
        let grant = store.issue_grant(&claim, &session, attempt).await.unwrap();
        let payload = store
            .synthetic_payload_for_grant(&grant, &session)
            .await
            .unwrap();
        assert_eq!(payload.recipient_e164, "+15551234567");
        assert_eq!(payload.body, "test only");
        let event = |evidence, event_id| RadioEvent {
            event_id,
            account_id: account,
            device_id: device,
            message_id: message,
            attempt_id: attempt,
            evidence,
            observed_at_ms: now_ms(),
            segment_index: None,
            segment_count: None,
        };
        assert!(matches!(
            store
                .record_radio_event(RadioEvent {
                    device_id: Uuid::new_v4(),
                    ..event(Evidence::DurableSubmitIntent, Uuid::new_v4())
                })
                .await,
            Err(StoreError::StaleFence)
        ));
        assert_eq!(
            store
                .record_radio_event(event(Evidence::DurableSubmitIntent, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(event(Evidence::CrashWithoutCallback, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Unknown
        );
        assert!(store.claim_due("worker-b").await.unwrap().is_none());
        let new_session = store
            .connect_session(account, device, "b", "hub-b", 60)
            .await
            .unwrap();
        assert!(matches!(
            store.synthetic_payload_for_grant(&grant, &session).await,
            Err(StoreError::StaleFence)
        ));
        assert!(matches!(
            store
                .issue_grant(&claim, &new_session, Uuid::new_v4())
                .await,
            Err(StoreError::StaleFence)
        ));

        let second_message = Uuid::new_v4();
        store
            .accept(NewMessage {
                client_message_id: second_message,
                idempotency_key: "two",
                ..input()
            })
            .await
            .unwrap();
        let second_claim = store.claim_due("worker-b").await.unwrap().unwrap();
        assert_eq!(second_claim.message_id, second_message);
        assert!(matches!(
            store
                .issue_grant(&second_claim, &new_session, Uuid::new_v4())
                .await,
            Err(StoreError::DeviceBusy)
        ));
        assert!(matches!(
            store.cancel(account, message).await,
            Err(StoreError::InvalidTransition)
        ));
        assert!(!store.cancel(other_account, second_message).await.unwrap());
        assert!(store.cancel(account, second_message).await.unwrap());
        assert!(store.claim_due("worker-d").await.unwrap().is_none());
    }
    let second_device = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'multipart phone')",
            &[&second_device, &account],
        )
        .await
        .unwrap();
    let third_message = Uuid::new_v4();
    let third_attempt = Uuid::new_v4();
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                client_message_id: third_message,
                device_id: second_device,
                idempotency_key: "three",
                ..input()
            })
            .await
            .unwrap();
        assert!(
            store
                .claim_due_for_device("wrong-tenant", other_account, second_device)
                .await
                .unwrap()
                .is_none()
        );
        let third_claim = store
            .claim_due_for_device("worker-c", account, second_device)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(third_claim.message_id, third_message);
        let third_session = store
            .connect_session(account, second_device, "a", "hub", 60)
            .await
            .unwrap();
        store
            .issue_grant(&third_claim, &third_session, third_attempt)
            .await
            .unwrap();
        let multipart = |evidence, index, event_id| RadioEvent {
            event_id,
            account_id: account,
            device_id: second_device,
            message_id: third_message,
            attempt_id: third_attempt,
            evidence,
            observed_at_ms: now_ms(),
            segment_index: index,
            segment_count: index.map(|_| 2),
        };
        assert_eq!(
            store
                .record_radio_event(multipart(
                    Evidence::DurableSubmitIntent,
                    None,
                    Uuid::new_v4()
                ))
                .await
                .unwrap(),
            MessageState::Submitting
        );
        let first_segment = multipart(Evidence::SentCallbackOk, Some(0), Uuid::new_v4());
        assert_eq!(
            store.record_radio_event(first_segment).await.unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store.record_radio_event(first_segment).await.unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(multipart(Evidence::SentCallbackOk, Some(1), Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Submitted
        );
        assert!(matches!(
            store
                .record_radio_event(multipart(
                    Evidence::SentCallbackFailed,
                    Some(1),
                    Uuid::new_v4()
                ))
                .await,
            Err(StoreError::InvalidInput)
        ));
        store
            .accept(NewMessage {
                client_message_id: Uuid::from_u128(42),
                device_id: second_device,
                idempotency_key: "expires",
                ..input()
            })
            .await
            .unwrap();
    }
    let expiring_message = Uuid::from_u128(42);
    client
        .execute(
            "UPDATE messages SET expires_at=now()-interval '1 second' WHERE id=$1",
            &[&expiring_message],
        )
        .await
        .unwrap();
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(store.expire_due(10).await.unwrap(), 1);
        assert!(store.claim_due("worker-e").await.unwrap().is_none());
    }
    let state: String = client
        .query_one(
            "SELECT state FROM messages WHERE id=$1",
            &[&expiring_message],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "expired");

    assert_eq!(
        DeliveryStore::new(&mut client)
            .reconcile_delivery_timeouts(10)
            .await
            .unwrap(),
        0
    );
    client
        .execute(
            "UPDATE messages SET updated_at=now()-interval '25 hours' WHERE id=$1",
            &[&third_message],
        )
        .await
        .unwrap();
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(store.reconcile_delivery_timeouts(10).await.unwrap(), 1);
        assert_eq!(store.reconcile_delivery_timeouts(10).await.unwrap(), 0);
        assert_eq!(
            store
                .status(account, third_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::DeliveryUnknown
        );
        assert_eq!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: account,
                    device_id: second_device,
                    message_id: third_message,
                    attempt_id: third_attempt,
                    evidence: Evidence::DeliveryCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: None,
                    segment_count: None,
                })
                .await
                .unwrap(),
            MessageState::Delivered
        );
    }

    let silent_grant_message = Uuid::new_v4();
    let silent_grant_attempt = Uuid::new_v4();
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                account_id: account,
                client_message_id: silent_grant_message,
                device_id: second_device,
                idempotency_key: "silent-grant",
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap();
        let claim = store
            .claim_due_for_device("timeout-grant", account, second_device)
            .await
            .unwrap()
            .unwrap();
        let session = store
            .connect_session(account, second_device, "a", "hub", 60)
            .await
            .unwrap();
        store
            .issue_grant(&claim, &session, silent_grant_attempt)
            .await
            .unwrap();
        assert_eq!(store.reconcile_silent_attempts(10).await.unwrap(), 0);
    }
    client.execute(
            "UPDATE dispatch_fences SET grant_expires_at=now()-interval '1 second' WHERE attempt_id=$1",
            &[&silent_grant_attempt],
        ).await.unwrap();
    let (mut timeout_blocker, timeout_connection) =
        tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
    tokio::spawn(async move { timeout_connection.await.unwrap() });
    timeout_blocker
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let timeout_lock = timeout_blocker.transaction().await.unwrap();
    timeout_lock
        .query_one(
            "SELECT id FROM messages WHERE id=$1 FOR UPDATE",
            &[&silent_grant_message],
        )
        .await
        .unwrap();
    assert_eq!(
        DeliveryStore::new(&mut client)
            .reconcile_silent_attempts(10)
            .await
            .unwrap(),
        0
    );
    timeout_lock.rollback().await.unwrap();
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(store.reconcile_silent_attempts(10).await.unwrap(), 1);
        assert_eq!(store.reconcile_silent_attempts(10).await.unwrap(), 0);
        assert_eq!(
            store
                .status(account, silent_grant_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Unknown
        );
        store
            .accept(NewMessage {
                account_id: account,
                client_message_id: Uuid::new_v4(),
                device_id: second_device,
                idempotency_key: "blocked-after-timeout",
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap();
        let blocked_claim = store
            .claim_due_for_device("again", account, second_device)
            .await
            .unwrap()
            .unwrap();
        let new_session = store
            .connect_session(account, second_device, "b", "hub", 60)
            .await
            .unwrap();
        assert!(matches!(
            store
                .issue_grant(&blocked_claim, &new_session, Uuid::new_v4())
                .await,
            Err(StoreError::DeviceBusy)
        ));
        assert!(matches!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: account,
                    device_id: second_device,
                    message_id: silent_grant_message,
                    attempt_id: silent_grant_attempt,
                    evidence: Evidence::SentCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: Some(0),
                    segment_count: Some(1),
                })
                .await,
            Err(StoreError::InvalidTransition)
        ));
    }
    let timeout_evidence: String = client
        .query_one(
            "SELECT evidence_code FROM message_events WHERE attempt_id=$1",
            &[&silent_grant_attempt],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(timeout_evidence, "grant_timeout");

    let timeout_device = Uuid::new_v4();
    client.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'callback timeout phone')",
            &[&timeout_device, &account],
        ).await.unwrap();
    let silent_callback_message = Uuid::new_v4();
    let silent_callback_attempt = Uuid::new_v4();
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                account_id: account,
                client_message_id: silent_callback_message,
                device_id: timeout_device,
                idempotency_key: "silent-callback",
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap();
        let claim = store
            .claim_due_for_device("timeout-callback", account, timeout_device)
            .await
            .unwrap()
            .unwrap();
        let session = store
            .connect_session(account, timeout_device, "a", "hub", 60)
            .await
            .unwrap();
        store
            .issue_grant(&claim, &session, silent_callback_attempt)
            .await
            .unwrap();
        store
            .record_radio_event(RadioEvent {
                event_id: Uuid::new_v4(),
                account_id: account,
                device_id: timeout_device,
                message_id: silent_callback_message,
                attempt_id: silent_callback_attempt,
                evidence: Evidence::DurableSubmitIntent,
                observed_at_ms: now_ms(),
                segment_index: None,
                segment_count: None,
            })
            .await
            .unwrap();
    }
    client
        .execute(
            "UPDATE message_attempts SET updated_at=now()-interval '3 minutes' WHERE id=$1",
            &[&silent_callback_attempt],
        )
        .await
        .unwrap();
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(store.reconcile_silent_attempts(10).await.unwrap(), 1);
        assert_eq!(
            store
                .status(account, silent_callback_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Unknown
        );
        assert_eq!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: account,
                    device_id: timeout_device,
                    message_id: silent_callback_message,
                    attempt_id: silent_callback_attempt,
                    evidence: Evidence::SentCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: Some(0),
                    segment_count: Some(1),
                })
                .await
                .unwrap(),
            MessageState::Submitted
        );
    }
    let timeout_evidence: String = client.query_one(
            "SELECT evidence_code FROM message_events WHERE attempt_id=$1 AND evidence_code='sent_callback_timeout'",
            &[&silent_callback_attempt],
        ).await.unwrap().get(0);
    assert_eq!(timeout_evidence, "sent_callback_timeout");
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: account,
                    device_id: timeout_device,
                    message_id: silent_callback_message,
                    attempt_id: silent_callback_attempt,
                    evidence: Evidence::DeliveryCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: None,
                    segment_count: None,
                })
                .await
                .unwrap(),
            MessageState::Delivered
        );
        let conflict = RadioEvent {
            event_id: Uuid::new_v4(),
            account_id: account,
            device_id: timeout_device,
            message_id: silent_callback_message,
            attempt_id: silent_callback_attempt,
            evidence: Evidence::CallbackConflict,
            observed_at_ms: now_ms(),
            segment_index: None,
            segment_count: None,
        };
        assert_eq!(
            store.record_radio_event(conflict).await.unwrap(),
            MessageState::Unknown
        );
        assert_eq!(
            store.record_radio_event(conflict).await.unwrap(),
            MessageState::Unknown
        );
        assert!(matches!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    evidence: Evidence::DeliveryCallbackOk,
                    ..conflict
                })
                .await,
            Err(StoreError::InvalidTransition)
        ));
    }
    let fence: String = client
        .query_one(
            "SELECT outcome FROM dispatch_fences WHERE attempt_id=$1",
            &[&silent_callback_attempt],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(fence, "unknown");

    // A durable phone proof can release an ambiguous fence exactly once.
    // This uses a distinct device so the prior unknown attempt stays fenced.
    let proof_device = Uuid::new_v4();
    let proof_message = Uuid::new_v4();
    let proof_attempt = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'no radio phone')",
            &[&proof_device, &account],
        )
        .await
        .unwrap();
    let proof_event = |evidence, event_id| RadioEvent {
        event_id,
        account_id: account,
        device_id: proof_device,
        message_id: proof_message,
        attempt_id: proof_attempt,
        evidence,
        observed_at_ms: now_ms(),
        segment_index: None,
        segment_count: None,
    };
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                account_id: account,
                client_message_id: proof_message,
                device_id: proof_device,
                idempotency_key: "proved-no-radio",
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap();
        let claim = store
            .claim_due_for_device("proof", account, proof_device)
            .await
            .unwrap()
            .unwrap();
        let session = store
            .connect_session(account, proof_device, "a", "proof-hub", 60)
            .await
            .unwrap();
        store
            .issue_grant(&claim, &session, proof_attempt)
            .await
            .unwrap();
        assert_eq!(
            store
                .record_radio_event(proof_event(Evidence::DurableSubmitIntent, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(proof_event(Evidence::CrashWithoutCallback, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Unknown
        );
        let no_radio = proof_event(Evidence::ProvenNoSubmit, Uuid::new_v4());
        assert_eq!(
            store.record_radio_event(no_radio).await.unwrap(),
            MessageState::Queued
        );
        assert_eq!(
            store.record_radio_event(no_radio).await.unwrap(),
            MessageState::Queued
        );
        assert!(matches!(
            store
                .record_radio_event(proof_event(Evidence::ProvenNoSubmit, Uuid::new_v4()))
                .await,
            Err(StoreError::StaleFence)
        ));
        let replay_claim = store
            .claim_due_for_device("proof-retry", account, proof_device)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay_claim.message_id, proof_message);
        let fresh_session = store
            .connect_session(account, proof_device, "b", "proof-hub", 60)
            .await
            .unwrap();
        let fresh_attempt = Uuid::new_v4();
        assert!(
            store
                .issue_grant(&replay_claim, &fresh_session, fresh_attempt)
                .await
                .is_ok()
        );
        assert!(matches!(
            store
                .record_radio_event(proof_event(Evidence::ProvenNoSubmit, Uuid::new_v4()))
                .await,
            Err(StoreError::StaleFence)
        ));
        assert_eq!(
            store
                .status(account, proof_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Claimed
        );
        let fresh_event = |evidence, event_id| RadioEvent {
            attempt_id: fresh_attempt,
            evidence,
            event_id,
            ..no_radio
        };
        assert_eq!(
            store
                .record_radio_event(fresh_event(Evidence::DurableSubmitIntent, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(RadioEvent {
                    segment_index: Some(0),
                    segment_count: Some(2),
                    ..fresh_event(Evidence::SentCallbackOk, Uuid::new_v4())
                })
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(fresh_event(Evidence::CrashWithoutCallback, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Unknown
        );
        assert!(matches!(
            store
                .record_radio_event(fresh_event(Evidence::ProvenNoSubmit, Uuid::new_v4()))
                .await,
            Err(StoreError::InvalidTransition)
        ));
    }
    let old_fence_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM dispatch_fences WHERE attempt_id=$1",
            &[&proof_attempt],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(old_fence_count, 0);
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn terminal_dispatch_backfill_and_live_claims_ignore_large_history() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("terminal_dispatch_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    for (_, migration) in TEST_MIGRATIONS.iter().take(29) {
        client.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let due = Uuid::new_v4();
    let expiring = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    // This is the historical shape left by old cancel/expiry code: terminal
    // messages, pre-grant jobs and old next-attempt times still indexed.
    client
        .execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
             transport_mode,transport_payload,request_digest,state,expires_at,updated_at) \
             SELECT md5('terminal-'||g::text)::uuid,$1,$2,'+15551234567', \
               decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'), \
               decode(repeat('22',32),'hex'), \
               CASE WHEN g%2=0 THEN 'cancelled' ELSE 'expired' END, \
               now()-interval '1 day',now()-interval '1 day' \
             FROM generate_series(1,8000) g",
            &[&account, &device],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO dispatch_jobs(message_id,account_id,device_id,next_attempt_at, \
             generation,lease_owner,lease_until) \
             SELECT id,account_id,device_id,now()-interval '1 day',3,'old-worker', \
               now()-interval '1 hour' FROM messages WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap();
    for (id, expiry) in [(due, "10 minutes"), (expiring, "-1 minute")] {
        client
            .execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
                 transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES($1,$2,$3,'+15551234567',decode(repeat('11',32),'hex'), \
                 'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'), \
                 'queued',now()+$4::text::interval)",
                &[&id, &account, &device, &expiry],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO dispatch_jobs(message_id,account_id,device_id,next_attempt_at) \
                 VALUES($1,$2,$3,now()-interval '1 minute')",
                &[&id, &account, &device],
            )
            .await
            .unwrap();
    }
    client.batch_execute(TEST_MIGRATIONS[29].1).await.unwrap();
    let counts = client
        .query_one(
            "SELECT count(*) FILTER (WHERE finished_at IS NOT NULL), \
             count(*) FILTER (WHERE finished_at IS NULL AND grant_issued_at IS NULL), \
             count(*) FILTER (WHERE finished_at IS NOT NULL AND \
               (generation<>3 OR lease_owner IS NOT NULL OR lease_until IS NOT NULL)) \
             FROM dispatch_jobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(counts.get::<_, i64>(0), 8000);
    assert_eq!(counts.get::<_, i64>(1), 2);
    assert_eq!(counts.get::<_, i64>(2), 0);
    let wrong_backfill_time: i64 = client.query_one(
            "SELECT count(*) FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
             WHERE m.state IN ('cancelled','expired') AND j.finished_at IS DISTINCT FROM m.updated_at",
            &[],
        ).await.unwrap().get(0);
    assert_eq!(wrong_backfill_time, 0);
    let index: String = client
        .query_one(
            "SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() \
             AND indexname='dispatch_jobs_due'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(index.contains("finished_at IS NULL"), "{index}");

    client
        .batch_execute("ANALYZE messages; ANALYZE dispatch_jobs; ANALYZE devices")
        .await
        .unwrap();
    let claim_plan = client
        .query(
            "EXPLAIN (ANALYZE, BUFFERS) \
             SELECT j.message_id FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
             JOIN devices d ON d.id=j.device_id AND d.account_id=j.account_id \
             WHERE j.next_attempt_at<=now() AND (j.lease_until IS NULL OR j.lease_until<now()) \
             AND j.grant_issued_at IS NULL AND j.finished_at IS NULL \
             AND m.state IN ('queued','claimed') AND m.expires_at>now() \
             AND d.revoked_at IS NULL \
             ORDER BY j.next_attempt_at,j.message_id FOR UPDATE OF j SKIP LOCKED LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !claim_plan.contains("Seq Scan on dispatch_jobs"),
        "{claim_plan}"
    );
    assert!(!claim_plan.contains("Seq Scan on messages"), "{claim_plan}");
    let expiry_plan = client
        .query(
            "EXPLAIN (ANALYZE, BUFFERS) \
             SELECT j.account_id,j.message_id FROM dispatch_jobs j \
             JOIN messages m ON m.id=j.message_id \
             WHERE j.grant_issued_at IS NULL AND j.finished_at IS NULL \
             AND m.expires_at<=now() AND m.state IN ('queued','claimed') \
             ORDER BY m.expires_at,m.id FOR UPDATE OF j SKIP LOCKED LIMIT 10",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !expiry_plan.contains("Seq Scan on dispatch_jobs"),
        "{expiry_plan}"
    );
    assert!(
        !expiry_plan.contains("Seq Scan on messages"),
        "{expiry_plan}"
    );

    // Both transitions commit the message state and index exclusion together.
    let mut store = DeliveryStore::new(&mut client);
    assert!(store.cancel(account, due).await.unwrap());
    assert_eq!(store.expire_due(10).await.unwrap(), 1);
    let terminal = client
        .query(
            "SELECT m.id,m.state,j.finished_at IS NOT NULL \
             FROM messages m JOIN dispatch_jobs j ON j.message_id=m.id \
             WHERE m.id=$1 OR m.id=$2 ORDER BY m.id",
            &[&due, &expiring],
        )
        .await
        .unwrap();
    assert_eq!(terminal.len(), 2);
    for row in terminal {
        let id: Uuid = row.get(0);
        let state: String = row.get(1);
        assert_eq!(state, if id == due { "cancelled" } else { "expired" });
        assert!(row.get::<_, bool>(2));
    }
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}
