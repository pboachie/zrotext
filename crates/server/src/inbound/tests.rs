use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use rand::rng;

async fn seed_dispatch_account(
    db: &Client,
    account: Uuid,
    endpoint_count: usize,
    event_count: usize,
) -> Vec<Uuid> {
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'dispatch fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
         transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')",
        &[&message,&account,&device,&vec![2_u8;32],&b"fixture".as_slice(),&vec![3_u8;32]],
    ).await.unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation, \
         session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')",
        &[&attempt, &account, &message, &device],
    )
    .await
    .unwrap();
    let mut events = Vec::new();
    for sequence in 1..=event_count {
        let event = Uuid::new_v4();
        db.execute(
            "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id, \
             device_sequence,classification,observed_at,part_count,content_kind,event_digest,signature_der) \
             VALUES($1,$2,$3,$4,$5,$6,'captured_local',now(),1,'metadata_only',$7,$8)",
            &[&event,&account,&device,&message,&attempt,&(sequence as i64),&vec![4_u8;32],&vec![5_u8;8]],
        ).await.unwrap();
        events.push(event);
    }
    let mut endpoints = Vec::new();
    for _ in 0..endpoint_count {
        let endpoint = Uuid::new_v4();
        db.execute(
            "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext, \
             signing_secret_key_version,enabled) VALUES($1,$2,'https://hooks.example.org/receive',$3,1,true)",
            &[&endpoint,&account,&vec![6_u8;32]],
        ).await.unwrap();
        for event in &events {
            db.execute(
                "INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,next_attempt_at,created_at) \
                 VALUES($1,$2,$3,$4,now()-interval '1 hour',now()-interval '2 hours')",
                &[&Uuid::new_v4(),&account,&endpoint,event],
            ).await.unwrap();
        }
        endpoints.push(endpoint);
    }
    endpoints
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_webhook_claims_rotate_accounts_and_serialize_each_endpoint() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("webhook_fairness_test_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    for migration in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    // Old workers could leave concurrent leases for one endpoint. Migration
    // must fail safely until every in-flight attempt is closed.
    let gate_account = Uuid::from_u128(9);
    let gate_endpoint = seed_dispatch_account(&db, gate_account, 1, 2).await[0];
    let gate_rows = db
        .query(
            "SELECT id FROM webhook_deliveries WHERE endpoint_id=$1",
            &[&gate_endpoint],
        )
        .await
        .unwrap();
    let gate_ids: Vec<Uuid> = gate_rows.iter().map(|row| row.get(0)).collect();
    for (index, delivery) in gate_ids.iter().enumerate() {
        let attempt_number = if index == 0 { 7_i16 } else { 1_i16 };
        let generation = if index == 0 { 2_i16 } else { 1_i16 };
        db.execute(
            "UPDATE webhook_deliveries SET status='leased',attempt_count=$2,generation=$3,lease_owner='old-worker',lease_until=now()+interval '5 minutes' WHERE id=$1",
            &[delivery, &attempt_number, &generation],
        ).await.unwrap();
        db.execute(
            "INSERT INTO webhook_attempts(id,delivery_id,generation,attempt_number) VALUES($1,$2,$3,$4)",
            &[&Uuid::new_v4(), delivery, &generation, &attempt_number],
        )
        .await
        .unwrap();
    }
    let tx = db.transaction().await.unwrap();
    let preflight = tx
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"
        ))
        .await
        .unwrap_err();
    assert!(
        preflight
            .as_db_error()
            .is_some_and(|error| error.message().contains("zero active leases")),
        "{preflight:?}"
    );
    tx.rollback().await.unwrap();
    for delivery in &gate_ids {
        db.execute(
            "UPDATE webhook_deliveries SET lease_until=now()-interval '1 second' WHERE id=$1",
            &[delivery],
        )
        .await
        .unwrap();
    }
    let tx = db.transaction().await.unwrap();
    tx.batch_execute(include_str!(
        "../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"
    ))
    .await
    .unwrap();
    tx.commit().await.unwrap();
    for (index, delivery) in gate_ids.iter().enumerate() {
        let row = db.query_one(
            "SELECT d.status,d.terminal_reason,d.next_attempt_at>now(),a.outcome,a.completed_at IS NOT NULL,d.generation,a.generation \
             FROM webhook_deliveries d JOIN webhook_attempts a ON a.delivery_id=d.id WHERE d.id=$1",
            &[delivery],
        ).await.unwrap();
        if index == 0 {
            assert_eq!(row.get::<_, String>(0), "dead");
            assert_eq!(row.get::<_, Option<String>>(1).as_deref(), Some("failed"));
        } else {
            assert_eq!(row.get::<_, String>(0), "pending");
            assert!(row.get::<_, bool>(2));
        }
        assert_eq!(row.get::<_, String>(3), "timeout");
        assert!(row.get::<_, bool>(4));
        assert_eq!(row.get::<_, i16>(5), if index == 0 { 2 } else { 1 });
        assert_eq!(row.get::<_, i16>(6), if index == 0 { 2 } else { 1 });
    }
    let account_a = Uuid::from_u128(1);
    let account_b = Uuid::from_u128(2);
    let a = seed_dispatch_account(&db, account_a, 8, 4).await;
    let b = seed_dispatch_account(&db, account_b, 1, 1).await;
    let (mut peer1, connection1) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection1.await.unwrap() });
    peer1
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let first = claim_webhook(&mut db, "fair-1").await.unwrap().unwrap();
    assert_eq!(first.account_id, account_a);
    // A remains leased and has 31 other due deliveries. B must not wait for
    // A's receiver or backlog to drain.
    let second = claim_webhook(&mut peer1, "fair-2").await.unwrap().unwrap();
    assert_eq!(second.account_id, account_b);
    assert_eq!(second.endpoint_id, b[0]);
    let third = claim_webhook(&mut db, "fair-3").await.unwrap().unwrap();
    assert_eq!(third.account_id, account_a);
    assert_ne!(third.endpoint_id, first.endpoint_id);
    assert!(a.contains(&third.endpoint_id));
    let (pending, age_seconds, in_flight) = crate::webhook_worker::queue_signal(&db).await.unwrap();
    assert_eq!((pending, in_flight), (31, 3));
    assert!(age_seconds.unwrap() >= 3600);

    db.execute(
        "UPDATE webhook_endpoints SET enabled=false WHERE account_id IN ($1,$2)",
        &[&account_a, &account_b],
    )
    .await
    .unwrap();
    let account_c = Uuid::from_u128(3);
    let c = seed_dispatch_account(&db, account_c, 1, 2).await;
    let (mut peer2, connection2) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection2.await.unwrap() });
    peer2
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        claim_webhook(&mut peer1, "parallel-1"),
        claim_webhook(&mut peer2, "parallel-2"),
    );
    let leases: Vec<_> = [left.unwrap(), right.unwrap()]
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].endpoint_id, c[0]);
    let leased: i64 = db
        .query_one(
            "SELECT count(*) FROM webhook_deliveries WHERE endpoint_id=$1 AND status='leased'",
            &[&c[0]],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(leased, 1);

    db.execute(
        "UPDATE webhook_endpoints SET failure_started_at=now()-interval '73 hours' WHERE id=$1",
        &[&c[0]],
    )
    .await
    .unwrap();
    finish_webhook(&mut db, &leases[0], WebhookOutcome::Timeout, None)
        .await
        .unwrap();
    let paused: bool = db
        .query_one(
            "SELECT paused_at IS NOT NULL FROM webhook_endpoints WHERE id=$1",
            &[&c[0]],
        )
        .await
        .unwrap()
        .get(0);
    assert!(paused);
    assert!(claim_webhook(&mut db, "paused").await.unwrap().is_none());
    db.execute(
        "UPDATE webhook_endpoints SET paused_at=NULL,failure_started_at=NULL WHERE id=$1",
        &[&c[0]],
    )
    .await
    .unwrap();
    let resumed = claim_webhook(&mut db, "resumed").await.unwrap().unwrap();
    assert_eq!(resumed.endpoint_id, c[0]);

    // A concurrent owner retirement locks the endpoint before deliveries.
    // The expiry sweep must skip that endpoint without taking its delivery
    // lock, then recover the lease after retirement releases its lock.
    db.execute(
        "UPDATE webhook_deliveries SET lease_until=now()-interval '1 second' WHERE id=$1",
        &[&resumed.delivery_id],
    )
    .await
    .unwrap();
    let retirement = peer1.transaction().await.unwrap();
    retirement
        .query_one(
            "SELECT id FROM webhook_endpoints WHERE id=$1 FOR UPDATE",
            &[&c[0]],
        )
        .await
        .unwrap();
    // The recovery sweep now runs once per lane tick, before any claim. It
    // must skip the retired endpoint's lock instead of blocking on it.
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        recover_expired_webhook_leases(&mut peer2),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        claim_webhook(&mut peer2, "sweep-during-retire")
            .await
            .unwrap()
            .is_none()
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        retirement.query_one(
            "SELECT id FROM webhook_deliveries WHERE id=$1 FOR UPDATE",
            &[&resumed.delivery_id],
        ),
    )
    .await
    .unwrap()
    .unwrap();
    retirement.rollback().await.unwrap();
    recover_expired_webhook_leases(&mut peer2).await.unwrap();
    assert!(
        claim_webhook(&mut peer2, "sweep-after-retire")
            .await
            .unwrap()
            .is_none()
    );
    let recovered = db.query_one(
        "SELECT d.status,a.outcome FROM webhook_deliveries d JOIN webhook_attempts a ON a.delivery_id=d.id WHERE d.id=$1 AND a.generation=d.generation AND a.attempt_number=d.attempt_count",
        &[&resumed.delivery_id],
    ).await.unwrap();
    assert_eq!(recovered.get::<_, String>(0), "pending");
    assert_eq!(recovered.get::<_, String>(1), "timeout");
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}

#[test]
fn early_reply_waits_for_sent_evidence_but_missing_source_is_permanent() {
    assert!(matches!(
        source_readiness(Some("submitting"), false),
        Err(InboundError::SourcePending)
    ));
    assert!(matches!(
        source_readiness(Some("unknown"), false),
        Err(InboundError::SourcePending)
    ));
    assert!(source_readiness(Some("submitted"), true).is_ok());
    assert!(matches!(
        source_readiness(Some("submitted"), false),
        Err(InboundError::UnknownSource)
    ));
    assert!(matches!(
        source_readiness(None, false),
        Err(InboundError::UnknownSource)
    ));
}

#[test]
fn opt_out_transitions_on_a_retired_source_are_deferred_not_permanent() {
    for classification in [
        Classification::OptOut,
        Classification::OptOutReview,
        Classification::OptIn,
    ] {
        assert!(
            matches!(
                retired_source_error(classification),
                InboundError::SourceRetired
            ),
            "{classification:?}"
        );
    }
    for classification in [
        Classification::CapturedLocal,
        Classification::SimUnverified,
        Classification::SendUnverified,
        Classification::EncryptionUnverified,
    ] {
        assert!(
            matches!(
                retired_source_error(classification),
                InboundError::UnknownSource
            ),
            "{classification:?}"
        );
    }
}

#[test]
fn metadata_signature_bytes_match_android_pilot_vector() {
    let session = InboundSession {
        account_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
        device_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        site_id: "vector",
        instance_id: "vector",
        connection_epoch: 3,
        deployment_epoch: 1,
    };
    let event = InboundEvent {
        event_id: Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
        sequence: 7,
        message_id: Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
        attempt_id: Uuid::parse_str("55555555-5555-4555-8555-555555555555").unwrap(),
        classification: Classification::CapturedLocal,
        observed_at_ms: 1_700_000_000_000,
        part_count: 2,
        content: Content::MetadataOnly,
        signature_der: &[],
    };
    let digest = Sha256::digest(signed_event_bytes(session, &event));
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        hex,
        "a5c16315ba6fdd194c57fcf9104f05ec7da26830c5cf784a962c4363b87dd199"
    );
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn signed_inbound_is_tenant_bound_deduplicated_and_queues_once() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("inbound_test_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    for migration in [
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
        include_str!("../../../../deploy/compose/migrations/020_enrollment_retention_indexes.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!("../../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../../deploy/compose/migrations/026_data_retention.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
        include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let endpoint = Uuid::new_v4();
    let vault = crate::webhook_worker::WebhookSecretVault::new(
        1,
        zeroize::Zeroizing::new(crate::test_keys::key(7)),
    )
    .unwrap();
    let endpoint_secret = vault
        .seal(account, endpoint, &crate::test_keys::key(8))
        .unwrap();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public = signing
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    db.execute(
        "INSERT INTO accounts(id) VALUES($1),($2)",
        &[&account, &other_account],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO sites(site_id) VALUES('test')", &[])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[&device, &account, &public, &vec![1u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) \
         VALUES($1,$2,'test','instance',2,now()+interval '10 minutes',1)",
        &[&device, &account],
    ).await.unwrap();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
         transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')",
        &[&message, &account, &device, &vec![2u8;32], &b"fixture".as_slice(), &vec![3u8;32]],
    ).await.unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation, \
         session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')",
        &[&attempt, &account, &message, &device],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code, \
         event_digest,observed_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now(),'submitted',0,1)",
        &[
            &Uuid::new_v4(),
            &account,
            &message,
            &attempt,
            &vec![4u8; 32],
        ],
    )
    .await
    .unwrap();
    // A synthetic endpoint is enough to exercise durable fanout and a fake
    // transport below; no external webhook request is made.
    db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext, \
         signing_secret_key_version,enabled) VALUES($1,$2,'https://hooks.example.org/hook',$3,1,true)",
        &[&endpoint, &account, &endpoint_secret],
    ).await.unwrap();

    let session = InboundSession {
        account_id: account,
        device_id: device,
        site_id: "test",
        instance_id: "instance",
        connection_epoch: 2,
        deployment_epoch: 1,
    };
    let unsigned = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 1,
        message_id: message,
        attempt_id: attempt,
        classification: Classification::CapturedLocal,
        observed_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        part_count: 1,
        content: Content::MetadataOnly,
        signature_der: &[],
    };
    let sig: Signature = signing.sign(&signed_event_bytes(session, &unsigned));
    let sig_bytes = sig.to_der().as_bytes().to_vec();
    let signed = InboundEvent {
        signature_der: &sig_bytes,
        ..unsigned
    };
    db.execute(
        "DELETE FROM message_events WHERE attempt_id=$1",
        &[&attempt],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE message_attempts SET status='submitting' WHERE id=$1",
        &[&attempt],
    )
    .await
    .unwrap();
    assert!(matches!(
        ingest(&mut db, session, &signed).await,
        Err(InboundError::SourcePending)
    ));
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code, \
         event_digest,observed_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now(),'submitted',0,1)",
        &[
            &Uuid::new_v4(),
            &account,
            &message,
            &attempt,
            &vec![4u8; 32],
        ],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE message_attempts SET status='submitted' WHERE id=$1",
        &[&attempt],
    )
    .await
    .unwrap();
    assert_eq!(
        ingest(&mut db, session, &signed).await.unwrap(),
        IngestOutcome {
            created: true,
            queued_deliveries: 1,
            suppression_cleared: false,
        }
    );
    assert_eq!(
        ingest(&mut db, session, &signed).await.unwrap(),
        IngestOutcome {
            created: false,
            queued_deliveries: 0,
            suppression_cleared: false,
        }
    );
    let counts = db.query_one(
        "SELECT (SELECT count(*) FROM inbound_events),(SELECT count(*) FROM webhook_deliveries)",
        &[],
    ).await.unwrap();
    assert_eq!((counts.get::<_, i64>(0), counts.get::<_, i64>(1)), (1, 1));

    let first_lease = claim_webhook(&mut db, "worker-a").await.unwrap().unwrap();
    assert_eq!(first_lease.attempt_number, 1);
    let payload = load_webhook_payload(&db, &first_lease).await.unwrap();
    assert_eq!(payload.event_digest.len(), 32);
    assert_eq!(payload.content_kind, "metadata_only");
    assert!(payload.content_ciphertext.is_none());
    assert!(claim_webhook(&mut db, "worker-b").await.unwrap().is_none());
    assert!(matches!(
        finish_webhook(&mut db, &first_lease, WebhookOutcome::Ack, Some(302)).await,
        Err(InboundError::InvalidInput)
    ));
    finish_webhook(&mut db, &first_lease, WebhookOutcome::HttpError, Some(500))
        .await
        .unwrap();
    let streak_started: bool = db
        .query_one(
            "SELECT failure_started_at IS NOT NULL FROM webhook_endpoints WHERE id=$1",
            &[&endpoint],
        )
        .await
        .unwrap()
        .get(0);
    assert!(streak_started);
    assert!(matches!(
        finish_webhook(&mut db, &first_lease, WebhookOutcome::HttpError, Some(500)).await,
        Err(InboundError::StaleLease)
    ));
    let retry: i64 = db.query_one(
        "SELECT (extract(epoch FROM next_attempt_at-now()))::bigint FROM webhook_deliveries WHERE id=$1",
        &[&first_lease.delivery_id],
    ).await.unwrap().get(0);
    assert!((0..=60).contains(&retry));
    assert!(claim_webhook(&mut db, "worker-b").await.unwrap().is_none());
    db.execute(
        "UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' WHERE id=$1",
        &[&first_lease.delivery_id],
    )
    .await
    .unwrap();
    let second_lease = claim_webhook(&mut db, "worker-b").await.unwrap().unwrap();
    assert_eq!(second_lease.attempt_number, 2);
    finish_webhook(&mut db, &second_lease, WebhookOutcome::Ack, Some(204))
        .await
        .unwrap();
    let streak_cleared: bool = db
        .query_one(
            "SELECT failure_started_at IS NULL FROM webhook_endpoints WHERE id=$1",
            &[&endpoint],
        )
        .await
        .unwrap()
        .get(0);
    assert!(streak_cleared);
    let status: String = db
        .query_one(
            "SELECT status FROM webhook_deliveries WHERE id=$1",
            &[&second_lease.delivery_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "succeeded");
    assert!(claim_webhook(&mut db, "worker-a").await.unwrap().is_none());

    // Exercise the assembled worker without touching the network. A target
    // rejected by local policy must consume one attempt and dead-letter it.
    let policy_endpoint = Uuid::new_v4();
    let policy_delivery = Uuid::new_v4();
    let encrypted = vault
        .seal(account, policy_endpoint, &crate::test_keys::key(8))
        .unwrap();
    db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext, \
         signing_secret_key_version,enabled) VALUES($1,$2,'https://example.invalid/hook',$3,1,true)",
        &[&policy_endpoint, &account, &encrypted],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id) VALUES($1,$2,$3,$4)",
        &[
            &policy_delivery,
            &account,
            &policy_endpoint,
            &signed.event_id,
        ],
    )
    .await
    .unwrap();
    assert!(
        crate::webhook_worker::dispatch_one(&scoped_url, &vault, "worker-policy")
            .await
            .unwrap()
    );
    let policy: (String, i16, String) = db
        .query_one(
            "SELECT d.status,d.attempt_count,a.outcome FROM webhook_deliveries d \
             JOIN webhook_attempts a ON a.delivery_id=d.id WHERE d.id=$1",
            &[&policy_delivery],
        )
        .await
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .unwrap();
    assert_eq!(policy, ("dead".into(), 1, "policy_rejected".into()));
    db.execute(
        "UPDATE webhook_endpoints SET enabled=false WHERE id=$1",
        &[&policy_endpoint],
    )
    .await
    .unwrap();

    let changed = InboundEvent {
        part_count: 2,
        signature_der: &[],
        ..signed
    };
    let changed_sig: Signature = signing.sign(&signed_event_bytes(session, &changed));
    let changed_der = changed_sig.to_der().as_bytes().to_vec();
    assert!(matches!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: &changed_der,
                ..changed
            }
        )
        .await,
        Err(InboundError::EventConflict)
    ));

    let same_sequence = InboundEvent {
        event_id: Uuid::new_v4(),
        signature_der: &[],
        ..signed
    };
    let sequence_sig: Signature = signing.sign(&signed_event_bytes(session, &same_sequence));
    let sequence_der = sequence_sig.to_der().as_bytes().to_vec();
    assert!(matches!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: &sequence_der,
                ..same_sequence
            }
        )
        .await,
        Err(InboundError::SequenceConflict)
    ));

    let stale = InboundSession {
        connection_epoch: 1,
        ..session
    };
    assert!(matches!(
        ingest(&mut db, stale, &signed).await,
        Err(InboundError::Unauthorized)
    ));
    let cross_tenant = InboundSession {
        account_id: other_account,
        ..session
    };
    assert!(matches!(
        ingest(&mut db, cross_tenant, &signed).await,
        Err(InboundError::Unauthorized)
    ));
    let bad_sig = InboundEvent {
        signature_der: &changed_der,
        ..signed
    };
    assert!(matches!(
        ingest(&mut db, session, &bad_sig).await,
        Err(InboundError::InvalidSignature)
    ));

    let no_source = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2,
        attempt_id: Uuid::new_v4(),
        signature_der: &[],
        ..signed
    };
    let no_source_sig: Signature = signing.sign(&signed_event_bytes(session, &no_source));
    let no_source_der = no_source_sig.to_der().as_bytes().to_vec();
    assert!(matches!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: &no_source_der,
                ..no_source
            }
        )
        .await,
        Err(InboundError::UnknownSource)
    ));

    // The same signed logical event reaches the worker once, then keeps its
    // delivery ID and exact body through a failed attempt and retry. A fake
    // transport inspects the prepared request without using external DNS.
    let retryable = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2,
        signature_der: &[],
        ..signed
    };
    let retry_sig: Signature = signing.sign(&signed_event_bytes(session, &retryable));
    let retry_der = retry_sig.to_der().as_bytes().to_vec();
    let retryable = InboundEvent {
        signature_der: &retry_der,
        ..retryable
    };
    // Committing that delivery wakes an in-process delivery lane at once
    // instead of leaving it to its poll interval. This test's own observer
    // replaces the process-wide notify (no other test can supply the wake)
    // and counts deliveries from a separate session at the instant of the
    // wake: a wake sent before the commit would not see the new row.
    let before: i64 = db
        .query_one("SELECT count(*) FROM webhook_deliveries", &[])
        .await
        .unwrap()
        .get(0);
    let (observer, seen) = crate::wakeups::committed_rows_observer(
        scoped_url.clone(),
        "SELECT count(*) FROM webhook_deliveries",
    );
    assert_eq!(
        crate::wakeups::observed(observer.clone(), ingest(&mut db, session, &retryable))
            .await
            .unwrap()
            .queued_deliveries,
        1
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(crate::wakeups::Queue::WebhookDelivery, before + 1)]
    );
    // A duplicate queues nothing and wakes nobody.
    assert_eq!(
        crate::wakeups::observed(observer, ingest(&mut db, session, &retryable))
            .await
            .unwrap()
            .queued_deliveries,
        0
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    let retry_event_id = retryable.event_id;
    let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    for (worker, status, acknowledged) in [("worker-fail", 500, false), ("worker-ack", 204, true)] {
        let captured = observed.clone();
        assert!(
            crate::webhook_worker::dispatch_one_with(
                &scoped_url,
                &vault,
                worker,
                move |url, body, secret| async move {
                    assert_eq!(url, "https://hooks.example.org/hook");
                    assert_eq!(secret.as_slice(), crate::test_keys::key(8).as_slice());
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(
                        json["event_id"].as_str(),
                        Some(retry_event_id.to_string().as_str())
                    );
                    assert_eq!(json["content_kind"], "metadata_only");
                    assert!(json["content_ciphertext_b64"].is_null());
                    assert!(json.get("sender_e164").is_none());
                    assert!(json.get("body").is_none());
                    let signature =
                        crate::webhook_egress::signature_header(&secret, 1_750_000_000, &body)
                            .unwrap();
                    assert_eq!(signature.len(), 67);
                    captured.lock().unwrap().push(body);
                    Ok(crate::webhook_egress::DeliveryResponse {
                        status,
                        acknowledged,
                    })
                }
            )
            .await
            .unwrap()
        );
        if !acknowledged {
            db.execute(
                "UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' WHERE event_id=$1",
                &[&retry_event_id],
            ).await.unwrap();
        }
    }
    {
        let bodies = observed.lock().unwrap();
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0], bodies[1]);
    }
    let result = db
        .query_one(
            "SELECT status,attempt_count FROM webhook_deliveries WHERE event_id=$1",
            &[&retry_event_id],
        )
        .await
        .unwrap();
    assert_eq!(result.get::<_, String>(0), "succeeded");
    assert_eq!(result.get::<_, i16>(1), 2);

    let opaque = vec![0x9du8; 64];
    let next = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 3,
        content: Content::OpaquePilot(&opaque),
        signature_der: &[],
        ..signed
    };
    let next_sig: Signature = signing.sign(&signed_event_bytes(session, &next));
    let next_der = next_sig.to_der().as_bytes().to_vec();
    assert_eq!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: &next_der,
                ..next
            }
        )
        .await
        .unwrap(),
        IngestOutcome {
            created: true,
            queued_deliveries: 1,
            suppression_cleared: false,
        }
    );
    // Make the due condition explicit instead of relying on nearly coincident
    // insertion and claim transaction timestamps.
    assert_eq!(
        db.execute(
            "UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' WHERE event_id=$1",
            &[&next.event_id],
        )
        .await
        .unwrap(),
        1
    );
    let stored_size: i32 = db
        .query_one(
            "SELECT octet_length(content_ciphertext) FROM inbound_events WHERE id=$1",
            &[&next.event_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored_size, 64);
    let too_short = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 4,
        content: Content::OpaquePilot(&opaque[..31]),
        signature_der: &next_der,
        ..next
    };
    assert!(matches!(
        ingest(&mut db, session, &too_short).await,
        Err(InboundError::InvalidInput)
    ));
    let unverified_content = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 5,
        classification: Classification::SimUnverified,
        content: Content::OpaquePilot(&opaque),
        signature_der: &next_der,
        ..next
    };
    assert!(matches!(
        ingest(&mut db, session, &unverified_content).await,
        Err(InboundError::InvalidInput)
    ));
    let key_lease = claim_webhook(&mut db, "worker-key").await.unwrap().unwrap();
    defer_webhook_key_failure(&mut db, &key_lease)
        .await
        .unwrap();
    let deferred = db
        .query_one(
            "SELECT status,attempt_count,key_failure_count FROM webhook_deliveries WHERE id=$1",
            &[&key_lease.delivery_id],
        )
        .await
        .unwrap();
    assert_eq!(deferred.get::<_, String>(0), "pending");
    assert_eq!(deferred.get::<_, i16>(1), 0);
    assert_eq!(deferred.get::<_, i32>(2), 1);
    let claim_records: i64 = db
        .query_one(
            "SELECT count(*) FROM webhook_attempts WHERE delivery_id=$1",
            &[&key_lease.delivery_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(claim_records, 0);
    assert!(matches!(
        defer_webhook_key_failure(&mut db, &key_lease).await,
        Err(InboundError::StaleLease)
    ));
    db.execute(
        "UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' WHERE id=$1",
        &[&key_lease.delivery_id],
    )
    .await
    .unwrap();
    let expiring_lease = claim_webhook(&mut db, "worker-c").await.unwrap().unwrap();
    db.execute(
        "UPDATE webhook_deliveries SET lease_until=now()-interval '1 second' WHERE id=$1",
        &[&expiring_lease.delivery_id],
    )
    .await
    .unwrap();
    // The lane recovers expired leases once per tick before claiming again.
    recover_expired_webhook_leases(&mut db).await.unwrap();
    assert!(claim_webhook(&mut db, "worker-d").await.unwrap().is_none());
    let recovered = db
        .query_one(
            "SELECT d.status,a.outcome FROM webhook_deliveries d JOIN webhook_attempts a \
         ON a.delivery_id=d.id WHERE d.id=$1",
            &[&expiring_lease.delivery_id],
        )
        .await
        .unwrap();
    assert_eq!(recovered.get::<_, String>(0), "pending");
    assert_eq!(recovered.get::<_, String>(1), "timeout");
    assert!(matches!(
        finish_webhook(&mut db, &expiring_lease, WebhookOutcome::Ack, Some(200)).await,
        Err(InboundError::StaleLease)
    ));
    for number in 2..=7 {
        db.execute(
            "UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' WHERE id=$1",
            &[&expiring_lease.delivery_id],
        )
        .await
        .unwrap();
        let retry_lease = claim_webhook(&mut db, "worker-d").await.unwrap().unwrap();
        assert_eq!(retry_lease.attempt_number, number);
        finish_webhook(&mut db, &retry_lease, WebhookOutcome::Timeout, None)
            .await
            .unwrap();
    }
    let dead: String = db
        .query_one(
            "SELECT status FROM webhook_deliveries WHERE id=$1",
            &[&expiring_lease.delivery_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(dead, "dead");
    assert!(claim_webhook(&mut db, "worker-e").await.unwrap().is_none());

    // Lock contention must not let a session outlive its wall-clock lease.
    let (mut peer, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    peer.batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()+interval '1 second' WHERE device_id=$1", &[&device]).await.unwrap();
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = peer.transaction().await.unwrap();
    blocker
        .query_one(
            "SELECT id FROM message_attempts WHERE id=$1 FOR UPDATE",
            &[&attempt],
        )
        .await
        .unwrap();
    let delayed = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 1000,
        ..unsigned
    };
    let signature: Signature = signing.sign(&signed_event_bytes(session, &delayed));
    let signature = signature.to_der();
    let delayed = InboundEvent {
        signature_der: signature.as_bytes(),
        ..delayed
    };
    let (result, ()) = tokio::join!(ingest(&mut db, session, &delayed), async {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let waiting: bool = blocker.query_one("SELECT cardinality(pg_blocking_pids($1))>0", &[&pid]).await.unwrap().get(0);
                    if waiting { break; }
                    tokio::task::yield_now().await;
                }
                loop {
                    let expired: bool = blocker.query_one("SELECT lease_until<=clock_timestamp() FROM device_sessions WHERE device_id=$1", &[&device]).await.unwrap().get(0);
                    if expired { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await.unwrap();
        blocker.commit().await.unwrap();
    });
    assert!(
        matches!(result, Err(InboundError::Unauthorized)),
        "expired lease accepted inbound event: {result:?}"
    );
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM inbound_events WHERE id=$1",
            &[&delayed.event_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    db.execute(
        "UPDATE device_sessions SET lease_until=now()+interval '10 minutes' WHERE device_id=$1",
        &[&device],
    )
    .await
    .unwrap();
    // STOP and START carry no body or sender field. The signed attempt binds
    // them to the writer's exact account-scoped recipient. Replays are inert.
    let pending_sms = Uuid::new_v4();
    zrotext_delivery_store::DeliveryStore::new(&mut db)
        .accept(zrotext_delivery_store::NewMessage {
            account_id: account,
            device_id: device,
            client_message_id: pending_sms,
            idempotency_key: "signed-opt-out-cancellation",
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic pending message",
            expires_at_ms: i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
                + 60_000,
        })
        .await
        .unwrap();
    let stop = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2001,
        classification: Classification::OptOut,
        signature_der: &[],
        ..unsigned
    };
    let stop_signature: Signature = signing.sign(&signed_event_bytes(session, &stop));
    let stop_der = stop_signature.to_der();
    let stop = InboundEvent {
        signature_der: stop_der.as_bytes(),
        ..stop
    };
    assert!(ingest(&mut db, session, &stop).await.unwrap().created);
    let pending_state: String = db
        .query_one("SELECT state FROM messages WHERE id=$1", &[&pending_sms])
        .await
        .unwrap()
        .get(0);
    assert_eq!(pending_state, "cancelled");
    assert!(!ingest(&mut db, session, &stop).await.unwrap().created);
    let active: bool = db.query_one(
        "SELECT active FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164='+15551234567'",
        &[&account],
    ).await.unwrap().get(0);
    assert!(active);
    assert!(db.query_opt(
        "SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164='+15551234567'",
        &[&other_account],
    ).await.unwrap().is_none());
    let other_attempt = Uuid::new_v4();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,2,2,1,'submitted')",
        &[&other_attempt, &account, &message, &device],
    ).await.unwrap();
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,event_digest,observed_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now(),'submitted',0,1)",
        &[&Uuid::new_v4(), &account, &message, &other_attempt, &vec![5u8; 32]],
    ).await.unwrap();
    let wrong_window = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2002,
        attempt_id: other_attempt,
        observed_at_ms: stop.observed_at_ms + 1,
        classification: Classification::OptIn,
        signature_der: &[],
        ..unsigned
    };
    let wrong_signature: Signature = signing.sign(&signed_event_bytes(session, &wrong_window));
    let wrong_der = wrong_signature.to_der();
    assert!(
        !ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: wrong_der.as_bytes(),
                ..wrong_window
            }
        )
        .await
        .unwrap()
        .suppression_cleared
    );
    assert!(db.query_one(
        "SELECT active FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164='+15551234567'",
        &[&account],
    ).await.unwrap().get::<_, bool>(0));
    // An owner-recorded off-channel hold predates this START. The signed START
    // is verified new consent and releases it; nothing else can.
    let hold_owner = Uuid::new_v4();
    db.execute(
        "INSERT INTO users(id,email,password_hash) VALUES($1,'inbound-hold@example.test','unused')",
        &[&hold_owner],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
        &[&account, &hold_owner],
    )
    .await
    .unwrap();
    // Migration 038: a hold starts unreleased at the insert time. Both inserts
    // pass migration 036's own constraints; only the 038 guard rejects them.
    let rejected = Uuid::new_v4();
    assert!(
        db.execute(
            "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by,created_at)              VALUES($1,$2,'+15551234567','phone_call','consent_withdrawn',clock_timestamp()-interval '1 hour',$3,clock_timestamp()-interval '1 hour')",
            &[&rejected, &account, &hold_owner],
        )
        .await
        .is_err(),
        "a hold cannot be backdated"
    );
    assert!(
        db.execute(
            "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by,released_at,release_event_id)              VALUES($1,$2,'+15551234567','phone_call','consent_withdrawn',clock_timestamp(),$3,clock_timestamp(),$4)",
            &[&rejected, &account, &hold_owner, &stop.event_id],
        )
        .await
        .is_err(),
        "a hold cannot start released"
    );
    // Test setup only: record a hold two minutes before the STOP. Production
    // inserts always pass the guard above.
    let earlier_hold = Uuid::new_v4();
    db.batch_execute(
        "ALTER TABLE owner_recipient_holds DISABLE TRIGGER owner_recipient_holds_before_insert",
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by,created_at) \
         VALUES($1,$2,'+15551234567','phone_call','consent_withdrawn',to_timestamp($3::float8),$4,to_timestamp($3::float8))",
        &[&earlier_hold, &account, &((stop.observed_at_ms - 120_000) as f64 / 1000.0), &hold_owner],
    )
    .await
    .unwrap();
    db.batch_execute(
        "ALTER TABLE owner_recipient_holds ENABLE TRIGGER owner_recipient_holds_before_insert",
    )
    .await
    .unwrap();
    assert!(
        db.execute(
            "UPDATE owner_recipient_holds SET released_at=clock_timestamp(),release_event_id=$2 WHERE id=$1",
            &[&earlier_hold, &stop.event_id],
        )
        .await
        .is_err(),
        "a STOP event cannot release an owner hold"
    );
    let resume = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2003,
        observed_at_ms: stop.observed_at_ms + 1,
        classification: Classification::OptIn,
        signature_der: &[],
        ..unsigned
    };
    let resume_signature: Signature = signing.sign(&signed_event_bytes(session, &resume));
    let resume_der = resume_signature.to_der();
    let resume = InboundEvent {
        signature_der: resume_der.as_bytes(),
        ..resume
    };
    assert!(
        ingest(&mut db, session, &resume)
            .await
            .unwrap()
            .suppression_cleared
    );
    assert!(
        ingest(&mut db, session, &resume)
            .await
            .unwrap()
            .suppression_cleared
    );
    let inactive: bool = db.query_one(
        "SELECT NOT active FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164='+15551234567'",
        &[&account],
    ).await.unwrap().get(0);
    assert!(inactive);
    // Observed only two minutes after the hold, inside the five-minute future
    // skew inbound accepts, this START may predate the withdrawal on a phone
    // whose clock runs fast. It clears the SMS suppression but not the hold,
    // in the ingest path and in the database guard.
    assert_eq!(hold_release_event(&db, earlier_hold).await, None);
    assert!(
        db.execute(
            "UPDATE owner_recipient_holds SET released_at=clock_timestamp(),release_event_id=$2 WHERE id=$1",
            &[&earlier_hold, &resume.event_id],
        )
        .await
        .is_err(),
        "the guard applies the same skew bound"
    );
    assert!(
        db.execute(
            "INSERT INTO owner_opt_out_audit(id,account_id,event,hold_id,release_event_id) \
             VALUES($1,$2,'hold_released',$3,$4)",
            &[&Uuid::new_v4(), &account, &earlier_hold, &resume.event_id],
        )
        .await
        .is_err(),
        "a release audit row must match a released hold"
    );
    // A START observed more than five minutes after the hold releases it.
    let later_start = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2004,
        observed_at_ms: stop.observed_at_ms + 181_000,
        classification: Classification::OptIn,
        signature_der: &[],
        ..unsigned
    };
    let later_signature: Signature = signing.sign(&signed_event_bytes(session, &later_start));
    let later_der = later_signature.to_der();
    let later_start = InboundEvent {
        signature_der: later_der.as_bytes(),
        ..later_start
    };
    assert!(
        ingest(&mut db, session, &later_start)
            .await
            .unwrap()
            .created
    );
    assert!(
        !ingest(&mut db, session, &later_start)
            .await
            .unwrap()
            .created
    );
    assert_eq!(
        hold_release_event(&db, earlier_hold).await,
        Some(later_start.event_id)
    );
    let release_audits: i64 = db
        .query_one(
            "SELECT count(*) FROM owner_opt_out_audit WHERE hold_id=$1 AND event='hold_released' \
             AND actor_user_id IS NULL AND release_event_id=$2",
            &[&earlier_hold, &later_start.event_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        release_audits, 1,
        "the replayed START wrote no second release"
    );
    // Migration 039: a phone clock reading can only tighten the five-minute
    // rule. Rows: observed, device_sent, received, hold_created (seconds from
    // a fixed hub time; observed and device_sent on the phone clock) and the
    // expected release.
    for (observed, sent, received, created, expected, case) in [
        (
            400,
            None,
            100,
            0,
            true,
            "no reading: more than five minutes later",
        ),
        (
            290,
            None,
            100,
            0,
            false,
            "no reading: inside the five-minute margin",
        ),
        (
            600,
            Some(1300),
            100,
            0,
            false,
            "phone 20 min fast, late upload: START was before the hold",
        ),
        (
            400,
            Some(500),
            500,
            0,
            true,
            "accurate phone: more than five minutes later",
        ),
        (
            90,
            Some(100),
            100,
            0,
            false,
            "accurate phone: the floor still needs five minutes",
        ),
        (
            120,
            Some(700),
            700,
            0,
            false,
            "clock stepped back before upload: floor holds",
        ),
        (0, Some(40), 120, 10, false, "network delay: floor holds"),
        (
            400,
            Some(450),
            100,
            0,
            false,
            "reading shows the phone fast: corrected time too early",
        ),
    ] {
        let allowed: bool = db
            .query_one(
                "SELECT owner_hold_release_allowed( \
                   to_timestamp(1700000000+$1::float8), \
                   to_timestamp(1700000000+$2::float8), \
                   to_timestamp(1700000000+$3::float8), to_timestamp(1700000000+$4::float8))",
                &[
                    &f64::from(observed),
                    &sent.map(f64::from),
                    &f64::from(received),
                    &f64::from(created),
                ],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(allowed, expected, "{case}");
    }
    // Wiring through ingest_with_clock. Test setup only: record a hold ten
    // minutes ago.
    let clock_hold = Uuid::new_v4();
    db.batch_execute(
        "ALTER TABLE owner_recipient_holds DISABLE TRIGGER owner_recipient_holds_before_insert",
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by,created_at) \
         VALUES($1,$2,'+15551234567','email','consent_withdrawn',clock_timestamp()-interval '10 minutes',$3,clock_timestamp()-interval '10 minutes')",
        &[&clock_hold, &account, &hold_owner],
    )
    .await
    .unwrap();
    db.batch_execute(
        "ALTER TABLE owner_recipient_holds ENABLE TRIGGER owner_recipient_holds_before_insert",
    )
    .await
    .unwrap();
    let now_ms = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    };
    let signed_start = |sequence: i64, observed_at_ms: i64| {
        let start = InboundEvent {
            event_id: Uuid::new_v4(),
            sequence,
            observed_at_ms,
            classification: Classification::OptIn,
            signature_der: &[],
            ..unsigned
        };
        let signature: Signature = signing.sign(&signed_event_bytes(session, &start));
        (start, signature.to_der())
    };
    // A phone running 20 minutes fast uploads late a START it received before
    // the withdrawal. Its own clock puts the START four minutes ahead of the
    // hub, beyond the old five-minute margin after the hold; the measured
    // offset places it before the hold, so the hold stays.
    let (fast, fast_der) = signed_start(2090, now_ms() + 4 * 60_000);
    let fast = InboundEvent {
        signature_der: fast_der.as_bytes(),
        ..fast
    };
    assert!(
        ingest_with_clock(&mut db, session, &fast, Some(now_ms() + 20 * 60_000))
            .await
            .unwrap()
            .created
    );
    assert_eq!(hold_release_event(&db, clock_hold).await, None);
    // A reading more than a day away is not stored and keeps the old rule.
    // Observed six minutes ago, inside the old margin after the hold.
    let (wild, wild_der) = signed_start(2091, now_ms() - 6 * 60_000);
    let wild = InboundEvent {
        signature_der: wild_der.as_bytes(),
        ..wild
    };
    assert!(
        ingest_with_clock(&mut db, session, &wild, Some(now_ms() - 2 * 86_400_000))
            .await
            .unwrap()
            .created
    );
    let wild_stored: bool = db
        .query_one(
            "SELECT device_sent_at IS NULL FROM inbound_events WHERE id=$1",
            &[&wild.event_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(wild_stored);
    assert_eq!(hold_release_event(&db, clock_hold).await, None);
    // An accurate phone's START now releases the hold.
    let (accurate, accurate_der) = signed_start(2092, now_ms());
    let accurate = InboundEvent {
        signature_der: accurate_der.as_bytes(),
        ..accurate
    };
    assert!(
        ingest_with_clock(&mut db, session, &accurate, Some(now_ms()))
            .await
            .unwrap()
            .created
    );
    assert_eq!(
        hold_release_event(&db, clock_hold).await,
        Some(accurate.event_id)
    );
    // A hold recorded after a START was observed is not released by it.
    let later_hold = Uuid::new_v4();
    db.execute(
        "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) \
         VALUES($1,$2,'+15551234567','email','opt_out',clock_timestamp(),$3)",
        &[&later_hold, &account, &hold_owner],
    )
    .await
    .unwrap();
    let stale_start = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2100,
        observed_at_ms: stop.observed_at_ms + 1,
        classification: Classification::OptIn,
        signature_der: &[],
        ..unsigned
    };
    let stale_signature: Signature = signing.sign(&signed_event_bytes(session, &stale_start));
    let stale_der = stale_signature.to_der();
    assert!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: stale_der.as_bytes(),
                ..stale_start
            }
        )
        .await
        .unwrap()
        .created
    );
    assert!(
        db.query_one(
            "SELECT released_at IS NULL FROM owner_recipient_holds WHERE id=$1",
            &[&later_hold],
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let forged = InboundEvent {
        classification: Classification::OptOut,
        ..resume
    };
    assert!(matches!(
        ingest(&mut db, session, &forged).await,
        Err(InboundError::InvalidSignature)
    ));
    let (mut suppression_db, suppression_connection) =
        tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
    tokio::spawn(async move { suppression_connection.await.unwrap() });
    suppression_db
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let disabled_event = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2004,
        // The disable fence keeps blocking consent transitions, which still
        // queue on the account row lock before touching suppression. A
        // capture event no longer takes that lock, so it must not be the one
        // proving this fence.
        classification: Classification::OptOut,
        signature_der: &[],
        ..unsigned
    };
    let disabled_signature: Signature = signing.sign(&signed_event_bytes(session, &disabled_event));
    let disabled_der = disabled_signature.to_der();
    let disabled_event = InboundEvent {
        signature_der: disabled_der.as_bytes(),
        ..disabled_event
    };
    let ingest_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let disable_tx = suppression_db.transaction().await.unwrap();
    disable_tx
        .query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&account],
        )
        .await
        .unwrap();
    let disabled_result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(ingest(&mut db, session, &disabled_event), async {
            loop {
                let waiting: bool = disable_tx
                    .query_one("SELECT cardinality(pg_blocking_pids($1))>0", &[&ingest_pid])
                    .await
                    .unwrap()
                    .get(0);
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
            disable_tx
                .execute(
                    "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
                    &[&account],
                )
                .await
                .unwrap();
            disable_tx.commit().await.unwrap();
        })
    })
    .await
    .unwrap()
    .0;
    assert!(matches!(disabled_result, Err(InboundError::Unauthorized)));
    assert!(
        db.query_opt(
            "SELECT 1 FROM inbound_events WHERE id=$1",
            &[&disabled_event.event_id]
        )
        .await
        .unwrap()
        .is_none()
    );
    suppression_db
        .execute(
            "UPDATE accounts SET disabled_at=NULL WHERE id=$1",
            &[&account],
        )
        .await
        .unwrap();
    let (mut accept_db, accept_connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { accept_connection.await.unwrap() });
    accept_db
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let accept_pid: i32 = accept_db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = suppression_db.transaction().await.unwrap();
    blocker
        .query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
            &[&account],
        )
        .await
        .unwrap();
    let race_id = Uuid::new_v4();
    let mut race_store = zrotext_delivery_store::DeliveryStore::new(&mut accept_db);
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            race_store.accept(
                zrotext_delivery_store::NewMessage {
                    account_id: account, client_message_id: race_id, device_id: device,
                    idempotency_key: "suppression-race", recipient_e164: "+15551234567",
                    synthetic_payload: b"synthetic", expires_at_ms: SystemTime::now()
                        .duration_since(UNIX_EPOCH).unwrap().as_millis() as i64 + 60_000,
                }
            ),
            async {
                loop {
                    let waiting: bool = blocker.query_one(
                        "SELECT cardinality(pg_blocking_pids($1))>0", &[&accept_pid]
                    ).await.unwrap().get(0);
                    if waiting { break; }
                    tokio::task::yield_now().await;
                }
                blocker.execute(
                    "UPDATE recipient_suppressions SET active=TRUE,source_event_id=$3,source='sms_keyword' WHERE account_id=$1 AND recipient_e164=$2",
                    &[&account, &"+15551234567", &stop.event_id],
                ).await.unwrap();
                blocker.commit().await.unwrap();
            }
        )
    }).await.unwrap().0;
    assert!(matches!(
        result,
        Err(zrotext_delivery_store::StoreError::RecipientSuppressed)
    ));
    assert!(
        db.query_opt("SELECT 1 FROM messages WHERE id=$1", &[&race_id])
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.query_opt(
            "SELECT 1 FROM idempotency_keys WHERE account_id=$1 AND key='suppression-race'",
            &[&account]
        )
        .await
        .unwrap()
        .is_none()
    );
    // Data retention nulls a terminal source's recipient and payload. A stored
    // event stays exact-replayable; a new STOP for that attempt is deferred
    // instead of reading the NULL recipient, and a new capture is refused
    // permanently.
    db.execute(
        "UPDATE recipient_suppressions SET active=FALSE,source_event_id=$2,source='sms_resume' WHERE account_id=$1",
        &[&account, &resume.event_id],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE messages SET state='delivered',recipient_e164=NULL,transport_payload=NULL WHERE id=$1",
        &[&message],
    )
    .await
    .unwrap();
    let redacted_replay = ingest(&mut db, session, &resume).await.unwrap();
    assert!(!redacted_replay.created);
    assert!(redacted_replay.suppression_cleared);
    assert!(!ingest(&mut db, session, &stop).await.unwrap().created);
    let late_stop = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2005,
        classification: Classification::OptOut,
        signature_der: &[],
        ..unsigned
    };
    let late_signature: Signature = signing.sign(&signed_event_bytes(session, &late_stop));
    let late_der = late_signature.to_der();
    let late_stop = InboundEvent {
        signature_der: late_der.as_bytes(),
        ..late_stop
    };
    assert!(matches!(
        ingest(&mut db, session, &late_stop).await,
        Err(InboundError::SourceRetired)
    ));
    assert!(
        db.query_opt(
            "SELECT 1 FROM inbound_events WHERE id=$1",
            &[&late_stop.event_id]
        )
        .await
        .unwrap()
        .is_none()
    );
    let late_capture = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2006,
        classification: Classification::CapturedLocal,
        signature_der: &[],
        ..unsigned
    };
    let capture_signature: Signature = signing.sign(&signed_event_bytes(session, &late_capture));
    let capture_der = capture_signature.to_der();
    assert!(matches!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: capture_der.as_bytes(),
                ..late_capture
            }
        )
        .await,
        Err(InboundError::UnknownSource)
    ));
    assert!(db.query_one(
        "SELECT NOT active FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164='+15551234567'",
        &[&account],
    ).await.unwrap().get::<_, bool>(0));
    db.execute(
        "UPDATE device_keys SET revoked_at=now() WHERE device_id=$1",
        &[&device],
    )
    .await
    .unwrap();
    assert!(matches!(
        ingest(&mut db, session, &signed).await,
        Err(InboundError::Unauthorized)
    ));
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn signed_stop_after_content_retention_still_suppresses_recipient() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("inbound_test_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    for migration in [
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
        include_str!("../../../../deploy/compose/migrations/020_enrollment_retention_indexes.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!("../../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
        include_str!("../../../../deploy/compose/migrations/025_account_recovery.sql"),
        include_str!("../../../../deploy/compose/migrations/026_data_retention.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
        include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
        include_str!("../../../../deploy/compose/migrations/041_device_preconditions.sql"),
        include_str!("../../../../deploy/compose/migrations/047_device_network_service.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public = signing
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute("INSERT INTO sites(site_id) VALUES('test')", &[])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[&device, &account, &public, &vec![1u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) \
         VALUES($1,$2,'test','instance',2,now()+interval '10 minutes',1)",
        &[&device, &account],
    ).await.unwrap();
    // Delivered past the default content window, with its sent callback
    // received at the same time: inside the default event window.
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
         transport_mode,transport_payload,request_digest,state,expires_at,created_at,updated_at) \
         VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'delivered',now()+interval '1 hour', \
         now()-interval '31 days',now()-interval '31 days')",
        &[&message, &account, &device, &vec![2u8;32], &b"fixture".as_slice(), &vec![3u8;32]],
    ).await.unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation, \
         session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')",
        &[&attempt, &account, &message, &device],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code, \
         event_digest,observed_at,received_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now()-interval '31 days',now()-interval '31 days', \
         'submitted',0,1)",
        &[&Uuid::new_v4(), &account, &message, &attempt, &vec![4u8; 32]],
    )
    .await
    .unwrap();
    let pruned = crate::retention::prune(
        &mut db,
        crate::retention::RetentionPolicy::default(),
        crate::retention::BATCH_SIZE,
    )
    .await
    .unwrap();
    assert_eq!(
        pruned.messages, 0,
        "reply target retired inside the event window"
    );
    let recipient_kept: Option<String> = db
        .query_one(
            "SELECT recipient_e164 FROM messages WHERE id=$1",
            &[&message],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(recipient_kept.as_deref(), Some("+15551234567"));

    let session = InboundSession {
        account_id: account,
        device_id: device,
        site_id: "test",
        instance_id: "instance",
        connection_epoch: 2,
        deployment_epoch: 1,
    };
    let unsigned = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 1,
        message_id: message,
        attempt_id: attempt,
        classification: Classification::OptOut,
        observed_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        part_count: 1,
        content: Content::MetadataOnly,
        signature_der: &[],
    };
    let stop_signature: Signature = signing.sign(&signed_event_bytes(session, &unsigned));
    let stop_der = stop_signature.to_der();
    let stop = InboundEvent {
        signature_der: stop_der.as_bytes(),
        ..unsigned
    };
    assert!(ingest(&mut db, session, &stop).await.unwrap().created);
    let active: bool = db.query_one(
        "SELECT active FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164='+15551234567'",
        &[&account],
    ).await.unwrap().get(0);
    assert!(active);
    let expires_at_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 60_000;
    assert!(matches!(
        zrotext_delivery_store::DeliveryStore::new(&mut db)
            .accept(zrotext_delivery_store::NewMessage {
                account_id: account,
                device_id: device,
                client_message_id: Uuid::new_v4(),
                idempotency_key: "after-retained-stop",
                recipient_e164: "+15551234567",
                synthetic_payload: b"synthetic",
                expires_at_ms,
            })
            .await,
        Err(zrotext_delivery_store::StoreError::RecipientSuppressed)
    ));
    let resume = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 2,
        observed_at_ms: unsigned.observed_at_ms + 1,
        classification: Classification::OptIn,
        signature_der: &[],
        ..unsigned
    };
    let resume_signature: Signature = signing.sign(&signed_event_bytes(session, &resume));
    let resume_der = resume_signature.to_der();
    assert!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: resume_der.as_bytes(),
                ..resume
            }
        )
        .await
        .unwrap()
        .suppression_cleared
    );
    zrotext_delivery_store::DeliveryStore::new(&mut db)
        .accept(zrotext_delivery_store::NewMessage {
            account_id: account,
            device_id: device,
            client_message_id: Uuid::new_v4(),
            idempotency_key: "after-retained-start",
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic",
            expires_at_ms,
        })
        .await
        .unwrap();
    // Once the sent evidence leaves the event window the recipient is retired
    // and its event row deleted in the same pass. A source retired under the
    // earlier rule can still carry sent evidence; a STOP for it is deferred,
    // not quarantined, and nothing is stored for it.
    db.execute(
        "UPDATE message_events SET received_at=now()-interval '91 days' WHERE attempt_id=$1",
        &[&attempt],
    )
    .await
    .unwrap();
    let retired = crate::retention::prune(
        &mut db,
        crate::retention::RetentionPolicy::default(),
        crate::retention::BATCH_SIZE,
    )
    .await
    .unwrap();
    assert_eq!(retired.messages, 1);
    assert!(
        db.query_one(
            "SELECT recipient_e164 FROM messages WHERE id=$1",
            &[&message]
        )
        .await
        .unwrap()
        .get::<_, Option<String>>(0)
        .is_none()
    );
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code, \
         event_digest,observed_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now(),'submitted',0,1)",
        &[
            &Uuid::new_v4(),
            &account,
            &message,
            &attempt,
            &vec![4u8; 32],
        ],
    )
    .await
    .unwrap();
    let late_stop = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 3,
        observed_at_ms: unsigned.observed_at_ms + 2,
        signature_der: &[],
        ..unsigned
    };
    let late_signature: Signature = signing.sign(&signed_event_bytes(session, &late_stop));
    let late_der = late_signature.to_der();
    assert!(matches!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: late_der.as_bytes(),
                ..late_stop
            }
        )
        .await,
        Err(InboundError::SourceRetired)
    ));
    assert!(
        db.query_opt(
            "SELECT 1 FROM inbound_events WHERE id=$1",
            &[&late_stop.event_id]
        )
        .await
        .unwrap()
        .is_none()
    );
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn fresh_signed_events_share_a_durable_budget_and_replays_are_free() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("inbound_budget_test_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    for migration in [
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
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
        include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let endpoint = Uuid::new_v4();
    let vault =
        crate::webhook_worker::WebhookSecretVault::new(1, zeroize::Zeroizing::new(vec![7_u8; 32]))
            .unwrap();
    let endpoint_secret = vault.seal(account, endpoint, &[8_u8; 32]).unwrap();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public = signing
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    db.execute(
        "INSERT INTO accounts(id) VALUES($1),($2)",
        &[&account, &other_account],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO sites(site_id) VALUES('test')", &[])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[&device, &account, &public, &vec![1u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) \
         VALUES($1,$2,'test','instance',2,now()+interval '10 minutes',1)",
        &[&device, &account],
    ).await.unwrap();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
         transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')",
        &[&message, &account, &device, &vec![2u8;32], &b"fixture".as_slice(), &vec![3u8;32]],
    ).await.unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation, \
         session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')",
        &[&attempt, &account, &message, &device],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code, \
         event_digest,observed_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now(),'submitted',0,1)",
        &[
            &Uuid::new_v4(),
            &account,
            &message,
            &attempt,
            &vec![4u8; 32],
        ],
    )
    .await
    .unwrap();
    // A synthetic endpoint is enough to exercise durable fanout and a fake
    // transport below; no external webhook request is made.
    db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext, \
         signing_secret_key_version,enabled) VALUES($1,$2,'https://hooks.example.org/hook',$3,1,true)",
        &[&endpoint, &account, &endpoint_secret],
    ).await.unwrap();

    let session = InboundSession {
        account_id: account,
        device_id: device,
        site_id: "test",
        instance_id: "instance",
        connection_epoch: 2,
        deployment_epoch: 1,
    };
    let unsigned = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 1,
        message_id: message,
        attempt_id: attempt,
        classification: Classification::CapturedLocal,
        observed_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        part_count: 1,
        content: Content::MetadataOnly,
        signature_der: &[],
    };
    let sig: Signature = signing.sign(&signed_event_bytes(session, &unsigned));
    let sig_bytes = sig.to_der().as_bytes().to_vec();
    let signed = InboundEvent {
        signature_der: &sig_bytes,
        ..unsigned
    };

    // Concurrent authenticated sockets target the same legitimate source.
    for sequence in 1..=180_i64 {
        let event = InboundEvent {
            event_id: Uuid::new_v4(),
            sequence,
            ..unsigned
        };
        let sig: Signature = signing.sign(&signed_event_bytes(session, &event));
        let sig = sig.to_der();
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: sig.as_bytes(),
                ..event
            },
        )
        .await
        .unwrap();
    }
    let mut tasks = Vec::new();
    for sequence in 181..=204_i64 {
        let url = url.clone();
        let schema = schema.clone();
        let signing = signing.clone();
        let unsigned = InboundEvent {
            event_id: Uuid::new_v4(),
            sequence,
            ..unsigned
        };
        tasks.push(tokio::spawn(async move {
            let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            db.batch_execute(&format!("SET search_path TO {schema}"))
                .await
                .unwrap();
            let sig: Signature = signing.sign(&signed_event_bytes(session, &unsigned));
            let sig = sig.to_der();
            let event = InboundEvent {
                signature_der: sig.as_bytes(),
                ..unsigned
            };
            let result = ingest(&mut db, session, &event).await;
            assert!(result.is_ok() || matches!(result, Err(InboundError::BudgetExhausted)));
            (
                unsigned.event_id,
                unsigned.sequence,
                sig.as_bytes().to_vec(),
                result.is_ok(),
            )
        }));
    }
    let mut accepted = Vec::new();
    for task in tasks {
        let row = task.await.unwrap();
        if row.3 {
            accepted.push(row);
        }
    }
    assert_eq!(
        accepted.len(),
        20,
        "fresh signed UUIDs must not evade the device budget"
    );
    let row = db.query_one("SELECT (SELECT count(*) FROM inbound_events),(SELECT count(*) FROM webhook_deliveries)", &[]).await.unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (200, 200));
    let replay = InboundEvent {
        event_id: accepted[0].0,
        sequence: accepted[0].1,
        signature_der: &accepted[0].2,
        ..unsigned
    };
    assert_eq!(
        ingest(&mut db, session, &replay).await.unwrap(),
        IngestOutcome {
            created: false,
            queued_deliveries: 0,
            suppression_cleared: false,
        }
    );
    // A bad signature cannot burn another charge, nor can an exact replay.
    let invalid = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 500,
        ..signed
    };
    assert!(matches!(
        ingest(&mut db, session, &invalid).await,
        Err(InboundError::InvalidSignature)
    ));
    assert!(matches!(
        ingest(&mut db, session, &signed).await,
        Err(InboundError::SequenceConflict)
    ));
    let counters = db
        .query(
            "SELECT attempts FROM auth_abuse_counters WHERE scope='inbound_daily'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(counters.len(), 2);
    assert!(counters.iter().all(|r| r.get::<_, i32>(0) == 200));
    // Cleanup must preserve budgets beyond the generic two-minute retention.
    db.execute("UPDATE auth_abuse_counters SET updated_at=now()-interval '3 minutes' WHERE scope='inbound_daily'", &[]).await.unwrap();
    crate::auth::abuse_limits::prune(&db).await.unwrap();
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM auth_abuse_counters WHERE scope='inbound_daily'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        2
    );
    // Seed the account's last slot while this device still has allowance.
    db.execute("UPDATE auth_abuse_counters SET attempts=999 WHERE scope='inbound_daily' AND subject_hash=$1", &[&budget_key("account", account)]).await.unwrap();
    db.execute(
        "UPDATE auth_abuse_counters SET attempts=1 WHERE scope='inbound_daily' AND subject_hash=$1",
        &[&budget_key("device", device)],
    )
    .await
    .unwrap();
    // Two sockets race with one exact event at the last account slot. The
    // second must observe a free replay even after the first fills the budget.
    let last_slot = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 501,
        ..unsigned
    };
    let mut last_slot_tasks = Vec::new();
    for _ in 0..2 {
        let url = url.clone();
        let schema = schema.clone();
        let signing = signing.clone();
        last_slot_tasks.push(tokio::spawn(async move {
            let (mut peer, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            peer.batch_execute(&format!("SET search_path TO {schema}"))
                .await
                .unwrap();
            let sig: Signature = signing.sign(&signed_event_bytes(session, &last_slot));
            let sig = sig.to_der();
            ingest(
                &mut peer,
                session,
                &InboundEvent {
                    signature_der: sig.as_bytes(),
                    ..last_slot
                },
            )
            .await
            .unwrap()
        }));
    }
    let mut last_slot_outcomes = Vec::new();
    for task in last_slot_tasks {
        last_slot_outcomes.push(task.await.unwrap());
    }
    assert_eq!(
        last_slot_outcomes
            .iter()
            .filter(|outcome| outcome.created)
            .count(),
        1
    );
    assert_eq!(
        last_slot_outcomes
            .iter()
            .filter(|outcome| !outcome.created)
            .count(),
        1
    );
    let over_limit = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 502,
        ..unsigned
    };
    let over_limit_sig: Signature = signing.sign(&signed_event_bytes(session, &over_limit));
    let over_limit_sig = over_limit_sig.to_der();
    assert!(matches!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: over_limit_sig.as_bytes(),
                ..over_limit
            },
        )
        .await,
        Err(InboundError::BudgetExhausted)
    ));
    assert_eq!(db.query_one("SELECT attempts FROM auth_abuse_counters WHERE scope='inbound_daily' AND subject_hash=$1", &[&budget_key("device", device)]).await.unwrap().get::<_,i32>(0), 2);
    let row = db.query_one("SELECT (SELECT count(*) FROM inbound_events),(SELECT count(*) FROM webhook_deliveries)", &[]).await.unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (201, 201));
    // A rejected fresh event must never reach the inbound_events INSERT.
    // Counting committed rows alone would miss rolled-back heap/index writes.
    db.batch_execute("CREATE FUNCTION reject_budget_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'over-budget inbound INSERT attempted'; END $$; CREATE TRIGGER reject_budget_insert BEFORE INSERT ON inbound_events FOR EACH ROW EXECUTE FUNCTION reject_budget_insert()")
        .await
        .unwrap();
    let over_budget = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 503,
        ..unsigned
    };
    let over_budget_sig: Signature = signing.sign(&signed_event_bytes(session, &over_budget));
    let over_budget_sig = over_budget_sig.to_der();
    assert!(matches!(
        ingest(
            &mut db,
            session,
            &InboundEvent {
                signature_der: over_budget_sig.as_bytes(),
                ..over_budget
            },
        )
        .await,
        Err(InboundError::BudgetExhausted)
    ));
    assert_eq!(
        ingest(&mut db, session, &replay).await.unwrap(),
        IngestOutcome {
            created: false,
            queued_deliveries: 0,
            suppression_cleared: false,
        }
    );
    // Rotating device identities cannot bypass a saturated account or grow counters.
    assert!(
        !consume_storage_budget(&db, account, Uuid::new_v4())
            .await
            .unwrap()
    );
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM auth_abuse_counters WHERE scope='inbound_daily'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        2
    );
    assert!(
        consume_storage_budget(&db, other_account, Uuid::new_v4())
            .await
            .unwrap()
    );
    // Window renewal uses database wall time, independent of device timestamps.
    db.execute("UPDATE auth_abuse_counters SET window_started_at=now()-interval '25 hours' WHERE scope='inbound_daily'", &[]).await.unwrap();
    assert!(consume_storage_budget(&db, account, device).await.unwrap());
    assert_eq!(db.query_one("SELECT attempts FROM auth_abuse_counters WHERE scope='inbound_daily' AND subject_hash=$1", &[&budget_key("account", account)]).await.unwrap().get::<_,i32>(0), 1);
    db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[test]
fn hold_release_skew_matches_the_database_guard() {
    // Migration 039's shared release rule always keeps the same five-minute
    // floor as MAX_FUTURE_MS; change both together.
    assert_eq!(MAX_FUTURE_MS, 5 * 60 * 1000);
    assert!(
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql")
            .contains(
                "extract(epoch FROM observed_at) > extract(epoch FROM hold_created_at) + 300"
            )
    );
}

async fn hold_release_event(db: &tokio_postgres::Client, hold: Uuid) -> Option<Uuid> {
    db.query_one(
        "SELECT release_event_id FROM owner_recipient_holds WHERE id=$1",
        &[&hold],
    )
    .await
    .unwrap()
    .get(0)
}

#[test]
fn only_consent_changes_skip_the_shared_storage_budget() {
    for classification in [
        Classification::CapturedLocal,
        Classification::SimUnverified,
        Classification::SendUnverified,
        Classification::EncryptionUnverified,
    ] {
        assert!(!classification.changes_consent(), "{classification:?}");
    }
    for classification in [
        Classification::OptOut,
        Classification::OptOutReview,
        Classification::OptIn,
    ] {
        assert!(classification.changes_consent(), "{classification:?}");
    }
}

struct BudgetDevice {
    device: Uuid,
    message: Uuid,
    attempt: Uuid,
    signing: SigningKey,
}

async fn seed_budget_device(db: &Client, account: Uuid, recipient: &str) -> BudgetDevice {
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public = signing
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'budget fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[
            &device,
            &account,
            &public,
            &Sha256::digest(&public).to_vec(),
        ],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) \
         VALUES($1,$2,'test','instance',2,now()+interval '10 minutes',1)",
        &[&device, &account],
    ).await.unwrap();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
         transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,$4,$5,'synthetic_alpha',$6,$7,'submitted',now()+interval '1 hour')",
        &[
            &message,
            &account,
            &device,
            &recipient,
            &vec![2u8; 32],
            &b"fixture".as_slice(),
            &vec![3u8; 32],
        ],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation, \
         session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')",
        &[&attempt, &account, &message, &device],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code, \
         event_digest,observed_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now(),'submitted',0,1)",
        &[
            &Uuid::new_v4(),
            &account,
            &message,
            &attempt,
            &vec![4u8; 32],
        ],
    )
    .await
    .unwrap();
    BudgetDevice {
        device,
        message,
        attempt,
        signing,
    }
}

async fn ingest_budget_event(
    db: &mut Client,
    account: Uuid,
    device: &BudgetDevice,
    sequence: i64,
    classification: Classification,
) -> Result<IngestOutcome, InboundError> {
    let session = InboundSession {
        account_id: account,
        device_id: device.device,
        site_id: "test",
        instance_id: "instance",
        connection_epoch: 2,
        deployment_epoch: 1,
    };
    let unsigned = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence,
        message_id: device.message,
        attempt_id: device.attempt,
        classification,
        observed_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        part_count: 1,
        content: Content::MetadataOnly,
        signature_der: &[],
    };
    let signature: Signature = device.signing.sign(&signed_event_bytes(session, &unsigned));
    let signature = signature.to_der();
    ingest(
        db,
        session,
        &InboundEvent {
            signature_der: signature.as_bytes(),
            ..unsigned
        },
    )
    .await
}

async fn suppression_active(db: &Client, account: Uuid, recipient: &str) -> Option<bool> {
    db.query_opt(
        "SELECT active FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2",
        &[&account, &recipient],
    )
    .await
    .unwrap()
    .map(|row| row.get(0))
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn consent_changes_are_not_deferred_by_a_spent_storage_budget() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("inbound_consent_budget_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    for migration in [
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
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
        include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute("INSERT INTO sites(site_id) VALUES('test')", &[])
        .await
        .unwrap();
    let flooder = seed_budget_device(&db, account, "+15550000001").await;
    let other = seed_budget_device(&db, account, "+15550000002").await;

    // One device spends its whole shared allowance on junk events.
    for sequence in 1..=200 {
        ingest_budget_event(
            &mut db,
            account,
            &flooder,
            sequence,
            Classification::CapturedLocal,
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        ingest_budget_event(
            &mut db,
            account,
            &flooder,
            201,
            Classification::CapturedLocal
        )
        .await,
        Err(InboundError::BudgetExhausted)
    ));
    // Other devices' traffic spends the rest of the account's shared budget.
    db.execute(
        "UPDATE auth_abuse_counters SET attempts=1000 WHERE scope='inbound_daily' AND subject_hash=$1",
        &[&budget_key("account", account)],
    )
    .await
    .unwrap();
    assert!(matches!(
        ingest_budget_event(&mut db, account, &other, 1, Classification::CapturedLocal).await,
        Err(InboundError::BudgetExhausted)
    ));

    // A STOP from another device, and from the flooding device itself, is
    // still recorded and suppresses its recipient.
    assert!(
        ingest_budget_event(&mut db, account, &other, 2, Classification::OptOut)
            .await
            .unwrap()
            .created
    );
    assert_eq!(
        suppression_active(&db, account, "+15550000002").await,
        Some(true)
    );
    assert!(
        ingest_budget_event(
            &mut db,
            account,
            &flooder,
            202,
            Classification::OptOutReview
        )
        .await
        .unwrap()
        .created
    );
    assert_eq!(
        suppression_active(&db, account, "+15550000001").await,
        Some(true)
    );
    // START is a consent change too and clears the matching STOP. It must be
    // observed strictly after the STOP it clears.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let resumed = ingest_budget_event(&mut db, account, &other, 3, Classification::OptIn)
        .await
        .unwrap();
    assert!(resumed.created && resumed.suppression_cleared);
    assert_eq!(
        suppression_active(&db, account, "+15550000002").await,
        Some(false)
    );
    // Consent changes left the shared counters untouched.
    let shared: Vec<i32> = db
        .query(
            "SELECT attempts FROM auth_abuse_counters WHERE scope='inbound_daily' ORDER BY attempts",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(shared, vec![200, 1000]);

    // The consent budget is per device with no account-wide ceiling, so a
    // device that exhausts its own allowance cannot defer another's STOP.
    db.execute(
        "UPDATE auth_abuse_counters SET attempts=10000 WHERE scope='inbound_consent_daily' AND subject_hash=$1",
        &[&budget_key("device", flooder.device)],
    )
    .await
    .unwrap();
    assert!(matches!(
        ingest_budget_event(&mut db, account, &flooder, 203, Classification::OptOut).await,
        Err(InboundError::BudgetExhausted)
    ));
    assert!(
        ingest_budget_event(&mut db, account, &other, 4, Classification::OptOut)
            .await
            .unwrap()
            .created
    );
    let consent = db
        .query(
            "SELECT subject_hash,attempts FROM auth_abuse_counters WHERE scope='inbound_consent_daily'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(consent.len(), 2, "consent budget keeps no account row");
    for row in consent {
        let subject: Vec<u8> = row.get(0);
        let expected = if subject == budget_key("device", flooder.device) {
            10_000
        } else {
            assert_eq!(subject, budget_key("device", other.device));
            3
        };
        assert_eq!(row.get::<_, i32>(1), expected);
    }
    db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// Only consent transitions queue on the account row lock. A capture ingest
/// must not wait behind an admission transaction, an admission must not wait
/// behind an open capture ingest, and a STOP must still wait exactly as
/// before (#497).
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn account_lock_serializes_only_consent_ingest_with_admission() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("inbound_lock_scope_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    for migration in [
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
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
        include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute("INSERT INTO sites(site_id) VALUES('test')", &[])
        .await
        .unwrap();
    let fixture = seed_budget_device(&db, account, "+15550000003").await;

    // An admission-shaped transaction holds the account row lock. A capture
    // event must still complete: nothing it writes conflicts with that lock,
    // and its account fence stays the key-lookup snapshot check.
    let (mut holder_db, holder_connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { holder_connection.await.unwrap() });
    holder_db
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let holder = holder_db.transaction().await.unwrap();
    holder
        .query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
            &[&account],
        )
        .await
        .unwrap();
    let capture = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ingest_budget_event(&mut db, account, &fixture, 1, Classification::CapturedLocal),
    )
    .await
    .expect("capture ingest must not wait behind the admission account lock")
    .unwrap();
    assert!(capture.created);
    holder.rollback().await.unwrap();

    // Park a capture ingest inside its transaction by holding its source
    // attempt row, then prove a real admission for the same account
    // completes while that ingest is open.
    let (mut park_db, park_connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { park_connection.await.unwrap() });
    park_db
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let park = park_db.transaction().await.unwrap();
    park.query_one(
        "SELECT id FROM message_attempts WHERE id=$1 FOR UPDATE",
        &[&fixture.attempt],
    )
    .await
    .unwrap();
    let ingest_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let (parked, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            ingest_budget_event(&mut db, account, &fixture, 2, Classification::CapturedLocal),
            async {
                // The only row lock this ingest can wait on is the parked
                // source lookup.
                loop {
                    let waiting: bool = park
                        .query_one("SELECT cardinality(pg_blocking_pids($1))>0", &[&ingest_pid])
                        .await
                        .unwrap()
                        .get(0);
                    if waiting {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                let (mut accept_db, accept_connection) =
                    tokio_postgres::connect(&url, tokio_postgres::NoTls)
                        .await
                        .unwrap();
                tokio::spawn(async move { accept_connection.await.unwrap() });
                accept_db
                    .batch_execute(&format!("SET search_path TO {schema}"))
                    .await
                    .unwrap();
                let mut store = zrotext_delivery_store::DeliveryStore::new(&mut accept_db);
                let accepted = store
                    .accept(zrotext_delivery_store::NewMessage {
                        account_id: account,
                        client_message_id: Uuid::new_v4(),
                        device_id: fixture.device,
                        idempotency_key: "capture-race",
                        recipient_e164: "+15550000004",
                        synthetic_payload: b"synthetic",
                        expires_at_ms: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as i64
                            + 60_000,
                    })
                    .await
                    .unwrap();
                assert!(
                    accepted.created,
                    "admission must complete while a capture ingest is open"
                );
                park.rollback().await.unwrap();
            }
        )
    })
    .await
    .expect("parked capture ingest and admission both finish");
    assert!(parked.unwrap().created);

    // A STOP still queues on the account row lock exactly as before: it must
    // fail fast behind a lock holder instead of silently proceeding, then
    // land once the holder releases.
    let holder = holder_db.transaction().await.unwrap();
    holder
        .query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
            &[&account],
        )
        .await
        .unwrap();
    db.batch_execute("SET lock_timeout='2s'").await.unwrap();
    let session = InboundSession {
        account_id: account,
        device_id: fixture.device,
        site_id: "test",
        instance_id: "instance",
        connection_epoch: 2,
        deployment_epoch: 1,
    };
    let stop_unsigned = InboundEvent {
        event_id: Uuid::new_v4(),
        sequence: 3,
        message_id: fixture.message,
        attempt_id: fixture.attempt,
        classification: Classification::OptOut,
        observed_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        part_count: 1,
        content: Content::MetadataOnly,
        signature_der: &[],
    };
    let stop_signature: Signature = fixture
        .signing
        .sign(&signed_event_bytes(session, &stop_unsigned));
    let stop_der = stop_signature.to_der();
    let stop = InboundEvent {
        signature_der: stop_der.as_bytes(),
        ..stop_unsigned
    };
    let stop_id = stop.event_id;
    let blocked = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ingest(&mut db, session, &stop),
    )
    .await
    .expect("STOP returns on lock timeout instead of hanging");
    assert!(matches!(blocked, Err(InboundError::Database(_))));
    assert!(
        db.query_opt("SELECT 1 FROM inbound_events WHERE id=$1", &[&stop_id])
            .await
            .unwrap()
            .is_none()
    );
    holder.rollback().await.unwrap();
    assert!(ingest(&mut db, session, &stop).await.unwrap().created);
    assert_eq!(
        suppression_active(&db, account, "+15550000003").await,
        Some(true)
    );
    db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// A lane tick probes first (idle means zero work with no claim
/// transaction), and one endpoint's undecryptable signing secret defers only
/// its own delivery: the healthy endpoint still delivers in the same tick
/// (#487).
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn lane_batch_survives_an_undecryptable_endpoint_secret() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("webhook_lane_batch_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    for migration in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let vault = crate::webhook_worker::WebhookSecretVault::new(
        1,
        zeroize::Zeroizing::new(crate::test_keys::key(7)),
    )
    .unwrap();
    let wrong_key_vault = crate::webhook_worker::WebhookSecretVault::new(
        1,
        zeroize::Zeroizing::new(crate::test_keys::key(9)),
    )
    .unwrap();
    let broken_account = Uuid::new_v4();
    let healthy_account = Uuid::new_v4();
    let broken_endpoint = Uuid::new_v4();
    let healthy_endpoint = Uuid::new_v4();
    db.execute(
        "INSERT INTO accounts(id) VALUES($1),($2)",
        &[&broken_account, &healthy_account],
    )
    .await
    .unwrap();
    // The broken endpoint's secret was sealed under a key this vault does not
    // hold; opening it defers only that endpoint's delivery.
    let broken_secret = wrong_key_vault
        .seal(broken_account, broken_endpoint, &crate::test_keys::key(8))
        .unwrap();
    let healthy_secret = vault
        .seal(healthy_account, healthy_endpoint, &crate::test_keys::key(8))
        .unwrap();
    for (endpoint, account, secret) in [
        (broken_endpoint, broken_account, &broken_secret),
        (healthy_endpoint, healthy_account, &healthy_secret),
    ] {
        db.execute(
            "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext, \
             signing_secret_key_version,enabled) VALUES($1,$2,'https://hooks.example.org/hook',$3,1,true)",
            &[&endpoint, &account, secret],
        )
        .await
        .unwrap();
        let device = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'lane fixture')",
            &[&device, &account],
        )
        .await
        .unwrap();
        let message = Uuid::new_v4();
        db.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
             transport_mode,transport_payload,request_digest,state,expires_at) \
             VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')",
            &[&message, &account, &device, &vec![2_u8; 32], &b"fixture".as_slice(), &vec![3_u8; 32]],
        )
        .await
        .unwrap();
        let attempt = Uuid::new_v4();
        db.execute(
            "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation, \
             session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')",
            &[&attempt, &account, &message, &device],
        )
        .await
        .unwrap();
        let event_id = Uuid::new_v4();
        db.execute(
            "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id, \
             device_sequence,classification,observed_at,part_count,content_kind,event_digest,signature_der) \
             VALUES($1,$2,$3,$4,$5,1,'captured_local',now(),1,'metadata_only',$6,$7)",
            &[&event_id, &account, &device, &message, &attempt,
              &vec![4_u8; 32], &vec![5_u8; 8]],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,next_attempt_at,created_at) \
             VALUES($1,$2,$3,$4,now()-interval '1 hour',now()-interval '2 hours')",
            &[&Uuid::new_v4(), &account, &endpoint, &event_id],
        )
        .await
        .unwrap();
    }
    // Before anything is due to this schema's clock the probe short-circuits
    // the tick: no claim, no account scan.
    // (Deliveries were seeded due above, so exercise the idle probe first.)
    db.execute(
        "UPDATE webhook_deliveries SET next_attempt_at=now()+interval '1 hour'",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        crate::webhook_worker::dispatch_lane_batch_with(
            &scoped_url,
            &vault,
            "idle-lane",
            16,
            |_url, _body, _secret| async move {
                panic!("an idle lane must not dispatch");
            }
        )
        .await
        .unwrap(),
        0
    );
    db.execute(
        "UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 hour'",
        &[],
    )
    .await
    .unwrap();
    let delivered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = delivered.clone();
    let processed = crate::webhook_worker::dispatch_lane_batch_with(
        &scoped_url,
        &vault,
        "lane-1",
        16,
        move |url, _body, _secret| {
            let seen = seen.clone();
            async move {
                assert_eq!(url, "https://hooks.example.org/hook");
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(crate::webhook_egress::DeliveryResponse {
                    status: 204,
                    acknowledged: true,
                })
            }
        },
    )
    .await
    .unwrap();
    // One delivered plus one deferred secret; the deferral did not abort the
    // rest of the batch.
    assert_eq!(processed, 2);
    assert_eq!(delivered.load(std::sync::atomic::Ordering::SeqCst), 1);
    let healthy_row = db
        .query_one(
            "SELECT status,attempt_count FROM webhook_deliveries WHERE endpoint_id=$1",
            &[&healthy_endpoint],
        )
        .await
        .unwrap();
    let healthy: (String, i16) = (healthy_row.get(0), healthy_row.get(1));
    let broken_row = db
        .query_one(
            "SELECT status,attempt_count,key_failure_count FROM webhook_deliveries WHERE endpoint_id=$1",
            &[&broken_endpoint],
        )
        .await
        .unwrap();
    let broken: (String, i16, i32) = (broken_row.get(0), broken_row.get(1), broken_row.get(2));
    assert_eq!(healthy, ("succeeded".to_string(), 1));
    assert_eq!(
        broken,
        ("pending".to_string(), 0, 1),
        "the undecryptable secret defers exactly its own delivery"
    );
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}

/// A fresh schema with the webhook dispatch migrations, for the lane and
/// claim tests below. The caller drops the returned schema.
async fn webhook_dispatch_schema(prefix: &str) -> (Client, String, String) {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    for migration in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let separator = if url.contains('?') { '&' } else { '?' };
    let scoped = format!("{url}{separator}options=-csearch_path%3D{schema}");
    (db, schema, scoped)
}

async fn drop_webhook_dispatch_schema(db: &Client, schema: &str) {
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}

/// Seal a signing secret the lane vault can open for this endpoint.
async fn seal_endpoint_secret(
    db: &Client,
    vault: &crate::webhook_worker::WebhookSecretVault,
    account: Uuid,
    endpoint: Uuid,
) {
    let sealed = vault
        .seal(account, endpoint, &crate::test_keys::key(8))
        .unwrap();
    db.execute(
        "UPDATE webhook_endpoints SET signing_secret_ciphertext=$2 WHERE id=$1",
        &[&endpoint, &sealed],
    )
    .await
    .unwrap();
}

fn lane_vault() -> crate::webhook_worker::WebhookSecretVault {
    crate::webhook_worker::WebhookSecretVault::new(
        1,
        zeroize::Zeroizing::new(crate::test_keys::key(7)),
    )
    .unwrap()
}

/// Put one delivery into the state a worker leaves when it crashes (or is
/// still running): leased with attempt 1 open.
async fn lease_delivery_as(db: &Client, delivery: Uuid, owner: &str, lease_until_sql: &str) {
    db.execute(
        &format!(
            "UPDATE webhook_deliveries SET status='leased',attempt_count=1,lease_owner=$2, \
             lease_until={lease_until_sql} WHERE id=$1"
        ),
        &[&delivery, &owner],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO webhook_attempts(id,delivery_id,generation,attempt_number) \
         SELECT $1,id,generation,1 FROM webhook_deliveries WHERE id=$2",
        &[&Uuid::new_v4(), &delivery],
    )
    .await
    .unwrap();
}

/// An idle lane must still recover a lease a crashed worker left behind.
/// Nothing is pending and due, so only the expired lease makes the tick
/// non-idle; the next tick closes the attempt as a timeout and reschedules
/// the delivery without dispatching it.
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn idle_lane_tick_recovers_an_expired_lease() {
    let (db, schema, scoped_url) = webhook_dispatch_schema("webhook_idle_recovery").await;
    let account = Uuid::new_v4();
    let endpoint = seed_dispatch_account(&db, account, 1, 1).await[0];
    let delivery: Uuid = db
        .query_one(
            "SELECT id FROM webhook_deliveries WHERE endpoint_id=$1",
            &[&endpoint],
        )
        .await
        .unwrap()
        .get(0);
    lease_delivery_as(&db, delivery, "crashed-worker", "now()-interval '1 second'").await;
    let vault = lane_vault();
    let processed = crate::webhook_worker::dispatch_lane_batch_with(
        &scoped_url,
        &vault,
        "idle-lane",
        16,
        |_url, _body, _secret| async move {
            panic!("a recovered lease is rescheduled, not dispatched in the same tick");
        },
    )
    .await
    .unwrap();
    assert_eq!(processed, 0);
    let row = db
        .query_one(
            "SELECT d.status,d.lease_owner,d.attempt_count,d.next_attempt_at>now(), \
             a.outcome,a.completed_at IS NOT NULL \
             FROM webhook_deliveries d JOIN webhook_attempts a ON a.delivery_id=d.id \
             WHERE d.id=$1",
            &[&delivery],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, String>(0),
        "pending",
        "an idle tick recovers the expired lease"
    );
    assert_eq!(row.get::<_, Option<String>>(1), None);
    assert_eq!(row.get::<_, i16>(2), 1, "recovery does not reset attempts");
    assert!(row.get::<_, bool>(3), "the retry is backed off");
    assert_eq!(row.get::<_, Option<String>>(4).as_deref(), Some("timeout"));
    assert!(row.get::<_, bool>(5));
    drop_webhook_dispatch_schema(&db, &schema).await;
}

/// A lease that has not expired belongs to a live worker. Neither an idle
/// tick nor a tick that recovers and drains other work may take it back.
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn lane_tick_leaves_an_unexpired_lease_alone() {
    let (db, schema, scoped_url) = webhook_dispatch_schema("webhook_live_lease").await;
    let vault = lane_vault();
    let live_account = Uuid::new_v4();
    let live_endpoint = seed_dispatch_account(&db, live_account, 1, 1).await[0];
    let live: Uuid = db
        .query_one(
            "SELECT id FROM webhook_deliveries WHERE endpoint_id=$1",
            &[&live_endpoint],
        )
        .await
        .unwrap()
        .get(0);
    lease_delivery_as(&db, live, "live-worker", "now()+interval '30 seconds'").await;
    let live_lease = "SELECT status,lease_owner,attempt_count FROM webhook_deliveries WHERE id=$1";
    // Only the live lease exists: the tick is idle and must not touch it.
    assert_eq!(
        crate::webhook_worker::dispatch_lane_batch_with(
            &scoped_url,
            &vault,
            "idle-lane",
            16,
            |_url, _body, _secret| async move {
                panic!("an idle lane must not dispatch");
            },
        )
        .await
        .unwrap(),
        0
    );
    // Another account now has due work, so the next tick recovers expired
    // leases and drains; the live lease must survive that sweep too.
    let busy_account = Uuid::new_v4();
    let busy_endpoint = seed_dispatch_account(&db, busy_account, 1, 1).await[0];
    seal_endpoint_secret(&db, &vault, busy_account, busy_endpoint).await;
    let processed = crate::webhook_worker::dispatch_lane_batch_with(
        &scoped_url,
        &vault,
        "lane-1",
        16,
        |_url, _body, _secret| async move {
            Ok(crate::webhook_egress::DeliveryResponse {
                status: 204,
                acknowledged: true,
            })
        },
    )
    .await
    .unwrap();
    assert_eq!(processed, 1, "only the other account's delivery is sent");
    let row = db.query_one(live_lease, &[&live]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, String>(0),
            row.get::<_, Option<String>>(1),
            row.get::<_, i16>(2)
        ),
        ("leased".to_string(), Some("live-worker".to_string()), 1),
        "a live worker's lease is not recovered"
    );
    let open: i64 = db
        .query_one(
            "SELECT count(*) FROM webhook_attempts WHERE delivery_id=$1 AND completed_at IS NULL",
            &[&live],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(open, 1, "the live attempt stays open");
    let busy: String = db
        .query_one(
            "SELECT status FROM webhook_deliveries WHERE endpoint_id=$1",
            &[&busy_endpoint],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(busy, "succeeded");
    drop_webhook_dispatch_schema(&db, &schema).await;
}

/// A retry that has come due is the only work anywhere: no fresh delivery
/// (attempt_count 0) is due. The probe must still see it and the tick must
/// send it.
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn lane_tick_dispatches_a_due_retry_when_nothing_fresh_is_due() {
    let (db, schema, scoped_url) = webhook_dispatch_schema("webhook_due_retry").await;
    let vault = lane_vault();
    let account = Uuid::new_v4();
    let endpoint = seed_dispatch_account(&db, account, 1, 1).await[0];
    seal_endpoint_secret(&db, &vault, account, endpoint).await;
    // Three earlier attempts failed and were closed; the fourth is due now.
    let delivery: Uuid = db
        .query_one(
            "UPDATE webhook_deliveries SET attempt_count=3,next_attempt_at=now()-interval '1 second' \
             WHERE endpoint_id=$1 RETURNING id",
            &[&endpoint],
        )
        .await
        .unwrap()
        .get(0);
    for attempt_number in 1_i16..=3 {
        db.execute(
            "INSERT INTO webhook_attempts(id,delivery_id,generation,attempt_number,completed_at,outcome) \
             SELECT $1,id,generation,$3,now()-interval '1 hour','network_error' \
             FROM webhook_deliveries WHERE id=$2",
            &[&Uuid::new_v4(), &delivery, &attempt_number],
        )
        .await
        .unwrap();
    }
    let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = sent.clone();
    let processed = crate::webhook_worker::dispatch_lane_batch_with(
        &scoped_url,
        &vault,
        "lane-1",
        16,
        move |_url, _body, _secret| {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(crate::webhook_egress::DeliveryResponse {
                    status: 204,
                    acknowledged: true,
                })
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(processed, 1, "the due retry makes the tick non-idle");
    assert_eq!(sent.load(std::sync::atomic::Ordering::SeqCst), 1);
    let row = db
        .query_one(
            "SELECT status,attempt_count FROM webhook_deliveries WHERE id=$1",
            &[&delivery],
        )
        .await
        .unwrap();
    assert_eq!(
        (row.get::<_, String>(0), row.get::<_, i16>(1)),
        ("succeeded".to_string(), 4)
    );
    drop_webhook_dispatch_schema(&db, &schema).await;
}

/// Seed one account with two due endpoints and return them in claim order
/// (both cursors start at 0, so the lower id is tried first).
async fn two_due_endpoints(db: &Client) -> (Uuid, Uuid) {
    let account = Uuid::new_v4();
    let mut endpoints = seed_dispatch_account(db, account, 2, 2).await;
    endpoints.sort();
    (endpoints[0], endpoints[1])
}

/// An endpoint that already holds a lease is skipped even though it sorts
/// first and still has due work; the claim goes to the next endpoint.
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn claim_skips_an_endpoint_that_already_holds_a_lease() {
    let (mut db, schema, _url) = webhook_dispatch_schema("webhook_claim_leased").await;
    let (first, second) = two_due_endpoints(&db).await;
    let held: Uuid = db
        .query_one(
            "SELECT id FROM webhook_deliveries WHERE endpoint_id=$1 ORDER BY id LIMIT 1",
            &[&first],
        )
        .await
        .unwrap()
        .get(0);
    lease_delivery_as(&db, held, "live-worker", "now()+interval '30 seconds'").await;
    let lease = claim_webhook(&mut db, "claimer")
        .await
        .expect("a leased endpoint is skipped, not claimed a second time")
        .expect("the other endpoint is due");
    assert_eq!(lease.endpoint_id, second);
    drop_webhook_dispatch_schema(&db, &schema).await;
}

/// An endpoint another worker has locked is skipped rather than waited on.
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn claim_skips_an_endpoint_another_worker_has_locked() {
    let (mut db, schema, url) = webhook_dispatch_schema("webhook_claim_locked").await;
    let (first, second) = two_due_endpoints(&db).await;
    let (mut peer, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    peer.batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let peer_tx = peer.transaction().await.unwrap();
    peer_tx
        .query_one(
            "SELECT id FROM webhook_endpoints WHERE id=$1 FOR UPDATE",
            &[&first],
        )
        .await
        .unwrap();
    let lease = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        claim_webhook(&mut db, "claimer"),
    )
    .await
    .expect("the claim must skip a locked endpoint, not wait for it")
    .unwrap()
    .expect("the unlocked endpoint is due");
    assert_eq!(lease.endpoint_id, second);
    peer_tx.rollback().await.unwrap();
    drop_webhook_dispatch_schema(&db, &schema).await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn dispatch_releases_the_worker_socket_while_the_endpoint_hangs() {
    let base_url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("webhook_socket_release_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (db, connection) = tokio_postgres::connect(&scoped_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    // One claimable delivery whose endpoint secret the vault can really open.
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let event = Uuid::new_v4();
    let endpoint = Uuid::new_v4();
    let delivery = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'socket release fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')",
        &[&message, &account, &device, &vec![2u8; 32], &b"fixture".as_slice(), &vec![3u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,1,2,1,'submitted')",
        &[&attempt, &account, &message, &device],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence,classification,observed_at,part_count,content_kind,event_digest,signature_der) \
         VALUES($1,$2,$3,$4,$5,1,'captured_local',now(),1,'metadata_only',$6,$7)",
        &[&event, &account, &device, &message, &attempt, &vec![4u8; 32], &vec![5u8; 8]],
    )
    .await
    .unwrap();
    let vault = crate::webhook_worker::WebhookSecretVault::new(
        1,
        zeroize::Zeroizing::new(crate::test_keys::key(95)),
    )
    .unwrap();
    let sealed = vault
        .seal(account, endpoint, &crate::test_keys::key(96))
        .unwrap();
    db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled) \
         VALUES($1,$2,'https://hooks.example.org/release',$3,1,true)",
        &[&endpoint, &account, &sealed],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,next_attempt_at,created_at) \
         VALUES($1,$2,$3,$4,now()-interval '1 hour',now()-interval '2 hours')",
        &[&delivery, &account, &endpoint, &event],
    )
    .await
    .unwrap();
    // The sender hangs until released; the dispatch must not hold a worker
    // socket while it waits, so recovery-style acquires still get one.
    let (entered, mut entered_rx) = tokio::sync::oneshot::channel::<()>();
    let (release, release_rx) = tokio::sync::oneshot::channel::<()>();
    let dispatch_url = scoped_url.clone();
    let mut dispatch = tokio::spawn(async move {
        crate::webhook_worker::dispatch_one_with(
            &dispatch_url,
            &vault,
            "socket-release",
            move |_url, _body, _secret| async move {
                entered.send(()).unwrap();
                let () = release_rx.await.unwrap();
                Ok(crate::webhook_egress::DeliveryResponse {
                    status: 200,
                    acknowledged: true,
                })
            },
        )
        .await
    });
    tokio::select! {
        entered = &mut entered_rx => entered.expect("sender must be entered"),
        done = &mut dispatch => panic!("dispatch exited before the sender: {done:?}"),
    }
    let idle = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if crate::runtime_db::worker_idle_sockets(&scoped_url) > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        idle.is_ok(),
        "claim socket must return to the pool while the endpoint hangs"
    );
    let recovery = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::runtime_db::connect_worker(&scoped_url),
    )
    .await
    .expect("recovery acquire resolves while a dispatch hangs")
    .expect("recovery acquires a worker socket while a dispatch hangs");
    recovery.query_one("SELECT 1", &[]).await.unwrap();
    drop(recovery);
    release.send(()).unwrap();
    assert!(dispatch.await.unwrap().unwrap());
    let row = db
        .query_one(
            "SELECT status,attempt_count FROM webhook_deliveries WHERE id=$1",
            &[&delivery],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "succeeded");
    assert_eq!(row.get::<_, i16>(1), 1);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
