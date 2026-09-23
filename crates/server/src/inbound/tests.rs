use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::elliptic_curve::rand_core::OsRng;

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
async fn signed_inbound_is_tenant_bound_deduplicated_and_queues_once() {
    let Ok(url) = std::env::var("ZT_INBOUND_TEST_DATABASE_URL") else {
        eprintln!("set ZT_INBOUND_TEST_DATABASE_URL to run inbound database test");
        return;
    };
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
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let endpoint = Uuid::new_v4();
    let signing = SigningKey::random(&mut OsRng);
    let public = signing
        .verifying_key()
        .to_encoded_point(false)
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
    // Endpoint creation is deliberately not exposed in the server. Seed an
    // enabled, encrypted-secret-shaped fixture to prove atomic fanout only.
    db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext, \
         signing_secret_key_version,enabled) VALUES($1,$2,'https://example.invalid/hook',$3,1,true)",
        &[&endpoint, &account, &vec![5u8;48]],
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
    assert_eq!(
        ingest(&mut db, session, &signed).await.unwrap(),
        IngestOutcome {
            created: true,
            queued_deliveries: 1
        }
    );
    assert_eq!(
        ingest(&mut db, session, &signed).await.unwrap(),
        IngestOutcome {
            created: false,
            queued_deliveries: 0
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
    let vault =
        crate::webhook_worker::WebhookSecretVault::new(1, zeroize::Zeroizing::new(vec![7_u8; 32]))
            .unwrap();
    let encrypted = vault.seal(account, policy_endpoint, &[8_u8; 32]).unwrap();
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
        crate::webhook_worker::dispatch_one(&mut db, &vault, "worker-policy")
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
            queued_deliveries: 1
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
