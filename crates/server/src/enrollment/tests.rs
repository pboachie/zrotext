use super::*;
use crate::auth::{TokenHasher, authenticate_session, login, register, verify_email};
use crate::billing::{self, SubscriptionSnapshot};
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use p256::pkcs8::EncodePublicKey;
use rand::rng;

#[test]
fn p256_android_spki_and_der_signature_round_trip() {
    let signing_key = SigningKey::generate_from_rng(&mut rng());
    let spki = signing_key.verifying_key().to_public_key_der().unwrap();
    let (_, sec1, fingerprint) = parse_public_key(spki.as_bytes()).unwrap();
    let bytes = enrollment_challenge_bytes(
        Uuid::new_v4(),
        Uuid::new_v4(),
        &fingerprint,
        &random_bytes(),
    );
    let signature: Signature = signing_key.sign(&bytes);
    assert!(verify_signature(
        &sec1,
        &bytes,
        signature.to_der().as_bytes()
    ));
    let mut tampered = bytes.clone();
    tampered[0] ^= 1;
    assert!(!verify_signature(
        &sec1,
        &tampered,
        signature.to_der().as_bytes()
    ));
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_one_use_tenant_replay_expiry_and_revocation() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("enrollment_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
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
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../deploy/compose/migrations/020_enrollment_retention_indexes.sql"),
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
    ] {
        client.batch_execute(sql).await.unwrap();
    }
    let auth_hasher = TokenHasher::new(crate::test_keys::key(17)).unwrap();
    let hasher = EnrollmentHasher::new(crate::test_keys::key(19)).unwrap();
    let password_a = Uuid::new_v4().to_string();
    let password_b = Uuid::new_v4().to_string();
    let a = register(
        &mut client,
        &auth_hasher,
        "enroll-a@example.test",
        &password_a,
    )
    .await
    .unwrap();
    let b = register(
        &mut client,
        &auth_hasher,
        "enroll-b@example.test",
        &password_b,
    )
    .await
    .unwrap();
    verify_email(&mut client, &auth_hasher, &a.verification_token)
        .await
        .unwrap();
    verify_email(&mut client, &auth_hasher, &b.verification_token)
        .await
        .unwrap();
    let sa = login(&client, &auth_hasher, "enroll-a@example.test", &password_a)
        .await
        .unwrap();
    let sb = login(&client, &auth_hasher, "enroll-b@example.test", &password_b)
        .await
        .unwrap();
    let pa = authenticate_session(&client, &auth_hasher, &sa.token)
        .await
        .unwrap();
    let pb = authenticate_session(&client, &auth_hasher, &sb.token)
        .await
        .unwrap();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let spki = signing.verifying_key().to_public_key_der().unwrap();

    let expired = create_pairing(&client, &hasher, &pa, "Expired")
        .await
        .unwrap();
    client.execute(
            "UPDATE pairing_requests SET created_at=now()-interval '10 minutes', expires_at=now()-interval '5 minutes' WHERE id=$1",
            &[&expired.id],
        ).await.unwrap();
    assert!(matches!(
        claim_pairing(
            &mut client,
            &hasher,
            expired.id,
            &expired.token,
            spki.as_bytes()
        )
        .await,
        Err(EnrollmentError::Unavailable)
    ));

    let bad = create_pairing(&client, &hasher, &pa, "Bad proof")
        .await
        .unwrap();
    let claimed_bad = claim_pairing(&mut client, &hasher, bad.id, &bad.token, spki.as_bytes())
        .await
        .unwrap();
    assert!(matches!(
        claim_pairing(&mut client, &hasher, bad.id, &bad.token, spki.as_bytes()).await,
        Err(EnrollmentError::Unavailable)
    ));
    let other_signing = SigningKey::generate_from_rng(&mut rng());
    let (_, _, bad_fingerprint) = parse_public_key(spki.as_bytes()).unwrap();
    let bad_payload = enrollment_challenge_bytes(
        a.account_id,
        bad.id,
        &bad_fingerprint,
        &claimed_bad.challenge_nonce,
    );
    let wrong_sig: Signature = other_signing.sign(&bad_payload);
    assert!(
        !prove_pairing_key(
            &mut client,
            &hasher,
            bad.id,
            &claimed_bad.challenge_nonce,
            wrong_sig.to_der().as_bytes()
        )
        .await
        .unwrap()
    );
    let good_sig: Signature = signing.sign(&bad_payload);
    assert!(
        !prove_pairing_key(
            &mut client,
            &hasher,
            bad.id,
            &claimed_bad.challenge_nonce,
            good_sig.to_der().as_bytes()
        )
        .await
        .unwrap()
    );

    let ticket = create_pairing(&client, &hasher, &pa, "Test Samsung")
        .await
        .unwrap();
    let claimed = claim_pairing(
        &mut client,
        &hasher,
        ticket.id,
        &ticket.token,
        spki.as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(claimed.account_id, a.account_id);
    let (_, _, fingerprint) = parse_public_key(spki.as_bytes()).unwrap();
    let payload = enrollment_challenge_bytes(
        a.account_id,
        ticket.id,
        &fingerprint,
        &claimed.challenge_nonce,
    );
    let signature: Signature = signing.sign(&payload);
    assert!(
        prove_pairing_key(
            &mut client,
            &hasher,
            ticket.id,
            &claimed.challenge_nonce,
            signature.to_der().as_bytes()
        )
        .await
        .unwrap()
    );
    assert!(
        !prove_pairing_key(
            &mut client,
            &hasher,
            ticket.id,
            &claimed.challenge_nonce,
            signature.to_der().as_bytes()
        )
        .await
        .unwrap()
    );
    assert!(
        pairing_view(&client, &pb, ticket.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        approve_pairing(
            &mut client,
            &pb,
            ticket.id,
            &claimed.comparison_code,
            &claimed.key_fingerprint
        )
        .await,
        Err(EnrollmentError::Unavailable)
    ));
    assert!(matches!(
        approve_pairing(
            &mut client,
            &pa,
            ticket.id,
            "00000000",
            &claimed.key_fingerprint
        )
        .await,
        Err(EnrollmentError::Unavailable)
    ));
    let device_id = approve_pairing(
        &mut client,
        &pa,
        ticket.id,
        &claimed.comparison_code,
        &claimed.key_fingerprint,
    )
    .await
    .unwrap();
    assert!(matches!(
        approve_pairing(
            &mut client,
            &pa,
            ticket.id,
            &claimed.comparison_code,
            &claimed.key_fingerprint
        )
        .await,
        Err(EnrollmentError::Unavailable)
    ));

    let challenge = issue_device_challenge(&client, &hasher, device_id)
        .await
        .unwrap();
    assert_eq!(challenge.account_id, a.account_id);
    let wrong_sig: Signature = other_signing.sign(&device_challenge_bytes(&challenge));
    assert!(matches!(
        authenticate_device_challenge(
            &mut client,
            &hasher,
            &challenge,
            wrong_sig.to_der().as_bytes()
        )
        .await,
        Err(EnrollmentError::Unauthorized)
    ));
    let good_sig: Signature = signing.sign(&device_challenge_bytes(&challenge));
    assert!(matches!(
        authenticate_device_challenge(
            &mut client,
            &hasher,
            &challenge,
            good_sig.to_der().as_bytes()
        )
        .await,
        Err(EnrollmentError::Unauthorized)
    ));
    let challenge = issue_device_challenge(&client, &hasher, device_id)
        .await
        .unwrap();
    let good_sig: Signature = signing.sign(&device_challenge_bytes(&challenge));
    let identity = authenticate_device_challenge(
        &mut client,
        &hasher,
        &challenge,
        good_sig.to_der().as_bytes(),
    )
    .await
    .unwrap();
    assert!(device_still_active(&client, identity).await.unwrap());
    assert!(matches!(
        authenticate_device_challenge(
            &mut client,
            &hasher,
            &challenge,
            good_sig.to_der().as_bytes()
        )
        .await,
        Err(EnrollmentError::Unauthorized)
    ));
    let stale_pairing = create_pairing(&client, &hasher, &pa, "Stale")
        .await
        .unwrap();
    client.execute(
            "UPDATE pairing_requests SET created_at=now()-interval '26 hours',expires_at=now()-interval '25 hours' WHERE id=$1",
            &[&stale_pairing.id],
        ).await.unwrap();
    let cancelled_pairing = create_pairing(&client, &hasher, &pa, "Cancelled")
        .await
        .unwrap();
    assert!(
        cancel_pairing(&client, &pa, cancelled_pairing.id)
            .await
            .unwrap()
    );
    client.execute(
            "UPDATE pairing_requests SET created_at=now()-interval '26 hours',expires_at=now()-interval '25 hours' WHERE id=$1",
            &[&cancelled_pairing.id],
        ).await.unwrap();
    let old_challenge = issue_device_challenge(&client, &hasher, device_id)
        .await
        .unwrap();
    client.execute(
            "UPDATE device_auth_challenges SET created_at=now()-interval '3 hours',expires_at=now()-interval '2 hours' WHERE id=$1",
            &[&old_challenge.id],
        ).await.unwrap();
    let live_challenge = issue_device_challenge(&client, &hasher, device_id)
        .await
        .unwrap();
    assert_eq!(prune_expired(&client).await.unwrap(), 2);
    for (table, id, expected) in [
        ("pairing_requests", stale_pairing.id, 0_i64),
        ("pairing_requests", cancelled_pairing.id, 1),
        ("pairing_requests", expired.id, 1),
        ("device_auth_challenges", old_challenge.id, 0),
        ("device_auth_challenges", live_challenge.id, 1),
    ] {
        let count: i64 = client
            .query_one(&format!("SELECT count(*) FROM {table} WHERE id=$1"), &[&id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, expected, "{table} {id}");
    }
    client
        .execute(
            "UPDATE pairing_requests SET cancelled_at=now()-interval '25 hours' WHERE id=$1",
            &[&cancelled_pairing.id],
        )
        .await
        .unwrap();
    assert_eq!(prune_expired(&client).await.unwrap(), 1);
    let live_signature: Signature = signing.sign(&device_challenge_bytes(&live_challenge));
    assert_eq!(
        authenticate_device_challenge(
            &mut client,
            &hasher,
            &live_challenge,
            live_signature.to_der().as_bytes()
        )
        .await
        .unwrap()
        .device_id,
        device_id
    );
    let expired_challenge = issue_device_challenge(&client, &hasher, device_id)
        .await
        .unwrap();
    client
            .execute(
                "UPDATE device_auth_challenges SET created_at=now()-interval '2 minutes', expires_at=now()-interval '1 minute' WHERE id=$1",
                &[&expired_challenge.id],
            )
            .await
            .unwrap();
    let expired_signature: Signature = signing.sign(&device_challenge_bytes(&expired_challenge));
    assert!(matches!(
        authenticate_device_challenge(
            &mut client,
            &hasher,
            &expired_challenge,
            expired_signature.to_der().as_bytes()
        )
        .await,
        Err(EnrollmentError::Unauthorized)
    ));
    let outstanding_challenge = issue_device_challenge(&client, &hasher, device_id)
        .await
        .unwrap();
    let outstanding_signature: Signature =
        signing.sign(&device_challenge_bytes(&outstanding_challenge));
    assert!(!revoke_device(&mut client, &pb, device_id).await.unwrap());
    assert!(revoke_device(&mut client, &pa, device_id).await.unwrap());
    assert!(!device_still_active(&client, identity).await.unwrap());
    assert!(matches!(
        authenticate_device_challenge(
            &mut client,
            &hasher,
            &outstanding_challenge,
            outstanding_signature.to_der().as_bytes()
        )
        .await,
        Err(EnrollmentError::Unauthorized)
    ));
    assert!(matches!(
        issue_device_challenge(&client, &hasher, device_id).await,
        Err(EnrollmentError::Unauthorized)
    ));
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

async fn proven_pairing(
    db: &mut Client,
    hasher: &EnrollmentHasher,
    principal: &SessionPrincipal,
) -> (Uuid, String, String, SigningKey) {
    let signing = SigningKey::generate_from_rng(&mut rng());
    let spki = signing.verifying_key().to_public_key_der().unwrap();
    let ticket = create_pairing(db, hasher, principal, "Virtual phone")
        .await
        .unwrap();
    let claimed = claim_pairing(db, hasher, ticket.id, &ticket.token, spki.as_bytes())
        .await
        .unwrap();
    let (_, _, fingerprint) = parse_public_key(spki.as_bytes()).unwrap();
    let proof: Signature = signing.sign(&enrollment_challenge_bytes(
        principal.tenant.account_id(),
        ticket.id,
        &fingerprint,
        &claimed.challenge_nonce,
    ));
    assert!(
        prove_pairing_key(
            db,
            hasher,
            ticket.id,
            &claimed.challenge_nonce,
            proof.to_der().as_bytes(),
        )
        .await
        .unwrap()
    );
    (
        ticket.id,
        claimed.comparison_code,
        claimed.key_fingerprint,
        signing,
    )
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_device_cap_downgrade_grandfathers_and_serializes_approval() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("device_cap_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&scoped_url, tokio_postgres::NoTls)
        .await
        .unwrap();
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
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let auth_hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let enrollment_hasher = EnrollmentHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let password = Uuid::new_v4().to_string();
    let owner = register(&mut db, &auth_hasher, "cap-owner@example.test", &password)
        .await
        .unwrap();
    verify_email(&mut db, &auth_hasher, &owner.verification_token)
        .await
        .unwrap();
    let session = login(&db, &auth_hasher, "cap-owner@example.test", &password)
        .await
        .unwrap();
    let principal = authenticate_session(&db, &auth_hasher, &session.token)
        .await
        .unwrap();
    billing::reset_test_quotas_on_start(&scoped_url, true, true, Some(&[1; 32]))
        .await
        .unwrap();
    let initial = proven_pairing(&mut db, &enrollment_hasher, &principal).await;
    assert!(matches!(
        approve_pairing(&mut db, &principal, initial.0, &initial.1, &initial.2).await,
        Err(EnrollmentError::DeviceLimitReached)
    ));
    billing::bind_customer(&mut db, owner.account_id, "cus_captest1")
        .await
        .unwrap();
    assert!(matches!(
        approve_pairing(&mut db, &principal, initial.0, &initial.1, &initial.2).await,
        Err(EnrollmentError::DeviceLimitReached)
    ));
    db.execute(
            "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES('sub_captest1',$1,'cus_captest1')",
            &[&owner.account_id],
        )
        .await
        .unwrap();
    let prices = vec!["price_basic1".to_owned(), "price_plus1".to_owned()];
    let plans =
        billing::parse_test_quota_plans("price_basic1:1:1,price_plus1:3:2", &prices).unwrap();
    let plus = SubscriptionSnapshot {
        subscription_id: "sub_captest1".into(),
        customer_id: "cus_captest1".into(),
        status: "active".into(),
        price_id: Some("price_plus1".into()),
        latest_invoice_id: None,
    };
    billing::reconcile_snapshot_with_quotas(&mut db, owner.account_id, &plus, &prices, &plans, 1)
        .await
        .unwrap();
    let mut enrolled = Vec::new();
    let mut initial = Some(initial);
    for index in 0..2 {
        let (pairing, code, fingerprint, signing) = if index == 0 {
            initial.take().unwrap()
        } else {
            proven_pairing(&mut db, &enrollment_hasher, &principal).await
        };
        let device = approve_pairing(&mut db, &principal, pairing, &code, &fingerprint)
            .await
            .unwrap();
        enrolled.push((device, signing));
    }
    db.execute(
            "UPDATE billing_reconciliations SET dirty_generation=2 WHERE stripe_subscription_id='sub_captest1'",
            &[],
        )
        .await
        .unwrap();
    assert!(
        billing::reconcile_snapshot_with_quotas(&mut db, owner.account_id, &plus, &prices, &[], 2,)
            .await
            .is_err()
    );
    let processed: i64 = db
            .query_one(
                "SELECT processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_captest1'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(processed, 1);
    let basic = SubscriptionSnapshot {
        price_id: Some("price_basic1".into()),
        ..plus
    };
    billing::reconcile_snapshot_with_quotas(&mut db, owner.account_id, &basic, &prices, &plans, 2)
        .await
        .unwrap();
    let row = db.query_one(
            "SELECT c.limit_devices,(SELECT count(*) FROM devices WHERE account_id=$1 AND revoked_at IS NULL) FROM billing_device_caps c WHERE c.account_id=$1",
            &[&owner.account_id],
        ).await.unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (1, 2));
    let audit = db.query_one(
            "SELECT previous_limit_devices,limit_devices,reason FROM billing_device_cap_audit WHERE account_id=$1 ORDER BY id DESC LIMIT 1",
            &[&owner.account_id],
        ).await.unwrap();
    assert_eq!(
        (
            audit.get::<_, Option<i64>>(0),
            audit.get::<_, i64>(1),
            audit.get::<_, String>(2)
        ),
        (Some(2), 1, "active".into())
    );
    for (device, signing) in &enrolled {
        let challenge = issue_device_challenge(&db, &enrollment_hasher, *device)
            .await
            .unwrap();
        let signature: Signature = signing.sign(&device_challenge_bytes(&challenge));
        let identity = authenticate_device_challenge(
            &mut db,
            &enrollment_hasher,
            &challenge,
            signature.to_der().as_bytes(),
        )
        .await
        .unwrap();
        assert!(device_still_active(&db, identity).await.unwrap());
    }
    let (pending, code, fingerprint, _) =
        proven_pairing(&mut db, &enrollment_hasher, &principal).await;
    assert!(matches!(
        approve_pairing(&mut db, &principal, pending, &code, &fingerprint).await,
        Err(EnrollmentError::DeviceLimitReached)
    ));
    assert!(
        revoke_device(&mut db, &principal, enrolled[0].0)
            .await
            .unwrap()
    );
    assert!(matches!(
        approve_pairing(&mut db, &principal, pending, &code, &fingerprint).await,
        Err(EnrollmentError::DeviceLimitReached)
    ));
    assert!(
        revoke_device(&mut db, &principal, enrolled[1].0)
            .await
            .unwrap()
    );
    let (mut second, connection) = tokio_postgres::connect(&scoped_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let (other, other_code, other_fingerprint, _) =
        proven_pairing(&mut db, &enrollment_hasher, &principal).await;
    let barrier = tokio::sync::Barrier::new(2);
    let (first_result, second_result) = tokio::join!(
        async {
            barrier.wait().await;
            approve_pairing(&mut db, &principal, pending, &code, &fingerprint).await
        },
        async {
            barrier.wait().await;
            approve_pairing(
                &mut second,
                &principal,
                other,
                &other_code,
                &other_fingerprint,
            )
            .await
        }
    );
    assert_eq!(first_result.is_ok() as u8 + second_result.is_ok() as u8, 1);
    assert!(
        matches!(first_result, Err(EnrollmentError::DeviceLimitReached))
            || matches!(second_result, Err(EnrollmentError::DeviceLimitReached))
    );
    let active: i64 = db
        .query_one(
            "SELECT count(*) FROM devices WHERE account_id=$1 AND revoked_at IS NULL",
            &[&owner.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active, 1);
    // The projected cap is still one when grace expires without a new
    // webhook. A free slot must not permit another approval afterward.
    let remaining_device: Uuid = db
        .query_one(
            "SELECT id FROM devices WHERE account_id=$1 AND revoked_at IS NULL",
            &[&owner.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        revoke_device(&mut db, &principal, remaining_device)
            .await
            .unwrap()
    );
    db.execute(
            "UPDATE billing_subscriptions SET stripe_status='past_due',payment_grace_started_at=clock_timestamp()-interval '7 days 1 second',latest_invoice_id='in_captest1',payment_grace_invoice_id='in_captest1' WHERE stripe_subscription_id='sub_captest1'",
            &[],
        ).await.unwrap();
    let (grace_pairing, grace_code, grace_fingerprint, _) =
        proven_pairing(&mut db, &enrollment_hasher, &principal).await;
    assert!(matches!(
        approve_pairing(
            &mut db,
            &principal,
            grace_pairing,
            &grace_code,
            &grace_fingerprint
        )
        .await,
        Err(EnrollmentError::DeviceLimitReached)
    ));
    let approved: bool = db
        .query_one(
            "SELECT approved_at IS NOT NULL FROM pairing_requests WHERE id=$1",
            &[&grace_pairing],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!approved);
    // The first check can be valid when a later write waits past the
    // deadline. The final check must roll back that provisional device.
    db.execute(
            "UPDATE billing_subscriptions SET payment_grace_started_at=clock_timestamp()-interval '7 days'+interval '1 second' WHERE stripe_subscription_id='sub_captest1'",
            &[],
        ).await.unwrap();
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = second.transaction().await.unwrap();
    blocker
        .batch_execute("LOCK TABLE device_keys IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let (late_approval, ()) = tokio::join!(
        approve_pairing(
            &mut db,
            &principal,
            grace_pairing,
            &grace_code,
            &grace_fingerprint,
        ),
        async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let waiting: bool = blocker
                        .query_one("SELECT cardinality(pg_blocking_pids($1))>0", &[&pid])
                        .await
                        .unwrap()
                        .get(0);
                    if waiting {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
            blocker.commit().await.unwrap();
        }
    );
    assert!(matches!(
        late_approval,
        Err(EnrollmentError::DeviceLimitReached)
    ));
    let active: i64 = db
        .query_one(
            "SELECT count(*) FROM devices WHERE account_id=$1 AND revoked_at IS NULL",
            &[&owner.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active, 0);
    db.execute(
            "UPDATE billing_subscriptions SET payment_grace_started_at=clock_timestamp()-interval '1 day' WHERE stripe_subscription_id='sub_captest1'",
            &[],
        ).await.unwrap();
    approve_pairing(
        &mut db,
        &principal,
        grace_pairing,
        &grace_code,
        &grace_fingerprint,
    )
    .await
    .unwrap();
    assert!(
        billing::reset_test_quotas_on_start(&scoped_url, true, false, Some(&[1; 32]))
            .await
            .is_err()
    );
    let row = db
            .query_one(
                "SELECT enabled,(SELECT limit_devices FROM billing_device_caps WHERE account_id=$1) FROM billing_device_cap_config WHERE singleton=true",
                &[&owner.account_id],
            )
            .await
            .unwrap();
    assert_eq!((row.get::<_, bool>(0), row.get::<_, i64>(1)), (true, 1));
    let generations = db
            .query_one(
                "SELECT dirty_generation,processed_generation FROM billing_reconciliations WHERE stripe_subscription_id='sub_captest1'",
                &[],
            )
            .await
            .unwrap();
    assert_eq!(
        (generations.get::<_, i64>(0), generations.get::<_, i64>(1)),
        (2, 2)
    );
    let (blocked, blocked_code, blocked_fingerprint, _) =
        proven_pairing(&mut db, &enrollment_hasher, &principal).await;
    assert!(matches!(
        approve_pairing(
            &mut db,
            &principal,
            blocked,
            &blocked_code,
            &blocked_fingerprint
        )
        .await,
        Err(EnrollmentError::DeviceLimitReached)
    ));
    // A logout that wins while approval waits for the account lock must
    // prevent installation of a new persistent device credential.
    db.execute("UPDATE billing_device_cap_config SET enabled=false", &[])
        .await
        .unwrap();
    let (blocked, code, fingerprint, _) =
        proven_pairing(&mut db, &enrollment_hasher, &principal).await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = second.transaction().await.unwrap();
    blocker
        .query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&owner.account_id],
        )
        .await
        .unwrap();
    let (result, ()) = tokio::join!(
        approve_pairing(&mut db, &principal, blocked, &code, &fingerprint),
        async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let waiting: bool = blocker
                        .query_one("SELECT cardinality(pg_blocking_pids($1))>0", &[&pid])
                        .await
                        .unwrap()
                        .get(0);
                    if waiting {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            blocker
                .execute(
                    "UPDATE sessions SET revoked_at=now() WHERE id=$1",
                    &[&principal.session_id],
                )
                .await
                .unwrap();
            blocker.commit().await.unwrap();
        }
    );
    assert!(
        matches!(result, Err(EnrollmentError::Unauthorized)),
        "revoked owner session enrolled a device: {result:?}"
    );
    let approved: bool = db
        .query_one(
            "SELECT approved_at IS NOT NULL FROM pairing_requests WHERE id=$1",
            &[&blocked],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!approved);
    drop(second);
    drop(db);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
