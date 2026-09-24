use super::*;
use crate::{
    auth::{TokenHasher, authenticate_session, login, register, verify_email},
    sealed_inbound::line_binding_ready,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::rand_core::OsRng,
};
use std::path::Path;
use tokio::time::{Duration, sleep};
use tokio_postgres::NoTls;

fn signatures(
    challenge: &LineChallenge,
    device_key: &SigningKey,
    owner_key: &SigningKey,
    selected_subscription_id: i32,
) -> (Vec<u8>, Vec<u8>) {
    let statement = device_line_statement(
        challenge,
        SimObservation {
            android_api_level: 31,
            active_subscription_count: 1,
            selected_subscription_id,
        },
    )
    .unwrap();
    let device_signature: Signature = device_key.sign(&statement);
    let device_signature = device_signature.to_der().as_bytes().to_vec();
    let owner_statement = owner_line_statement(&statement, &device_signature);
    let owner_signature: Signature = owner_key.sign(&owner_statement);
    (
        device_signature,
        owner_signature.to_der().as_bytes().to_vec(),
    )
}

fn proof<'a>(
    challenge: &LineChallenge,
    device_signature_der: &'a [u8],
    owner_signature_der: &'a [u8],
) -> LineActivationProof<'a> {
    LineActivationProof {
        challenge_id: challenge.id,
        nonce: challenge.nonce,
        observation: SimObservation {
            android_api_level: 31,
            active_subscription_count: 1,
            selected_subscription_id: 7,
        },
        device_signature_der,
        owner_signature_der,
    }
}

#[test]
fn transcript_is_role_separated_and_rejects_ambiguous_or_old_android() {
    let challenge = LineChallenge {
        account_id: Uuid::new_v4(),
        line_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        generation: 1,
        id: Uuid::new_v4(),
        nonce: [7_u8; 32],
    };
    let good_observation = SimObservation {
        android_api_level: 31,
        active_subscription_count: 1,
        selected_subscription_id: 7,
    };
    let good = device_line_statement(&challenge, good_observation).unwrap();
    assert!(good.starts_with(DEVICE_DOMAIN));
    assert!(owner_line_statement(&good, &[1, 2, 3]).starts_with(OWNER_DOMAIN));
    assert!(matches!(
        device_line_statement(
            &challenge,
            SimObservation {
                android_api_level: 30,
                ..good_observation
            }
        ),
        Err(LineActivationError::InvalidInput)
    ));
    assert!(matches!(
        device_line_statement(
            &challenge,
            SimObservation {
                active_subscription_count: 2,
                ..good_observation
            }
        ),
        Err(LineActivationError::InvalidInput)
    ));
    assert!(matches!(
        device_line_statement(
            &challenge,
            SimObservation {
                selected_subscription_id: -1,
                ..good_observation
            }
        ),
        Err(LineActivationError::InvalidInput)
    ));
    let key = SigningKey::random(&mut OsRng);
    let signed: Signature = key.sign(&good);
    let sec1 = key.verifying_key().to_encoded_point(false);
    assert!(verify_der(
        sec1.as_bytes(),
        &good,
        signed.to_der().as_bytes()
    ));
    let mut tampered = good;
    tampered[DEVICE_DOMAIN.len()] ^= 1;
    assert!(!verify_der(
        sec1.as_bytes(),
        &tampered,
        signed.to_der().as_bytes()
    ));
    assert!(!verify_der(
        sec1.as_bytes(),
        &owner_line_statement(&tampered, signed.to_der().as_bytes()),
        signed.to_der().as_bytes()
    ));
}

#[tokio::test]
async fn migration_preserves_pending_generation_high_water_mark() {
    let Ok(url) = std::env::var("ZT_INBOUND_TEST_DATABASE_URL") else {
        eprintln!("set ZT_INBOUND_TEST_DATABASE_URL for line activation database test");
        return;
    };
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("line_upgrade_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    let migration_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut migrations: Vec<_> = std::fs::read_dir(&migration_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect();
    migrations.sort();
    for path in migrations.iter().filter(|path| {
        path.file_name()
            .is_some_and(|name| name.to_string_lossy().as_ref() < "019_")
    }) {
        db.batch_execute(&std::fs::read_to_string(path).unwrap())
            .await
            .unwrap();
    }
    let hasher = TokenHasher::new(vec![7; 32]).unwrap();
    let owner = register(
        &mut db,
        &hasher,
        "upgrade-line-owner@example.test",
        "correct horse 123",
    )
    .await
    .unwrap();
    verify_email(&mut db, &hasher, &owner.verification_token)
        .await
        .unwrap();
    let login = login(
        &db,
        &hasher,
        "upgrade-line-owner@example.test",
        "correct horse 123",
    )
    .await
    .unwrap();
    let principal = authenticate_session(&db, &hasher, &login.token)
        .await
        .unwrap();
    let line = Uuid::new_v4();
    let lost_device = Uuid::new_v4();
    let replacement_device = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES
         ($1,$3,'lost virtual device'),($2,$3,'replacement virtual device')",
        &[&lost_device, &replacement_device, &owner.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation)
         VALUES($1,$2,'active',clock_timestamp(),2)",
        &[&line, &owner.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_line_bindings
         (account_id,line_id,device_id,generation,state,owner_approval_digest,
          device_confirmation_digest,activated_at)
         VALUES($1,$2,$3,2,'active',decode(repeat('11',32),'hex'),
                decode(repeat('22',32),'hex'),clock_timestamp())",
        &[&owner.account_id, &line, &lost_device],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation)
         VALUES($1,$2,$3,3)",
        &[&owner.account_id, &line, &lost_device],
    )
    .await
    .unwrap();
    let migration_019 = migration_dir.join("019_line_activation_contract.sql");
    db.batch_execute(&std::fs::read_to_string(migration_019).unwrap())
        .await
        .unwrap();
    let issued: i64 = db
        .query_one(
            "SELECT last_issued_generation FROM phone_lines WHERE account_id=$1 AND id=$2",
            &[&owner.account_id, &line],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(issued, 3);
    db.execute(
        "UPDATE devices SET revoked_at=clock_timestamp() WHERE account_id=$1 AND id=$2",
        &[&owner.account_id, &lost_device],
    )
    .await
    .unwrap();
    let owner_key = SigningKey::random(&mut OsRng);
    let owner_sec1 = owner_key.verifying_key().to_encoded_point(false);
    db.execute(
        "INSERT INTO line_owner_approval_keys(account_id,fingerprint,signing_key_sec1)
         VALUES($1,$2,$3)",
        &[
            &owner.account_id,
            &&digest(owner_sec1.as_bytes())[..],
            &owner_sec1.as_bytes(),
        ],
    )
    .await
    .unwrap();
    let replacement_key = SigningKey::random(&mut OsRng);
    let replacement_sec1 = replacement_key.verifying_key().to_encoded_point(false);
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint)
         VALUES($1,$2,$3,$4)",
        &[
            &replacement_device,
            &owner.account_id,
            &replacement_sec1.as_bytes(),
            &&digest(replacement_sec1.as_bytes())[..],
        ],
    )
    .await
    .unwrap();
    let challenge = issue_line_challenge(&mut db, &principal, line, replacement_device)
        .await
        .unwrap();
    assert_eq!(challenge.generation, 4);
    let rows = db
        .query(
            "SELECT generation,state FROM device_line_bindings
             WHERE account_id=$1 AND line_id=$2 ORDER BY generation",
            &[&owner.account_id, &line],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].get::<_, i64>(0), 2);
    assert_eq!(rows[0].get::<_, String>(1), "active");
    assert_eq!(rows[1].get::<_, i64>(0), 3);
    assert_eq!(rows[1].get::<_, String>(1), "revoked");
    assert_eq!(rows[2].get::<_, i64>(0), 4);
    assert_eq!(rows[2].get::<_, String>(1), "pending");
}

#[tokio::test]
async fn signed_activation_fences_owner_device_generation_and_replay() {
    let Ok(url) = std::env::var("ZT_INBOUND_TEST_DATABASE_URL") else {
        eprintln!("set ZT_INBOUND_TEST_DATABASE_URL for line activation database test");
        return;
    };
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("line_activation_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    let migration_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut migrations: Vec<_> = std::fs::read_dir(migration_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect();
    migrations.sort();
    for path in migrations {
        db.batch_execute(&std::fs::read_to_string(path).unwrap())
            .await
            .unwrap();
    }
    db.execute("INSERT INTO sites(site_id) VALUES('virtual-line-hub')", &[])
        .await
        .unwrap();
    let hasher = TokenHasher::new(vec![7; 32]).unwrap();
    let owner = register(
        &mut db,
        &hasher,
        "line-owner@example.test",
        "correct horse 123",
    )
    .await
    .unwrap();
    let other = register(
        &mut db,
        &hasher,
        "other-line-owner@example.test",
        "correct horse 456",
    )
    .await
    .unwrap();
    verify_email(&mut db, &hasher, &owner.verification_token)
        .await
        .unwrap();
    verify_email(&mut db, &hasher, &other.verification_token)
        .await
        .unwrap();
    let owner_login = login(&db, &hasher, "line-owner@example.test", "correct horse 123")
        .await
        .unwrap();
    let other_login = login(
        &db,
        &hasher,
        "other-line-owner@example.test",
        "correct horse 456",
    )
    .await
    .unwrap();
    let principal = authenticate_session(&db, &hasher, &owner_login.token)
        .await
        .unwrap();
    let other_principal = authenticate_session(&db, &hasher, &other_login.token)
        .await
        .unwrap();
    let device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let device_key = SigningKey::random(&mut OsRng);
    let owner_key = SigningKey::random(&mut OsRng);
    let other_key = SigningKey::random(&mut OsRng);
    let device_sec1 = device_key.verifying_key().to_encoded_point(false);
    let owner_sec1 = owner_key.verifying_key().to_encoded_point(false);
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual line device')",
        &[&device, &owner.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[
            &device,
            &owner.account_id,
            &device_sec1.as_bytes(),
            &&digest(device_sec1.as_bytes())[..],
        ],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) \
         VALUES($1,$2,$3)",
        &[
            &owner.account_id,
            &&digest(owner_sec1.as_bytes())[..],
            &owner_sec1.as_bytes(),
        ],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id, \
         connection_epoch,lease_until,deployment_epoch) \
         VALUES($1,$2,'virtual-line-hub','virtual-hub-a',2,now()+interval '10 minutes',1)",
        &[&device, &owner.account_id],
    )
    .await
    .unwrap();
    let session = InboundSession {
        account_id: owner.account_id,
        device_id: device,
        site_id: "virtual-line-hub",
        instance_id: "virtual-hub-a",
        connection_epoch: 2,
        deployment_epoch: 1,
    };

    // A different owner cannot claim this tenant's stable line UUID.
    let challenge = issue_line_challenge(&mut db, &principal, line, device)
        .await
        .unwrap();
    assert!(matches!(
        issue_line_challenge(&mut db, &other_principal, line, device).await,
        Err(LineActivationError::Unavailable)
    ));
    assert!(!line_binding_ready(&db, session, line, 1).await.unwrap());
    let (device_sig, owner_sig) = signatures(&challenge, &device_key, &owner_key, 7);
    let stale_owner_login = login(&db, &hasher, "line-owner@example.test", "correct horse 123")
        .await
        .unwrap();
    let stale_owner = authenticate_session(&db, &hasher, &stale_owner_login.token)
        .await
        .unwrap();
    db.execute(
        "UPDATE sessions SET revoked_at=now() WHERE id=$1",
        &[&stale_owner.session_id],
    )
    .await
    .unwrap();
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &stale_owner,
            session,
            line,
            1,
            proof(&challenge, &device_sig, &owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));
    let (_, wrong_owner_sig) = signatures(&challenge, &device_key, &other_key, 7);
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &principal,
            session,
            line,
            1,
            proof(&challenge, &device_sig, &wrong_owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));
    let mut wrong_nonce = proof(&challenge, &device_sig, &owner_sig);
    wrong_nonce.nonce[0] ^= 1;
    assert!(matches!(
        activate_line_binding(&mut db, &principal, session, line, 1, wrong_nonce).await,
        Err(LineActivationError::Unavailable)
    ));
    let (forged_device_sig, _) = signatures(&challenge, &other_key, &owner_key, 7);
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &principal,
            session,
            line,
            1,
            proof(&challenge, &forged_device_sig, &owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));
    let mut changed_selection = proof(&challenge, &device_sig, &owner_sig);
    changed_selection.observation.selected_subscription_id = 8;
    assert!(matches!(
        activate_line_binding(&mut db, &principal, session, line, 1, changed_selection).await,
        Err(LineActivationError::Unavailable)
    ));
    let expired = LineChallenge {
        id: Uuid::new_v4(),
        nonce: rand::random(),
        ..challenge
    };
    db.execute(
        "INSERT INTO line_activation_challenges \
         (id,account_id,line_id,device_id,generation,nonce_digest,created_at,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6,now()-interval '2 minutes',now()-interval '1 minute')",
        &[
            &expired.id,
            &expired.account_id,
            &expired.line_id,
            &expired.device_id,
            &expired.generation,
            &&digest(&expired.nonce)[..],
        ],
    )
    .await
    .unwrap();
    let (expired_device_sig, expired_owner_sig) = signatures(&expired, &device_key, &owner_key, 7);
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &principal,
            session,
            line,
            1,
            proof(&expired, &expired_device_sig, &expired_owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));
    let mut ambiguous = proof(&challenge, &device_sig, &owner_sig);
    ambiguous.observation.active_subscription_count = 2;
    assert!(matches!(
        activate_line_binding(&mut db, &principal, session, line, 1, ambiguous).await,
        Err(LineActivationError::InvalidInput)
    ));
    let mut old_android = proof(&challenge, &device_sig, &owner_sig);
    old_android.observation.android_api_level = 30;
    assert!(matches!(
        activate_line_binding(&mut db, &principal, session, line, 1, old_android).await,
        Err(LineActivationError::InvalidInput)
    ));
    assert!(!line_binding_ready(&db, session, line, 1).await.unwrap());
    activate_line_binding(
        &mut db,
        &principal,
        session,
        line,
        1,
        proof(&challenge, &device_sig, &owner_sig),
    )
    .await
    .unwrap();
    assert!(line_binding_ready(&db, session, line, 1).await.unwrap());
    let reset_challenge = db
        .execute(
            "UPDATE line_activation_challenges SET consumed_at=NULL WHERE id=$1",
            &[&challenge.id],
        )
        .await
        .unwrap_err();
    assert_eq!(
        reset_challenge.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &principal,
            session,
            line,
            1,
            proof(&challenge, &device_sig, &owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));

    let next = issue_line_challenge(&mut db, &principal, line, device)
        .await
        .unwrap();
    assert_eq!(next.generation, 2);
    let (next_device_sig, next_owner_sig) = signatures(&next, &device_key, &owner_key, 7);
    db.execute(
        "UPDATE device_sessions SET instance_id='virtual-hub-b',connection_epoch=3 \
         WHERE account_id=$1 AND device_id=$2",
        &[&owner.account_id, &device],
    )
    .await
    .unwrap();
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &principal,
            session,
            line,
            2,
            proof(&next, &next_device_sig, &next_owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));
    let moved = InboundSession {
        instance_id: "virtual-hub-b",
        connection_epoch: 3,
        ..session
    };
    activate_line_binding(
        &mut db,
        &principal,
        moved,
        line,
        2,
        proof(&next, &next_device_sig, &next_owner_sig),
    )
    .await
    .unwrap();
    assert!(!line_binding_ready(&db, moved, line, 1).await.unwrap());
    assert!(line_binding_ready(&db, moved, line, 2).await.unwrap());

    // A generation held by a missing phone must not pin this line forever.
    // Start an activation while the line row is locked, then let its nonce,
    // owner session, and device lease expire during the wait.
    let timed_login = login(&db, &hasher, "line-owner@example.test", "correct horse 123")
        .await
        .unwrap();
    let (mut attempt_db, attempt_connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { attempt_connection.await.unwrap() });
    attempt_db
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let timed_owner = authenticate_session(&attempt_db, &hasher, &timed_login.token)
        .await
        .unwrap();
    let attempt_pid: i32 = attempt_db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let abandoned = issue_line_challenge_with_lifetime(&mut db, &principal, line, device, 5)
        .await
        .unwrap();
    assert_eq!(abandoned.generation, 3);
    let (abandoned_device_sig, abandoned_owner_sig) =
        signatures(&abandoned, &device_key, &owner_key, 7);
    db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1",
        &[&timed_owner.session_id],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '5 seconds' \
         WHERE account_id=$1 AND device_id=$2",
        &[&owner.account_id, &device],
    )
    .await
    .unwrap();
    let (lock_db, lock_connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { lock_connection.await.unwrap() });
    lock_db
        .batch_execute(&format!("SET search_path TO {schema}; BEGIN"))
        .await
        .unwrap();
    lock_db
        .query_one(
            "SELECT id FROM phone_lines WHERE id=$1 FOR UPDATE",
            &[&line],
        )
        .await
        .unwrap();
    let blocked_activation = tokio::spawn(async move {
        activate_line_binding(
            &mut attempt_db,
            &timed_owner,
            moved,
            line,
            abandoned.generation,
            proof(&abandoned, &abandoned_device_sig, &abandoned_owner_sig),
        )
        .await
    });
    let mut saw_lock_wait = false;
    for _ in 0..40 {
        let wait: Option<String> = lock_db
            .query_one(
                "SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
                &[&attempt_pid],
            )
            .await
            .unwrap()
            .get(0);
        if wait.as_deref() == Some("Lock") {
            saw_lock_wait = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(saw_lock_wait, "activation never reached the line lock");
    sleep(Duration::from_secs(6)).await;
    lock_db.batch_execute("COMMIT").await.unwrap();
    assert!(matches!(
        blocked_activation.await.unwrap(),
        Err(LineActivationError::Unavailable)
    ));
    db.execute(
        "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '10 minutes' \
         WHERE account_id=$1 AND device_id=$2",
        &[&owner.account_id, &device],
    )
    .await
    .unwrap();
    let line_row = db
        .query_one(
            "SELECT current_binding_generation,last_issued_generation \
             FROM phone_lines WHERE account_id=$1 AND id=$2",
            &[&owner.account_id, &line],
        )
        .await
        .unwrap();
    assert_eq!(line_row.get::<_, i64>(0), 2);
    assert_eq!(line_row.get::<_, i64>(1), 3);

    let replacement = Uuid::new_v4();
    let replacement_key = SigningKey::random(&mut OsRng);
    let replacement_sec1 = replacement_key.verifying_key().to_encoded_point(false);
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'replacement line device')",
        &[&replacement, &owner.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[
            &replacement,
            &owner.account_id,
            &replacement_sec1.as_bytes(),
            &&digest(replacement_sec1.as_bytes())[..],
        ],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id, \
         connection_epoch,lease_until,deployment_epoch) \
         VALUES($1,$2,'virtual-line-hub','replacement-hub',1,now()+interval '10 minutes',1)",
        &[&replacement, &owner.account_id],
    )
    .await
    .unwrap();
    let replacement_session = InboundSession {
        device_id: replacement,
        instance_id: "replacement-hub",
        connection_epoch: 1,
        ..moved
    };
    let replacement_challenge = issue_line_challenge(&mut db, &principal, line, replacement)
        .await
        .unwrap();
    assert_eq!(replacement_challenge.generation, 4);
    let abandoned_state: String = db
        .query_one(
            "SELECT state FROM device_line_bindings WHERE account_id=$1 \
             AND line_id=$2 AND generation=3",
            &[&owner.account_id, &line],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(abandoned_state, "revoked");
    let (replacement_device_sig, replacement_owner_sig) =
        signatures(&replacement_challenge, &replacement_key, &owner_key, 11);
    let mut replacement_proof = proof(
        &replacement_challenge,
        &replacement_device_sig,
        &replacement_owner_sig,
    );
    replacement_proof.observation.selected_subscription_id = 11;
    activate_line_binding(
        &mut db,
        &principal,
        replacement_session,
        line,
        4,
        replacement_proof,
    )
    .await
    .unwrap();
    assert!(!line_binding_ready(&db, moved, line, 2).await.unwrap());
    assert!(
        line_binding_ready(&db, replacement_session, line, 4)
            .await
            .unwrap()
    );

    // Moving back to the original device must also use a fresh generation.
    let returned = issue_line_challenge(&mut db, &principal, line, device)
        .await
        .unwrap();
    assert_eq!(returned.generation, 5);
    let (returned_device_sig, returned_owner_sig) =
        signatures(&returned, &device_key, &owner_key, 7);
    activate_line_binding(
        &mut db,
        &principal,
        moved,
        line,
        5,
        proof(&returned, &returned_device_sig, &returned_owner_sig),
    )
    .await
    .unwrap();
    assert!(line_binding_ready(&db, moved, line, 5).await.unwrap());
    assert!(
        !line_binding_ready(&db, replacement_session, line, 4)
            .await
            .unwrap()
    );

    // Hold the *old active binding* after the initial time checks. The final
    // wall-clock check must roll back the row updates after this late wait.
    let late_login = login(&db, &hasher, "line-owner@example.test", "correct horse 123")
        .await
        .unwrap();
    let (mut late_db, late_connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { late_connection.await.unwrap() });
    late_db
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let late_owner = authenticate_session(&late_db, &hasher, &late_login.token)
        .await
        .unwrap();
    let late_pid: i32 = late_db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let late = issue_line_challenge_with_lifetime(&mut db, &principal, line, device, 5)
        .await
        .unwrap();
    assert_eq!(late.generation, 6);
    let (late_device_sig, late_owner_sig) = signatures(&late, &device_key, &owner_key, 7);
    db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1",
        &[&late_owner.session_id],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '5 seconds' \
         WHERE account_id=$1 AND device_id=$2",
        &[&owner.account_id, &device],
    )
    .await
    .unwrap();
    lock_db.batch_execute("BEGIN").await.unwrap();
    lock_db
        .query_one(
            "SELECT generation FROM device_line_bindings \
             WHERE account_id=$1 AND line_id=$2 AND generation=5 FOR UPDATE",
            &[&owner.account_id, &line],
        )
        .await
        .unwrap();
    let late_activation = tokio::spawn(async move {
        activate_line_binding(
            &mut late_db,
            &late_owner,
            moved,
            line,
            late.generation,
            proof(&late, &late_device_sig, &late_owner_sig),
        )
        .await
    });
    let mut saw_late_wait = false;
    for _ in 0..40 {
        let wait: Option<String> = lock_db
            .query_one(
                "SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
                &[&late_pid],
            )
            .await
            .unwrap()
            .get(0);
        if wait.as_deref() == Some("Lock") {
            saw_late_wait = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        saw_late_wait,
        "activation never reached the old-binding lock"
    );
    sleep(Duration::from_secs(6)).await;
    lock_db.batch_execute("COMMIT").await.unwrap();
    assert!(matches!(
        late_activation.await.unwrap(),
        Err(LineActivationError::Unavailable)
    ));
    db.execute(
        "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '10 minutes' \
         WHERE account_id=$1 AND device_id=$2",
        &[&owner.account_id, &device],
    )
    .await
    .unwrap();
    assert!(line_binding_ready(&db, moved, line, 5).await.unwrap());
    let failed_state: String = db
        .query_one(
            "SELECT state FROM device_line_bindings WHERE account_id=$1 \
             AND line_id=$2 AND generation=6",
            &[&owner.account_id, &line],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failed_state, "pending");

    let blocked = issue_line_challenge(&mut db, &principal, line, device)
        .await
        .unwrap();
    assert_eq!(blocked.generation, 7);
    let (blocked_device_sig, blocked_owner_sig) = signatures(&blocked, &device_key, &owner_key, 7);
    let alias_device = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'alias device')",
        &[&alias_device, &owner.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[
            &alias_device,
            &owner.account_id,
            &owner_sec1.as_bytes(),
            &&digest(owner_sec1.as_bytes())[..],
        ],
    )
    .await
    .unwrap();
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &principal,
            moved,
            line,
            blocked.generation,
            proof(&blocked, &blocked_device_sig, &blocked_owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));
    db.execute(
        "UPDATE line_owner_approval_keys SET revoked_at=now() WHERE account_id=$1",
        &[&owner.account_id],
    )
    .await
    .unwrap();
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &principal,
            moved,
            line,
            blocked.generation,
            proof(&blocked, &blocked_device_sig, &blocked_owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));
    let restore_key = db
        .execute(
            "UPDATE line_owner_approval_keys SET revoked_at=NULL WHERE account_id=$1",
            &[&owner.account_id],
        )
        .await
        .unwrap_err();
    assert_eq!(
        restore_key.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    db.execute(
        "INSERT INTO line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) \
         VALUES($1,$2,$3)",
        &[
            &owner.account_id,
            &&digest(device_sec1.as_bytes())[..],
            &device_sec1.as_bytes(),
        ],
    )
    .await
    .unwrap();
    let (alias_device_sig, alias_owner_sig) = signatures(&blocked, &device_key, &device_key, 7);
    assert!(matches!(
        activate_line_binding(
            &mut db,
            &principal,
            moved,
            line,
            blocked.generation,
            proof(&blocked, &alias_device_sig, &alias_owner_sig)
        )
        .await,
        Err(LineActivationError::Unavailable)
    ));

    db.execute(
        "UPDATE devices SET revoked_at=now() WHERE account_id=$1 AND id=$2",
        &[&owner.account_id, &device],
    )
    .await
    .unwrap();
    assert!(!line_binding_ready(&db, moved, line, 5).await.unwrap());
    assert!(matches!(
        issue_line_challenge(&mut db, &principal, line, device).await,
        Err(LineActivationError::Unavailable)
    ));
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}
