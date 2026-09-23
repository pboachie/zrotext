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

    let blocked = issue_line_challenge(&mut db, &principal, line, device)
        .await
        .unwrap();
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
            3,
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
            3,
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
            3,
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
    assert!(!line_binding_ready(&db, moved, line, 2).await.unwrap());
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
