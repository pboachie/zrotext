use super::*;
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use rand::rng;
use tokio::time::{Duration, timeout};
use tokio_postgres::NoTls;

macro_rules! migration {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/compose/migrations/",
            $name
        ))
    };
}

const TEST_MIGRATIONS: [&str; 23] = [
    migration!("001_foundation.sql"),
    migration!("002_auth.sql"),
    migration!("003_delivery.sql"),
    migration!("004_enrollment.sql"),
    migration!("005_verification_outbox.sql"),
    migration!("006_usage_metering.sql"),
    migration!("007_inbound_webhook_foundation.sql"),
    migration!("008_stripe_billing_foundation.sql"),
    migration!("009_webhook_manual_replay.sql"),
    migration!("010_billing_test_entitlement.sql"),
    migration!("011_billing_payment_holds.sql"),
    migration!("012_auth_abuse_limits.sql"),
    migration!("013_owner_mfa.sql"),
    migration!("014_owner_mfa_failure_budget.sql"),
    migration!("015_webhook_kek_commitments.sql"),
    migration!("016_auth_abuse_atomic.sql"),
    migration!("017_billing_device_caps.sql"),
    migration!("018_sealed_inbound_identity.sql"),
    migration!("019_line_activation_contract.sql"),
    migration!("031_recipient_suppression.sql"),
    migration!("032_line_opt_out_events.sql"),
    migration!("033_sms_line_binding_scope.sql"),
    migration!("035_sms_owner_key_ceremony.sql"),
];

fn observed_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn signed<'a>(
    session: InboundSession<'_>,
    key: &SigningKey,
    line_id: Uuid,
    sequence: i64,
    recipient_e164: &'a str,
) -> (LineOptOut<'a>, Vec<u8>) {
    let mut event = LineOptOut {
        id: Uuid::new_v4(),
        line_id,
        binding_generation: 1,
        sequence,
        recipient_e164,
        action: Action::Stop,
        observed_at_ms: observed_now(),
        signature_der: &[],
    };
    let statement = signed_line_opt_out_bytes(session, &event).unwrap();
    let signature: Signature = key.sign(&statement);
    let der = signature.to_der().as_bytes().to_vec();
    event.signature_der = &[];
    (event, der)
}

#[test]
fn transcript_binds_line_generation_action_and_sender() {
    let session = InboundSession {
        account_id: Uuid::from_u128(1),
        device_id: Uuid::from_u128(2),
        site_id: "test",
        instance_id: "test",
        connection_epoch: 1,
        deployment_epoch: 1,
    };
    let key = SigningKey::generate_from_rng(&mut rng());
    let (event, der) = signed(session, &key, Uuid::from_u128(3), 1, "+15551234567");
    let bytes = signed_line_opt_out_bytes(session, &event).unwrap();
    assert!(bytes.starts_with(DOMAIN));
    let signature = Signature::from_der(&der).unwrap();
    key.verifying_key().verify(&bytes, &signature).unwrap();
    for altered in [
        LineOptOut {
            line_id: Uuid::from_u128(4),
            ..event
        },
        LineOptOut {
            binding_generation: 2,
            ..event
        },
        LineOptOut {
            action: Action::Review,
            ..event
        },
        LineOptOut {
            recipient_e164: "+15551234568",
            ..event
        },
    ] {
        let changed = signed_line_opt_out_bytes(session, &altered).unwrap();
        assert!(key.verifying_key().verify(&changed, &signature).is_err());
    }
    assert!(matches!(
        signed_line_opt_out_bytes(
            session,
            &LineOptOut {
                recipient_e164: "15551234567",
                ..event
            }
        ),
        Err(LineOptOutError::InvalidInput)
    ));
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn signed_unsolicited_stop_is_attempt_free_line_bound_and_serialized() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("line_opt_out_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    for migration in TEST_MIGRATIONS {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let key = SigningKey::generate_from_rng(&mut rng());
    let sec1 = key.verifying_key().to_sec1_point(false);
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO sites(site_id) VALUES('line-opt-out-test')",
        &[],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual device')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&device, &account, &sec1.as_bytes(), &&Sha256::digest(sec1.as_bytes())[..]])
        .await.unwrap();
    db.execute("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) \
        VALUES($1,$2,'line-opt-out-test','virtual-hub',2,clock_timestamp()+interval '10 minutes',1)",
        &[&device, &account]).await.unwrap();
    db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) \
        VALUES($1,$2,'active',clock_timestamp(),1,1)", &[&line, &account]).await.unwrap();
    db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,purpose,owner_approval_digest,device_confirmation_digest,activated_at) \
        VALUES($1,$2,$3,1,'active','sms',$4,$5,clock_timestamp()-interval '1 second')",
        &[&account, &line, &device, &vec![1_u8;32], &vec![2_u8;32]]).await.unwrap();
    let session = InboundSession {
        account_id: account,
        device_id: device,
        site_id: "line-opt-out-test",
        instance_id: "virtual-hub",
        connection_epoch: 2,
        deployment_epoch: 1,
    };
    let (base, der) = signed(session, &key, line, 1, "+15551234567");
    let event = LineOptOut {
        signature_der: &der,
        ..base
    };
    assert_eq!(
        db.query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(ingest_line_opt_out(&mut db, session, &event).await.unwrap());
    assert!(!ingest_line_opt_out(&mut db, session, &event).await.unwrap());
    let row = db
        .query_one(
            "SELECT active,source,source_event_id,source_attempt_id,source_unsolicited_event_id \
        FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2",
            &[&account, &event.recipient_e164],
        )
        .await
        .unwrap();
    assert!(row.get::<_, bool>(0));
    assert_eq!(row.get::<_, String>(1), "sms_unsolicited_keyword");
    assert!(row.get::<_, Option<Uuid>>(2).is_none());
    assert!(row.get::<_, Option<Uuid>>(3).is_none());
    assert_eq!(row.get::<_, Option<Uuid>>(4), Some(event.id));

    // A legacy attempt-bound STOP cannot replace the attempt-free source
    // with one that an attempt-bound START could subsequently clear.
    db.execute(
        "UPDATE recipient_suppressions SET source='sms_keyword',source_event_id=$3, \
         source_attempt_id=$4,changed_at=clock_timestamp() \
         WHERE account_id=$1 AND recipient_e164=$2",
        &[
            &account,
            &event.recipient_e164,
            &Uuid::new_v4(),
            &Uuid::new_v4(),
        ],
    )
    .await
    .unwrap();
    let protected = db.query_one(
        "SELECT source,source_attempt_id,source_unsolicited_event_id FROM recipient_suppressions \
         WHERE account_id=$1 AND recipient_e164=$2",
        &[&account, &event.recipient_e164],
    ).await.unwrap();
    assert_eq!(protected.get::<_, String>(0), "sms_unsolicited_keyword");
    assert!(protected.get::<_, Option<Uuid>>(1).is_none());
    assert_eq!(protected.get::<_, Option<Uuid>>(2), Some(event.id));

    let changed = LineOptOut {
        action: Action::Review,
        ..event
    };
    assert!(matches!(
        ingest_line_opt_out(&mut db, session, &changed).await,
        Err(LineOptOutError::InvalidSignature)
    ));
    let conflict_unsigned = LineOptOut {
        action: Action::Review,
        signature_der: &[],
        ..event
    };
    let conflict_statement = signed_line_opt_out_bytes(session, &conflict_unsigned).unwrap();
    let conflict_signature: Signature = key.sign(&conflict_statement);
    let conflict_der = conflict_signature.to_der().as_bytes().to_vec();
    let conflict = LineOptOut {
        signature_der: &conflict_der,
        ..conflict_unsigned
    };
    assert!(matches!(
        ingest_line_opt_out(&mut db, session, &conflict).await,
        Err(LineOptOutError::EventConflict)
    ));
    let (wrong_base, wrong_der) = signed(session, &key, Uuid::new_v4(), 2, "+15551234567");
    let wrong = LineOptOut {
        signature_der: &wrong_der,
        ..wrong_base
    };
    assert!(matches!(
        ingest_line_opt_out(&mut db, session, &wrong).await,
        Err(LineOptOutError::Unauthorized)
    ));
    let generation_unsigned = LineOptOut {
        id: Uuid::new_v4(),
        binding_generation: 2,
        sequence: 7,
        signature_der: &[],
        ..event
    };
    let generation_statement = signed_line_opt_out_bytes(session, &generation_unsigned).unwrap();
    let generation_signature: Signature = key.sign(&generation_statement);
    let generation_der = generation_signature.to_der().as_bytes().to_vec();
    let wrong_generation = LineOptOut {
        signature_der: &generation_der,
        ..generation_unsigned
    };
    assert!(matches!(
        ingest_line_opt_out(&mut db, session, &wrong_generation).await,
        Err(LineOptOutError::Unauthorized)
    ));
    let (seq_base, seq_der) = signed(session, &key, line, 1, "+15551234567");
    let duplicate_sequence = LineOptOut {
        signature_der: &seq_der,
        ..seq_base
    };
    assert!(matches!(
        ingest_line_opt_out(&mut db, session, &duplicate_sequence).await,
        Err(LineOptOutError::SequenceConflict)
    ));
    let forged_key = SigningKey::generate_from_rng(&mut rng());
    let (forged_base, forged_der) = signed(session, &forged_key, line, 3, "+15551234567");
    let forged = LineOptOut {
        signature_der: &forged_der,
        ..forged_base
    };
    assert!(matches!(
        ingest_line_opt_out(&mut db, session, &forged).await,
        Err(LineOptOutError::InvalidSignature)
    ));

    // The account lock used by acceptance must serialize an opt-out. The
    // second writer cannot commit a suppression while the first holds it.
    let (mut peer, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    peer.batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let lock = db.transaction().await.unwrap();
    lock.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
        &[&account],
    )
    .await
    .unwrap();
    let (race_base, race_der) = signed(session, &key, line, 4, "+15557654321");
    let race = LineOptOut {
        signature_der: &race_der,
        ..race_base
    };
    let mut future = Box::pin(ingest_line_opt_out(&mut peer, session, &race));
    assert!(
        timeout(Duration::from_millis(150), future.as_mut())
            .await
            .is_err()
    );
    assert_eq!(
        lock.query_one(
            "SELECT count(*) FROM recipient_suppressions WHERE recipient_e164=$1",
            &[&race.recipient_e164]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    lock.commit().await.unwrap();
    assert!(
        timeout(Duration::from_secs(3), future)
            .await
            .unwrap()
            .unwrap()
    );
    let blocked: bool = db
        .query_one(
            "SELECT active FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2",
            &[&account, &race.recipient_e164],
        )
        .await
        .unwrap()
        .get(0);
    assert!(blocked);
    db.execute(
        "UPDATE phone_lines SET state='revoked' WHERE id=$1",
        &[&line],
    )
    .await
    .unwrap();
    let (revoked_base, revoked_der) = signed(session, &key, line, 5, "+15559876543");
    let revoked = LineOptOut {
        signature_der: &revoked_der,
        ..revoked_base
    };
    assert!(matches!(
        ingest_line_opt_out(&mut db, session, &revoked).await,
        Err(LineOptOutError::Unauthorized)
    ));
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}
