use super::*;
use tokio_postgres::{NoTls, error::SqlState};

#[derive(Clone, Copy)]
struct TestIdentity {
    account: Uuid,
    device: Uuid,
    line: Uuid,
}

async fn insert_event(
    db: &tokio_postgres::Client,
    identity: TestIdentity,
    generation: i64,
    id: Uuid,
    sequence: i64,
    bytes: &[u8],
) -> Result<u64, tokio_postgres::Error> {
    db.execute(
        "INSERT INTO sealed_inbound_events(id,account_id,device_id,line_id, \
         binding_generation,device_sequence,observed_at,part_count,envelope,unsigned_digest) \
         VALUES($1,$2,$3,$4,$5,$6,now(),1,$7,$8)",
        &[
            &id,
            &identity.account,
            &identity.device,
            &identity.line,
            &generation,
            &sequence,
            &bytes,
            &vec![9_u8; 32],
        ],
    )
    .await
}

#[tokio::test]
async fn sealed_identity_requires_live_writer_and_active_same_tenant_line() {
    let Ok(url) = std::env::var("ZT_INBOUND_TEST_DATABASE_URL") else {
        eprintln!("set ZT_INBOUND_TEST_DATABASE_URL for sealed identity database test");
        return;
    };
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("sealed_identity_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!("../../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }

    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let identity = TestIdentity {
        account,
        device,
        line,
    };
    db.execute(
        "INSERT INTO accounts(id) VALUES($1),($2)",
        &[&account, &other_account],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO sites(site_id) VALUES('sealed-test')", &[])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[&device, &account, &vec![4_u8; 65], &vec![1_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id, \
         connection_epoch,lease_until,deployment_epoch) \
         VALUES($1,$2,'sealed-test','virtual-hub',2,now()+interval '10 minutes',1)",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO phone_lines(id,account_id) VALUES($1,$2)",
        &[&line, &account],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation) \
         VALUES($1,$2,$3,1)",
        &[&account, &line, &device],
    )
    .await
    .unwrap();
    let second_device = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'second virtual fixture')",
        &[&second_device, &account],
    )
    .await
    .unwrap();
    let reused_generation = db
        .execute(
            "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation) \
             VALUES($1,$2,$3,1)",
            &[&account, &line, &second_device],
        )
        .await
        .unwrap_err();
    assert_eq!(reused_generation.code(), Some(&SqlState::UNIQUE_VIOLATION));

    let session = InboundSession {
        account_id: account,
        device_id: device,
        site_id: "sealed-test",
        instance_id: "virtual-hub",
        connection_epoch: 2,
        deployment_epoch: 1,
    };
    assert!(!line_binding_ready(&db, session, line, 1).await.unwrap());
    assert!(
        !line_binding_ready(&db, session, Uuid::nil(), 1)
            .await
            .unwrap()
    );
    assert!(!line_binding_ready(&db, session, line, 0).await.unwrap());
    assert!(
        !line_binding_ready(
            &db,
            InboundSession {
                account_id: other_account,
                ..session
            },
            line,
            1
        )
        .await
        .unwrap()
    );
    assert!(
        !line_binding_ready(
            &db,
            InboundSession {
                connection_epoch: 1,
                ..session
            },
            line,
            1
        )
        .await
        .unwrap()
    );
    assert!(!line_binding_ready(&db, session, line, 2).await.unwrap());

    // An account cannot bind a different tenant's line to its device.
    let other_line = Uuid::new_v4();
    db.execute(
        "INSERT INTO phone_lines(id,account_id) VALUES($1,$2)",
        &[&other_line, &other_account],
    )
    .await
    .unwrap();
    let cross_tenant = db
        .execute(
            "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation) \
         VALUES($1,$2,$3,1)",
            &[&account, &other_line, &device],
        )
        .await
        .unwrap_err();
    assert_eq!(cross_tenant.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));

    // Direct storage is closed while line enrollment remains pending.
    let event_id = Uuid::new_v4();
    let mut envelope = vec![0_u8; 426];
    envelope[..6].copy_from_slice(&[0x5a, 0x54, 0x53, 0x45, 1, 2]);
    let pending = insert_event(&db, identity, 1, event_id, 1, &envelope)
        .await
        .unwrap_err();
    assert_eq!(pending.code(), Some(&SqlState::CHECK_VIOLATION));

    // These are synthetic SQL fixtures, not evidence of real SIM enrollment.
    db.execute(
        "UPDATE phone_lines SET state='active',approved_at=now(), \
         current_binding_generation=1 WHERE id=$1",
        &[&line],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE device_line_bindings SET state='active',activated_at=now(), \
         owner_approval_digest=$2,device_confirmation_digest=$3 \
         WHERE account_id=$1 AND line_id=$4",
        &[&account, &vec![2_u8; 32], &vec![3_u8; 32], &line],
    )
    .await
    .unwrap();
    assert!(line_binding_ready(&db, session, line, 1).await.unwrap());

    // `now()` is fixed at transaction start. An ingest preflight must reject
    // a writer whose lease expires while the transaction remains open.
    let tx = db.transaction().await.unwrap();
    tx.execute(
        "UPDATE device_sessions SET lease_until=now()+interval '100 milliseconds' \
         WHERE account_id=$1 AND device_id=$2",
        &[&account, &device],
    )
    .await
    .unwrap();
    tx.query_one("SELECT pg_sleep(0.5)", &[]).await.unwrap();
    let times = tx
        .query_one(
            "SELECT lease_until<=clock_timestamp(),lease_until<=now() \
             FROM device_sessions WHERE device_id=$1",
            &[&device],
        )
        .await
        .unwrap();
    assert!(times.get::<_, bool>(0));
    assert!(!times.get::<_, bool>(1));
    assert!(!line_binding_ready(&tx, session, line, 1).await.unwrap());
    tx.rollback().await.unwrap();

    let rollback = db
        .execute(
            "UPDATE phone_lines SET current_binding_generation=0 WHERE id=$1",
            &[&line],
        )
        .await
        .unwrap_err();
    assert_eq!(rollback.code(), Some(&SqlState::CHECK_VIOLATION));

    // The sealed table's source is an inbound event, not a sent attempt.
    let outbound_count: i64 = db
        .query_one("SELECT count(*) FROM messages", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(outbound_count, 0);
    insert_event(&db, identity, 1, event_id, 1, &envelope)
        .await
        .unwrap();
    let altered_event = db
        .execute(
            "UPDATE sealed_inbound_events SET unsigned_digest=$2 WHERE id=$1",
            &[&event_id, &vec![8_u8; 32]],
        )
        .await
        .unwrap_err();
    assert_eq!(altered_event.code(), Some(&SqlState::CHECK_VIOLATION));
    let replay = insert_event(&db, identity, 1, Uuid::new_v4(), 1, &envelope)
        .await
        .unwrap_err();
    assert_eq!(replay.code(), Some(&SqlState::UNIQUE_VIOLATION));
    let plaintext = insert_event(&db, identity, 1, Uuid::new_v4(), 2, b"plain reply text")
        .await
        .unwrap_err();
    assert_eq!(plaintext.code(), Some(&SqlState::CHECK_VIOLATION));

    db.execute(
        "UPDATE device_line_bindings SET state='revoked' WHERE account_id=$1 AND line_id=$2",
        &[&account, &line],
    )
    .await
    .unwrap();
    assert!(!line_binding_ready(&db, session, line, 1).await.unwrap());
    let revoked = insert_event(&db, identity, 1, Uuid::new_v4(), 2, &envelope)
        .await
        .unwrap_err();
    assert_eq!(revoked.code(), Some(&SqlState::CHECK_VIOLATION));
    let resurrection = db
        .execute(
            "UPDATE device_line_bindings SET state='active' \
             WHERE account_id=$1 AND line_id=$2",
            &[&account, &line],
        )
        .await
        .unwrap_err();
    assert_eq!(resurrection.code(), Some(&SqlState::CHECK_VIOLATION));
    let delete_tombstone = db
        .execute(
            "DELETE FROM device_line_bindings WHERE account_id=$1 AND line_id=$2",
            &[&account, &line],
        )
        .await
        .unwrap_err();
    assert_eq!(delete_tombstone.code(), Some(&SqlState::CHECK_VIOLATION));

    // A replacement SIM binding uses a new generation; the old one remains
    // rejected even though its historical inbound event still exists.
    db.execute(
        "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation) \
         VALUES($1,$2,$3,2)",
        &[&account, &line, &device],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE phone_lines SET current_binding_generation=2 WHERE id=$1",
        &[&line],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE device_line_bindings SET state='active',activated_at=now(), \
         owner_approval_digest=$2,device_confirmation_digest=$3 \
         WHERE account_id=$1 AND line_id=$4 AND generation=2",
        &[&account, &vec![5_u8; 32], &vec![6_u8; 32], &line],
    )
    .await
    .unwrap();
    assert!(!line_binding_ready(&db, session, line, 1).await.unwrap());
    assert!(line_binding_ready(&db, session, line, 2).await.unwrap());
    let old_generation = insert_event(&db, identity, 1, Uuid::new_v4(), 2, &envelope)
        .await
        .unwrap_err();
    assert_eq!(old_generation.code(), Some(&SqlState::CHECK_VIOLATION));
    insert_event(&db, identity, 2, Uuid::new_v4(), 2, &envelope)
        .await
        .unwrap();

    db.execute(
        "UPDATE accounts SET disabled_at=now() WHERE id=$1",
        &[&account],
    )
    .await
    .unwrap();
    assert!(!line_binding_ready(&db, session, line, 2).await.unwrap());
    let disabled = insert_event(&db, identity, 2, Uuid::new_v4(), 3, &envelope)
        .await
        .unwrap_err();
    assert_eq!(disabled.code(), Some(&SqlState::CHECK_VIOLATION));

    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}
