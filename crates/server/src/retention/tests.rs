use super::*;
use tokio_postgres::{NoTls, error::SqlState};

async fn message(db: &Client, account: Uuid, device: Uuid, state: &str, age: i32) -> Uuid {
    let id = Uuid::new_v4();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
         transport_mode,transport_payload,request_digest,state,expires_at,created_at,updated_at) \
         VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,$7, \
         now()+interval '1 hour',now()-$8::int * interval '1 day',now()-$8::int * interval '1 day')",
        &[
            &id,
            &account,
            &device,
            &vec![1_u8; 32],
            &b"synthetic body".as_slice(),
            &vec![2_u8; 32],
            &state,
            &age,
        ],
    )
    .await
    .unwrap();
    id
}

async fn inbound(
    db: &Client,
    account: Uuid,
    device: Uuid,
    message: Uuid,
    sequence: i64,
    age: i32,
) -> Uuid {
    let attempt = Uuid::new_v4();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch, \
         deployment_epoch,status) VALUES($1,$2,$3,$4,$5,1,1,'submitted')",
        &[&attempt, &account, &message, &device, &sequence],
    )
    .await
    .unwrap();
    let id = Uuid::new_v4();
    db.execute(
        "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence, \
         classification,observed_at,received_at,part_count,content_kind,content_ciphertext, \
         event_digest,signature_der) VALUES($1,$2,$3,$4,$5,$6,'captured_local',now(), \
         now()-$7::int * interval '1 day',1,'opaque_pilot',$8,$9,$10)",
        &[
            &id,
            &account,
            &device,
            &message,
            &attempt,
            &sequence,
            &age,
            &vec![3_u8; 32],
            &vec![4_u8; 32],
            &vec![5_u8; 8],
        ],
    )
    .await
    .unwrap();
    id
}

async fn present(db: &Client, table: &str, id: Uuid) -> bool {
    db.query_one(
        &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id=$1)"),
        &[&id],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
async fn retention_respects_each_cutoff_and_replay_fences() {
    let Ok(url) = env::var("ZT_INBOUND_TEST_DATABASE_URL") else {
        eprintln!("set ZT_INBOUND_TEST_DATABASE_URL for retention database test");
        return;
    };
    let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("retention_test_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut files = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "sql"))
        .collect::<Vec<_>>();
    files.sort();
    for file in files {
        db.batch_execute(&std::fs::read_to_string(file).unwrap())
            .await
            .unwrap();
    }
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual fixture')",
        &[&device, &account],
    )
    .await
    .unwrap();
    let old = message(&db, account, device, "delivered", 31).await;
    let recent = message(&db, account, device, "delivered", 29).await;
    let unknown = message(&db, account, device, "unknown", 120).await;
    let fenced = message(&db, account, device, "delivered", 120).await;
    let fenced_attempt = Uuid::new_v4();
    db.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,1,1,'unknown')",
        &[&fenced_attempt,&account,&fenced,&device]).await.unwrap();
    db.execute("INSERT INTO dispatch_fences(message_id,account_id,device_id,attempt_id,generation,session_epoch,deployment_epoch,grant_expires_at,outcome) VALUES($1,$2,$3,$4,1,1,1,now()-interval '1 day','unknown')",
        &[&fenced,&account,&device,&fenced_attempt]).await.unwrap();

    for (key, mid, age) in [("expired", old, -1), ("live", recent, 1)] {
        db.execute("INSERT INTO idempotency_keys(account_id,key,request_digest,message_id,expires_at) VALUES($1,$2,$3,$4,now()+$5::int * interval '1 day')",
            &[&account,&key,&vec![6_u8; 32],&mid,&age]).await.unwrap();
    }
    let mut events = Vec::new();
    for (mid, age) in [(old, 91), (recent, 89), (unknown, 120), (fenced, 120)] {
        let id = Uuid::new_v4();
        db.execute("INSERT INTO message_events(id,account_id,message_id,evidence_code,event_digest,observed_at,received_at,resulting_state) VALUES($1,$2,$3,'fixture',$4,now(),now()-$5::int * interval '1 day','delivered')",
            &[&id,&account,&mid,&vec![7_u8; 32],&age]).await.unwrap();
        events.push(id);
    }
    let inbound_old = inbound(&db, account, device, old, 1, 31).await;
    let inbound_recent = inbound(&db, account, device, recent, 2, 29).await;
    let inbound_unknown = inbound(&db, account, device, unknown, 3, 120).await;
    let inbound_fenced = inbound(&db, account, device, fenced, 4, 120).await;
    let inbound_no_webhook = inbound(&db, account, device, old, 5, 31).await;
    let inbound_pending = inbound(&db, account, device, old, 6, 31).await;

    let endpoint = Uuid::new_v4();
    db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version) VALUES($1,$2,'https://example.test/hook',$3,1)",
        &[&endpoint,&account,&vec![8_u8; 32]]).await.unwrap();
    let mut deliveries = Vec::new();
    for (event, age) in [
        (inbound_old, 31),
        (inbound_recent, 29),
        (inbound_unknown, 120),
        (inbound_fenced, 120),
    ] {
        let id = Uuid::new_v4();
        db.execute("INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,status,created_at,updated_at) VALUES($1,$2,$3,$4,'succeeded',now()-$5::int * interval '1 day',now()-$5::int * interval '1 day')",
            &[&id,&account,&endpoint,&event,&age]).await.unwrap();
        deliveries.push(id);
    }
    let pending_delivery = Uuid::new_v4();
    db.execute("INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,status,created_at,updated_at) VALUES($1,$2,$3,$4,'pending',now()-interval '31 days',now()-interval '31 days')",
        &[&pending_delivery,&account,&endpoint,&inbound_pending]).await.unwrap();
    let old_attempt = Uuid::new_v4();
    db.execute("INSERT INTO webhook_attempts(id,delivery_id,attempt_number,completed_at,outcome) VALUES($1,$2,1,now(),'ack')",
        &[&old_attempt,&deliveries[0]]).await.unwrap();
    db.execute("INSERT INTO webhook_replay_requests(account_id,request_id,delivery_id,generation) VALUES($1,$2,$3,2)",
        &[&account,&Uuid::new_v4(),&deliveries[0]]).await.unwrap();

    // No sealed ingest route exists; bypass its admission trigger only to seed
    // cryptographically shaped, synthetic rows in this isolated test schema.
    db.batch_execute("ALTER TABLE sealed_inbound_events DISABLE TRIGGER sealed_inbound_active_line_before_insert")
        .await.unwrap();
    let mut envelope = vec![0_u8; 426];
    envelope[..6].copy_from_slice(b"ZTSE\x01\x02");
    let line = Uuid::new_v4();
    db.execute(
        "INSERT INTO phone_lines(id,account_id) VALUES($1,$2)",
        &[&line, &account],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation) VALUES($1,$2,$3,1)",
        &[&account,&line,&device]).await.unwrap();
    let sealed_old = Uuid::new_v4();
    let sealed_recent = Uuid::new_v4();
    for (id, seq, age) in [(sealed_old, 1_i64, 31), (sealed_recent, 2_i64, 29)] {
        db.execute("INSERT INTO sealed_inbound_events(id,account_id,device_id,line_id,binding_generation,device_sequence,observed_at,received_at,part_count,envelope,unsigned_digest) VALUES($1,$2,$3,$4,1,$5,now(),now()-$6::int * interval '1 day',1,$7,$8)",
            &[&id,&account,&device,&line,&seq,&age,&envelope,&vec![9_u8; 32]]).await.unwrap();
    }
    db.batch_execute(
        "ALTER TABLE sealed_inbound_events ENABLE TRIGGER sealed_inbound_active_line_before_insert",
    )
    .await
    .unwrap();

    let counts = prune(&mut db, RetentionPolicy::default(), 1).await.unwrap();
    assert_eq!(
        counts,
        RetentionCounts {
            idempotency_keys: 1,
            messages: 1,
            message_events: 1,
            webhook_deliveries: 1,
            inbound_events: 1,
            sealed_inbound_events: 1
        }
    );
    let second = prune(&mut db, RetentionPolicy::default(), 1).await.unwrap();
    assert_eq!(second.inbound_events, 1);
    assert_eq!(
        second.idempotency_keys
            + second.messages
            + second.message_events
            + second.webhook_deliveries
            + second.sealed_inbound_events,
        0
    );
    assert!(!present(&db, "message_events", events[0]).await);
    for id in &events[1..] {
        assert!(present(&db, "message_events", *id).await);
    }
    assert!(!present(&db, "webhook_deliveries", deliveries[0]).await);
    assert!(present(&db, "webhook_deliveries", pending_delivery).await);
    for id in &deliveries[1..] {
        assert!(present(&db, "webhook_deliveries", *id).await);
    }
    assert!(!present(&db, "webhook_attempts", old_attempt).await);
    assert!(
        !db.query_one(
            "SELECT EXISTS(SELECT 1 FROM webhook_replay_requests WHERE delivery_id=$1)",
            &[&deliveries[0]]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let old_row = db
        .query_one(
            "SELECT recipient_e164,transport_payload,recipient_digest FROM messages WHERE id=$1",
            &[&old],
        )
        .await
        .unwrap();
    assert!(old_row.get::<_, Option<String>>(0).is_none());
    assert!(old_row.get::<_, Option<Vec<u8>>>(1).is_none());
    assert_eq!(old_row.get::<_, Vec<u8>>(2), vec![1_u8; 32]);
    for id in [recent, unknown, fenced] {
        assert_eq!(
            db.query_one("SELECT recipient_e164 FROM messages WHERE id=$1", &[&id])
                .await
                .unwrap()
                .get::<_, String>(0),
            "+15551234567"
        );
    }
    for id in [inbound_old, inbound_no_webhook] {
        let row = db.query_one("SELECT device_sequence,event_digest,content_kind,content_ciphertext FROM inbound_events WHERE id=$1", &[&id]).await.unwrap();
        assert_eq!(row.get::<_, String>(2), "redacted");
        assert!(row.get::<_, Option<Vec<u8>>>(3).is_none());
        assert_eq!(row.get::<_, Vec<u8>>(1), vec![4_u8; 32]);
        assert!(row.get::<_, i64>(0) > 0);
    }
    for id in [
        inbound_recent,
        inbound_unknown,
        inbound_fenced,
        inbound_pending,
    ] {
        assert_eq!(
            db.query_one(
                "SELECT content_kind FROM inbound_events WHERE id=$1",
                &[&id]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
            "opaque_pilot"
        );
    }
    let row = db.query_one("SELECT envelope,unsigned_digest,device_sequence FROM sealed_inbound_events WHERE id=$1", &[&sealed_old]).await.unwrap();
    assert!(row.get::<_, Option<Vec<u8>>>(0).is_none());
    assert_eq!(row.get::<_, Vec<u8>>(1), vec![9_u8; 32]);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert!(
        db.query_one(
            "SELECT envelope IS NOT NULL FROM sealed_inbound_events WHERE id=$1",
            &[&sealed_recent]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let rejected = db
        .execute(
            "UPDATE sealed_inbound_events SET device_sequence=99 WHERE id=$1",
            &[&sealed_recent],
        )
        .await
        .unwrap_err();
    assert_eq!(rejected.code(), Some(&SqlState::CHECK_VIOLATION));
    assert_eq!(
        prune(&mut db, RetentionPolicy::default(), BATCH_SIZE)
            .await
            .unwrap(),
        RetentionCounts::default()
    );
    assert!(
        !db.query_one(
            "SELECT EXISTS(SELECT 1 FROM idempotency_keys WHERE account_id=$1 AND key='expired')",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    assert!(
        db.query_one(
            "SELECT EXISTS(SELECT 1 FROM idempotency_keys WHERE account_id=$1 AND key='live')",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let shorter = RetentionPolicy {
        message_days: 28,
        message_events_days: 88,
        webhook_days: 28,
        inbound_days: 28,
        sealed_inbound_days: 28,
        ..RetentionPolicy::default()
    };
    let shortened = prune(&mut db, shorter, BATCH_SIZE).await.unwrap();
    assert_eq!(
        shortened,
        RetentionCounts {
            messages: 1,
            message_events: 1,
            webhook_deliveries: 1,
            inbound_events: 1,
            sealed_inbound_events: 1,
            ..RetentionCounts::default()
        }
    );
    assert!(!present(&db, "message_events", events[1]).await);
    assert!(!present(&db, "webhook_deliveries", deliveries[1]).await);
    assert_eq!(
        db.query_one(
            "SELECT content_kind FROM inbound_events WHERE id=$1",
            &[&inbound_recent]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "redacted"
    );
    for id in [unknown, fenced] {
        assert_eq!(
            db.query_one("SELECT recipient_e164 FROM messages WHERE id=$1", &[&id])
                .await
                .unwrap()
                .get::<_, String>(0),
            "+15551234567"
        );
    }
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}
