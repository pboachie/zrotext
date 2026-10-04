// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    http_owner_conversations::activation::{
        self,
        tests::{activate, capture, pending},
    },
    webhook_worker::WebhookSecretVault,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

pub(super) fn vault() -> WebhookSecretVault {
    WebhookSecretVault::new(1, Zeroizing::new(crate::test_keys::key(125).to_vec())).unwrap()
}
pub(super) async fn endpoint(
    f: &crate::sealed_manifest_store::tests::Fixture,
    enabled: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    let cipher = vault()
        .seal(f.account, id, &crate::test_keys::key(126))
        .unwrap();
    f.db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled,sealed_events_enabled) VALUES($1,$2,'https://hooks.example.org/inbox',$3,1,true,$4)",&[&id,&f.account,&cipher,&enabled]).await.unwrap();
    id
}

#[test]
fn payload_is_exact_ciphertext_contract_and_retry_schedule_is_bounded() {
    let raw = vec![13; 426];
    let bytes = worker::event_body(
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        Uuid::from_u128(3),
        Uuid::from_u128(4),
        1,
        &raw,
        &[7; 32],
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 9);
    assert_eq!(body["type"], "sealed.inbound_event");
    assert_eq!(
        STANDARD
            .decode(body["envelope_b64"].as_str().unwrap())
            .unwrap(),
        raw
    );
    assert_eq!(
        (1..=7).map(retry_seconds).collect::<Vec<_>>(),
        vec![
            Some(60),
            Some(300),
            Some(900),
            Some(3600),
            Some(21600),
            Some(86400),
            None
        ]
    );
    assert!(
        worker::event_body(
            Uuid::nil(),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            Uuid::from_u128(4),
            1,
            &raw,
            &[7; 32]
        )
        .is_err()
    );
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn opt_in_capture_enqueues_once_and_exact_replay_never_adopts_new_endpoint() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    let first = endpoint(&f, false).await;
    capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.db.execute(
        "UPDATE webhook_endpoints SET sealed_events_enabled=true WHERE id=$1",
        &[&first],
    )
    .await
    .unwrap();
    let event = Uuid::new_v4();
    let bytes = capture(&f, &s, event, 2, b"+12").await.unwrap();
    endpoint(&f, true).await;
    let replay = crate::sealed_inbound::ingest::ingest_conversation(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &f.bytes,
        &bytes,
        activation::CaptureInterval {
            interval: s.interval,
            activation_digest: s.activation_digest,
        },
    )
    .await
    .unwrap();
    assert!(!replay.created);
    let rows =
        f.db.query(
            "SELECT event_id,interval_id,endpoint_id FROM sealed_event_deliveries",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, Uuid>(0), event);
    assert_eq!(rows[0].get::<_, Uuid>(1), s.interval);
    assert_eq!(rows[0].get::<_, Uuid>(2), first);
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM webhook_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn enqueue_failure_rolls_back_verified_event_sequence_and_budget() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    f.db.batch_execute(
        "ALTER TABLE sealed_event_deliveries ADD CONSTRAINT reject_synthetic_queue CHECK(false)",
    )
    .await
    .unwrap();
    let before: i64 =
        f.db.query_one(
            "SELECT coalesce(sum(attempts),0)::bigint FROM auth_abuse_counters",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let event = Uuid::new_v4();
    assert!(matches!(
        capture(&f, &s, event, 1, b"+12").await,
        Err(crate::sealed_inbound::ingest::IngestError::Delivery(
            DeliveryError::Database(_)
        ))
    ));
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_inbound_events", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM conversation_inbound_provenance", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one(
            "SELECT coalesce(sum(attempts),0)::bigint FROM auth_abuse_counters",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        before
    );
    f.db.batch_execute(
        "ALTER TABLE sealed_event_deliveries DROP CONSTRAINT reject_synthetic_queue",
    )
    .await
    .unwrap();
    capture(&f, &s, event, 1, b"+12").await.unwrap();
    f.cleanup().await;
}

async fn acknowledge(stream: impl sender::Stream) -> Vec<u8> {
    let mut stream = stream;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await.unwrap());
    }
    let text = std::str::from_utf8(&headers).unwrap();
    let count: usize = text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut body = vec![0; count];
    stream.read_exact(&mut body).await.unwrap();
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let timestamp: u64 = text
        .lines()
        .find_map(|line| line.strip_prefix("X-Zrotext-Timestamp: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let sig = text
        .lines()
        .find_map(|line| line.strip_prefix("X-Zrotext-Signature: "))
        .unwrap()
        .trim();
    assert_eq!(
        sig,
        crate::webhook_egress::signature_header(&crate::test_keys::key(126), timestamp, &body)
            .unwrap()
    );
    STANDARD
        .decode(json["envelope_b64"].as_str().unwrap())
        .unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn guarded_write_sends_exact_opaque_bytes_and_acknowledges_one_attempt() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    let bytes = capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    let (client, receiver) = sender::synthetic_tls_pair().await;
    let capture = tokio::spawn(acknowledge(receiver));
    assert!(
        worker::dispatch_with(&mut f.connect().await, &vault(), |_| async { Ok(client) })
            .await
            .unwrap()
    );
    assert_eq!(capture.await.unwrap(), bytes);
    let row=f.db.query_one("SELECT d.status,d.attempt_count,a.outcome FROM sealed_event_deliveries d JOIN sealed_event_delivery_attempts a ON a.delivery_id=d.id",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "succeeded");
    assert_eq!(row.get::<_, i16>(1), 1);
    assert_eq!(row.get::<_, String>(2), "ack");
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn purge_and_withdrawal_atomically_remove_attempts_and_cannot_rehydrate_on_replay() {
    let (f, owner, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    let event = Uuid::new_v4();
    let bytes = capture(&f, &s, event, 1, b"+12").await.unwrap();
    worker::dispatch_with(&mut f.connect().await, &vault(), |_| async {
        Err(crate::webhook_egress::EgressError::Transport)
    })
    .await
    .unwrap();
    f.db.execute(
        "UPDATE sealed_inbound_events SET envelope=NULL WHERE id=$1",
        &[&event],
    )
    .await
    .unwrap();
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_delivery_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(
        crate::sealed_inbound::ingest::ingest_conversation(
            &mut f.connect().await,
            f.session(),
            f.line,
            1,
            &f.bytes,
            &bytes,
            activation::CaptureInterval {
                interval: s.interval,
                activation_digest: s.activation_digest
            }
        )
        .await
        .is_err()
    );
    capture(&f, &s, Uuid::new_v4(), 2, b"+12").await.unwrap();
    activation::close(&mut f.connect().await, &owner, s.interval, true)
        .await
        .unwrap();
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn receipt_storage_failure_after_opaque_write_keeps_uncertain_lease_and_restart_identity() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    let original = capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    f.db.batch_execute("ALTER TABLE sealed_event_delivery_attempts ADD CONSTRAINT receipt_storage_failure CHECK(outcome IS DISTINCT FROM 'ack')").await.unwrap();
    let (socket, remote) = tokio::io::duplex(65_536);
    let received = tokio::spawn(acknowledge(remote));
    assert!(matches!(
        worker::dispatch_counted_with(&mut f.connect().await, &vault(), |_| async {
            Ok(sender::Connection::synthetic(socket))
        })
        .await,
        Err(DeliveryError::Database(_))
    ));
    assert_eq!(received.await.unwrap(), original);
    let row=f.db.query_one("SELECT d.id,d.event_id,d.status,a.completed_at IS NULL FROM sealed_event_deliveries d JOIN sealed_event_delivery_attempts a ON a.delivery_id=d.id",&[]).await.unwrap();
    let identity: Uuid = row.get(0);
    let event: Uuid = row.get(1);
    assert_eq!(row.get::<_, String>(2), "leased");
    assert!(row.get::<_, bool>(3));
    f.db.batch_execute("ALTER TABLE sealed_event_delivery_attempts DROP CONSTRAINT receipt_storage_failure; UPDATE sealed_event_deliveries SET lease_until=clock_timestamp()-interval '1 second'").await.unwrap();
    assert!(
        !worker::dispatch_counted_with(&mut f.connect().await, &vault(), |_| async {
            panic!("recovered uncertain lease must wait its retry delay")
        })
        .await
        .unwrap()
    );
    f.db.batch_execute(
        "UPDATE sealed_event_deliveries SET next_attempt_at=clock_timestamp()-interval '1 second'",
    )
    .await
    .unwrap();
    let (socket, remote) = tokio::io::duplex(65_536);
    let received = tokio::spawn(acknowledge(remote));
    assert!(
        worker::dispatch_counted_with(&mut f.connect().await, &vault(), |_| async {
            Ok(sender::Connection::synthetic(socket))
        })
        .await
        .unwrap()
    );
    assert_eq!(received.await.unwrap(), original);
    let row =
        f.db.query_one(
            "SELECT id,event_id,status,attempt_count FROM sealed_event_deliveries",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Uuid>(0), identity);
    assert_eq!(row.get::<_, Uuid>(1), event);
    assert_eq!(row.get::<_, String>(2), "succeeded");
    assert_eq!(row.get::<_, i16>(3), 2);
    let outcomes: Vec<String> =
        f.db.query(
            "SELECT outcome FROM sealed_event_delivery_attempts ORDER BY attempt_number",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(outcomes, vec!["timeout", "ack"]);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_expiry_during_connect_barrier_refuses_every_signed_byte() {
    let (f, owner, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    f.db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    let (socket, mut remote) = sender::synthetic_tls_pair().await;
    let (entered_tx, entered) = tokio::sync::oneshot::channel();
    let (release_tx, release) = tokio::sync::oneshot::channel();
    let mut db = f.connect().await;
    let secret = vault();
    let work = tokio::spawn(async move {
        worker::dispatch_with(&mut db, &secret, |_| async move {
            entered_tx.send(()).unwrap();
            release.await.unwrap();
            Ok(socket)
        })
        .await
    });
    entered.await.unwrap();
    assert!(
        f.db.query_one(
            "SELECT expires_at>clock_timestamp() FROM sessions WHERE id=$1",
            &[&owner.session_id]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let wait = tokio::time::Instant::now() + std::time::Duration::from_secs(6);
    while f
        .db
        .query_one(
            "SELECT expires_at>clock_timestamp() FROM sessions WHERE id=$1",
            &[&owner.session_id],
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    {
        assert!(tokio::time::Instant::now() < wait);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let _ = release_tx.send(());
    assert!(matches!(
        work.await.unwrap(),
        Err(DeliveryError::Conversation(
            crate::http_owner_conversations::ConversationError::Forbidden
        ))
    ));
    let mut raw = Vec::new();
    let closed = remote.read_to_end(&mut raw).await;
    assert!(
        closed.is_ok()
            || matches!(closed, Err(ref error) if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    assert!(raw.is_empty());
    assert_eq!(
        f.db.query_one("SELECT status FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "dead"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn selected_queue_capacity_error_rolls_back_admission_before_budget_commit() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    let mut ids = Vec::new();
    for _ in 0..6 {
        ids.push(endpoint(&f, true).await);
    }
    let event = Uuid::new_v4();
    assert!(matches!(
        capture(&f, &s, event, 1, b"+12").await,
        Err(crate::sealed_inbound::ingest::IngestError::Delivery(
            DeliveryError::Capacity
        ))
    ));
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_inbound_events", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.db.execute("DELETE FROM webhook_endpoints WHERE id=$1", &[&ids[5]])
        .await
        .unwrap();
    capture(&f, &s, event, 1, b"+12").await.unwrap();
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        5
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn root_withdrawal_refuses_connect_and_owner_takeout_has_only_delivery_metadata() {
    let (f, owner, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    let event = Uuid::new_v4();
    capture(&f, &s, event, 1, b"+12").await.unwrap();
    let export = lifecycle::export(&mut f.connect().await, &owner, None)
        .await
        .unwrap();
    assert_eq!(export.items.len(), 1);
    assert_eq!(export.items[0]["event_id"], event.to_string());
    assert!(export.items[0]["attempts"].as_array().unwrap().is_empty());
    assert!(export.items[0].get("envelope").is_none());
    assert!(export.items[0].get("signing_secret_ciphertext").is_none());
    f.db.execute(
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    assert!(
        worker::dispatch_with(&mut f.connect().await, &vault(), |_| async {
            panic!("revoked authority must refuse before connect")
        })
        .await
        .is_err()
    );
    // Resolve the maintained erasure statements by name. Optional proposal
    // tables may precede these entries and are absent in this fixture.
    let plan: Vec<_> = crate::http_owner_erasure::DELETE_PLAN
    let sealed_deletes: Vec<_> = crate::http_owner_erasure::DELETE_PLAN
        .iter()
        .filter(|(table, _)| {
            matches!(
                *table,
                "sealed_event_delivery_attempts" | "sealed_event_deliveries"
            )
        })
        .collect();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].0, "sealed_event_delivery_attempts");
    assert_eq!(plan[1].0, "sealed_event_deliveries");
    for (_, sql) in plan {
                "sealed_event_deliveries" | "sealed_event_delivery_attempts"
            )
        })
        .collect();
    assert_eq!(sealed_deletes.len(), 2);
    for (_, sql) in sealed_deletes {
        let tx = &mut f.connect().await;
        tx.execute(*sql, &[&f.account]).await.unwrap();
    }
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_delivery_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn withdrawal_waits_for_the_bounded_held_send_and_then_retires_the_exact_interval() {
    let (f, owner, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    let bytes = capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    let (socket, remote) = tokio::io::duplex(65_536);
    let received = tokio::spawn(acknowledge(remote));
    let mut db = f.connect().await;
    let sender_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let secret = vault();
    let (entered_tx, entered) = tokio::sync::oneshot::channel();
    let (release_tx, release) = tokio::sync::oneshot::channel();
    let work = tokio::spawn(async move {
        worker::dispatch_with(&mut db, &secret, |_| async move {
            entered_tx.send(()).unwrap();
            release.await.unwrap();
            Ok(sender::Connection::synthetic(socket))
        })
        .await
    });
    entered.await.unwrap();
    let mut closer = f.connect().await;
    let closer_pid: i32 = closer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let interval = s.interval;
    let close =
        tokio::spawn(async move { activation::close(&mut closer, &owner, interval, true).await });
    let stop = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let blocked: bool =
            f.db.query_one(
                "SELECT $1=ANY(pg_blocking_pids($2))",
                &[&sender_pid, &closer_pid],
            )
            .await
            .unwrap()
            .get(0);
        if blocked {
            break;
        }
        assert!(!close.is_finished());
        assert!(tokio::time::Instant::now() < stop);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    release_tx.send(()).unwrap();
    assert!(work.await.unwrap().unwrap());
    assert_eq!(received.await.unwrap(), bytes);
    close.await.unwrap().unwrap();
    assert_eq!(
        f.db.query_one(
            "SELECT phase FROM conversation_intervals WHERE id=$1",
            &[&interval]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "withdrawn"
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn paused_capture_is_retained_and_disabled_worker_cannot_consume_it_before_resume() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    let endpoint_id = endpoint(&f, true).await;
    f.db.execute(
        "UPDATE webhook_endpoints SET paused_at=clock_timestamp() WHERE id=$1",
        &[&endpoint_id],
    )
    .await
    .unwrap();
    let bytes = capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    let row =
        f.db.query_one(
            "SELECT status,attempt_count FROM sealed_event_deliveries",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "pending");
    assert_eq!(row.get::<_, i16>(1), 0);
    assert!(
        !dispatch_one("postgres://unused", &vault(), false)
            .await
            .unwrap()
    );
    assert!(
        !worker::dispatch_with(&mut f.connect().await, &vault(), |_| async {
            panic!("paused endpoint cannot connect")
        })
        .await
        .unwrap()
    );
    assert_eq!(
        f.db.query_one("SELECT attempt_count FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i16>(0),
        0
    );
    f.db.execute(
        "UPDATE webhook_endpoints SET paused_at=NULL,failure_started_at=NULL WHERE id=$1",
        &[&endpoint_id],
    )
    .await
    .unwrap();
    let (connection, receiver) = sender::synthetic_tls_pair().await;
    let received = tokio::spawn(acknowledge(receiver));
    assert!(
        worker::dispatch_with(&mut f.connect().await, &vault(), |_| async {
            Ok(connection)
        })
        .await
        .unwrap()
    );
    assert_eq!(received.await.unwrap(), bytes);
    assert_eq!(
        f.db.query_one("SELECT status FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "succeeded"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn enabled_sealed_batch_recovers_expired_legacy_lease_without_sending_or_exceeding_limit() {
    let (f, _, _) = pending().await;
    let endpoint_id = endpoint(&f, false).await;
    let message = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let event = Uuid::new_v4();
    let delivery = Uuid::new_v4();
    f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+12',$4,'synthetic_alpha',$5,$6,'submitted',clock_timestamp()+interval '1 hour')",&[&message,&f.account,&f.device,&vec![2u8;32],&b"synthetic".as_slice(),&vec![3u8;32]]).await.unwrap();
    f.db.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,1,2,1,'submitted')",&[&attempt_id,&f.account,&message,&f.device]).await.unwrap();
    f.db.execute("INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence,classification,observed_at,part_count,content_kind,event_digest,signature_der) VALUES($1,$2,$3,$4,$5,1,'captured_local',clock_timestamp(),1,'metadata_only',$6,$7)",&[&event,&f.account,&f.device,&message,&attempt_id,&vec![4u8;32],&vec![5u8;8]]).await.unwrap();
    f.db.execute("INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,status,attempt_count,lease_owner,lease_until) VALUES($1,$2,$3,$4,'leased',1,'synthetic',clock_timestamp()-interval '1 second')",&[&delivery,&f.account,&endpoint_id,&event]).await.unwrap();
    f.db.execute(
        "INSERT INTO webhook_attempts(id,delivery_id,generation,attempt_number) VALUES($1,$2,1,1)",
        &[&Uuid::new_v4(), &delivery],
    )
    .await
    .unwrap();
    let separator = if f.url.contains('?') { '&' } else { '?' };
    let scoped = format!("{}{separator}options=-csearch_path%3D{}", f.url, f.schema);
    let mut preferred = true;
    let draining = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        crate::webhook_worker::dispatch_lane_batch_with_sealed(
            &scoped,
            &vault(),
            "synthetic",
            1,
            true,
            &mut preferred,
            &draining
        )
        .await
        .unwrap(),
        0
    );
    let row=f.db.query_one("SELECT d.status,d.attempt_count,d.next_attempt_at>clock_timestamp(),a.outcome,a.completed_at IS NOT NULL FROM webhook_deliveries d JOIN webhook_attempts a ON a.delivery_id=d.id WHERE d.id=$1",&[&delivery]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "pending");
    assert_eq!(row.get::<_, i16>(1), 1);
    assert!(row.get::<_, bool>(2));
    assert_eq!(row.get::<_, String>(3), "timeout");
    assert!(row.get::<_, bool>(4));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn durably_closed_policy_rejections_count_one_each_but_no_work_does_not() {
    let (f, _, s) = pending().await;
    activate(&f, &s).await;
    endpoint(&f, true).await;
    capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.unwrap();
    capture(&f, &s, Uuid::new_v4(), 2, b"+12").await.unwrap();
    f.db.execute(
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    for _ in 0..2 {
        assert!(
            worker::dispatch_counted_with(&mut f.connect().await, &vault(), |_| async {
                panic!("revoked authority must not connect")
            })
            .await
            .unwrap()
        );
    }
    assert!(
        !worker::dispatch_counted_with(&mut f.connect().await, &vault(), |_| async {
            panic!("empty queue must not connect")
        })
        .await
        .unwrap()
    );
    assert_eq!(f.db.query_one("SELECT count(*) FROM sealed_event_deliveries d JOIN sealed_event_delivery_attempts a ON a.delivery_id=d.id WHERE d.status='dead' AND a.outcome='policy_rejected' AND a.completed_at IS NOT NULL",&[]).await.unwrap().get::<_,i64>(0),2);
    f.cleanup().await;
}
