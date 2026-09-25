// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise the real authenticated WebSocket route against disposable SQL.
//! No Android radio, SMS, provider, or external webhook is involved.

use super::*;
use crate::{
    enrollment::{DeviceChallenge, device_challenge_bytes},
    inbound::unsolicited::{Action, signed_line_opt_out_bytes},
};
use futures_util::{SinkExt, StreamExt};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use rand::rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

type TestSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn send_json(socket: &mut TestSocket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}

async fn receive_json(socket: &mut TestSocket) -> Value {
    let message = timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(message.to_text().unwrap()).unwrap()
}

async fn receive_close_code(socket: &mut TestSocket) -> u16 {
    let message = timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Close(Some(frame)) = message else {
        panic!("expected WebSocket close")
    };
    u16::from(frame.code)
}

async fn open_socket(
    address: std::net::SocketAddr,
    account: Uuid,
    device: Uuid,
    key: &SigningKey,
) -> (TestSocket, i64) {
    let (mut socket, _) = connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .unwrap();
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device}),
    )
    .await;
    let challenge_json = receive_json(&mut socket).await;
    let challenge = DeviceChallenge {
        id: Uuid::parse_str(challenge_json["challenge_id"].as_str().unwrap()).unwrap(),
        account_id: account,
        device_id: device,
        nonce: URL_SAFE_NO_PAD
            .decode(challenge_json["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let proof: Signature = key.sign(&device_challenge_bytes(&challenge));
    send_json(
        &mut socket,
        json!({
            "v":1,"type":"proof","challenge_id":challenge.id,"account_id":account,
            "device_id":device,"nonce":challenge_json["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())
        }),
    )
    .await;
    let session = receive_json(&mut socket).await;
    assert_eq!(session["type"], "session");
    (socket, session["connection_epoch"].as_i64().unwrap())
}

#[derive(Clone, Copy)]
struct FrameSpec<'a> {
    account: Uuid,
    device: Uuid,
    epoch: i64,
    line: Uuid,
    generation: i64,
    id: Uuid,
    sequence: i64,
    recipient: &'a str,
    action: Action,
}

fn signed_frame(spec: FrameSpec<'_>, key: &SigningKey) -> Value {
    let observed_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let session = InboundSession {
        account_id: spec.account,
        device_id: spec.device,
        site_id: "line-socket",
        instance_id: "virtual-hub",
        connection_epoch: spec.epoch,
        deployment_epoch: 1,
    };
    let event = LineOptOut {
        id: spec.id,
        line_id: spec.line,
        binding_generation: spec.generation,
        sequence: spec.sequence,
        recipient_e164: spec.recipient,
        action: spec.action,
        observed_at_ms,
        signature_der: &[],
    };
    let statement = signed_line_opt_out_bytes(session, &event).unwrap();
    let signature: Signature = key.sign(&statement);
    let action_wire = match spec.action {
        Action::Stop => "opt_out",
        Action::Review => "opt_out_review",
    };
    json!({
        "v":1,"type":"line_opt_out","connection_epoch":spec.epoch,
        "event_id":spec.id,"sequence":spec.sequence,"line_id":spec.line,
        "binding_generation":spec.generation,"action":action_wire,
        "recipient_e164":spec.recipient,"observed_at_ms":observed_at_ms,
        "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
    })
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn authenticated_line_opt_out_replays_and_rejects_wrong_line_epoch_and_sequence() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("line_opt_out_socket_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&schema_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
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
        include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/032_line_opt_out_events.sql"),
        include_str!("../../../../deploy/compose/migrations/033_sms_line_binding_scope.sql"),
        include_str!("../../../../deploy/compose/migrations/035_sms_owner_key_ceremony.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let other_device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let pending_line = Uuid::new_v4();
    let other_line = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let other_signing = SigningKey::generate_from_rng(&mut rng());
    db.execute("INSERT INTO sites(site_id) VALUES('line-socket')", &[])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO accounts(id) VALUES($1),($2)",
        &[&account, &other_account],
    )
    .await
    .unwrap();
    for (account_id, device_id, key) in [
        (account, device, &signing),
        (other_account, other_device, &other_signing),
    ] {
        let public = key.verifying_key().to_sec1_point(false);
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual device')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
            &[&device_id,&account_id,&public.as_bytes(),&&Sha256::digest(public.as_bytes())[..]])
            .await.unwrap();
    }
    for (line_id, account_id, device_id, active) in [
        (line, account, device, true),
        (pending_line, account, device, false),
        (other_line, other_account, other_device, true),
    ] {
        if active {
            db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) \
                VALUES($1,$2,'active',clock_timestamp(),1,1)", &[&line_id,&account_id]).await.unwrap();
            db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,purpose,owner_approval_digest,device_confirmation_digest,activated_at) \
                VALUES($1,$2,$3,1,'active','sms',$4,$5,clock_timestamp()-interval '1 second')",
                &[&account_id,&line_id,&device_id,&vec![1_u8;32],&vec![2_u8;32]]).await.unwrap();
        } else {
            db.execute(
                "INSERT INTO phone_lines(id,account_id,last_issued_generation) VALUES($1,$2,1)",
                &[&line_id, &account_id],
            )
            .await
            .unwrap();
            db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation) VALUES($1,$2,$3,1)",
                &[&account_id,&line_id,&device_id]).await.unwrap();
        }
    }
    let state = DeviceSocketState {
        database_url: schema_url.clone(),
        site_id: "line-socket".into(),
        instance_id: "virtual-hub".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: true,
        sms_line_activation_enabled: false,
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let disabled_state = DeviceSocketState {
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        ..state.clone()
    };
    let enabled_server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });

    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    let first_id = Uuid::new_v4();
    let first_spec = FrameSpec {
        account,
        device,
        epoch,
        line,
        generation: 1,
        id: first_id,
        sequence: 1,
        recipient: "+15551234567",
        action: Action::Stop,
    };
    let first = signed_frame(first_spec, &signing);
    send_json(&mut socket, first.clone()).await;
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_opt_out_ack","event_id":first_id,"created":true})
    );
    send_json(&mut socket, first.clone()).await;
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_opt_out_ack","event_id":first_id,"created":false})
    );
    assert_eq!(
        db.query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );

    let wrong_line = signed_frame(
        FrameSpec {
            line: pending_line,
            id: Uuid::new_v4(),
            sequence: 2,
            ..first_spec
        },
        &signing,
    );
    send_json(&mut socket, wrong_line).await;
    assert_eq!(receive_close_code(&mut socket).await, close_code::POLICY);

    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    let mut replay_after_reconnect = first.clone();
    replay_after_reconnect["connection_epoch"] = json!(epoch);
    send_json(&mut socket, replay_after_reconnect).await;
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_opt_out_ack","event_id":first_id,"created":false})
    );
    let changed = signed_frame(
        FrameSpec {
            epoch,
            recipient: "+15551234568",
            action: Action::Review,
            ..first_spec
        },
        &signing,
    );
    send_json(&mut socket, changed).await;
    assert_eq!(receive_close_code(&mut socket).await, EVIDENCE_REJECTED);

    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    let reused_sequence = signed_frame(
        FrameSpec {
            epoch,
            id: Uuid::new_v4(),
            ..first_spec
        },
        &signing,
    );
    send_json(&mut socket, reused_sequence).await;
    assert_eq!(receive_close_code(&mut socket).await, EVIDENCE_REJECTED);

    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    let mut altered_signature = first.clone();
    altered_signature["connection_epoch"] = json!(epoch);
    altered_signature["recipient_e164"] = json!("+15551234568");
    send_json(&mut socket, altered_signature).await;
    assert_eq!(receive_close_code(&mut socket).await, EVIDENCE_REJECTED);

    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    let wrong_generation = signed_frame(
        FrameSpec {
            epoch,
            generation: 2,
            id: Uuid::new_v4(),
            sequence: 2,
            ..first_spec
        },
        &signing,
    );
    send_json(&mut socket, wrong_generation).await;
    assert_eq!(receive_close_code(&mut socket).await, close_code::POLICY);

    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    let cross_account = signed_frame(
        FrameSpec {
            epoch,
            line: other_line,
            id: Uuid::new_v4(),
            sequence: 3,
            ..first_spec
        },
        &signing,
    );
    send_json(&mut socket, cross_account).await;
    assert_eq!(receive_close_code(&mut socket).await, close_code::POLICY);

    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    let lock = db.transaction().await.unwrap();
    lock.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
        &[&account],
    )
    .await
    .unwrap();
    let race_id = Uuid::new_v4();
    let race = signed_frame(
        FrameSpec {
            epoch,
            id: race_id,
            sequence: 4,
            recipient: "+15557654321",
            action: Action::Review,
            ..first_spec
        },
        &signing,
    );
    send_json(&mut socket, race).await;
    assert!(
        timeout(Duration::from_millis(150), socket.next())
            .await
            .is_err()
    );
    lock.commit().await.unwrap();
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_opt_out_ack","event_id":race_id,"created":true})
    );
    let row = db
        .query_one(
            "SELECT (SELECT count(*) FROM line_opt_out_events), \
        (SELECT count(*) FROM recipient_suppressions WHERE active), \
        (SELECT count(*) FROM webhook_deliveries)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (2, 2, 0)
    );

    // A second authenticated connection fences the first writer epoch.
    let (_new_socket, _new_epoch) = open_socket(address, account, device, &signing).await;
    let stale = signed_frame(
        FrameSpec {
            epoch,
            id: Uuid::new_v4(),
            sequence: 5,
            recipient: "+15559876543",
            ..first_spec
        },
        &signing,
    );
    send_json(&mut socket, stale).await;
    assert_eq!(receive_close_code(&mut socket).await, close_code::POLICY);

    // The feature flag is independent of the existing attempt-bound pilot.
    let disabled_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let disabled_address = disabled_listener.local_addr().unwrap();
    let disabled_server = tokio::spawn(async move {
        axum::serve(disabled_listener, router(disabled_state))
            .await
            .unwrap();
    });
    let (mut disabled_socket, disabled_epoch) =
        open_socket(disabled_address, account, device, &signing).await;
    let disabled_event = signed_frame(
        FrameSpec {
            epoch: disabled_epoch,
            id: Uuid::new_v4(),
            sequence: 6,
            ..first_spec
        },
        &signing,
    );
    send_json(&mut disabled_socket, disabled_event).await;
    assert_eq!(
        receive_close_code(&mut disabled_socket).await,
        close_code::POLICY
    );
    disabled_server.abort();

    enabled_server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
