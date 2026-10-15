// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise the real authenticated WebSocket route against disposable SQL.
//! No Android radio, SMS, provider, or external webhook is involved.

use super::*;
use crate::enrollment::{DeviceChallenge, device_challenge_bytes};
use futures_util::{SinkExt, StreamExt};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use rand::rng;
use serde_json::{Value, json};
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

/// The phone-side canonical readiness preimage (domain `ZT/line/readiness/v1`),
/// mirroring the Android store exactly.
fn readiness_digest(line: Uuid, kind: &str, since: Option<i64>, observed_at_ms: i64) -> String {
    let code = match kind {
        "inactive" => 1u8,
        "binding_not_active" => 2,
        "continuity_pending" => 3,
        "card_changed" => 4,
        "offline_past_threshold" => 5,
        "ready" => 6,
        _ => unreachable!("unknown kind"),
    };
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"ZT/line/readiness/v1\0");
    preimage.extend_from_slice(line.as_bytes());
    preimage.push(code);
    preimage.push(if since.is_none() { 0 } else { 1 });
    if let Some(age) = since {
        preimage.extend_from_slice(&age.to_be_bytes());
    }
    preimage.extend_from_slice(&observed_at_ms.to_be_bytes());
    URL_SAFE_NO_PAD.encode(Sha256::digest(&preimage))
}

fn readiness_frame(
    epoch: i64,
    line: Uuid,
    generation: i64,
    kind: &str,
    since: Option<i64>,
    observed_at_ms: i64,
    digest: String,
) -> Value {
    json!({
        "v":1,"type":"line_readiness","connection_epoch":epoch,"line_id":line,
        "binding_generation":generation,"kind":kind,
        "since_observation_ms":since,"observed_at_ms":observed_at_ms,"digest":digest
    })
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn line_readiness_observations_record_latest_and_refuse_foreign_or_stale_identity() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("line_readiness_socket_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
    let (db, connection) = tokio_postgres::connect(&schema_url, NoTls).await.unwrap();
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
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/095_device_session_line_activation_version.sql"
        ),
        include_str!("../../../../deploy/compose/migrations/099_line_readiness_observations.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let other_device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let other_line = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let other_signing = SigningKey::generate_from_rng(&mut rng());
    db.execute("INSERT INTO sites(site_id) VALUES('readiness-socket')", &[])
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
    for (line_id, account_id, device_id) in [
        (line, account, device),
        (other_line, other_account, other_device),
    ] {
        db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) \
            VALUES($1,$2,'active',clock_timestamp(),1,1)", &[&line_id,&account_id]).await.unwrap();
        db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,purpose,owner_approval_digest,device_confirmation_digest,activated_at) \
            VALUES($1,$2,$3,1,'active','sms',$4,$5,clock_timestamp()-interval '1 second')",
            &[&account_id,&line_id,&device_id,&vec![1_u8;32],&vec![2_u8;32]]).await.unwrap();
    }
    let state = DeviceSocketState {
        database_url: schema_url.clone(),
        site_id: "readiness-socket".into(),
        instance_id: "virtual-hub".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(11)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(12)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        sealed_dispatch_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        line_readiness_enabled: true,
        mms_spike_policy: std::sync::Arc::new(super::mms_spike_policy::MmsSpikePolicy::disabled()),
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let disabled_state = DeviceSocketState {
        line_readiness_enabled: false,
        ..state.clone()
    };
    let enabled_server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let disabled_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let disabled_address = disabled_listener.local_addr().unwrap();
    let disabled_server = tokio::spawn(async move {
        axum::serve(disabled_listener, router(disabled_state))
            .await
            .unwrap();
    });

    // With the frame dormant the observation is a policy refusal, not a
    // silent skip: a client that never negotiated the extension must learn.
    let (mut disabled_socket, disabled_epoch) =
        open_socket(disabled_address, account, device, &signing).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    send_json(
        &mut disabled_socket,
        readiness_frame(
            disabled_epoch,
            line,
            1,
            "ready",
            Some(1200),
            now,
            readiness_digest(line, "ready", Some(1200), now),
        ),
    )
    .await;
    assert_eq!(
        receive_close_code(&mut disabled_socket).await,
        close_code::POLICY
    );
    disabled_server.abort();

    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    // A ready observation backed by a fresh authenticated observation is
    // recorded as the line's latest.
    send_json(
        &mut socket,
        readiness_frame(
            epoch,
            line,
            1,
            "ready",
            Some(1200),
            now,
            readiness_digest(line, "ready", Some(1200), now),
        ),
    )
    .await;
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_readiness_ack","line_id":line,"accepted":true})
    );
    let stored = db
        .query_one(
            "SELECT kind,since_observation_ms,observed_at_ms FROM line_readiness_observations \
             WHERE account_id=$1 AND line_id=$2",
            &[&account, &line],
        )
        .await
        .unwrap();
    assert_eq!(stored.get::<_, String>("kind"), "ready");
    assert_eq!(
        stored.get::<_, Option<i64>>("since_observation_ms"),
        Some(1200)
    );
    assert_eq!(stored.get::<_, i64>("observed_at_ms"), now);

    // A newer observation replaces the latest.
    let changed_at = now + 1000;
    send_json(
        &mut socket,
        readiness_frame(
            epoch,
            line,
            1,
            "card_changed",
            Some(500),
            changed_at,
            readiness_digest(line, "card_changed", Some(500), changed_at),
        ),
    )
    .await;
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_readiness_ack","line_id":line,"accepted":true})
    );
    let kind: String = db
        .query_one(
            "SELECT kind FROM line_readiness_observations WHERE account_id=$1 AND line_id=$2",
            &[&account, &line],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kind, "card_changed");

    // An older phone clock never rolls the latest observation back, and the
    // honest answer says so.
    send_json(
        &mut socket,
        readiness_frame(
            epoch,
            line,
            1,
            "ready",
            Some(1200),
            now - 5000,
            readiness_digest(line, "ready", Some(1200), now - 5000),
        ),
    )
    .await;
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_readiness_ack","line_id":line,"accepted":false})
    );
    let kind: String = db
        .query_one(
            "SELECT kind FROM line_readiness_observations WHERE account_id=$1 AND line_id=$2",
            &[&account, &line],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kind, "card_changed");

    // A foreign line and a stale binding generation change nothing.
    send_json(
        &mut socket,
        readiness_frame(
            epoch,
            other_line,
            1,
            "ready",
            Some(1200),
            now + 2000,
            readiness_digest(other_line, "ready", Some(1200), now + 2000),
        ),
    )
    .await;
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_readiness_ack","line_id":other_line,"accepted":false})
    );
    send_json(
        &mut socket,
        readiness_frame(
            epoch,
            line,
            2,
            "ready",
            Some(1200),
            now + 3000,
            readiness_digest(line, "ready", Some(1200), now + 3000),
        ),
    )
    .await;
    assert_eq!(
        receive_json(&mut socket).await,
        json!({"v":1,"type":"line_readiness_ack","line_id":line,"accepted":false})
    );
    let kind: String = db
        .query_one(
            "SELECT kind FROM line_readiness_observations WHERE account_id=$1 AND line_id=$2",
            &[&account, &line],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kind, "card_changed");
    let other_rows: i64 = db
        .query_one(
            "SELECT count(*) FROM line_readiness_observations WHERE line_id=$1",
            &[&other_line],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(other_rows, 0, "a foreign line must never gain a row");

    // A frame whose digest does not bind the reported fields, and a ready
    // claim without an observation age, are malformed evidence.
    send_json(
        &mut socket,
        readiness_frame(
            epoch,
            line,
            1,
            "ready",
            Some(1300),
            now + 4000,
            readiness_digest(line, "ready", Some(1200), now + 4000),
        ),
    )
    .await;
    assert_eq!(receive_close_code(&mut socket).await, EVIDENCE_REJECTED);
    let (mut socket, epoch) = open_socket(address, account, device, &signing).await;
    send_json(
        &mut socket,
        readiness_frame(
            epoch,
            line,
            1,
            "ready",
            None::<i64>,
            now + 5000,
            readiness_digest(line, "ready", None, now + 5000),
        ),
    )
    .await;
    assert_eq!(receive_close_code(&mut socket).await, EVIDENCE_REJECTED);

    // An observation is telemetry, never send authority.
    assert_eq!(
        db.query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );

    enabled_server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
