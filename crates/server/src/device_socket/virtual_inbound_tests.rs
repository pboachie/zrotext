// SPDX-License-Identifier: AGPL-3.0-only
//! A localhost device speaks the real socket protocol against disposable SQL.
//! No Android radio, SMS, DNS lookup, or external webhook request is involved.

use super::*;
use crate::{
    enrollment::{DeviceChallenge, device_challenge_bytes},
    webhook_egress::{DeliveryResponse, EgressError},
    webhook_worker::{WebhookSecretVault, dispatch_one_with},
};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use rand::rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use zeroize::Zeroizing;

type TestSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn receive_json(socket: &mut TestSocket) -> Value {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("socket response timed out")
        .expect("socket closed")
        .expect("socket read failed");
    let Message::Text(text) = &frame else {
        panic!("expected a text frame, got {frame:?}");
    };
    serde_json::from_str(text).expect("invalid server JSON")
}

async fn send_json(socket: &mut TestSocket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .expect("socket send failed");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn authenticated_inbound_replay_retries_one_webhook_delivery() {
    let url = std::env::var("ZT_INBOUND_TEST_DATABASE_URL")
        .expect("set ZT_INBOUND_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("inbound_socket_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let endpoint_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public_key = signing.verifying_key().to_sec1_point(false);
    let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
    db.execute("INSERT INTO sites(site_id) VALUES('socket-test')", &[])
        .await
        .unwrap();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual device')",
        &[&device_id, &account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&device_id, &account_id, &public_key.as_bytes(), &&fingerprint[..]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,'+15555550101',$4,'synthetic_alpha',$5,$6,'submitted',now()+interval '1 hour')",
        &[&message_id, &account_id, &device_id, &vec![2u8; 32], &b"fixture".as_slice(), &vec![3u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,1,1,1,'submitted')",
        &[&attempt_id, &account_id, &message_id, &device_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,event_digest,observed_at,resulting_state,segment_index,segment_count) \
         VALUES($1,$2,$3,$4,'sent_callback_ok',$5,now(),'submitted',0,1)",
        &[&Uuid::new_v4(), &account_id, &message_id, &attempt_id, &vec![4u8; 32]],
    )
    .await
    .unwrap();
    let vault = WebhookSecretVault::new(1, Zeroizing::new(crate::test_keys::key(7))).unwrap();
    let secret = vault
        .seal(account_id, endpoint_id, &crate::test_keys::key(8))
        .unwrap();
    db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled) \
         VALUES($1,$2,'https://hooks.example.org/inbound',$3,1,true)",
        &[&endpoint_id, &account_id, &secret],
    )
    .await
    .unwrap();

    let state = DeviceSocketState {
        // The dispatch path acquires its own worker-class sockets through the
        // runtime pool; keep the schema-scoped URL for those calls.
        database_url: schema_url.clone(),
        site_id: "socket-test".into(),
        instance_id: "virtual-server".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: true,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        mms_spike_policy: Arc::new(MmsSpikePolicy::disabled()),
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let (mut socket, _) = connect_async(format!("ws://{address}/v1/device-stream"))
        .await
        .unwrap();
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device_id}),
    )
    .await;
    let challenge_json = receive_json(&mut socket).await;
    assert_eq!(challenge_json["type"], "challenge");
    let challenge = DeviceChallenge {
        id: Uuid::parse_str(challenge_json["challenge_id"].as_str().unwrap()).unwrap(),
        account_id,
        device_id,
        nonce: URL_SAFE_NO_PAD
            .decode(challenge_json["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let proof: Signature = signing.sign(&device_challenge_bytes(&challenge));
    send_json(
        &mut socket,
        json!({
            "v":1,"type":"proof","challenge_id":challenge.id,"account_id":account_id,
            "device_id":device_id,"nonce":challenge_json["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())
        }),
    )
    .await;
    let session_json = receive_json(&mut socket).await;
    assert_eq!(session_json["type"], "session");
    let connection_epoch = session_json["connection_epoch"].as_i64().unwrap();
    let observed_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let inbound_session = InboundSession {
        account_id,
        device_id,
        site_id: "socket-test",
        instance_id: "virtual-server",
        connection_epoch,
        deployment_epoch: 1,
    };
    let event = InboundEvent {
        event_id,
        sequence: 1,
        message_id,
        attempt_id,
        classification: inbound::Classification::CapturedLocal,
        observed_at_ms,
        part_count: 1,
        content: Content::MetadataOnly,
        signature_der: &[],
    };
    let signature: Signature = signing.sign(&inbound::signed_event_bytes(inbound_session, &event));
    let frame = json!({
        "v":1,"type":"inbound_event","connection_epoch":connection_epoch,
        "event_id":event_id,"sequence":1,"message_id":message_id,
        "attempt_id":attempt_id,"classification":"captured_local",
        "observed_at_ms":observed_at_ms,"part_count":1,
        "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
    });
    send_json(&mut socket, frame.clone()).await;
    let ack = receive_json(&mut socket).await;
    assert_eq!(
        ack,
        json!({"v":1,"type":"inbound_event_ack","event_id":event_id,"created":true,"queued_deliveries":1})
    );
    send_json(&mut socket, frame).await;
    let replay_ack = receive_json(&mut socket).await;
    assert_eq!(
        replay_ack,
        json!({"v":1,"type":"inbound_event_ack","event_id":event_id,"created":false,"queued_deliveries":0})
    );
    let row = db
        .query_one(
            "SELECT (SELECT count(*) FROM inbound_events WHERE id=$1), \
                    (SELECT count(*) FROM webhook_deliveries WHERE event_id=$1 AND endpoint_id=$2)",
            &[&event_id, &endpoint_id],
        )
        .await
        .unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (1, 1));

    // The socket replay above must still leave one logical event and delivery.
    // Drive that delivery through the real claim, payload, and retry code while
    // a local receiver stub checks the stable body and decrypted signing key.
    let received = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    for (attempt, expected_outcome) in ["http_error", "network_error", "ack"]
        .into_iter()
        .enumerate()
    {
        let received = received.clone();
        assert!(
            dispatch_one_with(
                &schema_url,
                &vault,
                "virtual-receiver",
                move |url, body, secret| async move {
                    assert_eq!(url, "https://hooks.example.org/inbound");
                    assert_eq!(secret.as_slice(), crate::test_keys::key(8).as_slice());
                    let parsed: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(parsed["event_id"], event_id.to_string());
                    assert_eq!(parsed["message_id"], message_id.to_string());
                    assert_eq!(parsed["content_kind"], "metadata_only");
                    assert!(parsed.get("sender_e164").is_none());
                    assert!(parsed.get("body").is_none());
                    let timestamp = 1_750_000_000_u64;
                    let header =
                        crate::webhook_egress::signature_header(&secret, timestamp, &body).unwrap();
                    let digest = header.strip_prefix("v1=").unwrap();
                    let digest = digest
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|pair| {
                            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect::<Vec<_>>();
                    let mut verifier =
                        <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&secret).unwrap();
                    verifier.update(timestamp.to_string().as_bytes());
                    verifier.update(b".");
                    verifier.update(&body);
                    verifier.verify_slice(&digest).unwrap();
                    received.lock().unwrap().push(body);
                    match attempt {
                        0 => Ok(DeliveryResponse {
                            status: 500,
                            acknowledged: false,
                        }),
                        1 => Err(EgressError::Transport),
                        _ => Ok(DeliveryResponse {
                            status: 204,
                            acknowledged: true,
                        }),
                    }
                }
            )
            .await
            .unwrap()
        );
        let outcome: String = db
            .query_one(
                "SELECT outcome FROM webhook_attempts a JOIN webhook_deliveries d ON d.id=a.delivery_id \
                 WHERE d.event_id=$1 AND d.endpoint_id=$2 AND a.attempt_number=$3",
                &[&event_id, &endpoint_id, &((attempt + 1) as i16)],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(outcome, expected_outcome);
        if attempt < 2 {
            assert!(
                !dispatch_one_with(&schema_url, &vault, "early-retry", |_, _, _| async {
                    unreachable!("retry must observe backoff")
                })
                .await
                .unwrap()
            );
            assert_eq!(
                db.execute(
                    "UPDATE webhook_deliveries SET next_attempt_at=now()-interval '1 second' \
                     WHERE event_id=$1 AND endpoint_id=$2 AND status='pending'",
                    &[&event_id, &endpoint_id],
                )
                .await
                .unwrap(),
                1
            );
        }
    }
    {
        let bodies = received.lock().unwrap();
        assert_eq!(bodies.len(), 3);
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
    }
    let row = db
        .query_one(
            "SELECT (SELECT count(*) FROM inbound_events WHERE id=$1), \
                    (SELECT count(*) FROM webhook_deliveries WHERE event_id=$1 AND endpoint_id=$2), \
                    (SELECT status FROM webhook_deliveries WHERE event_id=$1 AND endpoint_id=$2), \
                    (SELECT attempt_count FROM webhook_deliveries WHERE event_id=$1 AND endpoint_id=$2)",
            &[&event_id, &endpoint_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, String>(2), "succeeded");
    assert_eq!(row.get::<_, i16>(3), 3);
    assert!(
        !dispatch_one_with(&schema_url, &vault, "virtual-receiver", |_, _, _| async {
            unreachable!("a completed delivery must not be sent again")
        })
        .await
        .unwrap()
    );

    // Revoking a key must close an already-authenticated connection on its
    // next heartbeat, even though its original challenge succeeded.
    db.execute(
        "UPDATE device_keys SET revoked_at=now() WHERE device_id=$1",
        &[&device_id],
    )
    .await
    .unwrap();
    send_json(&mut socket, json!({"type":"heartbeat", "v":1})).await;
    let closed = timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap();
    assert!(matches!(closed, Some(Ok(Message::Close(_))) | None));
    server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// One enrolled phone behind a real socket router on a disposable schema.
struct HandshakeFixture {
    admin: tokio_postgres::Client,
    db: tokio_postgres::Client,
    schema: String,
    address: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    auth_hasher: Arc<TokenHasher>,
    account_id: Uuid,
    device_id: Uuid,
    signing: SigningKey,
}

impl HandshakeFixture {
    async fn start(prefix: &str) -> Self {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
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
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
            include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        ] {
            db.batch_execute(migration).await.unwrap();
        }
        let account_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let signing = SigningKey::generate_from_rng(&mut rng());
        let public_key = signing.verifying_key().to_sec1_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
        db.execute("INSERT INTO sites(site_id) VALUES('fixture')", &[])
            .await
            .unwrap();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
            .await
            .unwrap();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'handshake fixture')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device_id,&account_id,&public_key.as_bytes(),&&fingerprint[..]]).await.unwrap();
        let auth_hasher = Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap());
        let state = DeviceSocketState {
            database_url: schema_url,
            site_id: "fixture".into(),
            instance_id: "fixture".into(),
            deployment_epoch: 1,
            enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
            auth_hasher: auth_hasher.clone(),
            alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
            dispatch_runtime_enabled: false,
            inbound_pilot_enabled: false,
            line_opt_out_enabled: false,
            sms_line_activation_enabled: false,
            mms_spike_policy: Arc::new(MmsSpikePolicy::disabled()),
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        Self {
            admin,
            db,
            schema,
            address,
            server,
            auth_hasher,
            account_id,
            device_id,
            signing,
        }
    }

    /// Opens a socket and sends `hello` naming `device_id`.
    async fn hello(&self, device_id: Uuid) -> TestSocket {
        let (mut socket, _) = connect_async(format!("ws://{}/v1/device-stream", self.address))
            .await
            .unwrap();
        send_json(
            &mut socket,
            json!({"v":1,"type":"hello","device_id":device_id}),
        )
        .await;
        socket
    }

    /// Enrolls a second device on the fixture's account.
    async fn enroll(&self) -> (Uuid, SigningKey) {
        let device_id = Uuid::new_v4();
        let signing = SigningKey::generate_from_rng(&mut rng());
        let public_key = signing.verifying_key().to_sec1_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
        self.db
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'second fixture')",
                &[&device_id, &self.account_id],
            )
            .await
            .unwrap();
        self.db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device_id,&self.account_id,&public_key.as_bytes(),&&fingerprint[..]]).await.unwrap();
        (device_id, signing)
    }

    /// Opens a socket for the enrolled phone and returns its challenge frame.
    async fn challenge(&self) -> (TestSocket, Value) {
        self.challenge_for(self.device_id).await
    }

    /// Opens a socket for enrolled `device_id` and returns its challenge.
    async fn challenge_for(&self, device_id: Uuid) -> (TestSocket, Value) {
        let mut socket = self.hello(device_id).await;
        let challenge = receive_json(&mut socket).await;
        assert_eq!(challenge["type"], "challenge");
        assert_eq!(challenge["account_id"], json!(self.account_id));
        assert_eq!(challenge["device_id"], json!(device_id));
        (socket, challenge)
    }

    /// The phone's proof frame for `challenge`, signed with its device key.
    fn proof(&self, challenge: &Value) -> Value {
        self.proof_for(challenge, self.device_id, &self.signing)
    }

    /// A proof frame for `challenge` signed by `device_id`'s `signing` key.
    fn proof_for(&self, challenge: &Value, device_id: Uuid, signing: &SigningKey) -> Value {
        let typed = DeviceChallenge {
            id: Uuid::parse_str(challenge["challenge_id"].as_str().unwrap()).unwrap(),
            account_id: self.account_id,
            device_id,
            nonce: URL_SAFE_NO_PAD
                .decode(challenge["nonce"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let signature: Signature = signing.sign(&device_challenge_bytes(&typed));
        json!({
            "v":1,"type":"proof","challenge_id":challenge["challenge_id"],
            "account_id":self.account_id,"device_id":device_id,
            "nonce":challenge["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
        })
    }

    /// Attempts per route row of `scope`, smallest first.
    async fn route_attempts(&self, scope: &str) -> Vec<i32> {
        self.db
            .query(
                "SELECT attempts FROM auth_abuse_counters WHERE scope=$1 ORDER BY attempts",
                &[&scope],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    /// Spends the anonymous route ceiling (300) until it refuses.
    async fn fill_anonymous(&self, limit: Limit) {
        for _ in 0..=300 {
            if !abuse_limits::consume(&self.db, &self.auth_hasher, limit, None)
                .await
                .unwrap()
            {
                return;
            }
        }
        panic!("the anonymous route ceiling never refused");
    }

    /// Spends the verified route ceiling (3,000) until it refuses.
    async fn fill_verified(&self, limit: Limit) {
        for _ in 0..=3_000 {
            if !abuse_limits::consume_verified_route(&self.db, &self.auth_hasher, limit)
                .await
                .unwrap()
            {
                return;
            }
        }
        panic!("the verified route ceiling never refused");
    }

    async fn finish(self) {
        self.server.abort();
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

async fn expect_close(socket: &mut TestSocket, code: u16) {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("socket close timed out");
    assert!(
        matches!(
            &frame,
            Some(Ok(Message::Close(Some(close)))) if u16::from(close.code) == code
        ),
        "expected close {code}, got {frame:?}"
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn knowing_the_device_id_cannot_refuse_the_enrolled_phone() {
    let fixture = HandshakeFixture::start("socket_budget").await;
    // An unauthenticated attacker who knows only the public device ID asks
    // for 60 challenges in a minute: twice the per-device budget this flow
    // used to charge, and each request indistinguishable from the phone's.
    for _ in 0..60 {
        let mut probe = fixture.hello(fixture.device_id).await;
        let challenge = receive_json(&mut probe).await;
        assert_eq!(challenge["type"], "challenge");
        drop(probe);
    }
    // None of that spending can refuse the enrolled phone: with no
    // per-device counter, only the shared route ceiling gates issuance, and
    // it is far from full.
    let (mut socket, challenge) = fixture.challenge().await;
    // A garbage signature is a policy refusal, not a budget one, and leaves
    // the phone free to reconnect at once.
    let mut garbage = fixture.proof(&challenge);
    garbage["signature_der"] = json!(URL_SAFE_NO_PAD.encode([0u8; 16]));
    send_json(&mut socket, garbage).await;
    expect_close(&mut socket, close_code::POLICY).await;
    // The phone reconnects immediately and completes its handshake.
    let (mut socket, challenge) = fixture.challenge().await;
    send_json(&mut socket, fixture.proof(&challenge)).await;
    assert_eq!(receive_json(&mut socket).await["type"], "session");
    drop(socket);
    // Made-up proofs fill the anonymous proof ceiling. The enrolled phone's
    // valid proof is still admitted, through the verified-route ceiling.
    fixture.fill_anonymous(Limit::DeviceAuthenticate).await;
    let (mut socket, challenge) = fixture.challenge().await;
    send_json(&mut socket, fixture.proof(&challenge)).await;
    assert_eq!(receive_json(&mut socket).await["type"], "session");
    drop(socket);
    // A proof that does not verify is refused by policy and never reaches
    // the verified ceiling: only the phone's one valid proof was charged.
    let (mut socket, challenge) = fixture.challenge().await;
    let mut garbage = fixture.proof(&challenge);
    garbage["signature_der"] = json!(URL_SAFE_NO_PAD.encode([0u8; 16]));
    send_json(&mut socket, garbage).await;
    expect_close(&mut socket, close_code::POLICY).await;
    assert_eq!(
        fixture.route_attempts("device_authenticate").await,
        vec![1, 300]
    );
    // The verified ceiling still bounds enrolled devices: once it is full as
    // well, even a valid proof waits with a retryable close.
    fixture.fill_verified(Limit::DeviceAuthenticate).await;
    let (mut socket, challenge) = fixture.challenge().await;
    send_json(&mut socket, fixture.proof(&challenge)).await;
    expect_close(&mut socket, RETRY_LATER).await;
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn junk_filling_both_anonymous_ceilings_cannot_refuse_the_enrolled_phone() {
    let fixture = HandshakeFixture::start("socket_junk").await;
    // One anonymous source fills both shared handshake route ceilings with
    // made-up device IDs and proofs, as rapid hello/close cycles would.
    fixture.fill_anonymous(Limit::DeviceChallenge).await;
    fixture.fill_anonymous(Limit::DeviceAuthenticate).await;
    // Junk is refused with a retryable close and does not reach the verified
    // ceiling, because no enrolled device carries its ID.
    let mut junk = fixture.hello(Uuid::new_v4()).await;
    expect_close(&mut junk, RETRY_LATER).await;
    // The enrolled phone is admitted through the verified-route ceilings and
    // completes hello, challenge, proof and session.
    let (mut socket, challenge) = fixture.challenge().await;
    send_json(&mut socket, fixture.proof(&challenge)).await;
    assert_eq!(receive_json(&mut socket).await["type"], "session");
    drop(socket);
    // The phone's hello spent the verified route row and its own device
    // share once each; junk created no verified row at all.
    assert_eq!(
        fixture.route_attempts("device_challenge").await,
        vec![1, 1, 300]
    );
    assert_eq!(
        fixture.route_attempts("device_authenticate").await,
        vec![1, 300]
    );
    // The verified-route ceiling is the bound for enrolled devices: once it
    // is full too, the phone waits with a retryable close.
    fixture.fill_verified(Limit::DeviceChallenge).await;
    let mut waiting = fixture.hello(fixture.device_id).await;
    expect_close(&mut waiting, RETRY_LATER).await;
    // The refusal is retryable and bounded: once the 60-second window rolls
    // over, the enrolled phone completes its handshake again.
    fixture
        .db
        .execute(
            "UPDATE auth_abuse_counters SET window_started_at=clock_timestamp()-interval '61 seconds' WHERE scope IN ('device_challenge','device_authenticate')",
            &[],
        )
        .await
        .unwrap();
    let (mut socket, challenge) = fixture.challenge().await;
    send_json(&mut socket, fixture.proof(&challenge)).await;
    assert_eq!(receive_json(&mut socket).await["type"], "session");
    drop(socket);
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn a_proof_for_another_connections_challenge_is_refused() {
    let fixture = HandshakeFixture::start("socket_replay").await;
    // Stateless challenges are not marked used, so the socket's equality gate
    // (the proof must echo this connection's own challenge) is the only
    // barrier against a valid proof being reused on another connection.
    let (mut first, first_challenge) = fixture.challenge().await;
    let (mut second, second_challenge) = fixture.challenge().await;
    assert_ne!(
        first_challenge["challenge_id"],
        second_challenge["challenge_id"]
    );
    let first_proof = fixture.proof(&first_challenge);
    // A's valid, in-window proof sent on B is a policy close with no session.
    send_json(&mut second, first_proof.clone()).await;
    expect_close(&mut second, close_code::POLICY).await;
    // Replaying A's proof after A has gone, on a fresh connection, is
    // refused the same way.
    let _ = first.close(None).await;
    drop(first);
    let (mut third, _) = fixture.challenge().await;
    send_json(&mut third, first_proof).await;
    expect_close(&mut third, close_code::POLICY).await;
    // The refusals were about binding, not the phone: its own proof on a new
    // connection still opens a session.
    let (mut socket, challenge) = fixture.challenge().await;
    send_json(&mut socket, fixture.proof(&challenge)).await;
    assert_eq!(receive_json(&mut socket).await["type"], "session");
    drop(socket);
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn one_known_device_id_cannot_starve_another_enrolled_phone() {
    let fixture = HandshakeFixture::start("socket_share").await;
    let (other_device, other_signing) = fixture.enroll().await;
    // Junk has filled the anonymous issuance ceiling, so every enrolled
    // device is being admitted through the verified ceiling.
    fixture.fill_anonymous(Limit::DeviceChallenge).await;
    // An attacker who knows one live device ID hammers hellos naming it. It
    // gets that device's share of the verified ceiling (60 per window) and
    // no more: the 61st hello is a retryable refusal.
    for _ in 0..60 {
        let mut probe = fixture.hello(fixture.device_id).await;
        assert_eq!(receive_json(&mut probe).await["type"], "challenge");
    }
    let mut refused = fixture.hello(fixture.device_id).await;
    expect_close(&mut refused, RETRY_LATER).await;
    // Junk naming unknown device IDs still never reaches the verified ceiling.
    let mut junk = fixture.hello(Uuid::new_v4()).await;
    expect_close(&mut junk, RETRY_LATER).await;
    // Another enrolled phone is untouched: it completes its handshake.
    let (mut socket, challenge) = fixture.challenge_for(other_device).await;
    send_json(
        &mut socket,
        fixture.proof_for(&challenge, other_device, &other_signing),
    )
    .await;
    assert_eq!(receive_json(&mut socket).await["type"], "session");
    drop(socket);
    // Rows: the other phone's share (1), the targeted device's share (60),
    // the verified route (61) and the anonymous route (300). No junk row.
    assert_eq!(
        fixture.route_attempts("device_challenge").await,
        vec![1, 60, 61, 300]
    );
    // The targeted device's share resets with its window, while the
    // anonymous ceiling is still full: the phone is admitted again.
    let share = abuse_limits::subject_hash(
        &fixture.auth_hasher,
        Limit::DeviceChallenge,
        &fixture.device_id.to_string(),
        abuse_limits::Lane::Verified,
    )
    .unwrap();
    fixture
        .db
        .execute(
            "UPDATE auth_abuse_counters SET window_started_at=clock_timestamp()-interval '61 seconds' WHERE scope='device_challenge' AND subject_hash=$1",
            &[&&share[..]],
        )
        .await
        .unwrap();
    let (mut socket, challenge) = fixture.challenge().await;
    send_json(&mut socket, fixture.proof(&challenge)).await;
    assert_eq!(receive_json(&mut socket).await["type"], "session");
    drop(socket);
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn mms_spike_grant_follows_the_session_frame_only_when_due() {
    // The server, not the phone, gates the MMS spike (#438): the grant frame
    // rides directly behind the session frame, only for the founder-named
    // device and an allowlisted, un-suppressed recipient, and never when the
    // feature is off.
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("socket_mms_spike_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let other_device = Uuid::new_v4();
    let signing = SigningKey::generate_from_rng(&mut rng());
    let public_key = signing.verifying_key().to_sec1_point(false);
    let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
    db.execute("INSERT INTO sites(site_id) VALUES('fixture')", &[])
        .await
        .unwrap();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'mms spike fixture')",
        &[&device_id, &account_id],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device_id,&account_id,&public_key.as_bytes(),&&fingerprint[..]]).await.unwrap();
    let recipient = "+15551234567".to_string();
    let state_for = |policy: MmsSpikePolicy| DeviceSocketState {
        database_url: schema_url.clone(),
        site_id: "fixture".into(),
        instance_id: "fixture".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(9)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(10)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        mms_spike_policy: Arc::new(policy),
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let serve = |state: DeviceSocketState| async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        (address, server)
    };
    async fn connect_session(
        address: std::net::SocketAddr,
        device_id: Uuid,
        account_id: Uuid,
        signing: &SigningKey,
    ) -> (TestSocket, i64) {
        let (mut socket, _) = connect_async(format!("ws://{address}/v1/device-stream"))
            .await
            .unwrap();
        send_json(
            &mut socket,
            json!({"v":1,"type":"hello","device_id":device_id}),
        )
        .await;
        let challenge = receive_json(&mut socket).await;
        assert_eq!(challenge["type"], "challenge");
        let typed = DeviceChallenge {
            id: Uuid::parse_str(challenge["challenge_id"].as_str().unwrap()).unwrap(),
            account_id,
            device_id,
            nonce: URL_SAFE_NO_PAD
                .decode(challenge["nonce"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let signature: Signature = signing.sign(&device_challenge_bytes(&typed));
        send_json(&mut socket, json!({"v":1,"type":"proof","challenge_id":typed.id,"account_id":account_id,"device_id":device_id,"nonce":challenge["nonce"],"signature_der":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())})).await;
        let session = receive_json(&mut socket).await;
        assert_eq!(session["type"], "session");
        (socket, session["connection_epoch"].as_i64().unwrap())
    }
    async fn next_frame_within(socket: &mut TestSocket, ms: u64) -> Option<Value> {
        match tokio::time::timeout(Duration::from_millis(ms), socket.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => Some(serde_json::from_str(&text).unwrap()),
            _ => None,
        }
    }

    // Enabled and matching: the grant arrives right behind the session frame
    // with the exact field set the phone's validator demands.
    let (address, server) = serve(state_for(
        MmsSpikePolicy::parse(Some("true"), Some(&device_id.to_string()), Some(&recipient))
            .unwrap(),
    ))
    .await;
    let (mut socket, epoch) = connect_session(address, device_id, account_id, &signing).await;
    let grant: Value = next_frame_within(&mut socket, 5_000)
        .await
        .expect("grant frame follows the session frame");
    assert_eq!(grant["type"], "mms_spike_grant");
    let mut keys: Vec<String> = grant.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "connection_epoch",
            "device_id",
            "expires_at_ms",
            "grant_id",
            "recipient_digest",
            "recipient_e164",
            "type",
            "v"
        ]
    );
    assert_eq!(grant["v"], json!(1));
    assert_eq!(grant["device_id"], json!(device_id));
    assert_eq!(grant["connection_epoch"], json!(epoch));
    assert_eq!(grant["recipient_e164"], json!(recipient));
    assert_eq!(
        grant["recipient_digest"],
        json!(URL_SAFE_NO_PAD.encode(Sha256::digest(recipient.as_bytes())))
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let expires = grant["expires_at_ms"].as_i64().unwrap();
    assert!(
        expires > now && expires - now <= 35_000,
        "{expires} vs {now}"
    );
    // Exactly one grant per connection.
    assert!(next_frame_within(&mut socket, 500).await.is_none());
    server.abort();

    // STOP check: an active suppression withholds the grant.
    let stop_message = Uuid::new_v4();
    let stop_attempt = Uuid::new_v4();
    let stop_event = Uuid::new_v4();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,'+15557654321',$4,'synthetic_alpha',$5,$6,'delivered',now()+interval '1 hour')",
        &[&stop_message, &account_id, &device_id, &vec![9_u8; 32], &b"STOP_CHAIN".to_vec(), &vec![10_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,1,1,1,'submitted')",
        &[&stop_attempt, &account_id, &stop_message, &device_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence,classification,observed_at,received_at,part_count,content_kind,event_digest,signature_der) \
         VALUES($1,$2,$3,$4,$5,42,'sim_unverified',now(),now(),1,'metadata_only',$6,$7)",
        &[&stop_event, &account_id, &device_id, &stop_message, &stop_attempt, &vec![11_u8; 32], &vec![12_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO recipient_suppressions(account_id,recipient_e164,active,source_event_id,source_attempt_id,source_observed_at,source) \
         VALUES($1,$2,true,$3,$4,now(),'sms_keyword')",
        &[&account_id, &recipient, &stop_event, &stop_attempt],
    )
    .await
    .unwrap();
    let (address, server) = serve(state_for(
        MmsSpikePolicy::parse(Some("true"), Some(&device_id.to_string()), Some(&recipient))
            .unwrap(),
    ))
    .await;
    let (mut socket, _epoch) = connect_session(address, device_id, account_id, &signing).await;
    assert!(
        next_frame_within(&mut socket, 1_500).await.is_none(),
        "a suppressed recipient must not be granted"
    );
    server.abort();
    db.execute(
        "DELETE FROM recipient_suppressions WHERE account_id=$1",
        &[&account_id],
    )
    .await
    .unwrap();

    // A different founder-named device withholds the grant for this one.
    let (address, server) = serve(state_for(
        MmsSpikePolicy::parse(
            Some("true"),
            Some(&other_device.to_string()),
            Some(&recipient),
        )
        .unwrap(),
    ))
    .await;
    let (mut socket, _epoch) = connect_session(address, device_id, account_id, &signing).await;
    assert!(
        next_frame_within(&mut socket, 1_500).await.is_none(),
        "a device the founder did not name must not be granted"
    );
    server.abort();

    // Default-off withholds it too.
    let (address, server) = serve(state_for(MmsSpikePolicy::disabled())).await;
    let (mut socket, _epoch) = connect_session(address, device_id, account_id, &signing).await;
    assert!(
        next_frame_within(&mut socket, 1_500).await.is_none(),
        "a disabled policy must never grant"
    );
    server.abort();

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
