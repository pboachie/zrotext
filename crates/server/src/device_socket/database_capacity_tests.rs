// SPDX-License-Identifier: AGPL-3.0-only
//! Real WebSocket/SQL regression: socket admission must not pin pool clients.

use super::*;

pub(super) struct Fixture {
    admin: Client,
    pub(super) db: Client,
    schema: String,
    pub(super) url: String,
    pub(super) account_id: Uuid,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
        let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("socket_capacity_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if url.contains('?') { '&' } else { '?' };
        let url = format!("{url}{separator}options=-csearch_path%3D{schema}");
        let (db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for migration in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        ] {
            db.batch_execute(migration).await.unwrap();
        }
        let account_id = Uuid::new_v4();
        db.execute("INSERT INTO sites(site_id) VALUES('capacity-test')", &[])
            .await
            .unwrap();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
            .await
            .unwrap();
        Self {
            admin,
            db,
            schema,
            url,
            account_id,
        }
    }

    pub(super) async fn device(&self) -> (Uuid, SigningKey) {
        let device_id = Uuid::new_v4();
        let signing = SigningKey::generate_from_rng(&mut rng());
        let public_key = signing.verifying_key().to_sec1_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
        self.db
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'capacity phone')",
                &[&device_id, &self.account_id],
            )
            .await
            .unwrap();
        self.db.execute(
            "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
            &[&device_id, &self.account_id, &public_key.as_bytes(), &&fingerprint[..]],
        ).await.unwrap();
        (device_id, signing)
    }

    pub(super) async fn finish(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

async fn challenge(address: SocketAddr, device_id: Uuid) -> (TestSocket, Value) {
    let mut socket = open(address).await;
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device_id}),
    )
    .await;
    let frame = receive_json(&mut socket).await;
    assert_eq!(frame["type"], "challenge");
    (socket, frame)
}

pub(super) async fn prove(socket: &mut TestSocket, frame: Value, signing: &SigningKey) -> i64 {
    let challenge = DeviceChallenge {
        id: Uuid::parse_str(frame["challenge_id"].as_str().unwrap()).unwrap(),
        account_id: Uuid::parse_str(frame["account_id"].as_str().unwrap()).unwrap(),
        device_id: Uuid::parse_str(frame["device_id"].as_str().unwrap()).unwrap(),
        nonce: URL_SAFE_NO_PAD
            .decode(frame["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let proof: Signature = signing.sign(&device_challenge_bytes(&challenge));
    send_json(
        socket,
        json!({
            "v":1,"type":"proof","challenge_id":challenge.id,"account_id":challenge.account_id,
            "device_id":challenge.device_id,"nonce":frame["nonce"],
            "signature_der":URL_SAFE_NO_PAD.encode(proof.to_der().as_bytes())
        }),
    )
    .await;
    let session = receive_json(socket).await;
    assert_eq!(session["type"], "session");
    session["connection_epoch"].as_i64().unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn all_admitted_sessions_renew_while_proofs_wait_without_pinning_database_clients() {
    let fixture = Fixture::new().await;
    let admission = SocketAdmission::new(
        MAX_HANDSHAKING_DEVICE_SOCKETS,
        MAX_DEVICE_SOCKETS,
        AUTH_TIMEOUT,
        HANDSHAKE_DEADLINE,
    );
    let state = socket_state(fixture.url.clone(), "capacity-test");
    let (address, server) = serve(state.clone(), admission.clone()).await;

    // Keep 17 unproven challenges open, crossing the 16-client device budget.
    // A session-pinned checkout fails on the seventeenth challenge, before any
    // proof timeout can return the first client's slot.
    let started = Instant::now();
    let mut pending = Vec::new();
    for _ in 0..17 {
        let (device_id, _) = fixture.device().await;
        pending.push(challenge(address, device_id).await.0);
    }
    assert!(started.elapsed() < AUTH_TIMEOUT);
    assert_eq!(
        admission.handshaking.available_permits(),
        MAX_HANDSHAKING_DEVICE_SOCKETS - 17
    );
    assert_eq!(
        admission.established.available_permits(),
        MAX_DEVICE_SOCKETS
    );

    // All 32 authenticated sockets must coexist with those unproven peers.
    let mut phones = Vec::new();
    for _ in 0..MAX_DEVICE_SOCKETS {
        let (device_id, signing) = fixture.device().await;
        let (mut socket, frame) = challenge(address, device_id).await;
        let epoch = prove(&mut socket, frame, &signing).await;
        phones.push((socket, epoch));
    }
    assert_eq!(admission.established.available_permits(), 0);
    expect_refused(address).await;

    // Send a synchronized heartbeat burst, then read every acknowledgement.
    // Repeat past the periodic session check to exercise reacquisition there.
    for round in 0..2 {
        if round != 0 {
            tokio::time::sleep(Duration::from_secs(11)).await;
        }
        for (socket, _) in &mut phones {
            send_json(socket, json!({"v":1,"type":"heartbeat"})).await;
        }
        for (socket, epoch) in &mut phones {
            assert_eq!(
                receive_json(socket).await,
                json!({"v":1,"type":"heartbeat_ack","connection_epoch":epoch})
            );
        }
    }
    assert_eq!(admission.established.available_permits(), 0);

    // Reacquired clients still enforce key revocation rather than treating an
    // established socket as permanently authenticated.
    fixture
        .db
        .execute(
            "UPDATE device_keys SET revoked_at=now() WHERE account_id=$1",
            &[&fixture.account_id],
        )
        .await
        .unwrap();
    for (socket, _) in &mut phones {
        send_json(socket, json!({"v":1,"type":"heartbeat"})).await;
    }
    for (socket, _) in &mut phones {
        let frame = timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(frame, WsMessage::Close(_)));
    }
    drop(phones);
    drop(pending);
    server.abort();
    fixture.finish().await;
}
