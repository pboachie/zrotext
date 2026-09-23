// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated, heartbeat-only device stream. No message or radio commands.

use crate::enrollment::{self, AuthenticatedDevice, EnrollmentHasher};
use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{Notify, Semaphore},
    time::{interval, timeout},
};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_SECONDS: u64 = 30;
const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(45);
const SESSION_LEASE_SECONDS: i32 = 90;
const MAX_FRAME_BYTES: usize = 4096;
const MAX_DEVICE_SOCKETS: usize = 128;
static DEVICE_SOCKET_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_DEVICE_SOCKETS)));

#[derive(Clone)]
pub struct DeviceSocketState {
    pub database_url: String,
    pub site_id: String,
    pub instance_id: String,
    pub deployment_epoch: i64,
    pub enrollment_hasher: Arc<EnrollmentHasher>,
    pub draining: Arc<AtomicBool>,
    pub drain_notify: Arc<Notify>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSession {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub connection_epoch: i64,
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ClientFrame {
    #[serde(rename = "hello")]
    Hello { v: u8, device_id: Uuid },
    #[serde(rename = "proof")]
    Proof {
        v: u8,
        challenge_id: Uuid,
        account_id: Uuid,
        device_id: Uuid,
        nonce: String,
        signature_der: String,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat { v: u8 },
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerFrame {
    #[serde(rename = "challenge")]
    Challenge {
        v: u8,
        challenge_id: Uuid,
        account_id: Uuid,
        device_id: Uuid,
        nonce: String,
    },
    #[serde(rename = "session")]
    Session {
        v: u8,
        connection_epoch: i64,
        heartbeat_seconds: u64,
    },
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck { v: u8, connection_epoch: i64 },
}

/// Mount at `/v1/device-stream`. Deploy behind TLS/WSS; this route accepts
/// neither a browser Origin nor an identity token in URL or headers.
pub fn router(state: DeviceSocketState) -> Router {
    Router::new()
        .route("/v1/device-stream", get(upgrade))
        .with_state(state)
}

async fn upgrade(
    State(state): State<DeviceSocketState>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Response {
    if state.draining.load(Ordering::Acquire) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    // Native gateway clients have no browser Origin. Reject browser-initiated
    // sockets even though they could not produce the enrolled-key signature.
    if headers.contains_key(axum::http::header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(slot) = DEVICE_SOCKET_SLOTS.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    websocket
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            let _slot = slot;
            run_socket(socket, state).await;
        })
        .into_response()
}

async fn connect(database_url: &str) -> Result<Client, tokio_postgres::Error> {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
    tokio::spawn(async move {
        if connection.await.is_err() {
            eprintln!("device socket database connection closed");
        }
    });
    Ok(client)
}

async fn receive_frame(socket: &mut WebSocket) -> Option<ClientFrame> {
    loop {
        let message = socket.recv().await?.ok()?;
        match message {
            Message::Text(text) => return serde_json::from_str(text.as_str()).ok(),
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => return None,
        }
    }
}

async fn send_frame(socket: &mut WebSocket, frame: ServerFrame) -> bool {
    let Ok(json) = serde_json::to_string(&frame) else {
        return false;
    };
    socket.send(Message::Text(json.into())).await.is_ok()
}

async fn run_socket(mut socket: WebSocket, state: DeviceSocketState) {
    let Some(ClientFrame::Hello { v: 1, device_id }) =
        timeout(AUTH_TIMEOUT, receive_frame(&mut socket))
            .await
            .ok()
            .flatten()
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(mut client) = connect(&state.database_url).await else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(challenge) =
        enrollment::issue_device_challenge(&client, &state.enrollment_hasher, device_id).await
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if !send_frame(
        &mut socket,
        ServerFrame::Challenge {
            v: 1,
            challenge_id: challenge.id,
            account_id: challenge.account_id,
            device_id: challenge.device_id,
            nonce: URL_SAFE_NO_PAD.encode(challenge.nonce),
        },
    )
    .await
    {
        return;
    }
    let Some(ClientFrame::Proof {
        v: 1,
        challenge_id,
        account_id,
        device_id,
        nonce,
        signature_der,
    }) = timeout(AUTH_TIMEOUT, receive_frame(&mut socket))
        .await
        .ok()
        .flatten()
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(decoded_nonce) = URL_SAFE_NO_PAD.decode(nonce.as_bytes()) else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_der.as_bytes()) else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if challenge_id != challenge.id
        || account_id != challenge.account_id
        || device_id != challenge.device_id
        || decoded_nonce != challenge.nonce
        || signature.len() > 80
    {
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    let Ok(identity) = enrollment::authenticate_device_challenge(
        &mut client,
        &state.enrollment_hasher,
        &challenge,
        &signature,
    )
    .await
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if state.draining.load(Ordering::Acquire) {
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    let Ok(Some(session)) = claim_session(&mut client, identity, &state).await else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if !send_frame(
        &mut socket,
        ServerFrame::Session {
            v: 1,
            connection_epoch: session.connection_epoch,
            heartbeat_seconds: HEARTBEAT_SECONDS,
        },
    )
    .await
    {
        let _ = release_session(&client, session).await;
        return;
    }
    let mut last_heartbeat = Instant::now();
    let mut checks = interval(Duration::from_secs(10));
    checks.tick().await;
    loop {
        tokio::select! {
            message = receive_frame(&mut socket) => {
                match message {
                    Some(ClientFrame::Heartbeat { v: 1 }) => {
                        if !renew_session(&client, session, &state).await.unwrap_or(false) {
                            break;
                        }
                        last_heartbeat = Instant::now();
                        if !send_frame(&mut socket, ServerFrame::HeartbeatAck {
                            v: 1, connection_epoch: session.connection_epoch,
                        }).await { break; }
                    }
                    _ => break,
                }
            }
            _ = checks.tick() => {
                if last_heartbeat.elapsed() > HEARTBEAT_DEADLINE
                    || !session_current(&client, session, &state).await.unwrap_or(false)
                { break; }
            }
            _ = state.drain_notify.notified() => break,
        }
    }
    let _ = release_session(&client, session).await;
    let _ = socket.send(Message::Close(None)).await;
}

/// Compare-and-swap through the writer. A new proof increments the persistent
/// epoch; any older socket immediately loses renewal and all future work rights.
async fn claim_session(
    client: &mut Client,
    identity: AuthenticatedDevice,
    state: &DeviceSocketState,
) -> Result<Option<DeviceSession>, tokio_postgres::Error> {
    if state.draining.load(Ordering::Acquire) {
        return Ok(None);
    }
    let tx = client.transaction().await?;
    let writer = tx
        .query_one("SELECT NOT pg_is_in_recovery()", &[])
        .await?
        .get::<_, bool>(0);
    if !writer {
        return Ok(None);
    }
    if tx.query_opt(
        "SELECT 1 FROM deployment_authority WHERE singleton=TRUE AND epoch=$1 FOR SHARE",
        &[&state.deployment_epoch],
    ).await?.is_none() || tx.query_opt(
        "SELECT 1 FROM sites WHERE site_id=$1 AND enabled=TRUE AND draining=FALSE FOR SHARE",
        &[&state.site_id],
    ).await?.is_none() {
        return Ok(None);
    }
    let active = tx.query_opt(
        "SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL FOR UPDATE OF d",
        &[&identity.account_id, &identity.device_id],
    ).await?.is_some();
    if !active {
        return Ok(None);
    }
    let row = tx.query_one(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,$2,$3,$4,1,now()+($5::integer * interval '1 second'),$6) ON CONFLICT(device_id) DO UPDATE SET account_id=EXCLUDED.account_id,site_id=EXCLUDED.site_id,instance_id=EXCLUDED.instance_id,connection_epoch=device_sessions.connection_epoch+1,lease_until=EXCLUDED.lease_until,deployment_epoch=EXCLUDED.deployment_epoch RETURNING connection_epoch",
        &[&identity.device_id, &identity.account_id, &state.site_id, &state.instance_id, &SESSION_LEASE_SECONDS, &state.deployment_epoch],
    ).await?;
    tx.commit().await?;
    Ok(Some(DeviceSession {
        account_id: identity.account_id,
        device_id: identity.device_id,
        connection_epoch: row.get(0),
    }))
}

async fn session_current(
    client: &Client,
    session: DeviceSession,
    state: &DeviceSocketState,
) -> Result<bool, tokio_postgres::Error> {
    if state.draining.load(Ordering::Acquire) {
        return Ok(false);
    }
    Ok(client.query_opt(
        "SELECT 1 FROM device_sessions s JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>now() AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery()",
        &[&session.account_id, &session.device_id, &state.site_id, &state.instance_id, &session.connection_epoch, &state.deployment_epoch],
    ).await?.is_some())
}

async fn renew_session(
    client: &Client,
    session: DeviceSession,
    state: &DeviceSocketState,
) -> Result<bool, tokio_postgres::Error> {
    if state.draining.load(Ordering::Acquire) {
        return Ok(false);
    }
    Ok(client.execute(
        "UPDATE device_sessions s SET lease_until=now()+($7::integer * interval '1 second') WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>now() AND EXISTS (SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id JOIN sites t ON t.site_id=$3 JOIN deployment_authority p ON p.singleton=TRUE WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery())",
        &[&session.account_id, &session.device_id, &state.site_id, &state.instance_id, &session.connection_epoch, &state.deployment_epoch, &SESSION_LEASE_SECONDS],
    ).await? == 1)
}

async fn release_session(
    client: &Client,
    session: DeviceSession,
) -> Result<(), tokio_postgres::Error> {
    client.execute(
        "UPDATE device_sessions SET lease_until=now() WHERE account_id=$1 AND device_id=$2 AND connection_epoch=$3",
        &[&session.account_id, &session.device_id, &session.connection_epoch],
    ).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::{EnrollmentError, device_challenge_bytes};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    #[test]
    fn wire_v1_uses_only_documented_fields() {
        let account_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();
        let nonce = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let frame = serde_json::to_value(ServerFrame::Challenge {
            v: 1,
            challenge_id,
            account_id,
            device_id,
            nonce: nonce.clone(),
        })
        .unwrap();
        assert_eq!(
            frame,
            serde_json::json!({
                "type":"challenge", "v":1, "challenge_id":challenge_id,
                "account_id":account_id, "device_id":device_id, "nonce":nonce
            })
        );
        let session = serde_json::to_value(ServerFrame::Session {
            v: 1,
            connection_epoch: 7,
            heartbeat_seconds: HEARTBEAT_SECONDS,
        })
        .unwrap();
        assert_eq!(
            session,
            serde_json::json!({
                "type":"session", "v":1, "connection_epoch":7, "heartbeat_seconds":30
            })
        );
        let ack = serde_json::to_value(ServerFrame::HeartbeatAck {
            v: 1,
            connection_epoch: 7,
        })
        .unwrap();
        assert_eq!(
            ack,
            serde_json::json!({
                "type":"heartbeat_ack", "v":1, "connection_epoch":7
            })
        );
    }

    #[tokio::test]
    async fn writer_claim_replay_epoch_and_revocation() {
        let Ok(url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("socket_test_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        for sql in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        ] {
            client.batch_execute(sql).await.unwrap();
        }
        let account_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let signing = SigningKey::random(&mut OsRng);
        let sec1 = signing.verifying_key().to_encoded_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(sec1.as_bytes()).into();
        client
            .execute("INSERT INTO sites(site_id) VALUES('test-site')", &[])
            .await
            .unwrap();
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Test phone')",
                &[&device_id, &account_id],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
                &[&device_id, &account_id, &sec1.as_bytes(), &&fingerprint[..]],
            )
            .await
            .unwrap();
        let hasher = Arc::new(EnrollmentHasher::new(vec![77; 32]).unwrap());
        let state = DeviceSocketState {
            database_url: url,
            site_id: "test-site".into(),
            instance_id: "test-hub".into(),
            deployment_epoch: 1,
            enrollment_hasher: hasher.clone(),
            draining: Arc::new(AtomicBool::new(false)),
            drain_notify: Arc::new(Notify::new()),
        };

        let bad = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let wrong_signing = SigningKey::random(&mut OsRng);
        let wrong_signature: Signature = wrong_signing.sign(&device_challenge_bytes(&bad));
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &bad,
                wrong_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        let good_signature: Signature = signing.sign(&device_challenge_bytes(&bad));
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &bad,
                good_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));

        let expired = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        client
            .execute(
                "UPDATE device_auth_challenges SET created_at=now()-interval '2 minutes',expires_at=now()-interval '1 minute' WHERE id=$1",
                &[&expired.id],
            )
            .await
            .unwrap();
        let expired_signature: Signature = signing.sign(&device_challenge_bytes(&expired));
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &expired,
                expired_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));

        let first = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let cross_tenant = crate::enrollment::DeviceChallenge {
            id: first.id,
            account_id: Uuid::new_v4(),
            device_id: first.device_id,
            nonce: first.nonce,
        };
        let cross_signature: Signature = signing.sign(&device_challenge_bytes(&cross_tenant));
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &cross_tenant,
                cross_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        let first_signature: Signature = signing.sign(&device_challenge_bytes(&first));
        let first_identity = enrollment::authenticate_device_challenge(
            &mut client,
            &hasher,
            &first,
            first_signature.to_der().as_bytes(),
        )
        .await
        .unwrap();
        let first_session = claim_session(&mut client, first_identity, &state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_session.connection_epoch, 1);
        assert!(
            session_current(&client, first_session, &state)
                .await
                .unwrap()
        );
        assert!(matches!(
            enrollment::authenticate_device_challenge(
                &mut client,
                &hasher,
                &first,
                first_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));

        let second = enrollment::issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let second_signature: Signature = signing.sign(&device_challenge_bytes(&second));
        let second_identity = enrollment::authenticate_device_challenge(
            &mut client,
            &hasher,
            &second,
            second_signature.to_der().as_bytes(),
        )
        .await
        .unwrap();
        let second_session = claim_session(&mut client, second_identity, &state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second_session.connection_epoch, 2);
        assert!(
            !session_current(&client, first_session, &state)
                .await
                .unwrap()
        );
        assert!(!renew_session(&client, first_session, &state).await.unwrap());
        release_session(&client, first_session).await.unwrap();
        assert!(
            session_current(&client, second_session, &state)
                .await
                .unwrap()
        );
        assert!(
            renew_session(&client, second_session, &state)
                .await
                .unwrap()
        );

        // Two distinct, valid reconnection proofs may race on different hubs.
        // The writer serializes them and leaves only the higher epoch current.
        let mut identities = Vec::new();
        for _ in 0..2 {
            let challenge = enrollment::issue_device_challenge(&client, &hasher, device_id)
                .await
                .unwrap();
            let signature: Signature = signing.sign(&device_challenge_bytes(&challenge));
            identities.push(
                enrollment::authenticate_device_challenge(
                    &mut client,
                    &hasher,
                    &challenge,
                    signature.to_der().as_bytes(),
                )
                .await
                .unwrap(),
            );
        }
        let (mut peer_a, connection_a) = tokio_postgres::connect(&state.database_url, NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection_a.await.unwrap() });
        peer_a
            .batch_execute(&format!("SET search_path TO {schema}"))
            .await
            .unwrap();
        let (mut peer_b, connection_b) = tokio_postgres::connect(&state.database_url, NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection_b.await.unwrap() });
        peer_b
            .batch_execute(&format!("SET search_path TO {schema}"))
            .await
            .unwrap();
        let (left, right) = tokio::join!(
            claim_session(&mut peer_a, identities[0], &state),
            claim_session(&mut peer_b, identities[1], &state)
        );
        let left = left.unwrap().unwrap();
        let right = right.unwrap().unwrap();
        assert_eq!(
            [left.connection_epoch, right.connection_epoch]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            [3, 4].into_iter().collect()
        );
        let current_session = if left.connection_epoch > right.connection_epoch {
            left
        } else {
            right
        };
        assert!(
            !session_current(&client, second_session, &state)
                .await
                .unwrap()
        );
        assert!(
            session_current(&client, current_session, &state)
                .await
                .unwrap()
        );
        let stale_session = if current_session == left { right } else { left };
        assert!(!renew_session(&client, stale_session, &state).await.unwrap());

        client
            .execute(
                "UPDATE sites SET draining=TRUE WHERE site_id=$1",
                &[&state.site_id],
            )
            .await
            .unwrap();
        assert!(
            !session_current(&client, current_session, &state)
                .await
                .unwrap()
        );
        assert!(
            !renew_session(&client, current_session, &state)
                .await
                .unwrap()
        );
        client
            .execute(
                "UPDATE sites SET draining=FALSE WHERE site_id=$1",
                &[&state.site_id],
            )
            .await
            .unwrap();
        client
            .execute("UPDATE deployment_authority SET epoch=2", &[])
            .await
            .unwrap();
        assert!(
            !session_current(&client, current_session, &state)
                .await
                .unwrap()
        );
        assert!(
            !renew_session(&client, current_session, &state)
                .await
                .unwrap()
        );
        client
            .execute("UPDATE deployment_authority SET epoch=1", &[])
            .await
            .unwrap();

        client
            .execute(
                "UPDATE device_keys SET revoked_at=now() WHERE device_id=$1",
                &[&device_id],
            )
            .await
            .unwrap();
        assert!(
            !session_current(&client, current_session, &state)
                .await
                .unwrap()
        );
        assert!(
            !renew_session(&client, current_session, &state)
                .await
                .unwrap()
        );
        assert!(matches!(
            enrollment::issue_device_challenge(&client, &hasher, device_id).await,
            Err(EnrollmentError::Unauthorized)
        ));
        client
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }
}
