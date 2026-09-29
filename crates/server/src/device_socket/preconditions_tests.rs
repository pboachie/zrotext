// SPDX-License-Identifier: AGPL-3.0-only
use super::database_capacity_tests::{Fixture, prove};
use super::*;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

fn report(epoch: i64) -> Value {
    json!({"v":1,"type":"device_status","connection_epoch":epoch,
        "selected_sim":"active","sms_permission":"granted","airplane_mode":"disabled"})
}

async fn authenticated(
    address: SocketAddr,
    device: Uuid,
    signing: &SigningKey,
    negotiate: bool,
) -> (TestSocket, i64) {
    let mut request = format!("ws://{address}/v1/device-stream")
        .into_client_request()
        .unwrap();
    if negotiate {
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            preconditions::PROTOCOL.parse().unwrap(),
        );
    }
    let (mut socket, response) = connect_async(request).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("Sec-WebSocket-Protocol")
            .map(|v| v.to_str().unwrap()),
        negotiate.then_some(preconditions::PROTOCOL)
    );
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device}),
    )
    .await;
    let challenge = receive_json(&mut socket).await;
    let epoch = prove(&mut socket, challenge, signing).await;
    (socket, epoch)
}

fn report_v2(epoch: i64) -> Value {
    let mut frame = report(epoch);
    frame["type"] = json!("device_status_v2");
    frame["network_service"] = json!("in_service");
    frame
}

#[test]
fn network_service_has_strict_versioned_shape() {
    for state in [
        "in_service",
        "out_of_service",
        "emergency_only",
        "power_off",
        "unavailable",
    ] {
        let mut frame = report_v2(1);
        frame["network_service"] = json!(state);
        assert!(serde_json::from_value::<ClientFrame>(frame.clone()).is_ok());
        frame["type"] = json!("device_status");
        assert!(serde_json::from_value::<ClientFrame>(frame).is_err());
    }
    for invalid in [
        json!(null),
        json!(true),
        json!("ready"),
        json!(""),
        json!(7),
    ] {
        let mut frame = report_v2(1);
        frame["network_service"] = invalid;
        assert!(serde_json::from_value::<ClientFrame>(frame).is_err());
    }
    let mut missing = report_v2(1);
    missing.as_object_mut().unwrap().remove("network_service");
    assert!(serde_json::from_value::<ClientFrame>(missing).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn v2_status_is_explicitly_negotiated_and_v1_replacement_clears_radio() {
    let fixture = Fixture::new().await;
    fixture
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/041_device_preconditions.sql"
        ))
        .await
        .unwrap();
    fixture
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/047_device_network_service.sql"
        ))
        .await
        .unwrap();
    let (device, signing) = fixture.device().await;
    let state = socket_state(fixture.url.clone(), "capacity-test");
    let (address, server) = serve(
        state.clone(),
        SocketAdmission::new(8, 8, AUTH_TIMEOUT, HANDSHAKE_DEADLINE),
    )
    .await;
    let mut request = format!("ws://{address}/v1/device-stream")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        format!(
            "{}, {}",
            preconditions::PROTOCOL,
            preconditions::PROTOCOL_V2
        )
        .parse()
        .unwrap(),
    );
    let (mut socket, response) = connect_async(request).await.unwrap();
    assert_eq!(
        response.headers()["Sec-WebSocket-Protocol"],
        preconditions::PROTOCOL_V2
    );
    send_json(
        &mut socket,
        json!({"v":1,"type":"hello","device_id":device}),
    )
    .await;
    let challenge = receive_json(&mut socket).await;
    let epoch = prove(&mut socket, challenge, &signing).await;
    send_json(&mut socket, report_v2(epoch)).await;
    send_json(&mut socket, json!({"v":1,"type":"heartbeat"})).await;
    assert_eq!(receive_json(&mut socket).await["type"], "heartbeat_ack");
    assert_eq!(
        fixture
            .db
            .query_one(
                "SELECT network_service FROM device_preconditions WHERE device_id=$1",
                &[&device]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "in_service"
    );
    let mut throttled = report_v2(epoch);
    throttled["network_service"] = json!("power_off");
    send_json(&mut socket, throttled).await;
    send_json(&mut socket, json!({"v":1,"type":"heartbeat"})).await;
    receive_json(&mut socket).await;
    assert_eq!(
        fixture
            .db
            .query_one(
                "SELECT network_service FROM device_preconditions WHERE device_id=$1",
                &[&device]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "in_service"
    );
    // A v1-shaped frame cannot bypass v2 negotiation or share an alternate budget.
    send_json(&mut socket, report(epoch)).await;
    assert_eq!(expect_close(&mut socket).await, close_code::POLICY);
    let (mut replacement, new_epoch) = authenticated(address, device, &signing, true).await;
    send_json(&mut replacement, report(new_epoch)).await;
    send_json(&mut replacement, json!({"v":1,"type":"heartbeat"})).await;
    receive_json(&mut replacement).await;
    assert!(
        fixture
            .db
            .query_one(
                "SELECT network_service FROM device_preconditions WHERE device_id=$1",
                &[&device]
            )
            .await
            .unwrap()
            .get::<_, Option<String>>(0)
            .is_none()
    );
    send_json(&mut replacement, report_v2(new_epoch)).await;
    assert_eq!(expect_close(&mut replacement).await, close_code::POLICY);
    drop(socket);
    drop(replacement);
    server.abort();
    fixture.finish().await;
}

#[test]
fn status_frames_reject_unknown_enums_private_fields_and_large_payload_values() {
    assert!(serde_json::from_value::<ClientFrame>(report(1)).is_ok());
    for field in ["selected_sim", "sms_permission", "airplane_mode"] {
        for value in [
            json!(""),
            json!("x".repeat(5000)),
            json!(true),
            json!(null),
            json!(7),
        ] {
            let mut invalid = report(1);
            invalid[field] = value;
            assert!(serde_json::from_value::<ClientFrame>(invalid).is_err());
        }
    }
    for field in [
        "device_id",
        "account_id",
        "observed_at_ms",
        "subscription_id",
        "ready",
    ] {
        let mut invalid = report(1);
        invalid[field] = json!(1);
        assert!(serde_json::from_value::<ClientFrame>(invalid).is_err());
    }
}

#[tokio::test]
async fn unproven_status_is_refused_before_database_access() {
    let state = socket_state("invalid-database-url".into(), "status-test");
    let (address, server) = serve(
        state,
        SocketAdmission::new(2, 2, AUTH_TIMEOUT, HANDSHAKE_DEADLINE),
    )
    .await;
    let mut request = format!("ws://{address}/v1/device-stream")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        preconditions::PROTOCOL.parse().unwrap(),
    );
    let (mut socket, _) = connect_async(request).await.unwrap();
    send_json(&mut socket, report(1)).await;
    assert_eq!(expect_close(&mut socket).await, close_code::POLICY);
    server.abort();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn negotiated_status_is_bounded_session_fenced_and_old_clients_keep_heartbeats() {
    let mut fixture = Fixture::new().await;
    fixture
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/041_device_preconditions.sql"
        ))
        .await
        .unwrap();
    fixture
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/047_device_network_service.sql"
        ))
        .await
        .unwrap();
    let (device, signing) = fixture.device().await;
    let state = socket_state(fixture.url.clone(), "capacity-test");
    let (address, server) = serve(
        state.clone(),
        SocketAdmission::new(8, 8, AUTH_TIMEOUT, HANDSHAKE_DEADLINE),
    )
    .await;
    let (mut old, old_epoch) = authenticated(address, device, &signing, false).await;
    send_json(&mut old, json!({"v":1,"type":"heartbeat"})).await;
    assert_eq!(receive_json(&mut old).await["connection_epoch"], old_epoch);
    send_json(&mut old, report(old_epoch)).await;
    assert_eq!(expect_close(&mut old).await, close_code::POLICY);
    assert_eq!(
        fixture
            .db
            .query_one("SELECT count(*) FROM device_preconditions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );

    let (mut socket, epoch) = authenticated(address, device, &signing, true).await;
    send_json(&mut socket, report(epoch)).await;
    send_json(&mut socket, json!({"v":1,"type":"heartbeat"})).await;
    receive_json(&mut socket).await;
    let received=fixture.db.query_one("SELECT selected_sim,sms_permission,extract(epoch FROM received_at)::bigint FROM device_preconditions WHERE device_id=$1",&[&device]).await.unwrap();
    assert_eq!(received.get::<_, String>(0), "active");
    assert_eq!(received.get::<_, String>(1), "granted");
    assert!(received.get::<_, i64>(2) > 0);
    for _ in 0..10 {
        let mut changed = report(epoch);
        changed["sms_permission"] = json!("denied");
        send_json(&mut socket, changed).await;
    }
    send_json(&mut socket, json!({"v":1,"type":"heartbeat"})).await;
    receive_json(&mut socket).await;
    assert_eq!(
        fixture
            .db
            .query_one(
                "SELECT sms_permission FROM device_preconditions WHERE device_id=$1",
                &[&device]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "granted"
    );

    let prior = DeviceSession {
        account_id: fixture.account_id,
        device_id: device,
        connection_epoch: epoch,
    };
    let (mut replacement, new_epoch) = authenticated(address, device, &signing, true).await;
    assert!(new_epoch > epoch);
    let input = || preconditions::Report {
        selected_sim: preconditions::SelectedSim::Active,
        sms_permission: preconditions::SmsPermission::Granted,
        airplane_mode: preconditions::AirplaneMode::Disabled,
        network_service: None,
    };
    assert!(
        !preconditions::record(&mut fixture.db, prior, &state, input())
            .await
            .unwrap()
    );
    let current = DeviceSession {
        connection_epoch: new_epoch,
        ..prior
    };
    assert!(
        !preconditions::record(
            &mut fixture.db,
            DeviceSession {
                account_id: Uuid::new_v4(),
                ..current
            },
            &state,
            input()
        )
        .await
        .unwrap()
    );
    let stale_writer = DeviceSocketState {
        deployment_epoch: 2,
        ..state.clone()
    };
    assert!(
        !preconditions::record(&mut fixture.db, current, &stale_writer, input())
            .await
            .unwrap()
    );
    fixture
        .db
        .execute(
            "UPDATE sites SET draining=TRUE WHERE site_id=$1",
            &[&state.site_id],
        )
        .await
        .unwrap();
    assert!(
        !preconditions::record(&mut fixture.db, current, &state, input())
            .await
            .unwrap()
    );
    fixture
        .db
        .execute(
            "UPDATE sites SET draining=FALSE WHERE site_id=$1",
            &[&state.site_id],
        )
        .await
        .unwrap();
    assert!(
        preconditions::record(&mut fixture.db, current, &state, input())
            .await
            .unwrap()
    );
    assert_eq!(
        fixture
            .db
            .query_one(
                "SELECT count(*),max(connection_epoch) FROM device_preconditions",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    fixture
        .db
        .execute(
            "UPDATE device_keys SET revoked_at=now() WHERE device_id=$1",
            &[&device],
        )
        .await
        .unwrap();
    assert!(
        !preconditions::record(&mut fixture.db, current, &state, input())
            .await
            .unwrap()
    );
    send_json(&mut replacement, report(new_epoch - 1)).await;
    assert_eq!(expect_close(&mut replacement).await, close_code::POLICY);
    let cascades=fixture.db.query_one("SELECT count(*) FROM pg_constraint WHERE conrelid='device_preconditions'::regclass AND contype='f' AND confdeltype='c'",&[]).await.unwrap().get::<_,i64>(0);
    assert_eq!(cascades, 2);
    drop(socket);
    drop(replacement);
    drop(old);
    server.abort();
    fixture
        .db
        .execute("DELETE FROM device_sessions WHERE device_id=$1", &[&device])
        .await
        .unwrap();
    fixture
        .db
        .execute("DELETE FROM device_keys WHERE device_id=$1", &[&device])
        .await
        .unwrap();
    fixture
        .db
        .execute("DELETE FROM devices WHERE id=$1", &[&device])
        .await
        .unwrap();
    assert_eq!(
        fixture
            .db
            .query_one("SELECT count(*) FROM device_preconditions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    fixture.finish().await;
}
