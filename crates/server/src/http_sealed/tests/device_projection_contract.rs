// SPDX-License-Identifier: AGPL-3.0-only
//! #630 contract regressions for the sealed device projection: revoked line
//! bindings and site/session-epoch staleness must be observable through the
//! read-only routes, and the projection must stay read-only (no mutation
//! route widens observer/device authority).

use super::*;

async fn projection_case() -> (Fixture, String, String) {
    let (case, token) = resource_case("devices:read").await;
    (case.fixture, token, case.url)
}

fn projection_get(token: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[derive(serde::Deserialize)]
struct LineView {
    line_id: Uuid,
    binding_generation: i64,
    state: String,
}

#[derive(serde::Deserialize)]
struct DeviceView {
    device_id: Uuid,
    revoked: bool,
    active_socket_lease: bool,
    lines: Vec<LineView>,
}

#[derive(serde::Deserialize)]
struct DevicePage {
    devices: Vec<DeviceView>,
    #[expect(dead_code, reason = "cursor asserted by the merged pagination test")]
    next_cursor: Option<Uuid>,
}

async fn devices(app: &axum::Router, token: &str) -> DevicePage {
    let response = app
        .clone()
        .oneshot(projection_get(token, "/devices"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn revoked_line_bindings_report_their_stored_state() {
    let (f, token, url) = projection_case().await;
    // A second, revoked binding generation on a fresh line: the projection
    // must report stored state, not silently drop or revive it.
    let retired_line = Uuid::new_v4();
    f.db.execute(
        "INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) \
         VALUES($1,$2,'active',now(),2,2)",
        &[&retired_line, &f.account],
    ).await.unwrap();
    f.db.execute(
        "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,owner_approval_digest,device_confirmation_digest,activated_at,purpose) \
         VALUES($1,$2,$3,1,'revoked',$4,$5,now(),'sealed')",
        &[&f.account, &retired_line, &f.device, &vec![2u8; 32], &vec![3u8; 32]],
    ).await.unwrap();
    f.db.execute(
        "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,owner_approval_digest,device_confirmation_digest,activated_at,purpose) \
         VALUES($1,$2,$3,2,'active',$4,$5,now(),'sealed')",
        &[&f.account, &retired_line, &f.device, &vec![4u8; 32], &vec![5u8; 32]],
    ).await.unwrap();
    let app = router(SealedHttpState::new(url, hasher(), "manifest-test".into(), 1, true).unwrap());
    let page = devices(&app, &token).await;
    assert_eq!(page.devices.len(), 1);
    assert_eq!(page.devices[0].device_id, f.device);
    let mut bindings: Vec<_> = page.devices[0]
        .lines
        .iter()
        .filter(|line| line.line_id == retired_line)
        .map(|line| (line.binding_generation, line.state.as_str()))
        .collect();
    bindings.sort_unstable();
    assert_eq!(bindings, vec![(1, "revoked"), (2, "active")]);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn lease_snapshot_follows_site_and_session_epochs() {
    let (f, token, url) = projection_case().await;
    let app = router(SealedHttpState::new(url, hasher(), "manifest-test".into(), 1, true).unwrap());
    // Fixture session carries connection_epoch=1/deployment_epoch=1: live.
    let page = devices(&app, &token).await;
    assert!(page.devices[0].active_socket_lease, "fresh lease is live");
    // An expired lease reads false without any other change.
    f.db.execute(
        "UPDATE device_sessions SET lease_until=now()-interval '1 second'",
        &[],
    )
    .await
    .unwrap();
    let page = devices(&app, &token).await;
    assert!(
        !page.devices[0].active_socket_lease,
        "expired lease reads false"
    );
    // A mismatched deployment epoch reads false; zero is forbidden by the schema.
    f.db.execute(
        "UPDATE device_sessions SET lease_until=now()+interval '10 minutes',deployment_epoch=2",
        &[],
    )
    .await
    .unwrap();
    let page = devices(&app, &token).await;
    assert!(
        !page.devices[0].active_socket_lease,
        "stale epoch reads false"
    );
    // A draining site reads false even with a live, current lease.
    f.db.execute("UPDATE device_sessions SET deployment_epoch=1", &[])
        .await
        .unwrap();
    f.db.execute(
        "UPDATE sites SET draining=TRUE WHERE site_id='manifest-test'",
        &[],
    )
    .await
    .unwrap();
    let page = devices(&app, &token).await;
    assert!(
        !page.devices[0].active_socket_lease,
        "draining site reads false"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn revoked_devices_still_list_with_revoked_true() {
    let (f, token, url) = projection_case().await;
    f.db.execute(
        "UPDATE devices SET revoked_at=now() WHERE id=$1",
        &[&f.device],
    )
    .await
    .unwrap();
    let app = router(SealedHttpState::new(url, hasher(), "manifest-test".into(), 1, true).unwrap());
    let page = devices(&app, &token).await;
    assert_eq!(page.devices.len(), 1);
    assert_eq!(page.devices[0].device_id, f.device);
    assert!(page.devices[0].revoked);
    assert!(!page.devices[0].active_socket_lease);
    f.cleanup().await;
}
