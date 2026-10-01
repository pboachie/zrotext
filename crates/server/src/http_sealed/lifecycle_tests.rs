// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn request(method: &str, path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}
async fn json(response: Response) -> serde_json::Value {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await.unwrap()).unwrap()
}
async fn admit(case: &RouteCase, id: Uuid) {
    let now = route_now(&case.fixture.db).await;
    let response = router(case.state())
        .oneshot(case.submit(&case.token, case.envelope(id, now, 60_000).await))
        .await
        .unwrap();
    let status = response.status();
    let body = json(response).await;
    assert_eq!(status, StatusCode::ACCEPTED, "admission response: {body}");
}
async fn reader(case: &mut RouteCase) -> String {
    let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    insert_api_key(&mut case.fixture, &token, "messages:read", case.user).await;
    token
}

async fn other_tenant_token(case: &mut RouteCase, scope: &str) -> String {
    let original = case.fixture.account;
    let original_device = case.fixture.device;
    let account = Uuid::new_v4();
    case.fixture
        .db
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    let device = Uuid::new_v4();
    case.fixture
        .db
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic foreign')",
            &[&device, &account],
        )
        .await
        .unwrap();
    case.fixture.account = account;
    case.fixture.device = device;
    let user = insert_owner(&mut case.fixture).await;
    let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let key = insert_api_key(&mut case.fixture, &token, scope, user).await;
    case.fixture
        .db
        .execute(
            "UPDATE api_keys SET bound_device_id=NULL WHERE id=$1",
            &[&key],
        )
        .await
        .unwrap();
    case.fixture.account = original;
    case.fixture.device = original_device;
    token
}

#[tokio::test]
async fn disabled_lifecycle_routes_fail_before_authentication() {
    for (method, path) in [
        ("GET", "/messages"),
        ("GET", "/messages/00000000-0000-0000-0000-000000000000"),
        (
            "POST",
            "/messages/00000000-0000-0000-0000-000000000000/cancel",
        ),
    ] {
        let response = router(SealedHttpState::disabled(
            UNREACHABLE_DATABASE_URL.into(),
            hasher(),
        ))
        .oneshot(request(method, path, "invalid"))
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated PostgreSQL schemas"]
async fn scoped_status_contains_only_metadata_and_hides_foreign_identities() {
    let mut case = RouteCase::new().await;
    let id = Uuid::new_v4();
    admit(&case, id).await;
    let token = reader(&mut case).await;
    let response = router(case.state())
        .oneshot(request("GET", &format!("/messages/{id}"), &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["state"], "queued");
    assert_eq!(body.as_object().unwrap().len(), 7);
    let missing = Uuid::new_v4();
    let response = router(case.state())
        .oneshot(request("GET", &format!("/messages/{missing}"), &token))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::NOT_FOUND, "not_found".into())
    );
    let response = router(case.state())
        .oneshot(request("GET", &format!("/messages/{id}"), &case.token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let foreign_read = other_tenant_token(&mut case, "messages:read").await;
    let foreign_send = other_tenant_token(&mut case, "messages:send").await;
    for (method, path, token) in [
        ("GET", format!("/messages/{id}"), &foreign_read),
        ("GET", format!("/messages?cursor={id}"), &foreign_read),
        ("POST", format!("/messages/{id}/cancel"), &foreign_send),
    ] {
        let response = router(case.state())
            .oneshot(request(method, &path, token))
            .await
            .unwrap();
        assert_eq!(
            code(response).await,
            (StatusCode::NOT_FOUND, "not_found".into())
        );
    }
    let empty = json(
        router(case.state())
            .oneshot(request("GET", "/messages", &foreign_read))
            .await
            .unwrap(),
    )
    .await;
    assert!(empty["messages"].as_array().unwrap().is_empty());
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated PostgreSQL schemas"]
async fn pagination_is_bounded_and_rejects_foreign_and_wrong_device_cursors() {
    let mut case = RouteCase::new().await;
    for _ in 0..21 {
        let id = Uuid::new_v4();
        admit(&case, id).await;
        // Keep admission's real bounded queue intact while seeding history.
        let response = router(case.state())
            .oneshot(request(
                "POST",
                &format!("/messages/{id}/cancel"),
                &case.token,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let token = reader(&mut case).await;
    let page = json(
        router(case.state())
            .oneshot(request("GET", "/messages", &token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(page["messages"].as_array().unwrap().len(), 20);
    let cursor = page["next_cursor"].as_str().unwrap();
    let next = json(
        router(case.state())
            .oneshot(request(
                "GET",
                &format!("/messages?cursor={cursor}"),
                &token,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(next["messages"].as_array().unwrap().len(), 1);
    assert!(next["next_cursor"].is_null());
    let missing = Uuid::new_v4();
    let response = router(case.state())
        .oneshot(request(
            "GET",
            &format!("/messages?cursor={missing}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let wrong = Uuid::new_v4();
    case.fixture.db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic other device')",
        &[&wrong, &case.fixture.account],
    ).await.unwrap();
    case.fixture
        .db
        .execute(
            "UPDATE api_keys SET bound_device_id=$1 WHERE public_prefix=$2",
            &[&wrong, &&token[4..16]],
        )
        .await
        .unwrap();
    let response = router(case.state())
        .oneshot(request(
            "GET",
            &format!("/messages?cursor={cursor}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let empty = json(
        router(case.state())
            .oneshot(request("GET", "/messages", &token))
            .await
            .unwrap(),
    )
    .await;
    assert!(empty["messages"].as_array().unwrap().is_empty());
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated PostgreSQL schemas"]
async fn repeated_cancellation_refunds_once_without_rewriting_state_or_replay_identity() {
    let case = RouteCase::new().await;
    let id = Uuid::new_v4();
    let now = route_now(&case.fixture.db).await;
    let envelope = case.envelope(id, now, 60_000).await;
    let response = router(case.state())
        .oneshot(case.submit(&case.token, envelope.clone()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let mut version = None;
    for _ in 0..2 {
        let response = router(case.state())
            .oneshot(request(
                "POST",
                &format!("/messages/{id}/cancel"),
                &case.token,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["state"], "cancelled");
        if let Some(previous) = version {
            assert_eq!(body["state_version"], previous);
        }
        version = Some(body["state_version"].clone());
    }
    let row=case.fixture.db.query_one("SELECT count(*),sum(units) FROM usage_ledger WHERE message_id=$1 AND entry_kind='refund'", &[&id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, Option<i64>>(1), Some(-1));
    let response = router(case.state())
        .oneshot(case.submit(&case.token, envelope))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(json(response).await["created"], false);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated PostgreSQL schemas"]
async fn grant_boundary_wins_cancel_race_without_refund() {
    let case = RouteCase::new().await;
    let id = Uuid::new_v4();
    admit(&case, id).await;
    let mut client = connect(&case.url).await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "UPDATE dispatch_jobs SET grant_issued_at=clock_timestamp() WHERE message_id=$1",
        &[&id],
    )
    .await
    .unwrap();
    let app = router(case.state());
    let token = case.token.clone();
    let cancel = tokio::spawn(async move {
        app.oneshot(request("POST", &format!("/messages/{id}/cancel"), &token))
            .await
            .unwrap()
    });
    // Confirm the cancelled task cannot complete while grant ownership holds
    // the row, then publish that grant before releasing it.
    tokio::task::yield_now().await;
    assert!(!cancel.is_finished());
    tx.commit().await.unwrap();
    assert_eq!(
        code(cancel.await.unwrap()).await,
        (StatusCode::CONFLICT, "cancellation_conflict".into())
    );
    let refunds: i64 = case
        .fixture
        .db
        .query_one(
            "SELECT count(*) FROM usage_ledger WHERE message_id=$1 AND entry_kind='refund'",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(refunds, 0);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated PostgreSQL schemas"]
async fn revocation_after_header_authentication_fails_transaction_authority_check() {
    let case = RouteCase::new().await;
    let principal = auth::authenticate_api_key(&case.fixture.db, &hasher(), &case.token)
        .await
        .unwrap();
    let key = principal.key_id;
    let auth = super::super::lifecycle::LifecycleAuth {
        principal,
        _slot: crate::http_auth::preauth::AccountSlot::try_acquire(case.fixture.account).unwrap(),
    };
    case.fixture
        .db
        .execute(
            "UPDATE api_keys SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&key],
        )
        .await
        .unwrap();
    let mut client = connect(&case.url).await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(matches!(
        super::super::lifecycle::authorize(&tx, &auth, auth::Scope::MessagesSend).await,
        Err(SealedHttpError::Forbidden)
    ));
    tx.rollback().await.unwrap();
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated PostgreSQL schemas"]
async fn stale_device_cannot_readmit_but_ungranted_work_can_be_removed() {
    let case = RouteCase::new().await;
    let id = Uuid::new_v4();
    let now = route_now(&case.fixture.db).await;
    let envelope = case.envelope(id, now, 60_000).await;
    let response = router(case.state())
        .oneshot(case.submit(&case.token, envelope.clone()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    case.fixture
        .db
        .execute(
            "UPDATE devices SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&case.fixture.device],
        )
        .await
        .unwrap();
    let replay = router(case.state())
        .oneshot(case.submit(&case.token, envelope))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    let cancelled = router(case.state())
        .oneshot(request(
            "POST",
            &format!("/messages/{id}/cancel"),
            &case.token,
        ))
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::OK);
    assert_eq!(json(cancelled).await["state"], "cancelled");
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated PostgreSQL schemas"]
async fn expired_work_stays_expired_and_cancellation_does_not_double_refund() {
    let mut case = RouteCase::new().await;
    let id = Uuid::new_v4();
    let now = route_now(&case.fixture.db).await;
    let response = router(case.state())
        .oneshot(case.submit(&case.token, case.envelope(id, now, 1000).await))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let mut client = connect(&case.url).await.unwrap();
    assert_eq!(
        zrotext_delivery_store::DeliveryStore::new(&mut client)
            .expire_due(20)
            .await
            .unwrap(),
        1
    );
    let token = reader(&mut case).await;
    let expired = router(case.state())
        .oneshot(request("GET", &format!("/messages/{id}"), &token))
        .await
        .unwrap();
    assert_eq!(json(expired).await["state"], "expired");
    let cancelled = router(case.state())
        .oneshot(request(
            "POST",
            &format!("/messages/{id}/cancel"),
            &case.token,
        ))
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::CONFLICT);
    let refunds: i64 = case
        .fixture
        .db
        .query_one(
            "SELECT count(*) FROM usage_ledger WHERE message_id=$1 AND entry_kind='refund'",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(refunds, 1);
    case.fixture.cleanup().await;
}
