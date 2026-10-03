// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::activation::tests::pending;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

fn state(url: String, enabled: bool) -> WebhookHttpState {
    WebhookHttpState {
        sealed_delivery_enabled: enabled,
        database_url: url,
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        canonical_origin: "https://test.example".into(),
        vault: Arc::new(
            WebhookSecretVault::new(1, Zeroizing::new(crate::test_keys::key(125).to_vec()))
                .unwrap(),
        ),
    }
}

#[tokio::test]
async fn sealed_selection_route_is_absent_by_default_and_bearer_is_never_owner_authority() {
    let uri = format!("/v1/webhooks/{}/sealed-events", Uuid::from_u128(1));
    let response = router(state("postgres://unused".into(), false))
        .oneshot(request(Method::POST, &uri, json!({}), None, false))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let app = router(state("postgres://unused".into(), true));
    let mut bearer = request(Method::POST, &uri, json!({"enabled":true}), None, false);
    bearer
        .headers_mut()
        .insert(header::AUTHORIZATION, "Bearer synthetic".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(bearer).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn actual_owner_selection_requires_confirmation_closed_fields_csrf_current_session_and_same_account()
 {
    let (f, owner, _) = pending().await;
    let separator = if f.url.contains('?') { '&' } else { '?' };
    let app_state = state(
        format!("{}{separator}options=-csearch_path%3D{}", f.url, f.schema),
        true,
    );
    let endpoint = Uuid::new_v4();
    let secret = app_state
        .vault
        .seal(f.account, endpoint, &crate::test_keys::key(126))
        .unwrap();
    f.db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled) VALUES($1,$2,'https://hooks.example.org/inbox',$3,1,true)",&[&endpoint,&f.account,&secret]).await.unwrap();
    assert!(
        !f.db
            .query_one(
                "SELECT sealed_events_enabled FROM webhook_endpoints WHERE id=$1",
                &[&endpoint]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let digest = |domain: &[u8], value: &str| {
        let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
        mac.update(domain);
        mac.update(b"\0");
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    let session = Uuid::new_v4();
    f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
        &[&session,&f.account,&owner.user_id,&digest(b"session-v1",&token),&digest(b"csrf-v1",&csrf)]).await.unwrap();
    let app = router(app_state);
    let uri = format!("/v1/webhooks/{endpoint}/sealed-events");
    let selected = json!({"enabled":true,"encrypted_transfer_confirmed":true,"disclosure_version":"sealed-events-v1"});
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &uri,
                selected.clone(),
                Some((&token, &csrf)),
                false
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut extra = selected.clone();
    extra["reader_key"] = json!("synthetic");
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &uri,
                extra,
                Some((&token, &csrf)),
                true
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut unconfirmed = selected.clone();
    unconfirmed["encrypted_transfer_confirmed"] = json!(false);
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &uri,
                unconfirmed,
                Some((&token, &csrf)),
                true
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let foreign = Uuid::new_v4();
    let foreign_account = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&foreign_account])
        .await
        .unwrap();
    let foreign_secret = crate::webhook_worker::WebhookSecretVault::new(
        1,
        Zeroizing::new(crate::test_keys::key(125).to_vec()),
    )
    .unwrap()
    .seal(foreign_account, foreign, &crate::test_keys::key(126))
    .unwrap();
    f.db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled) VALUES($1,$2,'https://hooks.example.org/inbox',$3,1,true)",&[&foreign,&foreign_account,&foreign_secret]).await.unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/webhooks/{foreign}/sealed-events"),
                selected.clone(),
                Some((&token, &csrf)),
                true
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::POST,
                &uri,
                selected.clone(),
                Some((&token, &csrf)),
                true
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        f.db.query_one(
            "SELECT sealed_events_enabled FROM webhook_endpoints WHERE id=$1",
            &[&endpoint]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&session],
    )
    .await
    .unwrap();
    assert_eq!(
        app.oneshot(request(
            Method::POST,
            &uri,
            selected,
            Some((&token, &csrf)),
            true
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn concurrent_fifth_selection_serializes_and_sixth_is_refused_without_breaking_same_endpoint_replay()
 {
    let (f, owner, _) = pending().await;
    let mut endpoints = Vec::new();
    for _ in 0..6 {
        let id = Uuid::new_v4();
        let vault = WebhookSecretVault::new(1, Zeroizing::new(crate::test_keys::key(125).to_vec()))
            .unwrap();
        let packed = vault
            .seal(f.account, id, &crate::test_keys::key(126))
            .unwrap();
        f.db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled) VALUES($1,$2,'https://hooks.example.org/inbox',$3,1,true)",&[&id,&f.account,&packed]).await.unwrap();
        endpoints.push(id);
    }
    for id in &endpoints[..4] {
        set_sealed_selection(&mut f.connect().await, &owner, *id, true)
            .await
            .unwrap();
    }
    let mut left = f.connect().await;
    let mut right = f.connect().await;
    let (a, b) = tokio::join!(
        set_sealed_selection(&mut left, &owner, endpoints[4], true),
        set_sealed_selection(&mut right, &owner, endpoints[5], true)
    );
    assert!(matches!(
        (&a, &b),
        (Ok(()), Err(EndpointError::Limit)) | (Err(EndpointError::Limit), Ok(()))
    ));
    let winner = if a.is_ok() {
        endpoints[4]
    } else {
        endpoints[5]
    };
    set_sealed_selection(&mut f.connect().await, &owner, winner, true)
        .await
        .unwrap();
    assert_eq!(f.db.query_one("SELECT count(*) FROM webhook_endpoints WHERE account_id=$1 AND enabled AND sealed_events_enabled",&[&f.account]).await.unwrap().get::<_,i64>(0),5);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn disabling_revokes_selection_and_legacy_reenable_cannot_bypass_five_endpoint_cap() {
    let (f, owner, _) = pending().await;
    let mut endpoints = Vec::new();
    let vault =
        WebhookSecretVault::new(1, Zeroizing::new(crate::test_keys::key(125).to_vec())).unwrap();
    for _ in 0..6 {
        let id = Uuid::new_v4();
        let packed = vault
            .seal(f.account, id, &crate::test_keys::key(126))
            .unwrap();
        f.db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled) VALUES($1,$2,'https://hooks.example.org/inbox',$3,1,true)",&[&id,&f.account,&packed]).await.unwrap();
        endpoints.push(id);
    }
    for id in &endpoints[..5] {
        set_sealed_selection(&mut f.connect().await, &owner, *id, true)
            .await
            .unwrap();
    }
    retire(&mut f.connect().await, &owner, endpoints[0], None)
        .await
        .unwrap();
    assert!(
        !f.db
            .query_one(
                "SELECT sealed_events_enabled FROM webhook_endpoints WHERE id=$1",
                &[&endpoints[0]]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    set_sealed_selection(&mut f.connect().await, &owner, endpoints[5], true)
        .await
        .unwrap();
    enable(&mut f.connect().await, &owner, &vault, endpoints[0])
        .await
        .unwrap();
    let row =
        f.db.query_one(
            "SELECT enabled,sealed_events_enabled FROM webhook_endpoints WHERE id=$1",
            &[&endpoints[0]],
        )
        .await
        .unwrap();
    assert!(row.get::<_, bool>(0));
    assert!(!row.get::<_, bool>(1));
    assert!(matches!(
        set_sealed_selection(&mut f.connect().await, &owner, endpoints[0], true).await,
        Err(EndpointError::Limit)
    ));
    assert_eq!(f.db.query_one("SELECT count(*) FROM webhook_endpoints WHERE account_id=$1 AND enabled AND sealed_events_enabled",&[&f.account]).await.unwrap().get::<_,i64>(0),5);
    f.cleanup().await;
}
