// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn generic_authenticated_upload_and_replay_never_acquire_selected_interval_delivery() {
    let (mut fixture, owner, statement) =
        crate::http_owner_conversations::activation::tests::pending().await;
    crate::http_owner_conversations::activation::tests::activate(&fixture, &statement).await;
    let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    insert_api_key(&mut fixture, &token, "messages:send", owner.user_id).await;
    let separator = if fixture.url.contains('?') { '&' } else { '?' };
    let url = format!(
        "{}{separator}options=-csearch_path%3D{}",
        fixture.url, fixture.schema
    );
    let case = InboundCase {
        fixture,
        token,
        user: owner.user_id,
        url,
    };
    let secret = crate::webhook_worker::WebhookSecretVault::new(
        1,
        zeroize::Zeroizing::new(crate::test_keys::key(125).to_vec()),
    )
    .unwrap();
    let add_endpoint = |id| {
        secret
            .seal(case.fixture.account, id, &crate::test_keys::key(126))
            .unwrap()
    };
    let id = Uuid::new_v4();
    case.fixture.db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled,sealed_events_enabled) VALUES($1,$2,'https://hooks.example.org/inbox',$3,1,true,true)",&[&id,&case.fixture.account,&add_endpoint(id)]).await.unwrap();
    let event = Uuid::new_v4();
    let now = route_now(&case.fixture.db).await;
    let bytes = case.envelope(event, 1, now - 1000, 200).await;
    let app = router(case.state());
    let accepted = app
        .clone()
        .oneshot(inbound_post(&case.token, bytes.clone()))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let initial: serde_json::Value =
        serde_json::from_slice(&to_bytes(accepted.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(initial["created"], true);
    let extra = Uuid::new_v4();
    case.fixture.db.execute("INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled,sealed_events_enabled) VALUES($1,$2,'https://hooks.example.org/inbox',$3,1,true,true)",&[&extra,&case.fixture.account,&add_endpoint(extra)]).await.unwrap();
    let replay = app.oneshot(inbound_post(&case.token, bytes)).await.unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    let repeated: serde_json::Value =
        serde_json::from_slice(&to_bytes(replay.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(repeated["created"], false);
    assert_eq!(case.count().await, 1);
    assert_eq!(
        case.fixture
            .db
            .query_one("SELECT count(*) FROM sealed_event_deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        case.fixture
            .db
            .query_one(
                "SELECT count(*) FROM conversation_inbound_provenance WHERE event_id=$1",
                &[&event]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.fixture.cleanup().await;
}
