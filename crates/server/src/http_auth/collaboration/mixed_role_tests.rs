// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn mixed_observer_drafter_role_adds_only_drafting_and_each_half_revokes_independently() {
    let mut f = Fixture::with_device_status().await;
    let own_device = Uuid::new_v4();
    let foreign_device = Uuid::new_v4();
    let other = auth::authenticate_session(&f.db, &f.state.hasher, &f.other.token)
        .await
        .unwrap();
    assert_ne!(other.tenant.account_id(), f.account);
    seed_device(&f, own_device, f.account, "Own synthetic gateway").await;
    seed_device(
        &f,
        foreign_device,
        other.tenant.account_id(),
        "Foreign synthetic gateway",
    )
    .await;
    assert_device_scope(&f, &f.other, foreign_device).await;
    let draft =
        json!({"draft_id":Uuid::new_v4(),"ciphertext_base64":STANDARD.encode(vec![7_u8;32])});
    // Before any drafting grant: the observer seat reads status, cannot draft
    // and holds no owner authority.
    assert_device_scope(&f, &f.member, own_device).await;
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            draft.clone()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/grants",
            Some(&f.member),
            json!(null)
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // The drafting grant adds drafting only: status reads continue, owner
    // authority is not inherited.
    let grant = f.grant(f.member_id).await;
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            draft.clone()
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    assert_device_scope(&f, &f.member, own_device).await;
    assert_eq!(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/grants",
            Some(&f.member),
            json!(null)
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Revoking only the grant keeps the observer seat fully alive.
    assert_eq!(
        f.request(
            Method::DELETE,
            &format!("/v1/auth/collaboration/grants/{grant}"),
            Some(&f.owner),
            json!(null)
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            draft.clone()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_device_scope(&f, &f.member, own_device).await;
    // Removing the observer seat ends the whole membership: the session can
    // neither read status nor draft, and the introduced grants and ciphertext
    // are scrubbed.
    f.grant(f.member_id).await;
    // A new grant cannot rehydrate the old grant's tombstoned identity.
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            draft.clone()
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let new_draft = json!({"draft_id":Uuid::new_v4(),
        "ciphertext_base64":STANDARD.encode(vec![7_u8;32])});
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            new_draft.clone()
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    let owner = auth::authenticate_session(&f.db, &f.state.hasher, &f.owner.token)
        .await
        .unwrap();
    auth::seats::remove_observer(&mut f.db, &owner, f.member_id)
        .await
        .unwrap();
    for path in ["/v1/observer/devices", "/v1/auth/collaboration/drafts"] {
        let dead = f
            .request(Method::GET, path, Some(&f.member), json!(null))
            .await;
        assert_eq!(
            dead.status(),
            StatusCode::UNAUTHORIZED,
            "stale membership read {path}"
        );
    }
    assert_eq!(
        f.request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            new_draft
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM collaboration_draft_grants", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM collaboration_drafts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

async fn assert_device_scope(f: &Fixture, who: &SessionCredentials, expected: Uuid) {
    let response = f
        .request(Method::GET, "/v1/observer/devices", Some(who), json!(null))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = data(response).await;
    let devices = body["devices"].as_array().unwrap();
    assert_eq!(
        devices.len(),
        1,
        "status must contain exactly the caller's seeded device"
    );
    assert_eq!(devices[0]["device_id"], expected.to_string());
    assert!(body["next_cursor"].is_null());
}

async fn seed_device(f: &Fixture, id: Uuid, account: Uuid, name: &str) {
    use p256::elliptic_curve::Generate;
    use sha2::{Digest, Sha256};
    let key = p256::ecdsa::SigningKey::generate();
    let public = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let fingerprint = Sha256::digest(&public).to_vec();
    f.db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,$3)",
        &[&id, &account, &name],
    )
    .await
    .unwrap();
    f.db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&id, &account, &public, &fingerprint]).await.unwrap();
}
