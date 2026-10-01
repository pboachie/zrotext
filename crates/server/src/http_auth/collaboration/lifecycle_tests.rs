// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth;
use axum::http::Method;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn cached_principals_cannot_outlive_member_session_account_or_grant_revocation() {
    for condition in ["membership", "session", "account", "grant", "user"] {
        let mut f = Fixture::new().await;
        let grant = f.grant(f.member_id).await;
        let principal = auth::authenticate_session(&f.db, &f.state.hasher, &f.member.token)
            .await
            .unwrap();
        let old = Uuid::new_v4();
        drafts::create(&mut f.db, &principal, old, vec![73; 32])
            .await
            .unwrap();
        match condition {
            "user" => {
                f.db.execute(
                    "UPDATE users SET email_verified_at=NULL WHERE id=$1",
                    &[&f.member_id],
                )
                .await
                .unwrap();
            }
            "membership" => {
                f.db.execute("UPDATE memberships SET revoked_at=clock_timestamp() WHERE account_id=$1 AND user_id=$2", &[&f.account,&f.member_id]).await.unwrap();
            }
            "session" => {
                f.db.execute(
                    "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
                    &[&f.member.id],
                )
                .await
                .unwrap();
            }
            "account" => {
                f.db.execute(
                    "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
                    &[&f.account],
                )
                .await
                .unwrap();
            }
            "grant" => {
                let owner = auth::authenticate_session(&f.db, &f.state.hasher, &f.owner.token)
                    .await
                    .unwrap();
                drafts::revoke(&mut f.db, &owner, grant).await.unwrap();
            }
            _ => unreachable!(),
        }
        let expected = if condition == "grant" {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::UNAUTHORIZED
        };
        for (method, path, body) in [
            (
                Method::GET,
                "/v1/auth/collaboration/drafts".into(),
                json!(null),
            ),
            (
                Method::POST,
                "/v1/auth/collaboration/drafts".into(),
                artifact(Uuid::new_v4()),
            ),
            (
                Method::GET,
                format!("/v1/auth/collaboration/drafts/{old}"),
                json!(null),
            ),
            (
                Method::DELETE,
                format!("/v1/auth/collaboration/drafts/{old}"),
                json!(null),
            ),
        ] {
            assert_eq!(
                f.request(method, &path, Some(&f.member), body)
                    .await
                    .status(),
                expected,
                "{condition}"
            );
        }
        assert!(
            drafts::create(&mut f.db, &principal, Uuid::new_v4(), vec![73; 32])
                .await
                .is_err()
        );
        assert!(
            drafts::own_drafts(&mut f.db, &principal, None)
                .await
                .is_err()
        );
        assert!(
            drafts::delete_own(&mut f.db, &principal, old)
                .await
                .is_err()
        );
        if condition == "grant" {
            assert!(f.db.query_one("SELECT ciphertext IS NULL AND deleted_at IS NOT NULL FROM collaboration_drafts WHERE id=$1", &[&old]).await.unwrap().get::<_,bool>(0));
            assert!(
                f.db.execute(
                    "UPDATE collaboration_draft_grants SET revoked_at=NULL WHERE id=$1",
                    &[&grant]
                )
                .await
                .is_err()
            );
            let replacement = f.grant(f.member_id).await;
            assert_ne!(replacement, grant);
            assert!(
                drafts::create(&mut f.db, &principal, old, vec![73; 32])
                    .await
                    .is_err()
            );
        }
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn shared_grant_lock_serializes_live_and_lifetime_budgets() {
    let mut f = Fixture::new().await;
    let grant = f.grant(f.member_id).await;
    let principal = auth::authenticate_session(&f.db, &f.state.hasher, &f.member.token)
        .await
        .unwrap();
    for _ in 0..19 {
        drafts::create(&mut f.db, &principal, Uuid::new_v4(), vec![73; 32])
            .await
            .unwrap();
    }
    let (mut other_db, connection) = tokio_postgres::connect(&f.state.database_url, NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let (first, second) = tokio::join!(
        drafts::create(&mut f.db, &principal, Uuid::new_v4(), vec![73; 32]),
        drafts::create(&mut other_db, &principal, Uuid::new_v4(), vec![73; 32])
    );
    assert_ne!(first.is_ok(), second.is_ok());
    assert!(matches!(
        first.as_ref().err().or(second.as_ref().err()),
        Some(auth::AuthError::RateLimited)
    ));
    f.db.execute("INSERT INTO collaboration_drafts(id,account_id,user_id,grant_id,ciphertext,ciphertext_digest,deleted_at) SELECT gen_random_uuid(),$1,$2,$3,NULL,$4,clock_timestamp() FROM generate_series(1,80)", &[&f.account,&f.member_id,&grant,&vec![1_u8;32]]).await.unwrap();
    let current = drafts::own_drafts(&mut f.db, &principal, None)
        .await
        .unwrap();
    drafts::delete_own(&mut f.db, &principal, current[0].draft_id)
        .await
        .unwrap();
    assert!(matches!(
        drafts::create(&mut f.db, &principal, Uuid::new_v4(), vec![73; 32]).await,
        Err(auth::AuthError::RateLimited)
    ));
    f.db.execute("INSERT INTO collaboration_draft_grants(id,account_id,user_id,role,revoked_at) SELECT gen_random_uuid(),$1,$2,'encrypted_drafter',clock_timestamp() FROM generate_series(1,99)", &[&f.account,&f.member_id]).await.unwrap();
    let response=f.request(Method::POST,"/v1/auth/collaboration/grants",Some(&f.owner),json!({"user_id":f.owner_id,"role":"encrypted_drafter","confirm_widening":true,"current_password":f.password})).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn owner_export_pages_ciphertext_and_tombstones_and_erasure_removes_introduced_grants() {
    let mut f = Fixture::new().await;
    f.grant(f.member_id).await;
    let principal = auth::authenticate_session(&f.db, &f.state.hasher, &f.member.token)
        .await
        .unwrap();
    for _ in 0..20 {
        drafts::create(&mut f.db, &principal, Uuid::new_v4(), vec![73; 32])
            .await
            .unwrap();
    }
    let id = drafts::own_drafts(&mut f.db, &principal, None)
        .await
        .unwrap()[0]
        .draft_id;
    drafts::delete_own(&mut f.db, &principal, id).await.unwrap();
    drafts::create(&mut f.db, &principal, Uuid::new_v4(), vec![74; 32])
        .await
        .unwrap();
    let export = data(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/export",
            Some(&f.owner),
            json!(null),
        )
        .await,
    )
    .await;
    assert_eq!(export["drafts"].as_array().unwrap().len(), 20);
    assert_eq!(export["drafts_truncated"], true);
    let cursor = export["next_cursor"].as_str().unwrap();
    let next = data(
        f.request(
            Method::GET,
            &format!("/v1/auth/collaboration/export?before={cursor}"),
            Some(&f.owner),
            json!(null),
        )
        .await,
    )
    .await;
    assert_eq!(next["drafts"].as_array().unwrap().len(), 1);
    assert_eq!(next["drafts_truncated"], false);
    let combined = export["drafts"]
        .as_array()
        .unwrap()
        .iter()
        .chain(next["drafts"].as_array().unwrap());
    let mut count = 0;
    for record in combined {
        count += 1;
        if record["draft_id"] == id.to_string() {
            assert!(record["ciphertext_base64"].is_null());
        } else {
            let bytes = STANDARD
                .decode(record["ciphertext_base64"].as_str().unwrap())
                .unwrap();
            assert_eq!(bytes.len(), 32);
        }
    }
    assert_eq!(count, 21);
    let owner = auth::authenticate_session(&f.db, &f.state.hasher, &f.owner.token)
        .await
        .unwrap();
    auth::seats::remove_observer(&mut f.db, &owner, f.member_id)
        .await
        .unwrap();
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
    let own = f.grant(f.owner_id).await;
    let owner = auth::authenticate_session(&f.db, &f.state.hasher, &f.owner.token)
        .await
        .unwrap();
    drafts::create(&mut f.db, &owner, Uuid::new_v4(), vec![73; 32])
        .await
        .unwrap();
    f.db.execute("DELETE FROM accounts WHERE id=$1", &[&f.account])
        .await
        .unwrap();
    assert!(
        !f.db
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM collaboration_draft_grants WHERE id=$1)",
                &[&own]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
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

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn ciphertext_body_and_authenticated_member_budgets_are_bounded() {
    let f = Fixture::new().await;
    f.grant(f.member_id).await;
    let oversized = f
        .request(
            Method::POST,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            json!({"draft_id":Uuid::new_v4(),"ciphertext_base64":"A".repeat(17_000)}),
        )
        .await;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let subject = format!("{}:{}", f.account, f.member_id);
    for _ in 0..60 {
        assert!(
            auth::abuse_limits::consume(
                &f.db,
                &f.state.hasher,
                auth::abuse_limits::Limit::CollaborationDraft,
                Some(&subject)
            )
            .await
            .unwrap()
        );
    }
    let limited = f
        .request(
            Method::GET,
            "/v1/auth/collaboration/drafts",
            Some(&f.member),
            Value::Null,
        )
        .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let independent = f
        .request(
            Method::GET,
            "/v1/auth/collaboration/export",
            Some(&f.other),
            Value::Null,
        )
        .await;
    assert_eq!(independent.status(), StatusCode::OK);
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM auth_abuse_counters WHERE scope='collaboration_draft'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        2
    );
    f.cleanup().await;
}
