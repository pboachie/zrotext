// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth;
use axum::http::Method;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn owner_export_does_not_skip_equal_draft_ids_from_different_authors() {
    let mut f = Fixture::new().await;
    f.grant(f.owner_id).await;
    f.grant(f.member_id).await;
    let owner = auth::authenticate_session(&f.db, &f.state.hasher, &f.owner.token)
        .await
        .unwrap();
    let member = auth::authenticate_session(&f.db, &f.state.hasher, &f.member.token)
        .await
        .unwrap();
    let boundary = Uuid::from_u128(1);
    for value in 1..=20 {
        drafts::create(&mut f.db, &owner, Uuid::from_u128(value), vec![73; 32])
            .await
            .unwrap();
    }
    drafts::create(&mut f.db, &member, boundary, vec![74; 32])
        .await
        .unwrap();
    let first = data(
        f.request(
            Method::GET,
            "/v1/auth/collaboration/export",
            Some(&f.owner),
            Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(first["drafts"].as_array().unwrap().len(), 20);
    let cursor = first["next_cursor"].as_str().unwrap();
    let second = data(
        f.request(
            Method::GET,
            &format!("/v1/auth/collaboration/export?before={cursor}"),
            Some(&f.owner),
            Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(
        second["drafts"].as_array().unwrap().len(),
        1,
        "the second author at the page boundary must remain exportable"
    );
    let identities: std::collections::HashSet<_> = first["drafts"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["drafts"].as_array().unwrap())
        .map(|row| {
            (
                row["draft_id"].to_string(),
                row["author_user_id"].to_string(),
            )
        })
        .collect();
    assert_eq!(identities.len(), 21);
    assert_eq!(second["drafts_truncated"], false);
    let foreign = data(
        f.request(
            Method::GET,
            &format!("/v1/auth/collaboration/export?before={cursor}"),
            Some(&f.other),
            Value::Null,
        )
        .await,
    )
    .await;
    assert!(foreign["drafts"].as_array().unwrap().is_empty());
    assert!(foreign["grants"].as_array().unwrap().is_empty());
    assert_eq!(
        f.request(
            Method::GET,
            &format!("/v1/auth/collaboration/export?before={cursor}"),
            Some(&f.member),
            Value::Null
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    for invalid in [
        "not-a-cursor".to_owned(),
        boundary.to_string(),
        format!("{boundary}:{}", Uuid::nil()),
        format!("{cursor}:extra"),
        cursor.to_uppercase(),
    ] {
        assert_eq!(
            f.request(
                Method::GET,
                &format!("/v1/auth/collaboration/export?before={invalid}"),
                Some(&f.owner),
                Value::Null
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn session_expiry_during_delete_or_revoke_preserves_live_ciphertext_and_grant() {
    for revoke in [false, true] {
        let mut f = Fixture::new().await;
        let grant = f.grant(f.member_id).await;
        let member = auth::authenticate_session(&f.db, &f.state.hasher, &f.member.token)
            .await
            .unwrap();
        let id = Uuid::new_v4();
        drafts::create(&mut f.db, &member, id, vec![73; 32])
            .await
            .unwrap();
        let credentials = if revoke { &f.owner } else { &f.member };
        let principal = auth::authenticate_session(&f.db, &f.state.hasher, &credentials.token)
            .await
            .unwrap();
        let table = if revoke {
            "collaboration_draft_grants"
        } else {
            "collaboration_drafts"
        };
        f.db.batch_execute(&format!("CREATE FUNCTION delay_collaboration_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE TRIGGER delay_collaboration_update BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION delay_collaboration_update();")).await.unwrap();
        f.db.execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
            &[&credentials.id],
        )
        .await
        .unwrap();
        let result = if revoke {
            drafts::revoke(&mut f.db, &principal, grant)
                .await
                .map(|_| ())
        } else {
            drafts::delete_own(&mut f.db, &principal, id).await
        };
        assert!(matches!(result, Err(auth::AuthError::Unauthorized)));
        let row =
            f.db.query_one(
                "SELECT ciphertext,deleted_at IS NULL FROM collaboration_drafts WHERE id=$1",
                &[&id],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, Vec<u8>>(0), vec![73; 32]);
        assert!(row.get::<_, bool>(1));
        assert!(
            f.db.query_one(
                "SELECT revoked_at IS NULL FROM collaboration_draft_grants WHERE id=$1",
                &[&grant]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        );
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run documented PostgreSQL checks"]
async fn session_expiry_during_final_insert_rolls_back_ciphertext() {
    let mut f = Fixture::new().await;
    f.grant(f.member_id).await;
    let member = auth::authenticate_session(&f.db, &f.state.hasher, &f.member.token)
        .await
        .unwrap();
    f.db.batch_execute("CREATE FUNCTION delay_draft_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE TRIGGER delay_draft_insert BEFORE INSERT ON collaboration_drafts FOR EACH ROW EXECUTE FUNCTION delay_draft_insert();").await.unwrap();
    f.db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
        &[&f.member.id],
    )
    .await
    .unwrap();
    let result = drafts::create(&mut f.db, &member, Uuid::new_v4(), vec![73; 32]).await;
    assert!(
        matches!(result, Err(auth::AuthError::Unauthorized)),
        "expiry during the final write must reject and roll back"
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
async fn session_expiry_during_blocked_reads_withholds_member_and_owner_exports() {
    for owner_read in [false, true] {
        let mut f = Fixture::new().await;
        f.grant(f.member_id).await;
        let member = auth::authenticate_session(&f.db, &f.state.hasher, &f.member.token)
            .await
            .unwrap();
        drafts::create(&mut f.db, &member, Uuid::new_v4(), vec![73; 32])
            .await
            .unwrap();
        let credentials = if owner_read { &f.owner } else { &f.member };
        let principal = auth::authenticate_session(&f.db, &f.state.hasher, &credentials.token)
            .await
            .unwrap();
        let (mut blocker, connection) =
            tokio_postgres::connect(&std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap(), NoTls)
                .await
                .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        blocker
            .batch_execute(&format!("SET search_path TO {}", f.schema))
            .await
            .unwrap();
        let lock = blocker.transaction().await.unwrap();
        lock.batch_execute("LOCK TABLE collaboration_drafts IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        f.db.execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
            &[&credentials.id],
        )
        .await
        .unwrap();
        let release = async {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            lock.commit().await.unwrap();
        };
        let read = async {
            if owner_read {
                drafts::export(&mut f.db, &principal, None)
                    .await
                    .map(|_| ())
            } else {
                drafts::own_drafts(&mut f.db, &principal, None)
                    .await
                    .map(|_| ())
            }
        };
        let (result, ()) = tokio::join!(read, release);
        assert!(
            matches!(result, Err(auth::AuthError::Unauthorized)),
            "expired authority must not release buffered ciphertext, owner_read={owner_read}"
        );
        assert_eq!(
            f.db.query_one("SELECT count(*) FROM collaboration_drafts", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        f.cleanup().await;
    }
}

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
