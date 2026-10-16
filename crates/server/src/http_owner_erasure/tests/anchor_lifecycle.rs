// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full authenticated erasure with held account fences"]
async fn anchor_contention_rolls_back_users_sessions_content_and_account_deletion() {
    for tuple_lock in [false, true] {
        let (admin, mut db, url, schema) = migrated_schema("anchor_contention").await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(24)).unwrap());
        let (a, session, _b, _bsession, app) = fixture(&mut db, &hasher, &url, None).await;
        let (mut blocker, driver) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let driver = tokio::spawn(driver);
        let held = blocker.transaction().await.unwrap();
        if tuple_lock {
            held.query_one(
                "SELECT state FROM payload_profile_account_anchors WHERE account_id=$1 FOR SHARE",
                &[&a.account_id],
            )
            .await
            .unwrap();
        } else {
            held.query_one(
                "SELECT pg_advisory_xact_lock_shared(payload_profile_account_fence_key($1))",
                &[&a.account_id],
            )
            .await
            .unwrap();
        }
        let response = app
            .oneshot(erasure_post(
                Some(&session.token),
                Some(&session.csrf_token),
                Some(ORIGIN),
                &crate::test_keys::password(1),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        for (table, column, id) in [
            ("accounts", "id", a.account_id),
            ("users", "id", a.user_id),
            ("messages", "account_id", a.account_id),
            ("sessions", "account_id", a.account_id),
        ] {
            let count: i64 = db
                .query_one(
                    &format!("SELECT count(*) FROM {table} WHERE {column}=$1"),
                    &[&id],
                )
                .await
                .unwrap()
                .get(0);
            assert!(count > 0, "{table} must survive refused erasure");
        }
        let anchor=db.query_one("SELECT state,selection_epoch FROM payload_profile_account_anchors WHERE account_id=$1", &[&a.account_id]).await.unwrap();
        assert_eq!(anchor.get::<_, String>(0), "live");
        assert_eq!(anchor.get::<_, i64>(1), 0);
        held.rollback().await.unwrap();
        drop(blocker);
        driver.await.unwrap().unwrap();
        assert!(
            authenticate_session(&db, &hasher, &session.token)
                .await
                .is_ok()
        );
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; missing lifecycle update refuses full erasure"]
async fn an_uncommitted_tombstone_is_not_reported_as_successful_erasure() {
    let (admin, mut db, url, schema) = migrated_schema("anchor_drift").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(25)).unwrap());
    let (a, session, _b, _bsession, app) = fixture(&mut db, &hasher, &url, None).await;
    // Disposable corruption control, never a production repair or gate bypass.
    db.batch_execute("DROP TRIGGER payload_profile_anchor_after_account_delete ON accounts")
        .await
        .unwrap();
    let response = app
        .oneshot(erasure_post(
            Some(&session.token),
            Some(&session.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        authenticate_session(&db, &hasher, &session.token)
            .await
            .is_ok()
    );
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM accounts WHERE id=$1",
            &[&a.account_id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        db.query_one(
            "SELECT state FROM payload_profile_account_anchors WHERE account_id=$1",
            &[&a.account_id]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "live"
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
