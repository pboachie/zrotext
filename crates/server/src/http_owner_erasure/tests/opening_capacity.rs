// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// Scrubbed minimal occupancy is a legitimate state after authority erasure.
/// Seed that retained shape to test the real mounted account erasure endpoint;
/// source admission/confirmation are separately proven by allocation fixtures.
async fn seed(db: &tokio_postgres::Client, account: Uuid) {
    let opening = Uuid::new_v4();
    let offer = Uuid::new_v4();
    let allocation = Uuid::new_v4();
    db.execute("INSERT INTO workflow_openings(account_id,id,definition_version,state_version,capacity,phase) VALUES($1,$2,1,1,1,'closed')", &[&account,&opening]).await.unwrap();
    db.execute("INSERT INTO workflow_opening_offers(account_id,id,opening_id,opening_definition_version,state_version,phase,binding_scrubbed) VALUES($1,$2,$3,1,1,'withdrawn',true)", &[&account,&offer,&opening]).await.unwrap();
    db.execute("INSERT INTO workflow_opening_allocations(account_id,id,opening_id,binding_scrubbed,response_use_digest,phase,state_version) VALUES($1,$2,$3,true,$4,'confirmed',1)", &[&account,&allocation,&opening,&vec![7u8;32]]).await.unwrap();
    db.execute("INSERT INTO workflow_opening_requests(account_id,request_id,opening_id,redacted) VALUES($1,$2,$3,true)", &[&account,&Uuid::new_v4(),&opening]).await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; actual mounted account erasure and candidate schema"]
async fn mounted_erasure_counts_tombstones_isolates_accounts_and_rolls_back_later_failure() {
    for failure in [false, true] {
        let (admin, mut db, url, schema) = migrated_schema("opening_capacity").await;
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(12)).unwrap());
        let (a, session, other, _, app) = fixture(&mut db, &hasher, &url, None).await;
        seed(&db, a.account_id).await;
        seed(&db, other.account_id).await;
        if failure {
            db.batch_execute("CREATE FUNCTION synthetic_opening_delete_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic later delete refusal'; END $$; CREATE TRIGGER synthetic_opening_delete_failure BEFORE DELETE ON workflow_openings FOR EACH ROW EXECUTE FUNCTION synthetic_opening_delete_failure()").await.unwrap();
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
        if failure {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        } else {
            assert_eq!(response.status(), StatusCode::OK);
            let report = body(response).await;
            for table in [
                "workflow_opening_requests",
                "workflow_opening_allocations",
                "workflow_opening_offers",
                "workflow_openings",
            ] {
                assert_eq!(deleted_count(&report, table), 1);
            }
        }
        for table in [
            "workflow_opening_requests",
            "workflow_opening_allocations",
            "workflow_opening_offers",
            "workflow_openings",
        ] {
            assert_eq!(
                rows(
                    &db,
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    a.account_id
                )
                .await,
                i64::from(failure)
            );
            assert_eq!(
                rows(
                    &db,
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    other.account_id
                )
                .await,
                1
            );
        }
        if failure {
            let disabled: bool = db
                .query_one(
                    "SELECT disabled_at IS NOT NULL FROM accounts WHERE id=$1",
                    &[&a.account_id],
                )
                .await
                .unwrap()
                .get(0);
            assert!(!disabled);
        }
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; actual mounted partial candidate failure"]
async fn partial_opening_candidate_aborts_erasure_without_any_account_changes() {
    let (admin, mut db, url, schema) = migrated_schema("opening_partial").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(12)).unwrap());
    let (a, session, _, _, app) = fixture(&mut db, &hasher, &url, None).await;
    seed(&db, a.account_id).await;
    db.batch_execute("DROP TABLE workflow_opening_requests")
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
    assert_eq!(
        rows(
            &db,
            "SELECT count(*) FROM workflow_opening_allocations WHERE account_id=$1",
            a.account_id
        )
        .await,
        1
    );
    let disabled: bool = db
        .query_one(
            "SELECT disabled_at IS NOT NULL FROM accounts WHERE id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!disabled);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
