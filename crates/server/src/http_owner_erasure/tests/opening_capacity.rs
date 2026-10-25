// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

const TABLES: [&str; 4] = [
    "workflow_opening_requests",
    "workflow_opening_allocations",
    "workflow_opening_offers",
    "workflow_openings",
];

/// Scrubbed minimal occupancy is legitimate retained state after authority
/// erasure. This is storage coverage, not source admission or confirmation.
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
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; current numbered opening storage"]
async fn current_mounted_erasure_counts_opening_tombstones_and_isolates_accounts() {
    current_case(async |db, _admin, url| {
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(12)).unwrap());
        let (a, session, b, _, app) = fixture(db, &hasher, url, None).await;
        seed(&*db, a.account_id).await;
        seed(&*db, b.account_id).await;
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
        assert_eq!(response.status(), StatusCode::OK);
        let report = body(response).await;
        for table in TABLES {
            assert_eq!(deleted_count(&report, table), 1);
            assert_eq!(
                rows(
                    &*db,
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    a.account_id
                )
                .await,
                0
            );
            assert_eq!(
                rows(
                    &*db,
                    &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                    b.account_id
                )
                .await,
                1
            );
        }
        assert_eq!(
            rows(
                &*db,
                "SELECT count(*) FROM accounts WHERE id=$1",
                a.account_id
            )
            .await,
            0
        );
        assert_eq!(
            rows(
                &*db,
                "SELECT count(*) FROM accounts WHERE id=$1",
                b.account_id
            )
            .await,
            1
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; current partial/extra-trigger graph refuses"]
async fn current_partial_or_extra_trigger_opening_graph_refuses_without_account_changes() {
    for partial in [false, true] {
        current_case(async |db, admin, url| {
            let hasher=Arc::new(TokenHasher::new(crate::test_keys::key(12)).unwrap());
            let (a,session,b,_,app)=fixture(db,&hasher,url,None).await;
            seed(&*db,a.account_id).await; seed(&*db,b.account_id).await;
            crate::hosted_runtime_identity::require(&*db).await.unwrap();
            if partial {
                admin.batch_execute("DROP TABLE workflow_opening_requests").await.unwrap();
            } else {
                admin.batch_execute("CREATE FUNCTION public.synthetic_opening_delete_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic opening delete refusal'; END $$; CREATE TRIGGER synthetic_opening_delete_failure BEFORE DELETE ON public.workflow_openings FOR EACH ROW EXECUTE FUNCTION public.synthetic_opening_delete_failure()").await.unwrap();
            }
            assert!(crate::hosted_runtime_identity::require(&*db).await.is_err());
            let response=app.oneshot(erasure_post(Some(&session.token),Some(&session.csrf_token),Some(ORIGIN),&crate::test_keys::password(1),None)).await.unwrap();
            assert_eq!(response.status(),StatusCode::SERVICE_UNAVAILABLE);
            for table in TABLES {
                if partial && table=="workflow_opening_requests" {continue;}
                for account in [a.account_id,b.account_id] {
                    assert_eq!(rows(&*db,&format!("SELECT count(*) FROM {table} WHERE account_id=$1"),account).await,1);
                }
            }
            assert!(!db.query_one("SELECT disabled_at IS NOT NULL FROM accounts WHERE id=$1",&[&a.account_id]).await.unwrap().get::<_,bool>(0));
            for (table,column,count) in [("accounts","id",1),("messages","account_id",2),("sessions","account_id",1)] {
                assert_eq!(rows(&*db,&format!("SELECT count(*) FROM {table} WHERE {column}=$1"),a.account_id).await,count);
            }
        }).await;
    }
}

async fn snapshot(db: &tokio_postgres::Client) -> Vec<String> {
    let mut result = Vec::new();
    for table in TABLES
        .into_iter()
        .chain(["accounts", "payload_profile_account_anchors"])
    {
        result.push(db.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM {table} t"),&[]).await.unwrap().get(0));
    }
    result
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical exact opening lifecycle rollback, not HTTP"]
async fn historical_opening_deletes_roll_back_after_a_witnessed_later_account_failure() {
    let (admin, mut db, _, schema) = migrated_schema("opening_capacity").await;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1),($2)", &[&a, &b])
        .await
        .unwrap();
    seed(&db, a).await;
    seed(&db, b).await;
    db.batch_execute("CREATE SEQUENCE opening_failure_reached; CREATE FUNCTION synthetic_later_account_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('opening_failure_reached'); RAISE EXCEPTION 'synthetic later opening erasure failure' USING ERRCODE='P0001'; END $$; CREATE TRIGGER synthetic_later_account_failure BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION synthetic_later_account_failure()").await.unwrap();
    let before = snapshot(&db).await;
    assert!(
        !db.query_one("SELECT is_called FROM opening_failure_reached", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let tx = db.transaction().await.unwrap();
    zrotext_delivery_store::sealed::lock_account(&tx, a, false)
        .await
        .unwrap();
    assert_eq!(
        tx.execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&a]
        )
        .await
        .unwrap(),
        1
    );
    let counts = crate::workflow_runtime::openings::lifecycle::erase_account(&tx, a)
        .await
        .unwrap();
    assert_eq!(counts, TABLES.map(|table| (table, 1)).to_vec());
    for table in TABLES {
        assert_eq!(
            tx.query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&a]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert_eq!(
            tx.query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&b]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
    }
    let error = tx
        .execute("DELETE FROM accounts WHERE id=$1", &[&a])
        .await
        .unwrap_err();
    let error = error.as_db_error().unwrap();
    assert_eq!(
        error.code(),
        &tokio_postgres::error::SqlState::RAISE_EXCEPTION
    );
    assert_eq!(error.message(), "synthetic later opening erasure failure");
    tx.rollback().await.unwrap();
    assert!(
        db.query_one("SELECT is_called FROM opening_failure_reached", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(snapshot(&db).await, before);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical partial opening preflight refuses"]
async fn historical_partial_opening_preflight_refuses_before_deletion() {
    let (admin, mut db, _, schema) = migrated_schema("opening_partial").await;
    let account = Uuid::new_v4();
    db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    seed(&db, account).await;
    db.batch_execute("DROP TABLE workflow_opening_requests")
        .await
        .unwrap();
    let tx = db.transaction().await.unwrap();
    assert!(
        crate::workflow_runtime::openings::lifecycle::erase_account(&tx, account)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    for table in TABLES.into_iter().skip(1) {
        assert_eq!(
            rows(
                &db,
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                account
            )
            .await,
            1
        );
    }
    assert_eq!(
        rows(&db, "SELECT count(*) FROM accounts WHERE id=$1", account).await,
        1
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
