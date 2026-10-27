// SPDX-License-Identifier: AGPL-3.0-only
//! Current native refusals and historical candidate SQL contracts are separate.
use super::*;
use crate::provider_sms::receipts::{self, test_support as provider_fixture};
use postgres_protocol::escape::escape_identifier;
use tokio_postgres::{Client, GenericClient, Transaction};

const PROVIDER_TABLES: [&str; 2] = ["provider_receipt_events", "provider_receipt_attempts"];

async fn provider_rows<C: GenericClient + Sync>(
    db: &C,
    account: Uuid,
    events: &str,
) -> Vec<String> {
    let mut rows = Vec::new();
    for table in [events, "provider_receipt_attempts"] {
        rows.push(db.query_one(
            &format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM {table} t WHERE account_id=$1"),
            &[&account],
        ).await.unwrap().get(0));
    }
    rows
}

async fn account_row<C: GenericClient + Sync>(db: &C, account: Uuid) -> String {
    db.query_one(
        "SELECT to_jsonb(a)::text FROM accounts a WHERE id=$1",
        &[&account],
    )
    .await
    .unwrap()
    .get(0)
}

async fn execute_provider_plan(tx: &Transaction<'_>, account: Uuid) {
    // Filter the actual production statements, without copying or replacing
    // their SQL. A changed order or missing conditional child fails this proof.
    let plan: Vec<_> = DELETE_PLAN
        .iter()
        .filter(|(table, _)| PROVIDER_TABLES.contains(table))
        .collect();
    assert_eq!(
        plan.iter().map(|(table, _)| *table).collect::<Vec<_>>(),
        PROVIDER_TABLES
    );
    for &&(table, sql) in &plan {
        assert_eq!(tx.execute(sql, &[&account]).await.unwrap(), 1, "{table}");
    }
    assert_eq!(
        provider_rows(tx, account, PROVIDER_TABLES[0]).await,
        ["[]", "[]"]
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; current unpromoted provider candidate refusal"]
async fn current_complete_and_partial_receipt_candidates_refuse_erasure_without_changes() {
    for partial in [false, true] {
        current_case(async |db, admin, url| {
            let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(81)).unwrap());
            let password = crate::test_keys::password(1);
            let a = register(db, &hasher, "erase-provider@example.test", &password).await.unwrap();
            let b = register(db, &hasher, "keep-provider@example.test", &password).await.unwrap();
            assert!(verify_email(db, &hasher, &a.verification_token).await.unwrap());
            let session = login(&*db, &hasher, "erase-provider@example.test", &password).await.unwrap();
            // Materialize normal coarse activity before candidate installation;
            // refusal must not revoke or erase this live session.
            authenticate_session(&*db, &hasher, &session.token).await.unwrap();
            assert!(crate::hosted_runtime_identity::require(&*db).await.is_ok());
            {
                let mut client = crate::runtime_db::connect(url).await.unwrap();
                begin_erasure_transaction(&mut client).await.unwrap().rollback().await.unwrap();
            }
            assert!(db.query_one("SELECT graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton", &[]).await.unwrap().get::<_,bool>(0));
            // Owner-only disposable corruption. No grant change, graph re-pin, or
            // native fallback promotes this unnumbered proposal into service.
            let migration_owner: String = admin.query_one(
                "SELECT pg_catalog.pg_get_userbyid(c.relowner)::text FROM pg_catalog.pg_class c WHERE c.oid='public.accounts'::pg_catalog.regclass",
                &[],
            ).await.unwrap().get(0);
            let installer_path: String = admin.query_one("SHOW search_path", &[]).await.unwrap().get(0);
            admin.batch_execute(&format!(
                "BEGIN; SET LOCAL ROLE {}; SET LOCAL search_path=public,pg_catalog; {} COMMIT;",
                escape_identifier(&migration_owner), provider_fixture::PROPOSAL,
            )).await.unwrap();
            assert!(admin.query_one("SELECT CURRENT_USER=SESSION_USER", &[]).await.unwrap().get::<_,bool>(0));
            assert_eq!(admin.query_one("SHOW search_path", &[]).await.unwrap().get::<_,String>(0), installer_path);
            let candidate_owner = admin.query_one(
                "SELECT (SELECT count(*)=2 AND bool_and(c.relowner=a.relowner) FROM pg_catalog.pg_class c WHERE c.oid IN('public.provider_receipt_attempts'::pg_catalog.regclass,'public.provider_receipt_events'::pg_catalog.regclass)), (SELECT count(*)=2 AND bool_and(p.proowner=a.relowner) FROM pg_catalog.pg_proc p WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname IN('provider_receipt_attempt_immutable','provider_receipt_event_guard')) FROM pg_catalog.pg_class a WHERE a.oid='public.accounts'::pg_catalog.regclass",
                &[],
            ).await.unwrap();
            assert!(candidate_owner.get::<_,bool>(0) && candidate_owner.get::<_,bool>(1));
            for account in [a.account_id, b.account_id] {
                let attempt = Uuid::new_v4();
                provider_fixture::seed(admin, account, attempt).await;
                admin.execute("INSERT INTO provider_receipt_events(account_id,attempt_id,event_id,semantic_digest,fact,state_version) VALUES($1,$2,$3,$4,'carrier_submitted',1)", &[&account,&attempt,&Uuid::new_v4(),&vec![7u8;32]]).await.unwrap();
                admin.execute("UPDATE provider_receipt_attempts SET state='submitted',event_count=1,state_version=1 WHERE account_id=$1 AND attempt_id=$2", &[&account,&attempt]).await.unwrap();
            }
            let events = if partial {
                admin.batch_execute("ALTER TABLE provider_receipt_events RENAME TO receipt_partial_events").await.unwrap();
                "receipt_partial_events"
            } else {
                PROVIDER_TABLES[0]
            };
            // Unchanged stock owner defaults confer ordinary DML on new
            // public tables. Those privileges do not authorize an unpinned
            // graph; do not revoke them to turn this into a permission test.
            for table in [events, "provider_receipt_attempts"] {
                for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
                    assert!(db.query_one("SELECT has_table_privilege(CURRENT_USER,$1,$2)", &[&table,&privilege]).await.unwrap().get::<_,bool>(0));
                }
                assert!(!db.query_one("SELECT has_table_privilege(CURRENT_USER,$1,'TRUNCATE,REFERENCES,TRIGGER')", &[&table]).await.unwrap().get::<_,bool>(0));
            }
            assert!(!db.query_one("SELECT graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton", &[]).await.unwrap().get::<_,bool>(0));
            assert!(crate::hosted_runtime_identity::require(&*db).await.is_err());
            {
                let mut client = crate::runtime_db::connect(url).await.unwrap();
                assert!(matches!(begin_erasure_transaction(&mut client).await, Err(crate::runtime_db::ConnectError::Identity)));
            }
            let a_before = provider_rows(admin, a.account_id, events).await;
            let b_before = provider_rows(admin, b.account_id, events).await;
            let account_before = account_row(admin, a.account_id).await;
            let other_before = account_row(admin, b.account_id).await;
            let session_before: String = admin.query_one("SELECT to_jsonb(s)::text FROM sessions s WHERE id=$1", &[&session.id]).await.unwrap().get(0);
            let app = router(OwnerErasureState { database_url: url.to_owned(), auth_hasher: hasher.clone(), canonical_origin: ORIGIN.into(), mfa_cipher: None });
            let response = app.oneshot(erasure_post(Some(&session.token),Some(&session.csrf_token),Some(ORIGIN),&password,None)).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert_eq!(body(response).await, json!({"code":"unavailable"}));
            assert_eq!(provider_rows(admin, a.account_id, events).await, a_before);
            assert_eq!(provider_rows(admin, b.account_id, events).await, b_before);
            assert_eq!(account_row(admin, a.account_id).await, account_before);
            assert_eq!(account_row(admin, b.account_id).await, other_before);
            assert_eq!(admin.query_one("SELECT to_jsonb(s)::text FROM sessions s WHERE id=$1", &[&session.id]).await.unwrap().get::<_,String>(0), session_before);
        }).await;
    }
}

struct Historical {
    admin: Client,
    db: Client,
    url: String,
    schema: String,
    accounts: [Uuid; 2],
}
impl Historical {
    async fn new() -> Self {
        let (admin, mut db, url, schema) = migrated_schema("provider_receipts").await;
        assert!(crate::hosted_runtime_identity::require(&db).await.is_err());
        db.batch_execute(provider_fixture::PROPOSAL).await.unwrap();
        let accounts = [Uuid::new_v4(), Uuid::new_v4()];
        for account in accounts {
            db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
                .await
                .unwrap();
            provider_fixture::seed(&db, account, Uuid::new_v4()).await;
            let event = provider_fixture::receipt(
                &provider_fixture::request(account),
                Uuid::new_v4(),
                "sent",
            );
            receipts::record_known_receipt(
                &mut db,
                &receipts::ElectedWriterPermit::synthetic(account, provider_fixture::SITE, 1),
                &event,
            )
            .await
            .unwrap();
        }
        Self {
            admin,
            db,
            url,
            schema,
            accounts,
        }
    }
    async fn finish(self) {
        drop(self.db);
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical107 exact provider SQL-plan contract"]
async fn historical_provider_plan_commits_exact_counts_and_preserves_other_account() {
    let mut f = Historical::new().await;
    let [account, other] = f.accounts;
    let other_before = provider_rows(&f.db, other, PROVIDER_TABLES[0]).await;
    let account_before = account_row(&f.db, account).await;
    let tx = f.db.transaction().await.unwrap();
    assert!(receipts::lifecycle::installed(&tx).await.unwrap());
    zrotext_delivery_store::sealed::lock_account(&tx, account, false)
        .await
        .unwrap();
    execute_provider_plan(&tx, account).await;
    tx.commit().await.unwrap();
    assert_eq!(
        provider_rows(&f.db, account, PROVIDER_TABLES[0]).await,
        ["[]", "[]"]
    );
    assert_eq!(
        provider_rows(&f.db, other, PROVIDER_TABLES[0]).await,
        other_before
    );
    assert_eq!(account_row(&f.db, account).await, account_before);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical107 witnessed provider SQL-plan rollback"]
async fn historical_provider_plan_rolls_back_witnessed_later_account_failure() {
    let mut f = Historical::new().await;
    let [account, other] = f.accounts;
    let before = provider_rows(&f.db, account, PROVIDER_TABLES[0]).await;
    let other_before = provider_rows(&f.db, other, PROVIDER_TABLES[0]).await;
    let account_before = account_row(&f.db, account).await;
    f.db.batch_execute("CREATE SEQUENCE provider_fixture_failure_reached; CREATE FUNCTION provider_fixture_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('provider_fixture_failure_reached'); RAISE EXCEPTION 'synthetic later provider erasure failure' USING ERRCODE='P0001'; END $$; CREATE TRIGGER provider_fixture_late_failure BEFORE DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION provider_fixture_late_failure()").await.unwrap();
    assert!(
        !f.db
            .query_one(
                "SELECT is_called FROM provider_fixture_failure_reached",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let tx = f.db.transaction().await.unwrap();
    assert!(receipts::lifecycle::installed(&tx).await.unwrap());
    zrotext_delivery_store::sealed::lock_account(&tx, account, false)
        .await
        .unwrap();
    tx.execute(
        "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
        &[&account],
    )
    .await
    .unwrap();
    execute_provider_plan(&tx, account).await;
    let error = tx
        .execute("DELETE FROM accounts WHERE id=$1", &[&account])
        .await
        .unwrap_err();
    let error = error
        .as_db_error()
        .expect("injected later account deletion error");
    assert_eq!(
        error.code(),
        &tokio_postgres::error::SqlState::RAISE_EXCEPTION
    );
    assert_eq!(error.message(), "synthetic later provider erasure failure");
    tx.rollback().await.unwrap();
    // The sequence is nontransactional: unchanged rows alone cannot prove the
    // later statement was reached after both exact child statements succeeded.
    assert!(
        f.db.query_one(
            "SELECT is_called FROM provider_fixture_failure_reached",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    assert_eq!(
        provider_rows(&f.db, account, PROVIDER_TABLES[0]).await,
        before
    );
    assert_eq!(
        provider_rows(&f.db, other, PROVIDER_TABLES[0]).await,
        other_before
    );
    assert_eq!(account_row(&f.db, account).await, account_before);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical107 consent blocker with candidate receipt rows"]
async fn historical_consent_blocker_inventory_preserves_candidate_receipt_rows() {
    let mut f = Historical::new().await;
    let [account, other] = f.accounts;
    let user = Uuid::new_v4();
    f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,'provider-hold@example.test','synthetic-unusable-verifier',clock_timestamp())", &[&user]).await.unwrap();
    f.db.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
        &[&account, &user],
    )
    .await
    .unwrap();
    f.db.execute("INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) VALUES($1,$2,'+12','email','opt_out',clock_timestamp()-interval '1 hour',$3)", &[&Uuid::new_v4(),&account,&user]).await.unwrap();
    let before = provider_rows(&f.db, account, PROVIDER_TABLES[0]).await;
    let other_before = provider_rows(&f.db, other, PROVIDER_TABLES[0]).await;
    let account_before = account_row(&f.db, account).await;
    let hold_before: String =
        f.db.query_one(
            "SELECT to_jsonb(h)::text FROM owner_recipient_holds h WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    let tx = f.db.transaction().await.unwrap();
    assert!(receipts::lifecycle::installed(&tx).await.unwrap());
    let mut blocked = Vec::new();
    // This is the retained historical SQL inventory, not an HTTP bypass around
    // native entry. Current ordinary consent409 is qualified separately.
    for table in BLOCKED_TABLES.iter().chain(OPTIONAL_BLOCKED_TABLES.iter()) {
        let rows = count(
            &tx,
            &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
            account,
        )
        .await
        .unwrap();
        if rows > 0 {
            blocked.push((*table, rows));
        }
    }
    assert_eq!(blocked, [("owner_recipient_holds", 1)]);
    tx.rollback().await.unwrap();
    assert_eq!(
        provider_rows(&f.db, account, PROVIDER_TABLES[0]).await,
        before
    );
    assert_eq!(
        provider_rows(&f.db, other, PROVIDER_TABLES[0]).await,
        other_before
    );
    assert_eq!(account_row(&f.db, account).await, account_before);
    assert_eq!(
        f.db.query_one(
            "SELECT to_jsonb(h)::text FROM owner_recipient_holds h WHERE account_id=$1",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        hold_before
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical107 partial provider preflight contract"]
async fn historical_partial_provider_storage_refuses_preflight_without_changes() {
    let mut f = Historical::new().await;
    let [account, other] = f.accounts;
    f.db.batch_execute("ALTER TABLE provider_receipt_events RENAME TO receipt_partial_events")
        .await
        .unwrap();
    let before = provider_rows(&f.db, account, "receipt_partial_events").await;
    let other_before = provider_rows(&f.db, other, "receipt_partial_events").await;
    let account_before = account_row(&f.db, account).await;
    let tx = f.db.transaction().await.unwrap();
    assert_eq!(
        receipts::lifecycle::installed(&tx).await,
        Err(receipts::Error::Unavailable)
    );
    assert_eq!(account_row(&tx, account).await, account_before);
    tx.rollback().await.unwrap();
    assert_eq!(
        provider_rows(&f.db, account, "receipt_partial_events").await,
        before
    );
    assert_eq!(
        provider_rows(&f.db, other, "receipt_partial_events").await,
        other_before
    );
    assert_eq!(account_row(&f.db, account).await, account_before);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; historical107 actual account lock and exact provider SQL plan"]
async fn historical_provider_plan_account_fence_blocks_late_receipt_and_prevents_recreation() {
    let mut f = Historical::new().await;
    let [account, other] = f.accounts;
    let other_before = provider_rows(&f.db, other, PROVIDER_TABLES[0]).await;
    let (mut blocker, connection) = tokio_postgres::connect(&f.url, NoTls).await.unwrap();
    let blocker_driver = tokio::spawn(connection);
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let block = blocker.transaction().await.unwrap();
    block
        .query_one(
            "SELECT attempt_id FROM provider_receipt_attempts WHERE account_id=$1 FOR UPDATE",
            &[&account],
        )
        .await
        .unwrap();
    let erase_url = handler_url(&f.url, "zt_historical_provider_erasure");
    let erase = tokio::spawn(async move {
        let (mut eraser, connection) = tokio_postgres::connect(&erase_url, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let tx = eraser.transaction().await.unwrap();
        assert!(receipts::lifecycle::installed(&tx).await.unwrap());
        zrotext_delivery_store::sealed::lock_account(&tx, account, false)
            .await
            .unwrap();
        execute_provider_plan(&tx, account).await;
        assert_eq!(
            tx.execute("DELETE FROM accounts WHERE id=$1", &[&account])
                .await
                .unwrap(),
            1
        );
        assert!(matches!(
            crate::payload_profile_anchor::retention(&tx, account)
                .await
                .unwrap(),
            crate::payload_profile_anchor::Retention::Deleted
        ));
        tx.commit().await.unwrap();
        crate::test_database::Fixture::close_connection(eraser, driver).await;
    });
    wait_until_handler_is_blocked_by(&f.admin, "zt_historical_provider_erasure", blocker_pid).await;
    let eraser_pid: i32 = f.admin.query_one("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND $2=ANY(pg_blocking_pids(pid))", &[&"zt_historical_provider_erasure",&blocker_pid]).await.unwrap().get(0);
    let receipt_url = handler_url(&f.url, "zt_historical_provider_receipt");
    let record = tokio::spawn(async move {
        let (mut recorder, connection) =
            tokio_postgres::connect(&receipt_url, NoTls).await.unwrap();
        let driver = tokio::spawn(connection);
        let event = provider_fixture::receipt(
            &provider_fixture::request(account),
            Uuid::new_v4(),
            "delivered",
        );
        let result = receipts::record_known_receipt(
            &mut recorder,
            &receipts::ElectedWriterPermit::synthetic(account, provider_fixture::SITE, 1),
            &event,
        )
        .await;
        crate::test_database::Fixture::close_connection(recorder, driver).await;
        result
    });
    wait_until_handler_is_blocked_by(&f.admin, "zt_historical_provider_receipt", eraser_pid).await;
    block.commit().await.unwrap();
    erase.await.unwrap();
    assert_eq!(record.await.unwrap(), Err(receipts::Error::Uncorrelated));
    let retry = provider_fixture::receipt(
        &provider_fixture::request(account),
        Uuid::new_v4(),
        "delivered",
    );
    assert_eq!(
        receipts::record_known_receipt(
            &mut f.db,
            &receipts::ElectedWriterPermit::synthetic(account, provider_fixture::SITE, 1),
            &retry
        )
        .await,
        Err(receipts::Error::Uncorrelated)
    );
    assert_eq!(
        provider_rows(&f.db, account, PROVIDER_TABLES[0]).await,
        ["[]", "[]"]
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM accounts WHERE id=$1", &[&account])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        provider_rows(&f.db, other, PROVIDER_TABLES[0]).await,
        other_before
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM accounts WHERE id=$1", &[&other])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    crate::test_database::Fixture::close_connection(blocker, blocker_driver).await;
    f.finish().await;
}
