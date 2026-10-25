// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::test_database::Fixture;
use tokio_postgres::{Client, IsolationLevel, error::SqlState};
use uuid::Uuid;

fn hmac(secret: &[u8; 32], nonce: &[u8], namespace: Uuid, pid: i32) -> Vec<u8> {
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for i in 0..32 {
        inner[i] ^= secret[i];
        outer[i] ^= secret[i];
    }
    let mut payload = inner.to_vec();
    payload.extend_from_slice(b"ZROTEXT-HOSTED-RUNTIME-V1");
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(namespace.as_bytes());
    payload.extend_from_slice(&1i64.to_be_bytes());
    payload.extend_from_slice(&pid.to_be_bytes());
    let mut final_input = outer.to_vec();
    final_input.extend_from_slice(&Sha256::digest(&payload));
    Sha256::digest(final_input).to_vec()
}

async fn namespace(owner: &Client) -> (Uuid, [u8; 32]) {
    let namespace = Uuid::new_v4();
    let mut secret = [0u8; 32];
    secret[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    secret[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    owner.execute("INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_synthetic',1,true,true)",&[&namespace]).await.unwrap();
    owner
        .execute(
            "INSERT INTO public.hosted_runtime_secrets(namespace_id,runtime_key) VALUES($1,$2)",
            &[&namespace, &&secret[..]],
        )
        .await
        .unwrap();
    (namespace, secret)
}
async fn bind(db: &Client, namespace: Uuid, secret: &[u8; 32]) -> Vec<u8> {
    let row = db
        .query_one(
            "SELECT public.hosted_runtime_challenge($1,1),pg_backend_pid()",
            &[&namespace],
        )
        .await
        .unwrap();
    let nonce: Vec<u8> = row.get(0);
    assert_eq!(nonce.len(), 32);
    let proof = hmac(secret, &nonce, namespace, row.get(1));
    assert!(
        db.query_one(
            "SELECT public.hosted_runtime_bind($1,1,$2)",
            &[&namespace, &proof]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    proof
}
async fn refused(db: &Client, sql: &str, code: SqlState) {
    let error = db.batch_execute(sql).await.unwrap_err();
    assert_eq!(error.code(), Some(&code), "{sql}: {error:?}");
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn imported_entry_payload_cannot_supply_native_physical_transaction_provenance() {
    let mut f = Fixture::new().await;
    let (namespace, secret) = namespace(&f.owner).await;
    bind(&f.runtime, namespace, &secret).await;
    let tx = f.runtime.transaction().await.unwrap();
    tx.query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
        .await
        .unwrap();
    let original: String = tx
        .query_one("SELECT pg_current_xact_id()::text", &[])
        .await
        .unwrap()
        .get(0);
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    tx.commit().await.unwrap();
    let tx = f.runtime.transaction().await.unwrap();
    let current: String = tx
        .query_one("SELECT pg_current_xact_id()::text", &[])
        .await
        .unwrap()
        .get(0);
    // Explicit privileged restore simulation: preserve the real HMAC session,
    // backend start and original expiry; copy only bookkeeping into a different
    // actual transaction. Runtime has no privilege to perform this write.
    f.owner.execute("INSERT INTO public.hosted_runtime_entries SELECT backend_pid,$1::text::xid8,backend_start,namespace_id,policy_revision,expires_at FROM public.hosted_runtime_entries WHERE backend_pid=$2 AND native_xid=$3::text::xid8",&[&current,&pid,&original]).await.unwrap();
    assert!(
        !tx.query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    tx.rollback().await.unwrap();
    bind(&f.runtime, namespace, &secret).await;
    let tx = f.runtime.transaction().await.unwrap();
    tx.query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
        .await
        .unwrap();
    tx.batch_execute("SAVEPOINT after_native_entry")
        .await
        .unwrap();
    assert!(
        tx.query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    tx.batch_execute("RELEASE SAVEPOINT after_native_entry")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tx = f.runtime.transaction().await.unwrap();
    tx.batch_execute("SAVEPOINT before_native_entry")
        .await
        .unwrap();
    assert_eq!(
        tx.query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    tx.rollback().await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn native_bound_backend_requires_new_genuine_entry_for_each_transaction() {
    let mut f = Fixture::new().await;
    f.verify().await;
    require(&f.runtime).await.unwrap();
    assert!(require(&f.owner).await.is_err());
    let (namespace, secret) = namespace(&f.owner).await;
    let proof = bind(&f.runtime, namespace, &secret).await;
    let start: String = f
        .runtime
        .query_one("SELECT public.hosted_runtime_native_start()::text", &[])
        .await
        .unwrap()
        .get(0);
    let stored: String = f
        .owner
        .query_one(
            "SELECT backend_start::text FROM public.hosted_runtime_sessions WHERE backend_pid=$1",
            &[&f.runtime
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get::<_, i32>(0)],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(start, stored);
    assert!(
        !f.runtime
            .query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let tx = f.runtime.transaction().await.unwrap();
    let expiry: i64 = tx
        .query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
        .await
        .unwrap()
        .get(0);
    assert!(
        tx.query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(
        expiry,
        tx.query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, i64>(0)
    );
    tx.commit().await.unwrap();
    assert!(
        !f.runtime
            .query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let tx = f.runtime.transaction().await.unwrap();
    tx.query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert!(
        !f.runtime
            .query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let (other, driver) = f.another_runtime().await;
    assert!(
        !other
            .query_one(
                "SELECT public.hosted_runtime_bind($1,1,$2)",
                &[&namespace, &proof]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(
        other
            .query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    Fixture::close_connection(other, driver).await;
    assert!(
        !f.runtime
            .query_one(
                "SELECT public.hosted_runtime_bind($1,1,$2)",
                &[&namespace, &proof]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(
        f.runtime
            .query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    assert_eq!(
        f.owner
            .query_one("SELECT count(*) FROM public.hosted_runtime_requests", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn native_defaults_cannot_be_supplied_or_protected_proof_rows_copied() {
    let f = Fixture::new().await;
    require(&f.runtime).await.unwrap();
    let (namespace, secret) = namespace(&f.owner).await;
    bind(&f.runtime, namespace, &secret).await;
    for (column, value) in [
        ("native_pid", "pg_backend_pid()"),
        ("native_start", "clock_timestamp()"),
        ("native_xid", "pg_current_xact_id()"),
        ("native_role", "CURRENT_USER::regrole::oid"),
        ("result", "'{}'::jsonb"),
    ] {
        for suffix in [value, "DEFAULT"] {
            refused(&f.runtime,&format!("INSERT INTO public.hosted_runtime_requests(operation,namespace_id,policy_revision,{column}) VALUES('enter','{namespace}',1,{suffix})"),SqlState::INSUFFICIENT_PRIVILEGE).await;
        }
    }
    // This command must refuse before COPY mode. Do not create an input sink
    // whose abort frames can outlive the already-rejected permission check.
    refused(&f.runtime,"COPY public.hosted_runtime_requests(operation,namespace_id,policy_revision,native_start) FROM STDIN",SqlState::INSUFFICIENT_PRIVILEGE).await;
    for sql in [
        "SELECT * FROM public.hosted_runtime_entries",
        "SELECT * FROM public.hosted_runtime_sessions",
        "UPDATE public.hosted_runtime_requests SET result='{}'",
        "DELETE FROM public.hosted_runtime_requests",
        "SELECT public.hosted_runtime_native_schema_valid()",
        "SELECT public.hosted_runtime_expiry(NULL,NULL)",
        "SELECT public.hosted_runtime_request_apply()",
        "SET ROLE pg_read_all_stats",
    ] {
        refused(&f.runtime, sql, SqlState::INSUFFICIENT_PRIVILEGE).await;
    }
    f.runtime
        .batch_execute(&format!(
            "SET zrotext.hosted_namespace='{namespace}';SET zrotext.hosted_revision='1'"
        ))
        .await
        .unwrap();
    assert!(
        !f.runtime
            .query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn changed_native_graph_and_column_capability_refuse_then_stock_reset_restores() {
    let mut f = Fixture::new().await;
    for sql in [
        "ALTER TABLE public.hosted_runtime_requests ALTER native_start SET DEFAULT clock_timestamp()",
        "ALTER TABLE public.hosted_runtime_requests DISABLE TRIGGER hosted_runtime_request_apply",
        "ALTER TABLE public.hosted_runtime_requests DISABLE TRIGGER hosted_runtime_request_remove",
        "ALTER TABLE public.hosted_runtime_entries DISABLE TRIGGER zz_payload_profile_writer_before_change",
        "ALTER FUNCTION public.hosted_runtime_native_start() SECURITY DEFINER",
        "CREATE FUNCTION public.hosted_runtime_unreviewed() RETURNS boolean LANGUAGE sql AS 'SELECT true'",
        "ALTER TABLE public.hosted_runtime_entries ADD COLUMN copied_proof boolean",
        "CREATE RULE unreviewed AS ON INSERT TO public.hosted_runtime_requests DO INSTEAD NOTHING",
    ] {
        let tx = f.owner.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{sql}");
        tx.rollback().await.unwrap();
        require(&f.runtime).await.unwrap();
    }
    // A changed catalog version cannot disguise missing116 objects as an
    // explicit pre-installation fixture while the actual ledger retains116.
    let tx = f.owner.transaction().await.unwrap();
    // Explicit privileged counterfeit, rolled back below: remove the current
    // CHECK as well as its trigger so the old version reaches the validator.
    tx.batch_execute("DROP TABLE public.hosted_runtime_requests,public.hosted_runtime_entries; DROP FUNCTION public.hosted_runtime_native_start(),public.hosted_runtime_native_schema_valid(),public.hosted_runtime_identity_ready(),public.hosted_runtime_enter(uuid,bigint),public.hosted_runtime_expiry(uuid,bigint),public.hosted_runtime_request_apply(),public.hosted_runtime_request_remove(),public.hosted_runtime_scope(); ALTER TABLE public.payload_profile_writer_catalog DISABLE TRIGGER ALL; ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check; UPDATE public.payload_profile_writer_catalog SET migration_version=115").await.unwrap();
    assert!(optional(&tx).await.is_err());
    tx.rollback().await.unwrap();
    require(&f.runtime).await.unwrap();
    f.owner
        .batch_execute(&format!(
            "GRANT INSERT(native_start) ON public.hosted_runtime_requests TO {}",
            postgres_protocol::escape::escape_identifier(&f.runtime_role)
        ))
        .await
        .unwrap();
    assert!(require(&f.runtime).await.is_err());
    f.reprovision().await;
    f.verify().await;
    require(&f.runtime).await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn hosted_projection_needs_same_transaction_identity_and_keeps_original_expiry() {
    let mut f = Fixture::new().await;
    let account = Uuid::new_v4();
    f.owner
        .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    let (namespace, secret) = namespace(&f.owner).await;
    f.owner.execute("INSERT INTO public.hosted_billing_customers(namespace_id,account_id,customer_id) VALUES($1,$2,'cus_synthetic')",&[&namespace,&account]).await.unwrap();
    f.owner.execute("WITH t AS(SELECT floor(extract(epoch FROM clock_timestamp()))::bigint n) INSERT INTO public.hosted_billing_projections(namespace_id,account_id,customer_id,subscription_id,policy_revision,dirty_generation,processed_generation,per_read_sequence,payment_hold,review_required,phase,outbound_limit,device_limit,issued_at,valid_until,read_token,invoice_id,price_id,period_start,period_end) SELECT $1,$2,'cus_synthetic','sub_synthetic',1,1,1,1,false,false,'active',10,2,n-1,n+60,gen_random_uuid(),'in_synthetic','price_synthetic',n-1,n+3600 FROM t",&[&namespace,&account]).await.unwrap();
    bind(&f.runtime, namespace, &secret).await;
    assert_eq!(
        f.runtime
            .query_one("SELECT public.hosted_runtime_projection($1)", &[&account])
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    let tx = f.runtime.transaction().await.unwrap();
    let cap: i64 = tx
        .query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        tx.query_one(
            "SELECT(public.hosted_runtime_projection($1)).account_id",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, Uuid>(0),
        account
    );
    let stored: i64 = tx
        .query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
        .await
        .unwrap()
        .get(0);
    assert_eq!(cap, stored);
    tx.commit().await.unwrap();
    // Explicit privileged shortening of an already genuine proof isolates the
    // expiry boundary; no verified identity is seeded or fabricated.
    f.owner.execute("UPDATE public.hosted_runtime_sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE backend_pid=$1",&[&f.runtime.query_one("SELECT pg_backend_pid()",&[]).await.unwrap().get::<_,i32>(0)]).await.unwrap();
    let tx = f.runtime.transaction().await.unwrap();
    let shorter: i64 = tx
        .query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
        .await
        .unwrap()
        .get(0);
    assert!(shorter < cap);
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert!(
        !tx.query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        f.runtime
            .query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::CHECK_VIOLATION)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable cluster"]
async fn manual_namespace_absence_holds_real_configuration_tuple_in_both_transition_orders() {
    for isolation in [
        IsolationLevel::ReadCommitted,
        IsolationLevel::RepeatableRead,
        IsolationLevel::Serializable,
    ] {
        let mut f = Fixture::new().await;
        let (mut other, driver) = f.another_runtime().await;
        let entry = f
            .runtime
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        let mandatory = other
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        for tx in [&entry, &mandatory] {
            assert_eq!(
                tx.query_one("SELECT count(*) FROM public.hosted_billing_namespaces", &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                0
            );
        }
        // Commit the genuine existing configuration transition AFTER both
        // snapshots observed absence, without changing their isolation/clock.
        namespace(&f.owner).await;
        if matches!(isolation, IsolationLevel::ReadCommitted) {
            entry
                .query_one("SELECT public.hosted_runtime_scope()", &[])
                .await
                .unwrap();
            assert_eq!(
                entry
                    .query_one("SELECT count(*) FROM public.hosted_billing_namespaces", &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                1
            );
            assert_eq!(
                entry
                    .query_one("SELECT public.hosted_runtime_marker()", &[])
                    .await
                    .unwrap_err()
                    .code(),
                Some(&SqlState::CHECK_VIOLATION)
            );
        } else {
            assert_eq!(
                entry
                    .query_one("SELECT public.hosted_runtime_scope()", &[])
                    .await
                    .unwrap_err()
                    .code(),
                Some(&SqlState::T_R_SERIALIZATION_FAILURE)
            );
        }
        entry.rollback().await.unwrap();
        // A raw ordinary writer which omitted the entry API must meet the SAME
        // stable tuple at the mandatory device admission constraint.
        let account = Uuid::new_v4();
        mandatory
            .execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        mandatory
            .execute(
                "INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
                &[&Uuid::new_v4(), &account],
            )
            .await
            .unwrap();
        let code = if matches!(isolation, IsolationLevel::ReadCommitted) {
            SqlState::CHECK_VIOLATION
        } else {
            SqlState::T_R_SERIALIZATION_FAILURE
        };
        assert_eq!(
            mandatory
                .batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
                .await
                .unwrap_err()
                .code(),
            Some(&code)
        );
        mandatory.rollback().await.unwrap();
        Fixture::close_connection(other, driver).await;
        f.finish().await;

        let mut f = Fixture::new().await;
        let tx = f
            .runtime
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        let account = Uuid::new_v4();
        tx.execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        tx.execute(
            "INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
            &[&Uuid::new_v4(), &account],
        )
        .await
        .unwrap();
        // No explicit scope call: the actual deferred business constraint takes
        // it, allowing genuine manual admission while holding absence to COMMIT.
        tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
            .await
            .unwrap();
        let namespace_id = Uuid::new_v4();
        let sql = "INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_synthetic',1,true,true)";
        assert_eq!(
            f.owner
                .execute(sql, &[&namespace_id])
                .await
                .unwrap_err()
                .code(),
            Some(&SqlState::LOCK_NOT_AVAILABLE)
        );
        tx.commit().await.unwrap();
        assert_eq!(f.owner.execute(sql, &[&namespace_id]).await.unwrap(), 1);
        assert_eq!(
            f.runtime
                .query_one(
                    "SELECT count(*) FROM public.devices WHERE account_id=$1",
                    &[&account]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        f.finish().await;
    }
    let mut f = Fixture::new().await;
    let tx = f.runtime.transaction().await.unwrap();
    tx.query_one("SELECT public.hosted_runtime_scope()", &[])
        .await
        .unwrap();
    let namespace_id = Uuid::new_v4();
    let sql = "INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_synthetic',1,true,true)";
    assert_eq!(
        f.owner
            .execute(sql, &[&namespace_id])
            .await
            .unwrap_err()
            .code(),
        Some(&SqlState::LOCK_NOT_AVAILABLE)
    );
    tx.rollback().await.unwrap();
    assert_eq!(f.owner.execute(sql, &[&namespace_id]).await.unwrap(), 1);
    f.finish().await;
}

#[test]
fn every_native_required_body_matches_the_independent_closed_stock_pins() {
    for (name, pins) in [
        (
            "hosted_runtime_native_start",
            &["ec771eafcc009af67e4dcb156d3b5406c8cec64ea5e045ba624e6850d7614b54"] as &[&str],
        ),
        (
            "hosted_runtime_native_schema_valid",
            &["899ca98ace0d006efc0fde4e0fba02ef2f207fc112ad94f091013d2e9e503644"] as &[&str],
        ),
        (
            "hosted_runtime_identity_ready",
            &["88de695db32691204e5126b0b5e003aadced6f61ec77918a00618f1e2f59a532"] as &[&str],
        ),
        (
            "hosted_runtime_scope",
            &["604e7c39da10e1c34c5193dd04d5742637c611a40e3d7a28bf300ec066756dbe"] as &[&str],
        ),
        (
            "hosted_runtime_marker",
            &["22de9f7196cc521eecffc5652aac84040597db4f7a247cfd91ab208aed4c2082"] as &[&str],
        ),
        (
            "hosted_runtime_request_apply",
            &["71e1abc66badc284df0804536950134dc07560eb7ca9453876ebfd4c801b85e2"] as &[&str],
        ),
        (
            "hosted_runtime_request_remove",
            &["116d1461147797b8272d44684d9e85e7ce1ba5d515d9a2b36440287dac94dcb6"] as &[&str],
        ),
        (
            "hosted_runtime_challenge",
            &["da750b1b75c8cd0b61ea45e0502eaf421d29e9d46bf0ef21f504ea6c4b3adf37"] as &[&str],
        ),
        (
            "hosted_runtime_bind",
            &["fa7997c018ee674b417e09472bac835a69b0cd965f7b9859f89536b0cb2c5317"] as &[&str],
        ),
        (
            "hosted_runtime_enter",
            &["bcf16eeaf2b711c362ad7b65baa09276dd80cba1341529f7f94f004b0ddbf810"] as &[&str],
        ),
        (
            "hosted_runtime_verified",
            &["7dfb68c9052feb74e09a214fc2151a45766874d5e87ad0a36af18d695a0bb16c"] as &[&str],
        ),
        (
            "hosted_runtime_expiry",
            &["7b8ec8ff0ce04d481b95b815b9b44bc2416db7b6185af6a6d249e7f8e520edb9"] as &[&str],
        ),
        (
            "conversation_profile03_grant_billing",
            &["2e9f58851146928cebfe79ec54160f0718d6cdd6ed05b3fcec29e414c84e7bf3"] as &[&str],
        ),
        (
            "payload_profile_writer_guard",
            &["f0cc270d7de8b3c0cf1335c310bae04ab2653aa8cb0ce07c56e07d74e6b1af37"] as &[&str],
        ),
        (
            "payload_profile_writer_version",
            &["ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9"] as &[&str],
        ),
        (
            "payload_profile_writer_ready",
            &["04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3"] as &[&str],
        ),
        (
            "payload_profile_writer_json",
            &["33c468e0b9077291b6b6cd4f0816952d32aa8848ddf74141eed3379c1a237227"] as &[&str],
        ),
        (
            "payload_profile_writer_global_guard",
            &["b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106"] as &[&str],
        ),
        (
            "payload_profile_writer_catalog_guard",
            &["07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a"] as &[&str],
        ),
        (
            "payload_profile_writer_graph",
            &["93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061"] as &[&str],
        ),
        (
            "hosted_runtime_schema_ready",
            &[
                "7aa17580ac81a8f630b55797daee4fd22b178b236605f71c21491cb85e30865b",
                "f4317324a9ba8ed8799696d4944d9382a847eaa98251e8d147353b159433102b",
            ] as &[&str],
        ),
        (
            "hosted_runtime_role_safe",
            &[
                "898ddd403142d0b048b0e528c2b2ab9832ed3197ca86f1dc271e7d0ed7a26b9b",
                "3aa8eb73d8355243b5181d500582d38609e5f5effe681bd14a8c8383f5db48c3",
            ] as &[&str],
        ),
        (
            "hosted_runtime_projection",
            &[
                "25cd5c35228ee26a82bda8d04084a763681d209b4f17ec8e0e92b51e417ed72e",
                "ba7fcf05e3069d2766bf90f7a868c52e55b2d9c1278bc9bb2279ce30e3b794c0",
            ] as &[&str],
        ),
    ] {
        let extracted = body(name).unwrap();
        let actual = Sha256::digest(extracted.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(
            pins.contains(&actual.as_str()),
            "wrong declared body for {name}"
        );
    }
}

#[test]
fn trigger_calls_comments_unknown_and_duplicate_declarations_never_supply_bodies() {
    let source = "-- CREATE FUNCTION public.selected() AS $function$wrong$function$;\nCREATE TRIGGER first BEFORE INSERT ON public.example FOR EACH ROW EXECUTE FUNCTION public.selected();\nCREATE FUNCTION public.other() RETURNS void LANGUAGE sql AS $function$other$function$;\nCREATE OR REPLACE FUNCTION public.selected() RETURNS void LANGUAGE sql AS $function$exact$function$;\n";
    assert_eq!(
        declared_function_body(source, "selected", "$function$"),
        Some("exact")
    );
    assert_eq!(
        declared_function_body(source, "missing", "$function$"),
        None
    );
    let duplicate = format!(
        "{source}CREATE FUNCTION public.selected() RETURNS void LANGUAGE sql AS $function$duplicate$function$;\n"
    );
    assert_eq!(
        declared_function_body(&duplicate, "selected", "$function$"),
        None
    );
    assert_eq!(
        declared_function_body(
            "CREATE FUNCTION public.first() RETURNS void LANGUAGE sql AS $function$at-start$function$;",
            "first",
            "$function$"
        ),
        Some("at-start")
    );
}

#[test]
fn explicit_second_intent_native_body_routes_keep_exact_current_pins() {
    for (name, expected) in [
        (
            "hosted_runtime_native_schema_valid",
            "6fe7bf0ce4d4cb6f4113c45a2397502d99afafec4c4f026a9af6c37c5e610b4e",
        ),
        (
            "hosted_runtime_identity_ready",
            "7fda07320588b52036fe5002b3c4082f5fce7c19f57d9763ecda85beb02a343f",
        ),
        (
            "hosted_runtime_scope",
            "5af80385e9460db2d4381a082df2e6a1c63059b66019678518bf4133f5b5673f",
        ),
        (
            "payload_profile_writer_version",
            "887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6",
        ),
        (
            "payload_profile_writer_ready",
            "10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458",
        ),
    ] {
        let actual = Sha256::digest(body_for(name, 117).unwrap().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected, "{name}");
    }
}
