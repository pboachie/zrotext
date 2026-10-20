// SPDX-License-Identifier: AGPL-3.0-only
//! Actual ordinary owner/runtime, original HMAC and native transaction entry.
use super::test_database::Fixture;
use crate::{
    billing::hosted::namespace::{Gate, Marker, Mode, Namespace, ProviderIdentity},
    runtime_db,
};
use std::time::Duration;
use tokio_postgres::{Client, IsolationLevel};
use uuid::Uuid;
use zrotext_delivery_store::{DeliveryStore, StoreError};

fn binding(namespace: Uuid, key: [u8; 32]) -> runtime_db::HostedBinding {
    let namespace =
        Namespace::new(namespace.into_bytes(), Mode::Test, "acct_nativefixture").unwrap();
    let marker = Marker {
        namespace: namespace.clone(),
        policy_revision: 1,
        enabled: true,
    };
    let provider = ProviderIdentity {
        mode: Mode::Test,
        provider_account: "acct_nativefixture".into(),
    };
    let gate = Gate::verify(true, &namespace, 1, &marker, &provider).unwrap();
    runtime_db::HostedBinding::new(&gate, key).unwrap()
}
fn runtime_url(f: &Fixture) -> String {
    let mut url =
        url::Url::parse(&std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable URL"))
            .unwrap();
    url.set_username(f.reader_config.get_user().unwrap())
        .unwrap();
    url.set_password(Some(
        std::str::from_utf8(f.reader_config.get_password().unwrap()).unwrap(),
    ))
    .unwrap();
    url.set_path(f.reader_config.get_dbname().unwrap());
    // Replacing these candidate connection settings supplies no native proof.
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(name, _)| name != "options")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs(pairs)
        .append_pair("options", "-csearch_path=pg_catalog,public");
    url.into()
}
async fn seed(f: &Fixture, namespace: Uuid, key: &[u8; 32]) {
    f.owner.execute("INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_nativefixture',1,true,true)", &[&namespace]).await.unwrap();
    f.owner
        .execute(
            "INSERT INTO public.hosted_runtime_secrets(namespace_id,runtime_key) VALUES($1,$2)",
            &[&namespace, &&key[..]],
        )
        .await
        .unwrap();
}
async fn verified(db: &(impl tokio_postgres::GenericClient + Sync), namespace: Uuid) -> bool {
    db.query_one("SELECT public.hosted_runtime_verified($1,1)", &[&namespace])
        .await
        .unwrap()
        .get(0)
}
async fn close(db: runtime_db::PooledClient, owner: &Client) {
    let pid: i32 = db
        .query_one("SELECT pg_catalog.pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    drop(db);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let closed: bool = owner
                .query_one(
                    "SELECT NOT EXISTS(SELECT FROM pg_catalog.pg_stat_activity WHERE pid=$1)",
                    &[&pid],
                )
                .await
                .unwrap()
                .get(0);
            if closed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned pool driver closes normally");
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full public ordinary-runtime fixture"]
async fn actual_initialized_pool_and_store_enter_each_transaction_without_renewal() {
    let f = Fixture::runtime().await;
    let namespace = Uuid::new_v4();
    let key = [37; 32];
    seed(&f, namespace, &key).await;
    let url = runtime_url(&f);
    runtime_db::register_hosted(&url, binding(namespace, key)).unwrap();
    let mut db = runtime_db::fixture_connection(&url).await.unwrap();
    let pid: i32 = db
        .query_one("SELECT pg_catalog.pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let original: i64 = f.owner.query_one("SELECT floor(extract(epoch FROM expires_at)*1000)::bigint FROM public.hosted_runtime_sessions WHERE backend_pid=$1", &[&pid]).await.unwrap().get(0);
    assert!(
        !verified(&*db, namespace).await,
        "checkout is not business transaction entry"
    );
    // The real Store owns this BEGIN. A copied namespace alone does not
    // authenticate it; this SAME client completed the actual HMAC handshake.
    assert!(
        !db.delivery_store()
            .cancel(Uuid::new_v4(), Uuid::new_v4())
            .await
            .unwrap()
    );
    let entries: i64 = f
        .owner
        .query_one(
            "SELECT count(*) FROM public.hosted_runtime_entries WHERE backend_pid=$1",
            &[&pid],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        entries, 1,
        "Store committed its own actual native-xid entry"
    );
    let tx = db.native_transaction().await.unwrap();
    assert!(verified(&tx, namespace).await);
    let first: i64 = tx
        .query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
        .await
        .unwrap()
        .get(0);
    assert_eq!(first, original);
    tx.rollback().await.unwrap();
    let raw = db.transaction().await.unwrap();
    assert!(
        !verified(&raw, namespace).await,
        "next transaction cannot reuse an entry"
    );
    raw.rollback().await.unwrap();
    let tx = db
        .native_build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .unwrap();
    assert!(verified(&tx, namespace).await);
    assert_eq!(
        tx.query_one("SELECT public.hosted_runtime_enter($1,1)", &[&namespace])
            .await
            .unwrap()
            .get::<_, i64>(0),
        original
    );
    tx.commit().await.unwrap();
    // Operator session path is not an installation or identity selector.
    // The native business transaction pins the verified public installation
    // and explicitly places the implicit temporary namespace last.
    db.batch_execute("SET search_path TO pg_temp,pg_catalog")
        .await
        .unwrap();
    let tx = db.native_transaction().await.unwrap();
    assert_eq!(
        tx.query_one("SHOW search_path", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pg_catalog, public, pg_temp"
    );
    assert!(verified(&tx, namespace).await);
    tx.rollback().await.unwrap();
    // Native identity INSERT is required even for data-read-only fetch work;
    // an explicitly SQL READ ONLY transaction must fail rather than skip it.
    assert!(
        db.native_build_transaction()
            .read_only(true)
            .start()
            .await
            .is_err()
    );
    close(db, &f.owner).await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full public ordinary-runtime fixture"]
async fn absent_candidate_raw_erasure_wrong_hmac_and_disabled_namespace_refuse() {
    let mut f = Fixture::runtime().await;
    let namespace = Uuid::new_v4();
    let key = [53; 32];
    seed(&f, namespace, &key).await;
    let url = runtime_url(&f);
    let mut uninitialized = runtime_db::fixture_connection(&url).await.unwrap();
    assert!(uninitialized.native_transaction().await.is_err());
    assert!(matches!(
        uninitialized
            .delivery_store()
            .cancel(Uuid::new_v4(), Uuid::new_v4())
            .await,
        Err(StoreError::RuntimeIdentityUnavailable)
    ));
    // Even a matching public candidate does not bind this other backend.
    // Native SQL must reject the missing actual HMAC session on THIS client.
    let candidate = zrotext_delivery_store::HostedBackendCandidate::new(namespace, 1).unwrap();
    assert!(
        uninitialized
            .delivery_store()
            .with_hosted_backend(candidate)
            .cancel(Uuid::new_v4(), Uuid::new_v4())
            .await
            .is_err()
    );
    close(uninitialized, &f.owner).await;
    assert!(
        runtime_db::verify_hosted_connection(&f.reader, &binding(namespace, [54; 32]))
            .await
            .is_err()
    );
    runtime_db::verify_hosted_connection(&f.reader, &binding(namespace, key))
        .await
        .unwrap();
    // Static raw Client erasure retains no initialized configuration handoff.
    // It must not infer manual mode from the omitted candidate, even though
    // this particular backend genuinely performed a separate HMAC bind.
    assert!(runtime_db::begin_native(&mut f.reader).await.is_err());
    assert!(matches!(
        DeliveryStore::new(&mut f.reader)
            .cancel(Uuid::new_v4(), Uuid::new_v4())
            .await,
        Err(StoreError::RuntimeIdentityUnavailable)
    ));
    runtime_db::register_hosted(&url, binding(namespace, key)).unwrap();
    let mut db = runtime_db::fixture_connection(&url).await.unwrap();
    f.owner
        .execute(
            "UPDATE public.hosted_billing_namespaces SET enabled=false WHERE namespace_id=$1",
            &[&namespace],
        )
        .await
        .unwrap();
    assert!(db.native_transaction().await.is_err());
    close(db, &f.owner).await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full public ordinary-runtime fixture"]
async fn full_native_schema_with_no_namespace_preserves_manual_store_transactions() {
    let f = Fixture::runtime().await;
    let url = runtime_url(&f);
    let mut db = runtime_db::fixture_connection(&url).await.unwrap();
    let tx = db.native_transaction().await.unwrap();
    assert_eq!(
        tx.query_one("SELECT count(*) FROM public.hosted_billing_namespaces", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    tx.commit().await.unwrap();
    assert!(
        !db.delivery_store()
            .cancel(Uuid::new_v4(), Uuid::new_v4())
            .await
            .unwrap()
    );
    close(db, &f.owner).await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full public ordinary-runtime fixture"]
async fn manual_empty_namespace_is_fenced_through_commit_in_each_supported_isolation() {
    for isolation in [
        IsolationLevel::ReadCommitted,
        IsolationLevel::RepeatableRead,
        IsolationLevel::Serializable,
    ] {
        let mut f = Fixture::runtime().await;
        let url = runtime_url(&f);
        let mut db = runtime_db::fixture_connection(&url).await.unwrap();
        let manual = db
            .native_build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        let operator = f.owner.transaction().await.unwrap();
        operator
            .batch_execute("SET LOCAL lock_timeout='100ms'")
            .await
            .unwrap();
        let namespace = Uuid::new_v4();
        let error = operator.execute("INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_nativefixture',1,true,true)", &[&namespace]).await.expect_err("actual namespace transition conflicts with held manual absence fence");
        assert!(
            error
                .code()
                .is_some_and(|code| matches!(code.code(), "55P03" | "40001"))
        );
        operator.rollback().await.unwrap();
        manual.commit().await.unwrap();
        // The real operator operation can proceed after the manual COMMIT;
        // it was a lock conflict, not an invalid namespace fixture.
        f.owner.execute("INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_nativefixture',1,true,true)", &[&namespace]).await.unwrap();
        assert!(
            db.native_transaction().await.is_err(),
            "newly scoped database cannot use missing candidate"
        );
        close(db, &f.owner).await;
        f.finish().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full public ordinary-runtime fixture"]
async fn old_repeatable_snapshot_cannot_enter_manual_after_namespace_transition() {
    for isolation in [IsolationLevel::RepeatableRead, IsolationLevel::Serializable] {
        let f = Fixture::runtime().await;
        let url = runtime_url(&f);
        let mut db = runtime_db::fixture_connection(&url).await.unwrap();
        // Deliberately bypass native entry only to establish the negative
        // old snapshot. Production begins with native_build_transaction.
        let raw = db
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        assert_eq!(
            raw.query_one("SELECT count(*) FROM public.hosted_billing_namespaces", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        let namespace = Uuid::new_v4();
        f.owner.execute("INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_nativefixture',1,true,true)", &[&namespace]).await.unwrap();
        let failure = zrotext_delivery_store::enter_hosted_transaction(&raw, None)
            .await
            .expect_err("actual stable tuple version rejects stale absence snapshot");
        assert!(
            matches!(failure, StoreError::Database(ref error) if error.code().is_some_and(|code| code.code()=="40001"))
        );
        raw.rollback().await.unwrap();
        close(db, &f.owner).await;
        f.finish().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full public ordinary-runtime erasure entry"]
async fn actual_erasure_begin_enters_hosted_before_billing_and_preserves_final_owner_fence() {
    use crate::auth::{self, TokenHasher, account};

    let mut f = Fixture::runtime().await;
    let hasher = TokenHasher::new(crate::test_keys::key(181)).unwrap();
    let password = crate::test_keys::password(181);
    let signup = auth::register(
        &mut f.owner,
        &hasher,
        "native-erasure@example.test",
        &password,
    )
    .await
    .unwrap();
    auth::verify_email(&mut f.owner, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let credentials = auth::login(&f.reader, &hasher, "native-erasure@example.test", &password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&f.reader, &hasher, &credentials.token)
        .await
        .unwrap();
    let verified_hash = account::verify_current_password(&f.reader, &principal, &password)
        .await
        .unwrap();
    let namespace = Uuid::new_v4();
    let key = [71; 32];
    seed(&f, namespace, &key).await;
    let url = runtime_url(&f);
    runtime_db::register_hosted(&url, binding(namespace, key)).unwrap();
    let mut db = runtime_db::fixture_connection(&url).await.unwrap();

    // This is the SAME production BEGIN used by the erasure handler, not a
    // caller-selected native witness or a test replacement of the SQL helper.
    let tx = crate::http_owner_erasure::begin_erasure_transaction(&mut db)
        .await
        .unwrap();
    assert!(verified(&tx, namespace).await);
    let _admission = zrotext_delivery_store::sealed::lock_account(&tx, signup.account_id, false)
        .await
        .unwrap();
    assert!(matches!(
        account::fence_owner_mutation(&tx, None, &hasher, &principal, &verified_hash, None)
            .await
            .unwrap(),
        account::OwnerMutationFence::Cleared
    ));
    tx.rollback().await.unwrap();

    // A genuine initialized backend and the unchanged protected billing lock
    // cannot make a revoked original owner session authorize destruction.
    f.owner
        .execute(
            "UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&principal.session_id],
        )
        .await
        .unwrap();
    let tx = crate::http_owner_erasure::begin_erasure_transaction(&mut db)
        .await
        .unwrap();
    assert!(verified(&tx, namespace).await);
    let _admission = zrotext_delivery_store::sealed::lock_account(&tx, signup.account_id, false)
        .await
        .unwrap();
    assert!(matches!(
        account::fence_owner_mutation(&tx, None, &hasher, &principal, &verified_hash, None).await,
        Err(auth::AuthError::Unauthorized)
    ));
    tx.rollback().await.unwrap();
    assert_eq!(
        f.owner
            .query_one(
                "SELECT count(*) FROM public.accounts WHERE id=$1",
                &[&signup.account_id],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    // Whole HTTP erasure still has its stock operator-only blocker ACL. This
    // proves entry/billing/final-owner composition, not successful deletion.
    close(db, &f.owner).await;
    f.finish().await;
}
