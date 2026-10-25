// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::billing::hosted::namespace::{Gate, Marker, Mode, Namespace, ProviderIdentity};
use std::{future::Future, pin::Pin, task::Poll};

async fn assert_pending_once(future: Pin<&mut impl Future<Output = ()>>) {
    let mut future = future;
    let polled = std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await;
    assert!(polled.is_pending(), "fixture work has not settled yet");
}

#[tokio::test]
async fn settling_waits_for_nonreusable_driver_completion_only_for_its_exact_url() {
    let first: Arc<str> = format!("fixture-first-{}", uuid::Uuid::new_v4()).into();
    let second: Arc<str> = format!("fixture-second-{}", uuid::Uuid::new_v4()).into();
    let first_driver = Activity::driver(first.clone());
    let second_driver = Activity::driver(second.clone());
    let first_reset = Activity::reset(first.clone());
    drop(first_reset);
    // A reset's task can finish before its driver drains queued responses.
    assert_eq!(ACTIVE.lock().unwrap().get(&first).unwrap().resets, 0);
    let settled = settle_fixture_resets(&first);
    tokio::pin!(settled);
    assert_pending_once(settled.as_mut()).await;
    drop(first_driver);
    settled.await;
    assert_eq!(ACTIVE.lock().unwrap().get(&second).unwrap().drivers, 1);
    drop(second_driver);
}

async fn hosted_fixture() -> (crate::test_database::Fixture, HostedBinding) {
    let fixture = crate::test_database::Fixture::for_store("ZT_AUTH_TEST_DATABASE_URL").await;
    let id = uuid::Uuid::new_v4();
    let namespace = Namespace::new(id.into_bytes(), Mode::Test, "acct_fixture").unwrap();
    let marker = Marker {
        namespace: namespace.clone(),
        policy_revision: 1,
        enabled: true,
    };
    let gate = Gate::verify(
        true,
        &namespace,
        1,
        &marker,
        &ProviderIdentity {
            mode: Mode::Test,
            provider_account: "acct_fixture".into(),
        },
    )
    .unwrap();
    let key = [7u8; 32];
    fixture.owner.execute("INSERT INTO public.hosted_billing_namespaces(namespace_id,mode,provider_account,policy_revision,enabled,old_binary_fenced) VALUES($1,'test','acct_fixture',1,true,true)", &[&id]).await.unwrap();
    fixture
        .owner
        .execute(
            "INSERT INTO public.hosted_runtime_secrets VALUES($1,$2)",
            &[&id, &&key[..]],
        )
        .await
        .unwrap();
    let binding = HostedBinding::new(&gate, key).unwrap();
    register_hosted(&fixture.runtime_url, binding.clone()).unwrap();
    (fixture, binding)
}

// Inspect only non-secret row metadata. Never select or export key bytes.
#[derive(Debug, Eq, PartialEq)]
struct ConfigurationSnapshot {
    revision: i64,
    secret_xmin: String,
    secret_rows: i64,
    review_required: bool,
}

async fn configuration_snapshot(
    fixture: &crate::test_database::Fixture,
    binding: &HostedBinding,
) -> ConfigurationSnapshot {
    let row = fixture.owner.query_one(
        "SELECT g.revision,s.xmin::text,(SELECT count(*) FROM public.hosted_runtime_secrets),n.review_required FROM public.hosted_runtime_secrets s JOIN public.hosted_billing_namespaces n USING(namespace_id) CROSS JOIN public.payload_profile_writer_global_fences g WHERE s.namespace_id=$1 AND g.operation_class='hosted_configuration'",
        &[&binding.namespace],
    ).await.unwrap();
    ConfigurationSnapshot {
        revision: row.get(0),
        secret_xmin: row.get(1),
        secret_rows: row.get(2),
        review_required: row.get(3),
    }
}

async fn assert_configuration_write_completed(
    fixture: &crate::test_database::Fixture,
    binding: &HostedBinding,
    before: &ConfigurationSnapshot,
) {
    let after = configuration_snapshot(fixture, binding).await;
    assert_eq!(after.revision, before.revision + 1);
    assert_ne!(after.secret_xmin, before.secret_xmin);
    assert_eq!(after.secret_rows, before.secret_rows);
    assert_eq!(after.review_required, before.review_required);
}

async fn assert_native(client: &mut PooledClient, binding: &HostedBinding) {
    let tx = client.native_transaction().await.unwrap();
    assert!(
        tx.query_one(
            "SELECT public.hosted_runtime_verified($1,$2)",
            &[&binding.namespace, &binding.revision],
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; disposable current public databases"]
async fn settling_resets_preserves_reusable_backends_and_native_bindings() {
    let (first, first_binding) = hosted_fixture().await;
    let (second, second_binding) = hosted_fixture().await;
    let mut first_client = connect(&first.runtime_url).await.unwrap();
    let mut second_client = connect(&second.runtime_url).await.unwrap();
    let first_pid: i32 = first_client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let second_pid: i32 = second_client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    assert_native(&mut first_client, &first_binding).await;
    assert_native(&mut second_client, &second_binding).await;
    drop(first_client);
    drop(second_client);
    settle_fixture_resets(&first.runtime_url).await;
    settle_fixture_resets(&second.runtime_url).await;
    assert!(HOSTED_BINDINGS.lock().unwrap().get(&first.runtime_url) == Some(&first_binding));
    assert!(HOSTED_BINDINGS.lock().unwrap().get(&second.runtime_url) == Some(&second_binding));
    let mut first_client = connect(&first.runtime_url).await.unwrap();
    let mut second_client = connect(&second.runtime_url).await.unwrap();
    assert_eq!(
        first_client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        first_pid
    );
    assert_eq!(
        second_client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        second_pid
    );
    assert_native(&mut first_client, &first_binding).await;
    assert_native(&mut second_client, &second_binding).await;
    drop(first_client);
    drop(second_client);
    first.finish().await;
    second.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; witnessed native rollback and global writer fence"]
async fn pending_native_rollback_refuses_admin_mutation_until_its_fixture_settles() {
    let (fixture, binding) = hosted_fixture().await;
    let owner_pid: i32 = fixture
        .owner
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let before = configuration_snapshot(&fixture, &binding).await;
    assert_eq!(before.secret_rows, 1);
    // The two-key test lock is distinct from the native one-key fences.
    fixture
        .owner
        .batch_execute("SELECT pg_advisory_lock(7283,1)")
        .await
        .unwrap();
    let mut client = connect(&fixture.runtime_url).await.unwrap();
    let tx = client.native_transaction().await.unwrap();
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    {
        let blocked = tx.query_one("SELECT pg_advisory_xact_lock(7283,1)", &[]);
        tokio::pin!(blocked);
        let witness = async {
            loop {
                let waiting: bool = fixture.owner.query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted) AND $2=ANY(pg_blocking_pids($1))",
                    &[&pid, &owner_pid],
                ).await.unwrap().get(0);
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        };
        tokio::select! {
            result = &mut blocked => panic!("query completed before its lock-wait witness: {result:?}"),
            result = timeout(Duration::from_secs(2), witness) => result.expect("native query did not reach its witnessed test lock"),
        }
    }
    // Drop queues ROLLBACK; the real blocked query prevents it from reaching
    // PostgreSQL yet. PooledClient then queues its ordinary DISCARD ALL reset.
    drop(tx);
    drop(client);
    assert_eq!(
        ACTIVE
            .lock()
            .unwrap()
            .get(fixture.runtime_url.as_str())
            .unwrap()
            .resets,
        1
    );
    {
        let settled = settle_fixture_resets(&fixture.runtime_url);
        tokio::pin!(settled);
        assert_pending_once(settled.as_mut()).await;
        // The native entry holds the namespace tuple FOR SHARE. Updating that
        // tuple would wait before reaching the global trigger (and create a
        // deadlock with the test blocker). This no-op secret-row write reaches
        // the SAME stock hosted_configuration guard without that tuple wait.
        let error = fixture
            .owner
            .execute(
                "UPDATE public.hosted_runtime_secrets SET runtime_key=runtime_key WHERE namespace_id=$1",
                &[&binding.namespace],
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
        );
        assert_eq!(
            error.as_db_error().unwrap().message(),
            "global authority writer busy"
        );
        assert!(
            fixture
                .owner
                .query_one("SELECT pg_advisory_unlock(7283,1)", &[])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        settled.await;
    }
    let unchanged = fixture.owner.query_one(
        "SELECT n.review_required,g.revision FROM hosted_billing_namespaces n CROSS JOIN payload_profile_writer_global_fences g WHERE n.namespace_id=$1 AND g.operation_class='hosted_configuration'",
        &[&binding.namespace],
    ).await.unwrap();
    assert!(!unchanged.get::<_, bool>(0));
    assert_eq!(unchanged.get::<_, i64>(1), before.revision);
    assert_eq!(configuration_snapshot(&fixture, &binding).await, before);
    assert_eq!(
        fixture
            .owner
            .execute(
                "UPDATE public.hosted_runtime_secrets SET runtime_key=runtime_key WHERE namespace_id=$1",
                &[&binding.namespace],
            )
            .await
            .unwrap(),
        1
    );
    assert_configuration_write_completed(&fixture, &binding, &before).await;
    assert!(HOSTED_BINDINGS.lock().unwrap().get(&fixture.runtime_url) == Some(&binding));
    let mut client = connect(&fixture.runtime_url).await.unwrap();
    assert_native(&mut client, &binding).await;
    drop(client);
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE; actual reset timeout and queued native rollback"]
async fn settling_waits_for_native_driver_after_the_real_reset_deadline() {
    let (fixture, binding) = hosted_fixture().await;
    let before = configuration_snapshot(&fixture, &binding).await;
    assert_eq!(before.secret_rows, 1);
    let mut client = connect(&fixture.runtime_url).await.unwrap();
    let tx = client.native_transaction().await.unwrap();
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    // COPY's real protocol input is the blocker: it has no borrowed Client and
    // remains pending until this sink is dropped. No rows are sent. Inherited
    // statement/lock deadlines and the production reset deadline are unchanged.
    let input = tx
        .copy_in::<_, &'static [u8]>("COPY public.messages (id,account_id) FROM STDIN")
        .await
        .unwrap();
    assert!(fixture.owner.query_one(
        "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation='public.messages'::regclass AND mode='RowExclusiveLock' AND granted)",
        &[&pid],
    ).await.unwrap().get::<_, bool>(0));
    drop(tx);
    let started = Instant::now();
    drop(client);
    wait_for(&fixture.runtime_url, |counts| counts.resets == 0).await;
    assert!(
        started.elapsed() >= RESET_DEADLINE,
        "the real reset must time out, not finish successfully"
    );
    assert_eq!(
        ACTIVE
            .lock()
            .unwrap()
            .get(fixture.runtime_url.as_str())
            .unwrap()
            .drivers,
        1
    );
    assert_eq!(reusable_fixture_drivers(&fixture.runtime_url), 0);
    {
        let settled = settle_fixture_resets(&fixture.runtime_url);
        tokio::pin!(settled);
        assert_pending_once(settled.as_mut()).await;
        // The native entry holds the namespace tuple FOR SHARE. Updating that
        // tuple would wait before reaching the global trigger (and create a
        // deadlock with the test blocker). This no-op secret-row write reaches
        // the SAME stock hosted_configuration guard without that tuple wait.
        let error = fixture
            .owner
            .execute(
                "UPDATE public.hosted_runtime_secrets SET runtime_key=runtime_key WHERE namespace_id=$1",
                &[&binding.namespace],
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
        );
        assert_eq!(
            error.as_db_error().unwrap().message(),
            "global authority writer busy"
        );
        // The sink sends CopyFail, then the queued ROLLBACK can release the
        // genuine native fence and the last Client's driver can terminate.
        drop(input);
        settled.await;
    }
    assert!(
        !ACTIVE
            .lock()
            .unwrap()
            .contains_key(fixture.runtime_url.as_str())
    );
    assert_eq!(
        fixture
            .owner
            .query_one("SELECT count(*) FROM public.messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(configuration_snapshot(&fixture, &binding).await, before);
    assert_eq!(
        fixture
            .owner
            .execute(
                "UPDATE public.hosted_runtime_secrets SET runtime_key=runtime_key WHERE namespace_id=$1",
                &[&binding.namespace],
            )
            .await
            .unwrap(),
        1
    );
    assert_configuration_write_completed(&fixture, &binding, &before).await;
    assert!(HOSTED_BINDINGS.lock().unwrap().get(&fixture.runtime_url) == Some(&binding));
    let mut client = connect(&fixture.runtime_url).await.unwrap();
    assert_ne!(
        client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        pid,
        "a reset-timed-out backend must not be reused"
    );
    assert_native(&mut client, &binding).await;
    drop(client);
    fixture.finish().await;
}
