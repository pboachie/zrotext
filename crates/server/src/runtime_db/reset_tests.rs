// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn shutdown_with_pending_reset(poll_reset: bool) {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let pool = ClassPool::new(1, false);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let client = acquire(&pool, &url).await.unwrap();
        client.query_one("SELECT 1", &[]).await.unwrap();
        if poll_reset {
            // Dropping this query future leaves its already queued statement
            // ahead of DISCARD ALL. The reset therefore remains pending.
            assert!(
                timeout(
                    Duration::from_millis(10),
                    client.batch_execute("SELECT pg_sleep(1)")
                )
                .await
                .is_err()
            );
        }
        drop(client);
        if poll_reset {
            tokio::task::yield_now().await;
        }
        assert_eq!(pool.resets_in_flight.load(Ordering::Acquire), 1);
    });
    // Abort the actual PooledClient reset, including one not polled at all.
    drop(runtime);
    assert_eq!(pool.resets_in_flight.load(Ordering::Acquire), 0);
    assert_eq!(pool.slots.available_permits(), 1);
}

#[test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated native fixture"]
fn runtime_shutdown_releases_unpolled_socket_reset() {
    shutdown_with_pending_reset(false);
}

#[test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated native fixture"]
fn runtime_shutdown_releases_polled_socket_reset() {
    shutdown_with_pending_reset(true);
}
