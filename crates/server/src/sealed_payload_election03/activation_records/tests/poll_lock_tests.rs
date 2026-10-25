// SPDX-License-Identifier: AGPL-3.0-only
//! Actual registered poll/proof ordering with unchanged original signatures.
use super::*;
use std::time::Duration;
use tokio_postgres::Client;

// The second waiter may be behind the poll's queued tuple lock. Accept only
// the known two-edge root wait chain; reject cycles or unrelated blockers.
async fn blocked_on(db: &Client, waiter: i32, holder: i32, queued_poll: Option<i32>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blockers: Vec<i32> = db.query_one(
                "SELECT pg_catalog.pg_blocking_pids($1)", &[&waiter],
            ).await.unwrap().get(0);
            assert!(blockers.iter().all(|pid| *pid == holder || Some(*pid) == queued_poll),
                "unexpected blocker or cycle in known root wait schedule");
            if !blockers.is_empty() {
                assert!(db.query_one(
                    "SELECT query LIKE '%sealed_manifest_authorities%' AND wait_event_type='Lock' AND wait_event IN ('transactionid','tuple') FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                    &[&waiter],
                ).await.unwrap().get::<_, bool>(0), "wait must be on the root acquisition");
                if let Some(poll) = queued_poll.filter(|pid| blockers.contains(pid)) {
                    let parent: Vec<i32> = db.query_one(
                        "SELECT pg_catalog.pg_blocking_pids($1)", &[&poll],
                    ).await.unwrap().get(0);
                    assert_eq!(parent, vec![holder], "queued poll must wait only on the known root holder");
                    assert!(db.query_one(
                        "SELECT query LIKE '%sealed_manifest_authorities%' AND wait_event_type='Lock' AND wait_event IN ('transactionid','tuple') FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                        &[&poll],
                    ).await.unwrap().get::<_, bool>(0));
                }
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("actual poll/proof waits on held root");
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; registered poll/proof root-before-account schedule"]
async fn registered_poll_waits_for_root_without_holding_account_and_original_proof_completes() {
    let mut c = Case::new().await;
    let account = c.principal.tenant.account_id();
    let lease = c.lease();
    let challenge = c.challenge.id;
    let observation = c.device_statement[134..255].to_vec();
    let signature = c.device_der.clone();
    let (mut poll, poll_driver) = c.db.runtime_peer().await;
    let (mut proof, proof_driver) = c.db.runtime_peer().await;
    let poll_pid: i32 = poll
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let proof_pid: i32 = proof
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let holder_pid: i32 =
        c.db.owner
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
    let holder = c.db.owner.transaction().await.unwrap();
    holder.query_one("SELECT account_id FROM public.sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE", &[&account]).await.unwrap();
    // No SMS candidate needs the sealed root; a root held elsewhere must not
    // turn an empty, otherwise authenticated SMS poll into a blocked poll.
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            run::next_challenge(&mut c.db.reader, lease, run::Purpose::Sms)
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
    let polling = tokio::spawn(async move {
        let result = run::next_challenge(&mut poll, lease, run::Purpose::Sealed).await;
        drop(poll);
        result
    });
    blocked_on(&c.db.reader, poll_pid, holder_pid, None).await;
    // This NOWAIT acquisition fails on the old inverted poll ordering. The
    // root holder can safely proceed to account before releasing either lock.
    holder
        .query_one(
            "SELECT id FROM public.accounts WHERE id=$1 FOR UPDATE NOWAIT",
            &[&account],
        )
        .await
        .unwrap();
    let proving = tokio::spawn(async move {
        let result = run::record_device_proof(
            &mut proof,
            lease,
            run::Purpose::Sealed,
            challenge,
            &observation,
            &signature,
        )
        .await;
        drop(proof);
        result
    });
    blocked_on(&c.db.reader, proof_pid, holder_pid, Some(poll_pid)).await;
    holder.rollback().await.unwrap();
    let (polled, proved) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(polling, proving)
    })
    .await
    .expect("ordered poll and original proof complete without deadlock");
    assert!(
        polled.unwrap().unwrap().is_none(),
        "original proof already retained"
    );
    assert!(proved.unwrap().unwrap());
    poll_driver.await.unwrap().unwrap();
    proof_driver.await.unwrap().unwrap();
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; poll rechecks actual lease after root wait"]
async fn registered_poll_refuses_a_lease_expired_while_waiting_for_root() {
    let mut c = Case::new().await;
    let account = c.principal.tenant.account_id();
    let lease = c.lease();
    let (mut poll, driver) = c.db.runtime_peer().await;
    let pid: i32 = poll
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let holder_pid: i32 =
        c.db.owner
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
    let holder = c.db.owner.transaction().await.unwrap();
    holder.query_one("SELECT account_id FROM public.sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE", &[&account]).await.unwrap();
    let polling = tokio::spawn(async move {
        let result = run::next_challenge(&mut poll, lease, run::Purpose::Sealed).await;
        drop(poll);
        result
    });
    blocked_on(&c.db.reader, pid, holder_pid, None).await;
    holder.execute("UPDATE public.device_sessions SET lease_until=clock_timestamp()-interval '1 second' WHERE account_id=$1 AND device_id=$2", &[&account, &c.device]).await.unwrap();
    holder.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), polling)
            .await
            .unwrap()
            .unwrap(),
        Err(crate::sealed_inbound::line_activation::LineActivationError::Unavailable)
    ));
    driver.await.unwrap().unwrap();
    c.db.finish().await;
}
