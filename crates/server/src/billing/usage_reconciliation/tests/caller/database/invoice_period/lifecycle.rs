// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; bounded live-owner takeout and atomic erase"]
async fn invoice_observations_export_all_pages_prune_only_old_evidence_and_erase_atomically() {
    let mut f = invoice_fixture().await;
    let hasher = crate::auth::TokenHasher::new(crate::test_keys::key(91)).unwrap();
    let password = crate::test_keys::password(91);
    let signup = crate::auth::register(
        &mut f.db,
        &hasher,
        "observation-owner@example.test",
        &password,
    )
    .await
    .unwrap();
    crate::auth::verify_email(&mut f.db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let session = crate::auth::login(&f.db, &hasher, "observation-owner@example.test", &password)
        .await
        .unwrap();
    let owner = crate::auth::authenticate_session(&f.db, &hasher, &session.token)
        .await
        .unwrap();
    f.account = signup.account_id;
    f.device = Uuid::new_v4();
    f.db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
        &[&f.device, &f.account],
    )
    .await
    .unwrap();
    let period = anchored(&f).await;
    let (worker, server) = tls(responses(1)).await;
    worker
        .reconcile_invoice_period(&mut f.db, f.account, period, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(server.await.unwrap().len(), 6);
    let before = authority_snapshot(&f.db, f.account).await;
    // Explicit historical fixture rows, not weakening the UPDATE-immutable gate.
    for index in 1..=21i32 {
        f.db.execute("INSERT INTO billing_invoice_usage_observations SELECT account_id,$1,period_id,policy_version,identity_digest,snapshot_digest,finalized_units,acknowledged_units,pending_units,review_units,open_units,provider_units,invoice_units,state,CASE WHEN $2=1 THEN clock_timestamp()-interval '181 days' ELSE clock_timestamp() END FROM billing_invoice_usage_observations WHERE account_id=$3 LIMIT 1",&[&Uuid::new_v4(),&index,&f.account]).await.unwrap();
    }
    assert_eq!(
        crate::billing::usage_reconciliation::lifecycle::prune(&f.db, 1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(authority_snapshot(&f.db, f.account).await, before);
    let first = crate::billing::usage_reconciliation::lifecycle::export(&mut f.db, &owner, None)
        .await
        .unwrap();
    assert_eq!(first.observations.len(), 20);
    assert!(first.next.is_some());
    let second =
        crate::billing::usage_reconciliation::lifecycle::export(&mut f.db, &owner, first.next)
            .await
            .unwrap();
    assert_eq!(second.observations.len(), 1);
    assert!(second.next.is_none());
    assert!(
        crate::billing::usage_reconciliation::lifecycle::export(
            &mut f.db,
            &owner,
            Some(Uuid::new_v4())
        )
        .await
        .is_err()
    );
    let tx = f.db.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &owner)
        .await
        .unwrap();
    assert_eq!(
        crate::billing::usage_reconciliation::lifecycle::erase(&tx, f.account)
            .await
            .unwrap()[0]
            .1,
        21
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        crate::billing::usage_reconciliation::lifecycle::export(&mut f.db, &owner, None)
            .await
            .unwrap()
            .observations
            .len(),
        20
    );
    let tx = f.db.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &owner)
        .await
        .unwrap();
    crate::billing::usage_reconciliation::lifecycle::erase(&tx, f.account)
        .await
        .unwrap();
    crate::billing::invoice::lifecycle::erase(&tx, f.account)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        crate::billing::usage_reconciliation::lifecycle::export(&mut f.db, &owner, None)
            .await
            .unwrap()
            .observations
            .is_empty()
    );
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    assert!(
        crate::billing::usage_reconciliation::lifecycle::export(&mut f.db, &owner, None)
            .await
            .is_err()
    );
    f.cleanup().await;
}
