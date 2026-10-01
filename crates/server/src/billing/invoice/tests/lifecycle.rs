// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn live_owner_exports_populated_invoice_planes_and_atomic_erasure_removes_all_four() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.send("exportable").await.unwrap();
    let exported = super::super::lifecycle::export(&mut case.db, &case.owner, None, None, None)
        .await
        .unwrap();
    assert!(exported.entitlement.is_some());
    assert_eq!(exported.periods.len(), 1);
    assert_eq!(exported.usage.len(), 1);
    assert_eq!(exported.audit.len(), 1);
    let tx = case.db.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &case.owner)
        .await
        .unwrap();
    let counts = super::super::lifecycle::erase(&tx, case.account)
        .await
        .unwrap();
    assert_eq!(counts.len(), 4);
    assert!(counts.iter().all(|(_, n)| *n == 1));
    tx.rollback().await.unwrap();
    assert_eq!(
        super::super::lifecycle::export(&mut case.db, &case.owner, None, None, None)
            .await
            .unwrap()
            .usage
            .len(),
        1
    );
    let tx = case.db.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &case.owner)
        .await
        .unwrap();
    super::super::lifecycle::erase(&tx, case.account)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let erased = super::super::lifecycle::export(&mut case.db, &case.owner, None, None, None)
        .await
        .unwrap();
    assert!(erased.entitlement.is_none());
    assert!(erased.periods.is_empty() && erased.usage.is_empty() && erased.audit.is_empty());
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses a unique disposable schema"]
async fn invoice_export_rechecks_live_owner_and_retention_preserves_unknown_liabilities() {
    let mut case = Case::new().await;
    let paid = case.observation("active", "paid", "subscription_cycle");
    case.observe(&paid).await.unwrap();
    case.send("unknown").await.unwrap();
    case.db
        .execute(
            "UPDATE billing_invoice_audit SET recorded_at=clock_timestamp()-interval '181 days'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        super::super::lifecycle::prune(&case.db, 1).await.unwrap(),
        1
    );
    let exported = super::super::lifecycle::export(&mut case.db, &case.owner, None, None, None)
        .await
        .unwrap();
    assert_eq!(exported.usage.len(), 1);
    assert_eq!(exported.periods.len(), 1);
    assert!(exported.audit.is_empty());
    case.db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&case.owner.session_id],
        )
        .await
        .unwrap();
    assert!(
        super::super::lifecycle::export(&mut case.db, &case.owner, None, None, None)
            .await
            .is_err()
    );
    case.cleanup().await;
}
