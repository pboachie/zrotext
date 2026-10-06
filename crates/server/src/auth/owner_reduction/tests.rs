// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::{self, TokenHasher};
use uuid::Uuid;

async fn owner() -> (
    crate::sealed_manifest_store::tests::Fixture,
    SessionPrincipal,
) {
    let f = crate::sealed_manifest_store::tests::Fixture::without_authority().await;
    let hasher = TokenHasher::new(crate::test_keys::key(92)).unwrap();
    let mut db = f.connect().await;
    let email = format!("contact-reduction-{}@example.test", Uuid::new_v4());
    let signup = auth::register(&mut db, &hasher, &email, "synthetic reduction password")
        .await
        .unwrap();
    assert!(
        auth::verify_email_with_password(
            &mut db,
            &hasher,
            &signup.verification_token,
            "synthetic reduction password"
        )
        .await
        .unwrap()
    );
    let credentials = auth::login(&db, &hasher, &email, "synthetic reduction password")
        .await
        .unwrap();
    let principal = auth::authenticate_session(&db, &hasher, &credentials.token)
        .await
        .unwrap();
    (f, principal)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; real registered owner and maintained schema"]
async fn held_ordinary_owner_needs_no_root_or_enabled_factor() {
    let (f, p) = owner().await;
    let mut db = f.connect().await;
    assert!(
        !db.query_one(
            "SELECT EXISTS(SELECT 1 FROM sealed_manifest_authorities WHERE account_id=$1)",
            &[&p.tenant.account_id()]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let tx = db.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await
        .unwrap();
    let fence = OwnerReductionFence::acquire(&tx, &p).await.unwrap();
    assert!(fence.final_check(0).await.unwrap() > 0);
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; sequential same-transaction authority changes"]
async fn final_ordinary_fence_refuses_lost_owner_session_and_regressed_clock() {
    let (f, p) = owner().await;
    let mut db = f.connect().await;
    for sql in [
        "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
        // Owner memberships cannot be marked revoked. Losing the row is a
        // schema-valid authority loss; final_check must still refuse it.
        "DELETE FROM memberships WHERE account_id=$1",
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE account_id=$1",
        "UPDATE sessions SET last_used_at=clock_timestamp()-interval '73 hours' WHERE account_id=$1",
        "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE account_id=$1",
    ] {
        let tx = db.transaction().await.unwrap();
        let fence = OwnerReductionFence::acquire(&tx, &p).await.unwrap();
        tx.execute(sql, &[&p.tenant.account_id()]).await.unwrap();
        assert!(fence.final_check(0).await.is_err());
        tx.rollback().await.unwrap();
    }
    let tx = db.transaction().await.unwrap();
    let fence = OwnerReductionFence::acquire(&tx, &p).await.unwrap();
    assert!(fence.final_check(i64::MAX).await.is_err());
    tx.rollback().await.unwrap();
    f.cleanup().await;
}
