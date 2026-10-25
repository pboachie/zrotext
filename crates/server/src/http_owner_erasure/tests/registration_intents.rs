// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::auth::registration_intent::{self, Credentials};

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; full numbered schema and authenticated erasure"]
async fn erasure_counts_registration_intents_and_preserves_another_accounts_pending_proof() {
    current_case(async |db, _admin, database_url| {
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(26)).unwrap());
        let a_proof = Credentials::random();
        let a = crate::auth::register_with_intent(
            db,
            &hasher,
            "erase-intent-a@example.test",
            &crate::test_keys::password(1),
            Some(&a_proof),
        )
        .await
        .unwrap();
        let b_proof = Credentials::random();
        let b = crate::auth::register_with_intent(
            db,
            &hasher,
            "keep-intent-b@example.test",
            &crate::test_keys::password(2),
            Some(&b_proof),
        )
        .await
        .unwrap();
        assert!(
            registration_intent::verify(db, &hasher, &a_proof, &a.verification_token)
                .await
                .unwrap()
        );
        let session = login(
            &*db,
            &hasher,
            "erase-intent-a@example.test",
            &crate::test_keys::password(1),
        )
        .await
        .unwrap();
        let app = router(OwnerErasureState {
            database_url: database_url.to_owned(),
            auth_hasher: hasher.clone(),
            canonical_origin: ORIGIN.to_owned(),
            mfa_cipher: None,
        });
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
        assert_eq!(deleted_count(&report, "registration_browser_intents"), 1);
        assert_eq!(deleted_count(&report, "email_verifications"), 1);
        assert_eq!(
            db.query_one(
                "SELECT count(*) FROM registration_browser_intents WHERE account_id=$1",
                &[&a.account_id],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert_eq!(
            db.query_one(
                "SELECT count(*) FROM registration_browser_intents i \
                 JOIN email_verifications v ON v.id=i.verification_id \
                 JOIN memberships m ON (m.account_id,m.user_id)=(i.account_id,i.user_id) \
                 WHERE i.account_id=$1 AND i.consumed_at IS NULL AND v.used_at IS NULL",
                &[&b.account_id],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        assert!(
            !registration_intent::verify(db, &hasher, &a_proof, &a.verification_token)
                .await
                .unwrap()
        );
        assert!(
            registration_intent::verify(db, &hasher, &b_proof, &b.verification_token)
                .await
                .unwrap()
        );
    })
    .await;
}
