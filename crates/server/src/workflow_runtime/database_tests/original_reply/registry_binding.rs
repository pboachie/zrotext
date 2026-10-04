// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; exact selected-reader workflow binding"]
async fn selected_workflow_grant_requires_exact_original_authority_and_replacement_cannot_revive_it()
 {
    let mut f = OriginalCase::new().await;
    f.case.request.permissions =
        Permissions::new(&[Operation::Propose, Operation::ContextContent]).unwrap();
    f.case.request.content_envelope = Some(f.case.projection().await);
    f.case.fresh_factor().await;
    assert!(matches!(
        f.case.issue().await,
        Err(auth::AuthError::Forbidden)
    ));
    let original = f.issue().await;
    f.case.request.original_grant_id = Some(Uuid::new_v4());
    f.case.fresh_factor().await;
    assert!(matches!(
        f.case.issue().await,
        Err(auth::AuthError::Forbidden)
    ));
    f.bind_workflow_request(original.grant_id).await;
    let allowed_expiry = f.case.request.expires_ms;
    f.case.request.expires_ms = allowed_expiry + 1;
    f.case.fresh_factor().await;
    assert!(matches!(
        f.case.issue().await,
        Err(auth::AuthError::Forbidden)
    ));
    f.case.request.expires_ms = allowed_expiry;
    // The same genuine recovery factor remains usable: refusal preceded MFA.
    let output = f.case.issue().await.unwrap();
    let principal = authenticate(&f.case.f.db, &f.case.hasher, &output.token)
        .await
        .unwrap();
    let descriptor = f.case.descriptor().await;
    let proposed = propose_action(
        &mut f.case.f.connect().await,
        &principal,
        Uuid::new_v4(),
        descriptor,
    )
    .await
    .unwrap();
    assert!(
        f.case
            .f
            .db
            .query_one(
                "SELECT workflow_integration_grant_current($1,$2,$3,8)",
                &[&f.case.f.account, &output.grant_id, &proposed.key.action_id],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let stored: Uuid = f.case.f.db.query_one(
        "SELECT supplemental_original_grant_id FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$2",
        &[&f.case.f.account, &output.grant_id],
    ).await.unwrap().get(0);
    assert_eq!(stored, original.grant_id);
    service::withdraw(
        &mut f.case.f.connect().await,
        &f.case.owner,
        original.grant_id,
    )
    .await
    .unwrap();
    assert!(matches!(
        authenticate(&f.case.f.db, &f.case.hasher, &output.token).await,
        Err(auth::AuthError::Unauthorized)
    ));
    assert!(
        !f.case
            .f
            .db
            .query_one(
                "SELECT workflow_integration_grant_current($1,$2,$3,8)",
                &[&f.case.f.account, &output.grant_id, &proposed.key.action_id],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let replacement = f.issue().await;
    assert_ne!(replacement.grant_id, original.grant_id);
    assert!(matches!(
        authenticate(&f.case.f.db, &f.case.hasher, &output.token).await,
        Err(auth::AuthError::Unauthorized)
    ));
    let mut client = f.case.f.connect().await;
    let tx = client.transaction().await.unwrap();
    assert!(tx.execute(
        "UPDATE workflow_integration_grants SET supplemental_original_grant_id=$3 WHERE account_id=$1 AND grant_id=$2",
        &[&f.case.f.account, &output.grant_id, &replacement.grant_id],
    ).await.is_err());
    tx.rollback().await.unwrap();
    f.case.request.original_grant_id = Some(original.grant_id);
    f.case.fresh_factor().await;
    assert!(matches!(
        f.case.issue().await,
        Err(auth::AuthError::Forbidden)
    ));
    f.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; supplemental reader owner and root fences"]
async fn selected_workflow_binding_refuses_original_creator_logout_and_signed_root_successor() {
    for advance_root in [false, true] {
        let mut f = OriginalCase::new().await;
        let workflow_owner = f.case.owner.clone();
        let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let creator_id = Uuid::new_v4();
        f.case.f.db.execute(
            "INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
            &[&creator_id, &f.case.f.account, &workflow_owner.user_id,
              &digest(b"session-v1", &token).as_slice(), &vec![4u8; 32]],
        ).await.unwrap();
        f.case.owner = auth::authenticate_session(&f.case.f.db, &f.case.hasher, &token)
            .await
            .unwrap();
        let original = f.issue().await;
        f.case.owner = workflow_owner;
        f.bind_workflow_request(original.grant_id).await;
        f.case.request.permissions =
            Permissions::new(&[Operation::Propose, Operation::ContextContent]).unwrap();
        f.case.request.content_envelope = Some(f.case.projection().await);
        let output = f.case.issue_another().await;
        let principal = authenticate(&f.case.f.db, &f.case.hasher, &output.token)
            .await
            .unwrap();
        let descriptor = f.case.descriptor().await;
        let proposed = propose_action(
            &mut f.case.f.connect().await,
            &principal,
            Uuid::new_v4(),
            descriptor,
        )
        .await
        .unwrap();
        assert!(
            f.case
                .f
                .db
                .query_one(
                    "SELECT workflow_integration_grant_current($1,$2,$3,8)",
                    &[&f.case.f.account, &output.grant_id, &proposed.key.action_id],
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        if advance_root {
            f.case.f.advance();
            let mut client = f.case.f.connect().await;
            let tx = client.transaction().await.unwrap();
            let mut accepted = sealed_manifest_store::admit(
                &tx,
                f.case.f.session(),
                f.case.f.line,
                1,
                &f.case.f.bytes,
            )
            .await
            .unwrap();
            accepted.context(&f.case.f.wanted()).await.unwrap();
            drop(accepted);
            tx.commit().await.unwrap();
        } else {
            assert!(
                auth::revoke_session(&f.case.f.db, &f.case.owner, creator_id)
                    .await
                    .unwrap()
            );
        }
        assert!(matches!(
            authenticate(&f.case.f.db, &f.case.hasher, &output.token).await,
            Err(auth::AuthError::Unauthorized)
        ));
        assert!(
            !f.case
                .f
                .db
                .query_one(
                    "SELECT workflow_integration_grant_current($1,$2,$3,8)",
                    &[&f.case.f.account, &output.grant_id, &proposed.key.action_id],
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        f.case.fresh_factor().await;
        assert!(matches!(
            f.case.issue().await,
            Err(auth::AuthError::Forbidden)
        ));
        f.case.f.cleanup().await;
    }
}
