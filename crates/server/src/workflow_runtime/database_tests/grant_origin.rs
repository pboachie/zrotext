// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

async fn fresh_creator(case: &mut Case) {
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let hash = digest(b"session-v1", &token);
    let session = Uuid::new_v4();
    case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')", &[&session,&case.f.account,&case.owner.user_id,&hash.as_slice(),&vec![4u8;32]]).await.unwrap();
    case.owner = auth::authenticate_session(&case.f.db, &case.hasher, &token)
        .await
        .unwrap();
    assert_eq!(case.owner.session_id, session);
    case.request.permissions =
        Permissions::new(&[Operation::ContextMetadata, Operation::ContextContent]).unwrap();
    case.request.content_envelope = Some(case.projection().await);
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn fresh_grant_creator_cannot_replace_expired_or_revoked_interval_origin() {
    // A distinct current creator can issue while the actual interval origin lives.
    let mut positive = Case::new().await;
    let original = positive.owner.session_id;
    fresh_creator(&mut positive).await;
    assert_ne!(positive.owner.session_id, original);
    let issued = positive.issue().await.unwrap();
    let principal = authenticate(&positive.f.db, &positive.hasher, &issued.token)
        .await
        .unwrap();
    assert_eq!(
        read_context_content(
            &mut positive.f.connect().await,
            &principal,
            Uuid::new_v4(),
            positive.header.context
        )
        .await
        .unwrap(),
        positive.request.content_envelope.clone().unwrap()
    );
    positive.f.cleanup().await;

    for withdrawn in ["expired", "revoked"] {
        let mut case = Case::new().await;
        let origin = case.owner.session_id;
        fresh_creator(&mut case).await;
        assert_ne!(case.owner.session_id, origin);
        let sql = if withdrawn == "expired" {
            "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1"
        } else {
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1"
        };
        assert_eq!(case.f.db.execute(sql, &[&origin]).await.unwrap(), 1);
        assert!(case.f.db.query_one("SELECT revoked_at IS NULL AND expires_at>clock_timestamp() FROM sessions WHERE id=$1", &[&case.owner.session_id]).await.unwrap().get::<_,bool>(0));
        assert!(
            matches!(case.issue().await, Err(auth::AuthError::Forbidden)),
            "withdrawn interval origin must refuse fresh grant issuance"
        );
        let counts = case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_integration_grants),(SELECT count(*) FROM workflow_connector_context_envelopes),(SELECT count(*) FROM workflow_integration_access),(SELECT count(*) FROM owner_mfa_recovery_codes WHERE used_at IS NULL)", &[]).await.unwrap();
        for index in 0..3 {
            assert_eq!(counts.get::<_, i64>(index), 0);
        }
        assert_eq!(counts.get::<_, i64>(3), 1);
        case.f.cleanup().await;
    }
}
