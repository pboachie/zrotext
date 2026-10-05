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
    assert_selected_origin_deadline(
        &f,
        output.grant_id,
        proposed.key.action_id,
        original.grant_id,
    )
    .await;
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
    assert_origin_equivalence(
        &f.case.f.db,
        f.case.f.account,
        output.grant_id,
        proposed.key.action_id,
        false,
    )
    .await;
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
    assert_origin_equivalence(
        &f.case.f.db,
        f.case.f.account,
        output.grant_id,
        proposed.key.action_id,
        false,
    )
    .await;
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
        assert_selected_origin_deadline(
            &f,
            output.grant_id,
            proposed.key.action_id,
            original.grant_id,
        )
        .await;
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
        assert_origin_equivalence(
            &f.case.f.db,
            f.case.f.account,
            output.grant_id,
            proposed.key.action_id,
            false,
        )
        .await;
        f.case.fresh_factor().await;
        assert!(matches!(
            f.case.issue().await,
            Err(auth::AuthError::Forbidden)
        ));
        f.case.f.cleanup().await;
    }
}

// The fixture uses maintained registration, selected-reader issuance and proposal
// APIs. Its signed root, phone approval and opaque archive remain synthetic.
async fn assert_origin_equivalence<C: tokio_postgres::GenericClient + Sync>(
    db: &C,
    account: Uuid,
    grant: Uuid,
    action: Uuid,
    current: bool,
) {
    let row = db
        .query_one(
            "SELECT workflow_integration_grant_current($1,$2,$3,8),original_reply_integration_origin_deadline($1,$2,$3),floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[&account, &grant, &action],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, bool>(0), current);
    let deadline: Option<i64> = row.get(1);
    assert_eq!(deadline.is_some(), current);
    if let Some(deadline) = deadline {
        assert!(deadline > row.get::<_, i64>(2));
    }
}

async fn assert_selected_origin_deadline(
    f: &OriginalCase,
    grant: Uuid,
    action: Uuid,
    original: Uuid,
) {
    assert_origin_equivalence(&f.case.f.db, f.case.f.account, grant, action, true).await;
    let row = f.case.f.db.query_one(
        "SELECT g.supplemental_original_grant_id,r.manifest_generation=g.trust_generation,(r.manifest_version,r.manifest_digest)<>(g.manifest_version,g.manifest_digest),(g.trust_generation,g.manifest_version,g.manifest_digest)=(root.generation,root.version,root.semantic_digest),g.expires_ms,floor(extract(epoch FROM creator.expires_at)*1000)::bigint,floor(extract(epoch FROM origin.expires_at)*1000)::bigint,r.expires_ms,k.valid_until_ms,c.expires_at_ms,i.expires_at_ms,original_reply_grant_deadline(g.account_id,$3),original_reply_integration_origin_deadline(g.account_id,g.grant_id,$4),floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM workflow_integration_grants g JOIN connector_registrations r ON (r.account_id,r.connector_id,r.key_id)=(g.account_id,g.connector_id,g.reader_key_id) JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(g.account_id,g.connector_id,g.reader_key_id) JOIN sealed_manifest_authorities root ON root.account_id=g.account_id JOIN sessions creator ON (creator.account_id,creator.user_id,creator.id)=(g.account_id,g.created_by_user,g.created_session) JOIN workflow_contexts c ON (c.account_id,c.id,c.revision)=(g.account_id,g.context_id,g.context_revision) JOIN conversation_intervals i ON (i.account_id,i.id)=(c.account_id,c.interval_id) JOIN sessions origin ON (origin.account_id,origin.id)=(i.account_id,i.initiating_session_id) WHERE g.account_id=$1 AND g.grant_id=$2",
        &[&f.case.f.account, &grant, &original, &action],
    ).await.unwrap();
    assert_eq!(row.get::<_, Uuid>(0), original);
    assert!(
        row.get::<_, bool>(1),
        "selected registration retains the generation"
    );
    assert!(
        row.get::<_, bool>(2),
        "the real selected successor has a different version or digest"
    );
    assert!(row.get::<_, bool>(3), "grant binds the actual current root");
    let original_cap = row.get::<_, Option<i64>>(11).unwrap();
    let caps = [
        row.get::<_, i64>(4),
        row.get::<_, i64>(5),
        row.get::<_, i64>(6),
        row.get::<_, i64>(7),
        row.get::<_, i64>(8),
        row.get::<_, i64>(9),
        row.get::<_, i64>(10),
        original_cap,
    ];
    let deadline = row.get::<_, Option<i64>>(12).unwrap();
    assert_eq!(deadline, *caps.iter().min().unwrap());
    assert!(caps.iter().all(|cap| *cap > row.get::<_, i64>(13)));
}

async fn origin_effects<C: tokio_postgres::GenericClient + Sync>(
    db: &C,
    account: Uuid,
) -> (i64, i64, i64) {
    let row = db.query_one(
        "SELECT (SELECT count(*) FROM workflow_actions WHERE account_id=$1),(SELECT count(*) FROM original_reply_sources WHERE account_id=$1),(SELECT count(*) FROM original_reply_consumptions WHERE account_id=$1)",
        &[&account],
    ).await.unwrap();
    (row.get(0), row.get(1), row.get(2))
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; selected successor origin caps and rollback"]
async fn selected_successor_origin_refuses_registry_key_generation_and_wrong_identity_without_effects()
 {
    let mut f = OriginalCase::new().await;
    let original = f.issue().await;
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
    assert_selected_origin_deadline(
        &f,
        output.grant_id,
        proposed.key.action_id,
        original.grant_id,
    )
    .await;
    let effects = origin_effects(&f.case.f.db, f.case.f.account).await;
    assert_eq!(effects, (1, 0, 0));
    for sql in [
        "UPDATE connector_registrations SET state='revoked',revoked_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint,revoked_by_user=approved_by_user,revocation_reason='synthetic test withdrawal' WHERE account_id=$1 AND connector_id=$2",
        "UPDATE connector_keys SET retired_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE account_id=$1 AND connector_id=$2 AND key_id=(SELECT reader_key_id FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$3)",
    ] {
        // Controlled catalog-state fault, isolated by the real transaction.
        let mut client = f.case.f.connect().await;
        let tx = client.transaction().await.unwrap();
        // Every statement consumes all three typed parameters.
        let sql = format!(
            "{sql} AND EXISTS(SELECT 1 FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$3)"
        );
        assert_eq!(
            tx.execute(
                &sql,
                &[
                    &f.case.f.account,
                    &f.case.request.connector,
                    &output.grant_id
                ]
            )
            .await
            .unwrap(),
            1
        );
        assert_origin_equivalence(
            &tx,
            f.case.f.account,
            output.grant_id,
            proposed.key.action_id,
            false,
        )
        .await;
        assert_eq!(origin_effects(&tx, f.case.f.account).await, effects);
        tx.rollback().await.unwrap();
        assert_selected_origin_deadline(
            &f,
            output.grant_id,
            proposed.key.action_id,
            original.grant_id,
        )
        .await;
        assert_eq!(
            origin_effects(&f.case.f.db, f.case.f.account).await,
            effects
        );
    }
    let mut client = f.case.f.connect().await;
    let tx = client.transaction().await.unwrap();
    assert!(tx.execute(
        "UPDATE connector_registrations SET manifest_generation=manifest_generation+1 WHERE account_id=$1 AND connector_id=$2",
        &[&f.case.f.account, &f.case.request.connector],
    ).await.is_err());
    tx.rollback().await.unwrap();
    assert_selected_origin_deadline(
        &f,
        output.grant_id,
        proposed.key.action_id,
        original.grant_id,
    )
    .await;
    assert_eq!(
        origin_effects(&f.case.f.db, f.case.f.account).await,
        effects
    );
    for (account, grant, action) in [
        (Uuid::new_v4(), output.grant_id, proposed.key.action_id),
        (f.case.f.account, Uuid::new_v4(), proposed.key.action_id),
        (f.case.f.account, output.grant_id, Uuid::new_v4()),
    ] {
        assert_origin_equivalence(&f.case.f.db, account, grant, action, false).await;
        assert_eq!(
            origin_effects(&f.case.f.db, f.case.f.account).await,
            effects
        );
    }
    assert_selected_origin_deadline(
        &f,
        output.grant_id,
        proposed.key.action_id,
        original.grant_id,
    )
    .await;
    f.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; ordinary exact binding and observed creator expiry"]
async fn ordinary_origin_requires_exact_registration_and_keeps_earliest_creator_expiry_after_rollback()
 {
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions =
        Permissions::new(&[Operation::Propose, Operation::ContextContent]).unwrap();
    case.request.content_envelope = Some(case.projection().await);
    let output = case.issue_another().await;
    let principal = authenticate(&case.f.db, &case.hasher, &output.token)
        .await
        .unwrap();
    let descriptor = case.descriptor().await;
    let proposed = propose_action(
        &mut case.f.connect().await,
        &principal,
        Uuid::new_v4(),
        descriptor,
    )
    .await
    .unwrap();
    let row = case.f.db.query_one(
        "SELECT g.supplemental_original_grant_id,(r.manifest_generation,r.manifest_version,r.manifest_digest)=(g.trust_generation,g.manifest_version,g.manifest_digest) FROM workflow_integration_grants g JOIN connector_registrations r ON (r.account_id,r.connector_id,r.key_id)=(g.account_id,g.connector_id,g.reader_key_id) WHERE g.account_id=$1 AND g.grant_id=$2",
        &[&case.f.account, &output.grant_id],
    ).await.unwrap();
    assert!(row.get::<_, Option<Uuid>>(0).is_none());
    assert!(row.get::<_, bool>(1));
    assert_origin_equivalence(
        &case.f.db,
        case.f.account,
        output.grant_id,
        proposed.key.action_id,
        true,
    )
    .await;
    let effects = origin_effects(&case.f.db, case.f.account).await;
    assert_eq!(effects, (1, 0, 0));
    let mut client = case.f.connect().await;
    let tx = client.transaction().await.unwrap();
    assert!(tx.execute(
        "UPDATE connector_registrations SET manifest_version=manifest_version+1 WHERE account_id=$1 AND connector_id=$2",
        &[&case.f.account, &case.request.connector],
    ).await.is_err());
    tx.rollback().await.unwrap();
    assert_origin_equivalence(
        &case.f.db,
        case.f.account,
        output.grant_id,
        proposed.key.action_id,
        true,
    )
    .await;

    let tx = client.transaction().await.unwrap();
    // Shorten this synthetic creator session only; never extend any authority.
    let expiry: i64 = tx.query_one(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE account_id=$1 AND id=$2 RETURNING floor(extract(epoch FROM expires_at)*1000)::bigint",
        &[&case.f.account, &case.owner.session_id],
    ).await.unwrap().get(0);
    assert_origin_equivalence(
        &tx,
        case.f.account,
        output.grant_id,
        proposed.key.action_id,
        true,
    )
    .await;
    let row = tx.query_one(
        "SELECT original_reply_integration_origin_deadline(g.account_id,g.grant_id,$3),g.expires_ms,r.expires_ms,k.valid_until_ms,c.expires_at_ms,i.expires_at_ms,floor(extract(epoch FROM origin.expires_at)*1000)::bigint,floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM workflow_integration_grants g JOIN connector_registrations r ON (r.account_id,r.connector_id,r.key_id)=(g.account_id,g.connector_id,g.reader_key_id) JOIN connector_keys k ON (k.account_id,k.connector_id,k.key_id)=(g.account_id,g.connector_id,g.reader_key_id) JOIN workflow_contexts c ON (c.account_id,c.id,c.revision)=(g.account_id,g.context_id,g.context_revision) JOIN conversation_intervals i ON (i.account_id,i.id)=(c.account_id,c.interval_id) JOIN sessions origin ON (origin.account_id,origin.id)=(i.account_id,i.initiating_session_id) WHERE g.account_id=$1 AND g.grant_id=$2",
        &[&case.f.account, &output.grant_id, &proposed.key.action_id],
    ).await.unwrap();
    assert_eq!(row.get::<_, Option<i64>>(0), Some(expiry));
    assert!((1usize..=6).all(|index| row.get::<_, i64>(index) >= expiry));
    let now: i64 = row.get(7);
    let remaining = u64::try_from(expiry - now).unwrap();
    assert!(remaining <= 5000);
    tokio::time::sleep(std::time::Duration::from_millis(remaining + 1)).await;
    let observed: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        observed >= expiry,
        "observe expiry before the refusal assertion"
    );
    assert_origin_equivalence(
        &tx,
        case.f.account,
        output.grant_id,
        proposed.key.action_id,
        false,
    )
    .await;
    assert_eq!(origin_effects(&tx, case.f.account).await, effects);
    tx.rollback().await.unwrap();
    authenticate(&case.f.db, &case.hasher, &output.token)
        .await
        .unwrap();
    assert_origin_equivalence(
        &case.f.db,
        case.f.account,
        output.grant_id,
        proposed.key.action_id,
        true,
    )
    .await;
    assert_eq!(origin_effects(&case.f.db, case.f.account).await, effects);
    case.f.cleanup().await;
}
