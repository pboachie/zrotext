// SPDX-License-Identifier: AGPL-3.0-only
//! Maintained Owner/context fixture, with deliberately synthetic provider metadata.
//! No provider eligibility, review, reader grant, writer or live SMS is established.
use super::super::{
    action_profile::{ProviderAction, tests as wire_fixture},
    store,
};
use super::*;
use serde_json::{Value, json};

fn value(c: &Case) -> Value {
    let mut value = wire_fixture::fixture();
    // The real maintained fixture's complete ciphertext/current context is
    // independently selected. Route/reader/disclosure remain synthetic metadata.
    value["action"] = serde_json::to_value(&c.descriptor).unwrap();
    value
}
fn parse(value: &Value) -> ProviderAction {
    ProviderAction::parse(&wire_fixture::bytes(value)).unwrap()
}
async fn propose(c: &Case, request: Uuid, value: &Value) -> ActionState {
    store::register_provider(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request,
        parse(value),
    )
    .await
    .unwrap()
}
async fn mutations(c: &Case) -> i64 {
    c.base
        .f
        .db
        .query_one(
            "SELECT count(*) FROM workflow_action_mutations WHERE account_id=$1",
            &[&c.base.f.account],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated maintained Owner/context with synthetic provider metadata"]
async fn whole_provider_bytes_digest_actor_and_export_roundtrip_with_exact_replay() {
    let c = Case::new().await;
    let v = value(&c);
    let raw = wire_fixture::bytes(&v);
    let expected_digest: [u8; 32] = Sha256::digest(&raw).into();
    let request = Uuid::new_v4();
    let result = propose(&c, request, &v).await;
    assert_eq!(result.key.binding_digest, expected_digest);
    assert_eq!(result.phase, Phase::Proposed);
    let replay = propose(&c, request, &v).await;
    assert_eq!(replay.key, result.key);
    assert_eq!(replay.record_version, 1);
    let row=c.base.f.db.query_one("SELECT v.descriptor,v.binding_digest,m.actor_user_id,m.actor_kind,(SELECT count(*) FROM workflow_actions),(SELECT count(*) FROM workflow_action_versions),(SELECT count(*) FROM workflow_action_mutations) FROM workflow_action_versions v JOIN workflow_action_mutations m ON m.account_id=v.account_id AND m.subject_id=v.action_id WHERE v.account_id=$1 AND v.action_id=$2",&[&c.base.f.account,&result.key.action_id]).await.unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), raw);
    assert_eq!(row.get::<_, Vec<u8>>(1), expected_digest);
    assert_eq!(row.get::<_, Uuid>(2), c.base.owner.user_id);
    assert_eq!(row.get::<_, String>(3), "owner");
    for i in 4..7 {
        assert_eq!(row.get::<_, i64>(i), 1);
    }
    let exported =
        super::super::lifecycle::export(&mut c.base.f.connect().await, &c.base.owner, [None; 7])
            .await
            .unwrap();
    assert_eq!(exported.versions.items.len(), 1);
    assert_eq!(
        exported.versions.items[0]["descriptor"],
        format!("{}x{}", char::from(92), super::super::descriptor::hex(&raw))
    );
    let mut changed = v.clone();
    changed["route"]["route_version"] = json!(2);
    assert!(
        store::register_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            request,
            parse(&changed)
        )
        .await
        .is_err()
    );
    assert_eq!(mutations(&c).await, 1);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated maintained Owner/context with synthetic provider metadata"]
async fn internal_provider_edit_retains_whole_history_invalidates_and_replays_without_new_rows() {
    let c = Case::new().await;
    let old = value(&c);
    let initial = propose(&c, Uuid::new_v4(), &old).await;
    let mut next = old.clone();
    next["action"]["revision"] = json!(2);
    next["route"]["route_version"] = json!(2);
    let raw = wire_fixture::bytes(&next);
    let expected: [u8; 32] = Sha256::digest(&raw).into();
    let request = Uuid::new_v4();
    let edited = store::edit_provider(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request,
        1,
        initial.key,
        &raw,
    )
    .await
    .unwrap();
    assert_eq!(edited.phase, Phase::Invalidated);
    assert_eq!(edited.record_version, 2);
    assert_eq!(edited.key.binding_digest, expected);
    assert_eq!(
        store::edit_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            request,
            1,
            initial.key,
            &raw
        )
        .await
        .unwrap()
        .key,
        edited.key
    );
    let history=c.base.f.db.query("SELECT revision,descriptor,binding_digest FROM workflow_action_versions ORDER BY revision",&[]).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].get::<_, Vec<u8>>(1), wire_fixture::bytes(&old));
    assert_eq!(history[1].get::<_, Vec<u8>>(1), raw);
    assert_eq!(history[1].get::<_, Vec<u8>>(2), expected);
    let head = c
        .base
        .f
        .db
        .query_one(
            "SELECT phase,approved_by,approved_at IS NULL,record_version FROM workflow_actions",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(head.get::<_, String>(0), "invalidated");
    assert!(head.get::<_, Option<Uuid>>(1).is_none());
    assert!(head.get::<_, bool>(2));
    assert_eq!(head.get::<_, i64>(3), 2);
    next["reader"]["manifest_version"] = json!(2);
    assert!(
        store::edit_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            request,
            1,
            initial.key,
            &wire_fixture::bytes(&next)
        )
        .await
        .is_err()
    );
    assert!(
        store::edit_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            initial.key,
            &raw
        )
        .await
        .is_err()
    );
    assert_eq!(mutations(&c).await, 2);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated maintained Owner/context with synthetic provider metadata"]
async fn provider_cancel_is_metadata_only_and_approval_phone_binding_and_legacy_loading_refuse() {
    let c = Case::new().await;
    let initial = propose(&c, Uuid::new_v4(), &value(&c)).await;
    let before=c.base.f.db.query_one("SELECT (SELECT count(*) FROM messages),(SELECT count(*) FROM workflow_message_links),(SELECT count(*) FROM workflow_action_mutations)",&[]).await.unwrap();
    assert!(matches!(
        decide(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            initial.key,
            Decision::Approve
        )
        .await,
        Err(crate::http_owner_conversations::ConversationError::Unavailable)
    ));
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(store::descriptor(&tx, initial.key).await.is_err());
    assert!(
        lock_approved(&tx, &c.base.owner, initial.key)
            .await
            .is_err()
    );
    drop(tx);
    assert!(
        bind_message(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            initial.key,
            store::RenderedBinding {
                message_id: Uuid::new_v4(),
                dispatch_id: Uuid::new_v4(),
                message_digest: "77".repeat(32)
            }
        )
        .await
        .is_err()
    );
    let after=c.base.f.db.query_one("SELECT (SELECT count(*) FROM messages),(SELECT count(*) FROM workflow_message_links),(SELECT count(*) FROM workflow_action_mutations)",&[]).await.unwrap();
    for i in 0..3 {
        assert_eq!(before.get::<_, i64>(i), after.get::<_, i64>(i));
    }
    let request = Uuid::new_v4();
    let cancelled = decide(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request,
        1,
        initial.key,
        Decision::Cancel,
    )
    .await
    .unwrap();
    assert_eq!(cancelled.phase, Phase::Cancelled);
    assert_eq!(cancelled.record_version, 2);
    assert_eq!(
        decide(
            &mut c.base.f.connect().await,
            &c.base.owner,
            request,
            1,
            initial.key,
            Decision::Cancel
        )
        .await
        .unwrap()
        .record_version,
        2
    );
    assert_eq!(mutations(&c).await, 2);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated maintained Owner/context with synthetic provider metadata"]
async fn provider_edit_refuses_cross_profile_identity_cas_and_lineage_without_mutation() {
    let c = Case::new().await;
    let phone = c.propose(c.descriptor.clone()).await;
    let mut v = value(&c);
    v["action"]["revision"] = json!(2);
    v["route"]["route_version"] = json!(2);
    assert!(
        store::edit_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            phone.key,
            &wire_fixture::bytes(&v)
        )
        .await
        .is_err()
    );
    v["action"]["revision"] = json!(1);
    v["action"]["action_id"] = json!(Uuid::new_v4());
    v["action"]["routine_id"] = json!(Uuid::new_v4());
    let provider = propose(&c, Uuid::new_v4(), &v).await;
    let mut phone_next = c.descriptor.clone();
    phone_next.action_id = provider.key.action_id.to_string();
    phone_next.revision = 2;
    phone_next.window_id = "changed".into();
    assert!(
        edit(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            provider.key,
            phone_next
        )
        .await
        .is_err()
    );
    v["action"]["revision"] = json!(2);
    v["disclosure"]["request_digest"] = json!("77".repeat(32));
    let raw = wire_fixture::bytes(&v);
    assert!(
        store::edit_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            99,
            provider.key,
            &raw
        )
        .await
        .is_err()
    );
    let mut wrong = provider.key;
    wrong.account_id = Uuid::new_v4();
    assert!(
        store::edit_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            wrong,
            &raw
        )
        .await
        .is_err()
    );
    v["action"]["routine_id"] = json!(&c.descriptor.routine_id);
    assert!(
        store::edit_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            provider.key,
            &wire_fixture::bytes(&v)
        )
        .await
        .is_err()
    );
    assert_eq!(mutations(&c).await, 2);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated maintained Owner/context with synthetic provider metadata"]
async fn provider_replay_read_cancel_and_edit_recheck_current_owner_after_revocation() {
    let c = Case::new().await;
    let v = value(&c);
    let request = Uuid::new_v4();
    let initial = propose(&c, request, &v).await;
    c.base
        .f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.base.owner.session_id],
        )
        .await
        .unwrap();
    assert!(
        store::register_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            request,
            parse(&v)
        )
        .await
        .is_err()
    );
    assert!(
        read(&mut c.base.f.connect().await, &c.base.owner, initial.key)
            .await
            .is_err()
    );
    assert!(
        decide(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            initial.key,
            Decision::Cancel
        )
        .await
        .is_err()
    );
    let mut next = v.clone();
    next["action"]["revision"] = json!(2);
    next["route"]["route_version"] = json!(2);
    assert!(
        store::edit_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            1,
            initial.key,
            &wire_fixture::bytes(&next)
        )
        .await
        .is_err()
    );
    assert_eq!(mutations(&c).await, 1);
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT phase FROM workflow_actions", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "proposed"
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated maintained Owner/context with synthetic provider metadata"]
async fn provider_final_owner_loss_rolls_back_version_action_and_audit_together() {
    let c = Case::new().await;
    // The trigger body cannot be parameterized, so the session id is read back
    // from the isolated fixture instead of embedding the principal's field.
    let trigger_target: Uuid = c
        .base
        .f
        .db
        .query_one(
            "SELECT id FROM sessions WHERE account_id=$1 AND user_id=$2",
            &[&c.base.f.account, &c.base.owner.user_id],
        )
        .await
        .unwrap()
        .get(0);
    c.base.f.db.batch_execute(&format!("CREATE FUNCTION revoke_provider_owner_on_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE sessions SET revoked_at=clock_timestamp() WHERE id='{}'; RETURN NEW; END $$; CREATE TRIGGER revoke_provider_owner_on_audit BEFORE INSERT ON workflow_action_mutations FOR EACH ROW EXECUTE FUNCTION revoke_provider_owner_on_audit();",trigger_target)).await.unwrap();
    assert!(
        store::register_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            parse(&value(&c))
        )
        .await
        .is_err()
    );
    let row=c.base.f.db.query_one("SELECT (SELECT count(*) FROM workflow_actions),(SELECT count(*) FROM workflow_action_versions),(SELECT count(*) FROM workflow_action_mutations),(SELECT revoked_at IS NULL FROM sessions WHERE id=$1)",&[&c.base.owner.session_id]).await.unwrap();
    for i in 0..3 {
        assert_eq!(row.get::<_, i64>(i), 0);
    }
    assert!(row.get::<_, bool>(3));
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated maintained Owner/context with synthetic provider metadata"]
async fn provider_context_digest_version_and_expiry_substitutions_cannot_record_metadata() {
    let c = Case::new().await;
    for (field, replacement) in [
        ("content_digest", json!("77".repeat(32))),
        ("content_version", json!(2)),
        ("line_id", json!(Uuid::new_v4())),
        ("expires_at", json!(c.descriptor.not_before)),
    ] {
        let mut v = value(&c);
        v["action"][field] = replacement;
        match ProviderAction::parse(&wire_fixture::bytes(&v)) {
            Ok(d) => assert!(
                store::register_provider(
                    &mut c.base.f.connect().await,
                    &c.base.owner,
                    Uuid::new_v4(),
                    d
                )
                .await
                .is_err()
            ),
            Err(_) => assert_eq!(field, "expires_at"),
        }
    }
    // An independently observed DB clock supplies a valid but already expired
    // proposal; no sleep, forced clock or accepted authority is synthesized.
    let now = c
        .base
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    let mut expired = value(&c);
    expired["action"]["not_before"] = json!(now / 1000 - 10);
    expired["action"]["expires_at"] = json!(now / 1000 - 1);
    assert!(
        store::register_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            parse(&expired)
        )
        .await
        .is_err()
    );
    // Loss of the actual stored context prevents otherwise identical metadata.
    c.base.f.db.execute("UPDATE workflow_contexts SET purged_at=clock_timestamp() WHERE account_id=$1 AND id=$2", &[&c.base.f.account,&c.base.h.context]).await.unwrap();
    assert!(
        store::register_provider(
            &mut c.base.f.connect().await,
            &c.base.owner,
            Uuid::new_v4(),
            parse(&value(&c))
        )
        .await
        .is_err()
    );
    assert_eq!(mutations(&c).await, 0);
    c.cleanup().await;
}

// Authentication is checked by the actual dormant router before it can poll
// even the first body byte; this establishes no positive provider authority.
#[tokio::test]
async fn original_provider_intake_rejects_non_cookie_owner_before_polling_body() {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;
    for bearer in [false, true] {
        let state = crate::http_owner_conversations::OwnerConversationsState {
            database_url: "postgres://unused".into(),
            auth_hasher: std::sync::Arc::new(
                crate::http_owner_conversations::TokenHasher::new(crate::test_keys::key(83))
                    .unwrap(),
            ),
            canonical_origin: "https://zrotext.example".into(),
        };
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/owner/workflow/actions")
            .header(header::CONTENT_TYPE, "application/json");
        if bearer {
            request = request.header(header::AUTHORIZATION, "Bearer synthetic");
        }
        let body = Body::from_stream(futures_util::stream::poll_fn(
            |_| -> std::task::Poll<Option<Result<Vec<u8>, std::io::Error>>> {
                panic!("unauthorized body must not be polled")
            },
        ));
        let response = super::super::http::router(state)
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
    }
}
