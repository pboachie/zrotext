// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_dispatch::{self, wire::Ready};
use crate::sealed_outbound::{admit_candidate02_with_limit, tests::TestCase};
use zrotext_delivery_store::{DeliveryStore, RadioEvent, SessionRecord};
use zrotext_domain::Evidence;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn candidate_preserves_existing_sealed_grant_admission_history_and_deletion() {
    let case = TestCase::new().await;
    for schema in [
        include_str!(
            "../../../../../../deploy/compose/migrations/064_owner_conversation_consent.sql"
        ),
        include_str!("../../../../../../deploy/compose/migrations/065_conversation_activation.sql"),
        SCHEMA,
        EXECUTION_SCHEMA,
    ] {
        case.db.batch_execute(schema).await.unwrap();
    }
    case.db
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let message = Uuid::new_v4();
    let bytes = case.envelope(message).await;
    admit_candidate02_with_limit(
        &mut case.connect().await,
        &case.principal,
        &case.hasher,
        case.writer(),
        &bytes,
        Some(1),
    )
    .await
    .unwrap();
    let session = SessionRecord {
        account_id: case.account,
        device_id: case.device,
        site_id: "manifest-test".into(),
        instance_id: "fixture".into(),
        epoch: 1,
        deployment_epoch: 1,
    };
    let ready = Ready {
        grant_version: 1,
        connection_epoch: 1,
        line_id: case.line,
        binding_generation: 1,
        reader_key_id: URL_SAFE_NO_PAD.encode(case.readers[0].key_id),
    };
    let policy = crate::alpha_policy::AlphaPolicy::parse(
        Some("true"),
        Some(&case.account.to_string()),
        Some("+12"),
    )
    .unwrap();
    let grant = sealed_dispatch::grant(&mut case.connect().await, &session, &ready, &policy)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.message_id, message);
    let row = case
        .db
        .query_one(
            "SELECT (SELECT count(*) FROM sealed_grant_authorizations), \
         (SELECT count(*) FROM conversation_confirmation_records), \
         (SELECT count(*) FROM conversation_execution_records),state FROM messages WHERE id=$1",
            &[&message],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (1, 0, 0)
    );
    assert_eq!(row.get::<_, String>(3), "claimed");
    let observed_at_ms = case
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let mut radio = case.connect().await;
    assert_eq!(
        DeliveryStore::new(&mut radio)
            .record_radio_event(RadioEvent {
                event_id: Uuid::new_v4(),
                account_id: case.account,
                device_id: case.device,
                message_id: message,
                attempt_id: grant.attempt_id,
                evidence: Evidence::DurableSubmitIntent,
                observed_at_ms,
                segment_index: None,
                segment_count: None,
            })
            .await
            .unwrap(),
        zrotext_domain::MessageState::Submitting
    );
    let error = case.db.execute(
        "UPDATE dispatch_fences SET recipient_digest=decode(repeat('00',32),'hex') WHERE attempt_id=$1",
        &[&grant.attempt_id],
    ).await.unwrap_err();
    assert_eq!(
        error.as_db_error().unwrap().code(),
        &tokio_postgres::error::SqlState::CHECK_VIOLATION
    );
    case.db
        .execute(
            "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()",
            &[],
        )
        .await
        .unwrap();
    assert!(
        !case
            .db
            .query_one("SELECT sealed_grant_current($1)", &[&grant.attempt_id])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    for sql in [
        "UPDATE message_attempts SET status='unknown' WHERE id=$1",
        "UPDATE dispatch_fences SET outcome='unknown' WHERE attempt_id=$1",
    ] {
        assert_eq!(case.db.execute(sql, &[&grant.attempt_id]).await.unwrap(), 1);
    }
    // Preserve historical reconciliation and retention behavior without granting fresh authority.
    assert_eq!(
        case.db
            .execute(
                "UPDATE messages SET state='unknown' WHERE id=$1",
                &[&message]
            )
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        case.db
            .execute(
                "DELETE FROM dispatch_fences WHERE attempt_id=$1",
                &[&grant.attempt_id]
            )
            .await
            .unwrap(),
        1
    );
    // Remove this fixture's receipt before its referenced attempt, matching
    // the existing foreign-key cleanup order.
    case.db
        .execute(
            "DELETE FROM message_events WHERE attempt_id=$1",
            &[&grant.attempt_id],
        )
        .await
        .unwrap();
    assert_eq!(
        case.db
            .execute(
                "DELETE FROM message_attempts WHERE id=$1",
                &[&grant.attempt_id]
            )
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        case.db
            .query_one("SELECT count(*) FROM sealed_grant_authorizations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn candidate_confirmation_tombstone_cannot_fall_back_to_generic_sealed_grants() {
    let case = prepared().await;
    let (envelope, confirmation, signature) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &confirmation, &signature)
        .await
        .unwrap();
    case.f.db.execute(
        "UPDATE conversation_confirmation_records SET confirmation=NULL,signature=NULL WHERE message_id=$1",
        &[&confirmation.message],
    ).await.unwrap();
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT count(*) FROM conversation_confirmation_records WHERE confirmation IS NULL",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    let attempt = Uuid::new_v4();
    let error = case.f.db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,1,1,1,'granted')",
        &[&attempt, &case.f.account, &confirmation.message, &case.f.device],
    ).await.unwrap_err();
    let error = error.as_db_error().unwrap();
    assert_eq!(
        error.code(),
        &tokio_postgres::error::SqlState::CHECK_VIOLATION
    );
    assert_eq!(
        error.message(),
        "effects require exact confirmed execution identity"
    );
    for sql in [
        "UPDATE dispatch_jobs SET generation=generation+1 WHERE message_id=$1",
        "UPDATE messages SET state='claimed' WHERE id=$1",
    ] {
        let error = case
            .f
            .db
            .execute(sql, &[&confirmation.message])
            .await
            .unwrap_err();
        assert_eq!(
            error.as_db_error().unwrap().code(),
            &tokio_postgres::error::SqlState::CHECK_VIOLATION
        );
    }
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn candidate_final_submit_predicate_requires_live_exact_conversation_authority() {
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    let session = delivery_identity(&case);
    let attempt = Uuid::new_v4();
    let frame = request(&case, &session, c.message, attempt, &envelope);
    issue(&case, &session, &frame).await.unwrap();
    let row = case
        .f
        .db
        .query_one(
            "SELECT conversation_execution_initial_valid(r),sealed_grant_current(r.attempt_id), \
         EXISTS(SELECT 1 FROM sealed_grant_authorizations WHERE attempt_id=r.attempt_id) \
         FROM conversation_execution_records r WHERE attempt_id=$1",
            &[&attempt],
        )
        .await
        .unwrap();
    assert!(row.get::<_, bool>(0));
    assert!(row.get::<_, bool>(1));
    assert!(!row.get::<_, bool>(2));
    assert!(
        !case
            .f
            .db
            .query_one("SELECT sealed_grant_current($1)", &[&Uuid::new_v4()])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    for replacement in [
        None,
        Some(
            "CREATE FUNCTION conversation_execution_lock_intent(uuid,uuid,uuid,uuid) RETURNS boolean LANGUAGE sql AS $$SELECT NULL::boolean$$",
        ),
        Some(
            "CREATE FUNCTION conversation_execution_lock_intent(uuid,uuid,uuid,uuid) RETURNS text LANGUAGE sql AS $$SELECT 'unexpected'$$",
        ),
    ] {
        case.f
            .db
            .batch_execute(
                "DROP FUNCTION IF EXISTS conversation_execution_lock_intent(uuid,uuid,uuid,uuid)",
            )
            .await
            .unwrap();
        if let Some(sql) = replacement {
            case.f.db.batch_execute(sql).await.unwrap();
        }
        let before = state(&case).await;
        let observed_at_ms = case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let result = DeliveryStore::new(&mut case.f.connect().await)
            .record_radio_event(RadioEvent {
                event_id: Uuid::new_v4(),
                account_id: c.account,
                device_id: c.device,
                message_id: c.message,
                attempt_id: attempt,
                evidence: Evidence::DurableSubmitIntent,
                observed_at_ms,
                segment_index: None,
                segment_count: None,
            })
            .await;
        assert!(result.is_err());
        assert_eq!(state(&case).await, before);
    }
    case.f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&case.owner.session_id],
        )
        .await
        .unwrap();
    assert!(
        !case
            .f
            .db
            .query_one("SELECT sealed_grant_current($1)", &[&attempt])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    case.f.cleanup().await;
}
