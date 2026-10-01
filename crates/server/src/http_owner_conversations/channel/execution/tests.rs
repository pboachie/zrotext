// SPDX-License-Identifier: AGPL-3.0-only
// Nested in the real queue fixture module; no relaxed schema or identity adapter.
use super::*;
use crate::http_owner_conversations::channel::{self, AuthenticatedChannelSession};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

const EXECUTION_SCHEMA: &str = include_str!(
    "../../../../../../deploy/compose/migration-candidates/NNN_conversation_execution_records.sql"
);

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_radio_event_cannot_borrow_another_devices_attempt() {
    let case = prepared().await;
    let (envelope, confirmation, signature) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &confirmation, &signature)
        .await
        .unwrap();
    let session = delivery_identity(&case);
    let frame = request(
        &case,
        &session,
        confirmation.message,
        Uuid::new_v4(),
        &envelope,
    );
    issue(&case, &session, &frame).await.unwrap();
    let other_device = Uuid::new_v4();
    let other_message = Uuid::new_v4();
    let other_attempt = Uuid::new_v4();
    case.f.db.execute("INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic other device')",
        &[&other_device,&case.f.account]).await.unwrap();
    case.f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
        VALUES($1,$2,$3,'+12',$4,'synthetic_alpha',$5,$4,'claimed',clock_timestamp()+interval '1 minute')",
        &[&other_message,&case.f.account,&other_device,&vec![8u8;32],&b"synthetic".as_slice()]).await.unwrap();
    case.f.db.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
        VALUES($1,$2,$3,$4,1,1,1,'granted')",&[&other_attempt,&case.f.account,&other_message,&other_device]).await.unwrap();
    let before = state(&case).await;
    let events: i64 = case
        .f
        .db
        .query_one("SELECT count(*) FROM message_events", &[])
        .await
        .unwrap()
        .get(0);
    let error = case.f.db.execute("INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,event_digest,observed_at,resulting_state,segment_count) \
        VALUES($1,$2,$3,$4,'durable_intent',$5,clock_timestamp(),'submitting',1)",
        &[&Uuid::new_v4(),&case.f.account,&confirmation.message,&other_attempt,&vec![7u8;32]]).await.unwrap_err();
    assert_eq!(error.as_db_error().unwrap().code().code(), "23514");
    assert_eq!(state(&case).await, before);
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM message_events", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        events
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_outbound_deadline_refuses_inbound_direction_and_foreign_account() {
    let case = prepared().await;
    let mut db = case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let mut authority = crate::sealed_manifest_store::outbound::lock_current(&tx, case.f.account)
        .await
        .unwrap();
    let mut wanted = case.f.wanted();
    assert!(
        authority
            .outbound_admission_deadline(&wanted)
            .await
            .is_err()
    );
    wanted.kind = crate::sealed_envelope::Kind::Outbound;
    assert!(authority.admission_deadline(&wanted).await.is_err());
    wanted.account_id = *Uuid::new_v4().as_bytes();
    assert!(
        authority
            .outbound_admission_deadline(&wanted)
            .await
            .is_err()
    );
    drop(authority);
    tx.rollback().await.unwrap();
    case.f.cleanup().await;
}
async fn prepared() -> Case {
    let case = Case::new().await;
    case.f.db.batch_execute(EXECUTION_SCHEMA).await.unwrap();
    case.f
        .db
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    case
}
fn request(
    case: &Case,
    session: &AuthenticatedChannelSession<'_>,
    message: Uuid,
    attempt: Uuid,
    envelope: &[u8],
) -> Vec<u8> {
    let mut bytes = delivery_frame(session, &case.interval, message, Uuid::new_v4());
    bytes[5] = 18;
    bytes.extend(attempt.as_bytes());
    bytes.extend(Sha256::digest(envelope));
    assert!((434..=447).contains(&bytes.len()));
    bytes
}
async fn state(case: &Case) -> String {
    case.f.db.query_one("SELECT jsonb_build_object('messages',(SELECT jsonb_agg(to_jsonb(m)) FROM messages m), \
        'jobs',(SELECT jsonb_agg(to_jsonb(j)) FROM dispatch_jobs j),'records',(SELECT jsonb_agg(to_jsonb(r)) FROM conversation_execution_records r), \
        'attempts',(SELECT jsonb_agg(to_jsonb(a)) FROM message_attempts a),'fences',(SELECT jsonb_agg(to_jsonb(f)) FROM dispatch_fences f), \
        'usage',(SELECT jsonb_agg(to_jsonb(u)) FROM usage_ledger u))::text",&[]).await.unwrap().get(0)
}
async fn issue(
    case: &Case,
    session: &AuthenticatedChannelSession<'_>,
    bytes: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    channel::handle(&mut case.f.connect().await, session, bytes).await
}
fn fields(bytes: &[u8], request: &[u8]) -> serde_json::Value {
    let mut header = request[..118].to_vec();
    header[5] = 19;
    assert_eq!(bytes[..118], header);
    assert!(bytes.len() <= 2168);
    let n = u16::from_be_bytes(bytes[118..120].try_into().unwrap()) as usize;
    assert!((1..=2048).contains(&n));
    assert_eq!(bytes.len(), 120 + n);
    serde_json::from_slice(&bytes[120..]).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_commits_exact_attempt_and_fence_before_reply_without_spending_again() {
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    let counts = case.counts().await;
    let session = delivery_identity(&case);
    let attempt = Uuid::new_v4();
    let frame = request(&case, &session, c.message, attempt, &envelope);
    let reply = issue(&case, &session, &frame).await.unwrap();
    let grant = fields(&reply, &frame);
    assert_eq!(grant.as_object().unwrap().len(), 18);
    assert_eq!(grant["attempt_id"], attempt.to_string());
    assert_eq!(grant["message_id"], c.message.to_string());
    assert_eq!(grant["reader_role"], 1);
    assert_eq!(grant["attempt_generation"], 1);
    assert_eq!(grant["segment_count"], 6);
    assert_eq!(
        grant["reader_key_id"],
        URL_SAFE_NO_PAD.encode(case.phone_reader.key_id)
    );
    assert_eq!(
        grant["envelope_sha256"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(&envelope))
    );
    let parsed =
        crate::sealed_envelope::parse(&envelope, crate::sealed_envelope::Profile::Draft02Candidate)
            .unwrap();
    assert_eq!(
        grant["unsigned_sha256"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(parsed.unsigned))
    );
    assert!(grant["expires_at_ms"].as_i64().unwrap() <= c.expires_ms);
    assert_eq!(case.counts().await, counts);
    let row=case.f.db.query_one("SELECT (SELECT count(*) FROM conversation_execution_records), \
        (SELECT count(*) FROM message_attempts),(SELECT count(*) FROM dispatch_fences),(SELECT state FROM messages)",&[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (1, 1, 1)
    );
    assert_eq!(row.get::<_, String>(3), "claimed");
    let before = state(&case).await;
    let retry = issue(&case, &session, &frame).await.unwrap();
    assert_eq!(retry, reply);
    assert_eq!(state(&case).await, before);
    let mut db = case.f.connect().await;
    let inventory = crate::http_owner_conversations::channel::execution::lifecycle::inventory(
        &mut db,
        &case.owner,
        None,
    )
    .await
    .unwrap();
    assert_eq!(inventory.records.len(), 1);
    assert_eq!(inventory.records[0].message_id, c.message);
    assert_eq!(inventory.records[0].attempt_id, attempt);
    assert!(!inventory.truncated);
    let public = serde_json::to_value(inventory).unwrap();
    assert_eq!(public["records"][0].as_object().unwrap().len(), 6);
    assert!(
        crate::http_owner_conversations::channel::execution::lifecycle::inventory(
            &mut db,
            &case.owner,
            Some(Uuid::new_v4())
        )
        .await
        .is_err()
    );
    let mut revoked = case.owner.clone();
    revoked.session_id = Uuid::new_v4();
    assert!(
        crate::http_owner_conversations::channel::execution::lifecycle::inventory(
            &mut db, &revoked, None
        )
        .await
        .is_err()
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_denies_selector_digest_scope_and_current_authority_tampering_without_effects() {
    for revoked in 0..7 {
        let case = prepared().await;
        let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
        case.enqueue(&envelope, &c, &sig).await.unwrap();
        let session = delivery_identity(&case);
        let mut frame = request(&case, &session, c.message, Uuid::new_v4(), &envelope);
        match revoked {
            0 => frame[6] ^= 1,
            1 => {
                let n = frame.len();
                frame[n - 1] ^= 1;
            }
            2 => {
                let end = frame.len() - 64;
                frame[end..end + 16].copy_from_slice(Uuid::new_v4().as_bytes());
            }
            3 => {
                case.f
                    .db
                    .execute("UPDATE sessions SET revoked_at=clock_timestamp()", &[])
                    .await
                    .unwrap();
            }
            4 => {
                case.f
                    .db
                    .execute(
                        "UPDATE deployment_authority SET dispatch_enabled=FALSE",
                        &[],
                    )
                    .await
                    .unwrap();
            }
            5 => {
                case.f
                    .db
                    .execute("UPDATE device_keys SET revoked_at=clock_timestamp()", &[])
                    .await
                    .unwrap();
            }
            _ => {
                crate::http_owner_conversations::activation::close(
                    &mut case.f.connect().await,
                    &case.owner,
                    case.interval.interval,
                    true,
                )
                .await
                .unwrap();
            }
        }
        let before = state(&case).await;
        assert!(
            matches!(
                issue(&case, &session, &frame).await,
                Err(ConversationError::Forbidden)
            ),
            "case {revoked}"
        );
        assert_eq!(state(&case).await, before);
        case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_rejects_reconnect_replacement_attempt_and_uncertain_or_expired_replay() {
    for changed in 0..4 {
        let case = prepared().await;
        let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
        case.enqueue(&envelope, &c, &sig).await.unwrap();
        let mut session = delivery_identity(&case);
        let attempt = Uuid::new_v4();
        let frame = request(&case, &session, c.message, attempt, &envelope);
        issue(&case, &session, &frame).await.unwrap();
        assert!(
            crate::http_owner_conversations::channel::execution::permission::current(
                &mut case.f.connect().await,
                &session,
                c.message,
                attempt
            )
            .await
            .unwrap()
        );
        let frame = match changed {
            0 => {
                session.phone_session = Uuid::new_v4();
                request(&case, &session, c.message, attempt, &envelope)
            }
            1 => request(&case, &session, c.message, Uuid::new_v4(), &envelope),
            2 => {
                case.f
                    .db
                    .execute("UPDATE message_attempts SET status='unknown'", &[])
                    .await
                    .unwrap();
                case.f
                    .db
                    .execute("UPDATE dispatch_fences SET outcome='unknown'", &[])
                    .await
                    .unwrap();
                frame
            }
            _ => {
                case.f.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second'",&[]).await.unwrap();
                frame
            }
        };
        let before = state(&case).await;
        assert!(matches!(
            issue(&case, &session, &frame).await,
            Err(ConversationError::Forbidden)
        ));
        assert_eq!(state(&case).await, before);
        case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_two_concurrent_attempts_and_busy_device_commit_only_one_permit() {
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    let session = delivery_identity(&case);
    let first = request(&case, &session, c.message, Uuid::new_v4(), &envelope);
    let second = request(&case, &session, c.message, Uuid::new_v4(), &envelope);
    let (mut a, mut b) = (case.f.connect().await, case.f.connect().await);
    let (one, two) = tokio::join!(
        channel::handle(&mut a, &session, &first),
        channel::handle(&mut b, &session, &second)
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    assert!(
        matches!(one, Ok(_) | Err(ConversationError::Forbidden))
            && matches!(two, Ok(_) | Err(ConversationError::Forbidden))
    );
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    let before = state(&case).await;
    assert!(matches!(
        issue(
            &case,
            &session,
            &request(&case, &session, c.message, Uuid::new_v4(), &envelope)
        )
        .await,
        Err(ConversationError::Forbidden)
    ));
    assert_eq!(state(&case).await, before);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_failure_after_attempt_insert_rolls_back_claim_permit_and_quota() {
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    case.f.db.batch_execute("CREATE FUNCTION fixture_reject_execution_fence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
        RAISE EXCEPTION 'synthetic post-attempt failure'; END $$; CREATE TRIGGER zz_fixture_fence_failure \
        BEFORE INSERT ON dispatch_fences FOR EACH ROW EXECUTE FUNCTION fixture_reject_execution_fence()").await.unwrap();
    let before = state(&case).await;
    let session = delivery_identity(&case);
    assert!(matches!(
        issue(
            &case,
            &session,
            &request(&case, &session, c.message, Uuid::new_v4(), &envelope)
        )
        .await,
        Err(ConversationError::Database(_))
    ));
    assert_eq!(state(&case).await, before);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_cancel_refund_prevents_grant_and_historical_status_cannot_reopen_or_swap_identity()
 {
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    zrotext_delivery_store::DeliveryStore::new(&mut case.f.connect().await)
        .cancel(c.account, c.message)
        .await
        .unwrap();
    let before = state(&case).await;
    let session = delivery_identity(&case);
    assert!(
        issue(
            &case,
            &session,
            &request(&case, &session, c.message, Uuid::new_v4(), &envelope)
        )
        .await
        .is_err()
    );
    assert_eq!(state(&case).await, before);
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    case.f.cleanup().await;
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    let session = delivery_identity(&case);
    issue(
        &case,
        &session,
        &request(&case, &session, c.message, Uuid::new_v4(), &envelope),
    )
    .await
    .unwrap();
    for sql in [
        "UPDATE conversation_execution_records SET expires_at_ms=expires_at_ms+1",
        "UPDATE conversation_execution_records SET phone_session='11111111-1111-4111-8111-111111111111'",
        "UPDATE message_attempts SET generation=generation+1",
        "UPDATE dispatch_fences SET grant_expires_at=grant_expires_at+interval '1 second'",
        "UPDATE dispatch_jobs SET lease_until=lease_until+interval '1 second'",
        "UPDATE dispatch_jobs SET generation=generation+1",
        "UPDATE dispatch_jobs SET lease_owner=NULL,lease_until=NULL",
        "DELETE FROM dispatch_fences",
        "DELETE FROM message_attempts",
        "DELETE FROM conversation_execution_records",
    ] {
        let before = state(&case).await;
        assert!(case.f.db.batch_execute(sql).await.is_err(), "{sql}");
        assert_eq!(state(&case).await, before);
    }
    case.f
        .db
        .execute("UPDATE sessions SET revoked_at=clock_timestamp()", &[])
        .await
        .unwrap();
    assert_eq!(
        crate::http_owner_conversations::confirmation_records::redact(&case.f.db, 10)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM conversation_execution_records", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    // Retained callback status can advance after revocation/redaction, but cannot reopen.
    case.f
        .db
        .execute("UPDATE message_attempts SET status='unknown'", &[])
        .await
        .unwrap();
    case.f
        .db
        .execute("UPDATE dispatch_fences SET outcome='unknown'", &[])
        .await
        .unwrap();
    assert!(
        case.f
            .db
            .execute("UPDATE message_attempts SET status='granted'", &[])
            .await
            .is_err()
    );
    assert!(
        case.f
            .db
            .execute("UPDATE dispatch_fences SET outcome='granted'", &[])
            .await
            .is_err()
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_fixed_deadline_expires_without_replacement_and_existing_sweep_keeps_uncertainty()
{
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    // The independently live phone lease safely shortens the signed deadline.
    case.f
        .db
        .execute(
            "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '3 seconds'",
            &[],
        )
        .await
        .unwrap();
    let session = delivery_identity(&case);
    let attempt = Uuid::new_v4();
    let frame = request(&case, &session, c.message, attempt, &envelope);
    let reply = issue(&case, &session, &frame).await.unwrap();
    let grant = fields(&reply, &frame);
    assert!(grant["expires_at_ms"].as_i64().unwrap() < c.expires_ms);
    assert!(case.f.db.query_one("SELECT expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000) FROM conversation_execution_records",&[]).await.unwrap().get::<_,bool>(0));
    // Extend the connection lease, not the immutable grant, then observe its actual expiry.
    case.f
        .db
        .execute(
            "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '1 minute'",
            &[],
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            if case.f.db.query_one("SELECT expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000) FROM conversation_execution_records",&[]).await.unwrap().get::<_,bool>(0) { break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    let before = state(&case).await;
    assert!(matches!(
        issue(&case, &session, &frame).await,
        Err(ConversationError::Forbidden)
    ));
    assert!(matches!(
        issue(
            &case,
            &session,
            &request(&case, &session, c.message, Uuid::new_v4(), &envelope)
        )
        .await,
        Err(ConversationError::Forbidden)
    ));
    assert_eq!(state(&case).await, before);
    let mut db = case.f.connect().await;
    assert_eq!(
        zrotext_delivery_store::DeliveryStore::new(&mut db)
            .reconcile_silent_attempts(10)
            .await
            .unwrap(),
        1
    );
    let row=case.f.db.query_one("SELECT a.status,f.outcome,m.state FROM message_attempts a JOIN dispatch_fences f ON f.attempt_id=a.id JOIN messages m ON m.id=a.message_id",&[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, String>(0),
            row.get::<_, String>(1),
            row.get::<_, String>(2)
        ),
        ("unknown".into(), "unknown".into(), "unknown".into())
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_raw_sql_cannot_create_unbacked_attempt_or_partial_execution_record() {
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    let attempt = Uuid::new_v4();
    assert!(
        case.f
            .db
            .execute(
                "UPDATE messages SET state='claimed' WHERE id=$1",
                &[&c.message]
            )
            .await
            .is_err()
    );
    assert!(case.f.db.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
        VALUES($1,$2,$3,$4,1,1,1,'granted')",&[&attempt,&c.account,&c.message,&c.device]).await.is_err());
    let before = state(&case).await;
    let mut db = case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    tx.execute("INSERT INTO conversation_execution_records(account_id,message_id,device_id,attempt_id,generation,phone_session,origin_hash,site_id,instance_id, \
        session_epoch,deployment_epoch,reader_key_id,envelope_digest,unsigned_digest,expires_at_ms,segment_count) \
        SELECT p.account_id,p.message_id,p.device_id,$3,1,$4,$5,'manifest-test','fixture',1,1,$6,p.envelope_digest,m.request_digest,p.expires_at_ms,6 \
        FROM conversation_confirmation_records p JOIN messages m ON (m.account_id,m.id)=(p.account_id,p.message_id) \
        WHERE p.account_id=$1 AND p.message_id=$2",&[&c.account,&c.message,&attempt,&Uuid::new_v4(),&vec![9u8;32],&case.phone_reader.key_id.as_slice()]).await.unwrap();
    assert!(tx.commit().await.is_err());
    assert_eq!(state(&case).await, before);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_candidate_preserves_alpha_effect_boundary_and_guarded_record_deletion_order() {
    let case = prepared().await;
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    case.f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+12',$4,'synthetic_alpha',$5,$4,'claimed',clock_timestamp()+interval '1 minute')",&[&message,&case.f.account,&case.f.device,&vec![8u8;32],&b"synthetic".as_slice()]).await.unwrap();
    case.f.db.execute("INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) VALUES($1,$2,$3,$4,7,1,1,'granted')",&[&attempt,&case.f.account,&message,&case.f.device]).await.unwrap();
    case.f.db.execute("INSERT INTO dispatch_fences(message_id,account_id,device_id,attempt_id,generation,session_epoch,deployment_epoch,recipient_digest,grant_expires_at,outcome) VALUES($1,$2,$3,$4,7,1,1,$5,clock_timestamp()+interval '1 minute','granted')",&[&message,&case.f.account,&case.f.device,&attempt,&vec![8u8;32]]).await.unwrap();
    case.f
        .db
        .execute(
            "UPDATE message_attempts SET status='unknown' WHERE id=$1",
            &[&attempt],
        )
        .await
        .unwrap();
    case.f
        .db
        .execute(
            "DELETE FROM dispatch_fences WHERE attempt_id=$1",
            &[&attempt],
        )
        .await
        .unwrap();
    case.f
        .db
        .execute("DELETE FROM message_attempts WHERE id=$1", &[&attempt])
        .await
        .unwrap();
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM conversation_execution_records", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    let session = delivery_identity(&case);
    issue(
        &case,
        &session,
        &request(&case, &session, c.message, Uuid::new_v4(), &envelope),
    )
    .await
    .unwrap();
    assert!(
        case.f
            .db
            .execute(
                "DELETE FROM conversation_confirmation_records WHERE message_id=$1",
                &[&c.message]
            )
            .await
            .is_err()
    );
    let mut db = case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    tx.execute(
        "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
        &[&c.account],
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM conversation_execution_records WHERE account_id=$1",
        &[&c.account],
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM conversation_confirmation_records WHERE account_id=$1",
        &[&c.account],
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM dispatch_fences WHERE account_id=$1",
        &[&c.account],
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM message_attempts WHERE account_id=$1",
        &[&c.account],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; synthetic evidence only, no radio"]
async fn execution_existing_evidence_reconciles_delivery_or_no_radio_without_replacement() {
    use zrotext_domain::{Evidence, MessageState};
    for no_radio in [false, true] {
        let case = prepared().await;
        let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
        case.enqueue(&envelope, &c, &sig).await.unwrap();
        let session = delivery_identity(&case);
        let attempt = Uuid::new_v4();
        let frame = request(&case, &session, c.message, attempt, &envelope);
        issue(&case, &session, &frame).await.unwrap();
        let mut db = case.f.connect().await;
        let events: Vec<_> = if no_radio {
            vec![(Evidence::ProvenNoSubmit, None, None, MessageState::Queued)]
        } else {
            vec![
                (
                    Evidence::DurableSubmitIntent,
                    None,
                    None,
                    MessageState::Submitting,
                ),
                (
                    Evidence::SentCallbackOk,
                    Some(0),
                    Some(1),
                    MessageState::Submitted,
                ),
                (
                    Evidence::DeliveryCallbackOk,
                    None,
                    None,
                    MessageState::Delivered,
                ),
            ]
        };
        for (evidence, segment_index, segment_count, expected) in events {
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
            let actual = zrotext_delivery_store::DeliveryStore::new(&mut db)
                .record_radio_event(zrotext_delivery_store::RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: c.account,
                    device_id: c.device,
                    message_id: c.message,
                    attempt_id: attempt,
                    evidence,
                    observed_at_ms,
                    segment_index,
                    segment_count,
                })
                .await
                .unwrap();
            assert_eq!(actual, expected);
            if expected == MessageState::Submitting {
                assert!(
                    crate::http_owner_conversations::channel::execution::permission::current(
                        &mut case.f.connect().await,
                        &session,
                        c.message,
                        attempt
                    )
                    .await
                    .unwrap()
                );
            }
        }
        assert_eq!(
            case.f
                .db
                .query_one("SELECT count(*) FROM dispatch_fences", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            if no_radio { 0 } else { 1 }
        );
        let before = state(&case).await;
        assert!(matches!(
            issue(
                &case,
                &session,
                &request(&case, &session, c.message, Uuid::new_v4(), &envelope)
            )
            .await,
            Err(ConversationError::Forbidden)
        ));
        assert_eq!(state(&case).await, before);
        if no_radio {
            assert!(
                zrotext_delivery_store::DeliveryStore::new(&mut db)
                    .cancel(c.account, c.message)
                    .await
                    .unwrap()
            );
            assert_eq!(
                case.f
                    .db
                    .query_one(
                        "SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'",
                        &[]
                    )
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                1
            );
        }
        case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_requires_immutable_trusted_metering_receipt_and_original_reservation() {
    // Old proof schema remains usable for queue admission but cannot acquire
    // execution retrospectively when the additive candidate is installed.
    let case = Case::new().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    case.f.db.batch_execute(EXECUTION_SCHEMA).await.unwrap();
    case.f
        .db
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let session = delivery_identity(&case);
    let before = state(&case).await;
    assert!(matches!(
        issue(
            &case,
            &session,
            &request(&case, &session, c.message, Uuid::new_v4(), &envelope)
        )
        .await,
        Err(ConversationError::Forbidden)
    ));
    assert!(
        case.f
            .db
            .execute(
                "UPDATE conversation_confirmation_records SET execution_metered=TRUE",
                &[]
            )
            .await
            .is_err()
    );
    assert_eq!(state(&case).await, before);
    case.f.cleanup().await;
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    let confirmation = c.encode().unwrap();
    enqueue_confirmed_send(
        &mut case.f.connect().await,
        &case.owner,
        case.f.session(),
        false,
        ConfirmedPacket {
            envelope: &envelope,
            confirmation: &confirmation,
            signature: &sig,
        },
    )
    .await
    .unwrap();
    // A changed configuration on exact queue retry cannot rewrite the receipt.
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT execution_metered FROM conversation_confirmation_records",
                &[]
            )
            .await
            .unwrap()
            .get::<_, Option<bool>>(0),
        Some(false)
    );
    assert_eq!(case.counts().await.3, 0);
    let session = delivery_identity(&case);
    issue(
        &case,
        &session,
        &request(&case, &session, c.message, Uuid::new_v4(), &envelope),
    )
    .await
    .unwrap();
    assert_eq!(case.counts().await.3, 0);
    case.f.cleanup().await;
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    assert_eq!(
        case.f
            .db
            .query_one(
                "SELECT execution_metered FROM conversation_confirmation_records",
                &[]
            )
            .await
            .unwrap()
            .get::<_, Option<bool>>(0),
        Some(true)
    );
    case.f
        .db
        .execute("DELETE FROM usage_ledger WHERE entry_kind='reserve'", &[])
        .await
        .unwrap();
    let session = delivery_identity(&case);
    let before = state(&case).await;
    assert!(matches!(
        issue(
            &case,
            &session,
            &request(&case, &session, c.message, Uuid::new_v4(), &envelope)
        )
        .await,
        Err(ConversationError::Forbidden)
    ));
    assert_eq!(state(&case).await, before);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_concurrent_cancellation_commits_either_one_permit_or_one_refund() {
    let case = prepared().await;
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    let session = delivery_identity(&case);
    let frame = request(&case, &session, c.message, Uuid::new_v4(), &envelope);
    let mut grant_db = case.f.connect().await;
    let mut cancel_db = case.f.connect().await;
    let mut cancellation_store = zrotext_delivery_store::DeliveryStore::new(&mut cancel_db);
    let (grant, cancel) = tokio::join!(
        channel::handle(&mut grant_db, &session, &frame),
        cancellation_store.cancel(c.account, c.message)
    );
    let row=case.f.db.query_one("SELECT (SELECT count(*) FROM conversation_execution_records),(SELECT count(*) FROM usage_ledger WHERE entry_kind='refund')",&[]).await.unwrap();
    if grant.is_ok() {
        assert!(matches!(
            cancel,
            Err(zrotext_delivery_store::StoreError::InvalidTransition)
        ));
        assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (1, 0));
    } else {
        assert!(matches!(grant, Err(ConversationError::Forbidden)));
        assert!(cancel.unwrap());
        assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (0, 1));
    }
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_unknown_schema_shape_is_unavailable_and_legacy_proof_cannot_gain_receipt() {
    for changed in 0..2 {
        let case = prepared().await;
        let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
        case.enqueue(&envelope, &c, &sig).await.unwrap();
        let sql = if changed == 0 {
            "ALTER TABLE conversation_confirmation_records ADD COLUMN unrelated bytea"
        } else {
            "ALTER TABLE conversation_execution_records ADD COLUMN unrelated bytea"
        };
        case.f.db.batch_execute(sql).await.unwrap();
        let before = state(&case).await;
        let session = delivery_identity(&case);
        assert!(matches!(
            issue(
                &case,
                &session,
                &request(&case, &session, c.message, Uuid::new_v4(), &envelope)
            )
            .await,
            Err(ConversationError::Forbidden)
        ));
        assert_eq!(state(&case).await, before);
        case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; synthetic evidence only, no radio"]
async fn execution_submit_permission_rechecks_original_proof_session_keys_and_withdrawal() {
    for change in 0..5 {
        let case = prepared().await;
        let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
        case.enqueue(&envelope, &c, &sig).await.unwrap();
        let mut session = delivery_identity(&case);
        let attempt = Uuid::new_v4();
        issue(
            &case,
            &session,
            &request(&case, &session, c.message, attempt, &envelope),
        )
        .await
        .unwrap();
        assert!(
            crate::http_owner_conversations::channel::execution::permission::current(
                &mut case.f.connect().await,
                &session,
                c.message,
                attempt
            )
            .await
            .unwrap()
        );
        match change {
            0 => session.phone_session = Uuid::new_v4(),
            1 => {
                case.f
                    .db
                    .execute("UPDATE sessions SET revoked_at=clock_timestamp()", &[])
                    .await
                    .unwrap();
            }
            2 => {
                case.f
                    .db
                    .execute("UPDATE device_keys SET revoked_at=clock_timestamp()", &[])
                    .await
                    .unwrap();
            }
            3 => {
                case.f.db.execute("UPDATE conversation_confirmation_records SET confirmation=NULL,signature=NULL",&[]).await.unwrap();
            }
            _ => {
                activation::close(
                    &mut case.f.connect().await,
                    &case.owner,
                    case.interval.interval,
                    true,
                )
                .await
                .unwrap();
            }
        }
        assert!(
            !crate::http_owner_conversations::channel::execution::permission::current(
                &mut case.f.connect().await,
                &session,
                c.message,
                attempt
            )
            .await
            .unwrap_or(false)
        );
        if change != 0 {
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
            let before = state(&case).await;
            let mut db = case.f.connect().await;
            assert!(
                zrotext_delivery_store::DeliveryStore::new(&mut db)
                    .record_radio_event(zrotext_delivery_store::RadioEvent {
                        event_id: Uuid::new_v4(),
                        account_id: c.account,
                        device_id: c.device,
                        message_id: c.message,
                        attempt_id: attempt,
                        evidence: zrotext_domain::Evidence::DurableSubmitIntent,
                        observed_at_ms,
                        segment_index: None,
                        segment_count: None,
                    })
                    .await
                    .is_err()
            );
            assert_eq!(state(&case).await, before);
        }
        case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn execution_raw_sql_requires_actual_envelope_reader_not_another_live_key() {
    let case = Case::with_extra_phone_reader(true).await;
    case.f.db.batch_execute(EXECUTION_SCHEMA).await.unwrap();
    case.f
        .db
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let other_reader = case.f.bytes[151..case.f.bytes.len() - 64]
        .chunks_exact(149)
        .find(|entry| entry[0] == 1 && entry[1..33] != case.phone_reader.key_id)
        .unwrap()[1..33]
        .to_vec();
    let (envelope, c, sig) = case.packet(Uuid::new_v4(), 30_000).await;
    case.enqueue(&envelope, &c, &sig).await.unwrap();
    assert!(case.f.db.query_one(
        "SELECT conversation_execution_key_live($1,1,$2,$3,$4,floor(extract(epoch FROM clock_timestamp())*1000)::bigint,$5)",
        &[&case.f.bytes,&other_reader,&c.device,&c.line,&c.expires_ms]
    ).await.unwrap().get::<_,bool>(0));
    let before = state(&case).await;
    let attempt = Uuid::new_v4();
    let insert_sql = "INSERT INTO conversation_execution_records(account_id,message_id,device_id,attempt_id,generation,phone_session,origin_hash,site_id,instance_id, \
        session_epoch,deployment_epoch,reader_key_id,envelope_digest,unsigned_digest,expires_at_ms,segment_count) \
        SELECT p.account_id,p.message_id,p.device_id,$3,1,$4,$5,'manifest-test','fixture',1,1,$6,p.envelope_digest,m.request_digest,p.expires_at_ms,6 \
        FROM conversation_confirmation_records p JOIN messages m ON (m.account_id,m.id)=(p.account_id,p.message_id) \
        WHERE p.account_id=$1 AND p.message_id=$2";
    let phone_session = Uuid::new_v4();
    let origin_hash = vec![9u8; 32];
    let mut db = case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert_eq!(
        tx.execute(
            insert_sql,
            &[
                &c.account,
                &c.message,
                &attempt,
                &phone_session,
                &origin_hash,
                &case.phone_reader.key_id.as_slice()
            ]
        )
        .await
        .unwrap(),
        1
    );
    // The matching raw insert passes the same immediate admission guard. Roll
    // back before its deferred effects requirement; only the reader changes.
    tx.rollback().await.unwrap();
    assert_eq!(state(&case).await, before);
    let error = case
        .f
        .db
        .execute(
            insert_sql,
            &[
                &c.account,
                &c.message,
                &attempt,
                &phone_session,
                &origin_hash,
                &other_reader,
            ],
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    assert_eq!(state(&case).await, before);
    let extracted: Vec<u8> = case
        .f
        .db
        .query_one(
            "SELECT conversation_execution_payload_reader($1::bytea)",
            &[&envelope],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(extracted, case.phone_reader.key_id);
    let mut malformed_envelopes = vec![
        envelope[..10].to_vec(),
        envelope[..envelope.len() - 1].to_vec(),
        [envelope.as_slice(), &[0]].concat(),
    ];
    let protected_end = 10 + u16::from_be_bytes(envelope[8..10].try_into().unwrap()) as usize;
    let body_end = protected_end
        + 16
        + u32::from_be_bytes(
            envelope[protected_end + 12..protected_end + 16]
                .try_into()
                .unwrap(),
        ) as usize;
    for offset in [
        4,
        5,
        6,
        8,
        163,
        protected_end + 12,
        body_end,
        body_end + 1,
        body_end + 147,
    ] {
        let mut changed = envelope.clone();
        changed[offset] ^= 0xff;
        malformed_envelopes.push(changed);
    }
    for malformed in malformed_envelopes {
        assert!(
            case.f
                .db
                .query_one(
                    "SELECT conversation_execution_payload_reader($1::bytea) IS NULL",
                    &[&malformed]
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
    }
    let session = delivery_identity(&case);
    let frame = request(&case, &session, c.message, attempt, &envelope);
    let reply = issue(&case, &session, &frame).await.unwrap();
    assert_eq!(
        fields(&reply, &frame)["reader_key_id"],
        URL_SAFE_NO_PAD.encode(case.phone_reader.key_id)
    );
    case.f.cleanup().await;
}
