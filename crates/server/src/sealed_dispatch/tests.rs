// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_outbound::{admit_candidate02_with_limit, tests::TestCase};
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use zrotext_delivery_store::{DeliveryStore, RadioEvent};
use zrotext_domain::Evidence;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn device_revocation_serializes_without_deadlock_with_grant_fetch_and_first_intent() {
    for operation in ["grant", "fetch", "intent"] {
        let case = Case::new(Some(1)).await;
        let frame = if operation == "grant" {
            None
        } else {
            case.grant().await.unwrap()
        };
        let request = frame.clone().map(|frame| case.request(frame));
        let observed = case
            .admission
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let mut blocker = case.admission.connect().await;
        let revocation = blocker.transaction().await.unwrap();
        revocation
            .execute(
                "UPDATE devices SET revoked_at=clock_timestamp() WHERE id=$1",
                &[&case.admission.device],
            )
            .await
            .unwrap();
        let mut connection = case.admission.connect().await;
        let pid: i32 = connection
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let execute = async {
            match operation {
                "grant" => grant(&mut connection, &case.session, &case.ready, &case.policy)
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("{error:?}")),
                "fetch" => fetch(
                    &mut connection,
                    request.as_ref().unwrap(),
                    "manifest-test",
                    1,
                    &case.policy,
                )
                .await
                .map(|_| ())
                .map_err(|error| format!("{error:?}")),
                _ => DeliveryStore::new(&mut connection)
                    .record_radio_event(RadioEvent {
                        event_id: Uuid::new_v4(),
                        account_id: case.admission.account,
                        device_id: case.admission.device,
                        message_id: case.message,
                        attempt_id: frame.as_ref().unwrap().attempt_id,
                        evidence: Evidence::DurableSubmitIntent,
                        observed_at_ms: observed,
                        segment_index: None,
                        segment_count: None,
                    })
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("{error:?}")),
            }
        };
        let revoke = async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let waiting: bool = case.admission.db.query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
                        &[&pid],
                    ).await.unwrap().get(0);
                    if waiting { break; }
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            revocation
                .execute(
                    "UPDATE device_keys SET revoked_at=clock_timestamp() WHERE device_id=$1",
                    &[&case.admission.device],
                )
                .await
                .unwrap();
            revocation
                .execute(
                    "DELETE FROM device_sessions WHERE device_id=$1",
                    &[&case.admission.device],
                )
                .await
                .unwrap();
            revocation.commit().await.unwrap();
        };
        let (result, ()) = tokio::join!(execute, revoke);
        let error = result.expect_err("revocation must fence new execution");
        assert!(!error.contains("40P01"), "{operation} deadlocked: {error}");
        let row = case.admission.db.query_one(
            "SELECT (SELECT count(*) FROM device_sessions), (SELECT count(*) FROM message_attempts), \
             (SELECT count(*) FROM message_events WHERE evidence_code='durable_intent')", &[],
        ).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 0);
        assert_eq!(row.get::<_, i64>(1), i64::from(operation != "grant"));
        assert_eq!(row.get::<_, i64>(2), 0);
        case.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn intent_that_expires_during_final_fence_write_rolls_back_all_effects() {
    let case = Case::new(Some(1)).await;
    let frame = case.grant().await.unwrap().unwrap();
    case.fetch(&case.request(frame.clone())).await.unwrap();
    case.admission.db.batch_execute(
        "CREATE FUNCTION delay_sealed_intent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
           PERFORM pg_sleep(GREATEST(0,extract(epoch FROM OLD.grant_expires_at-clock_timestamp()))+0.01);
           RETURN NEW; END $$;
         CREATE TRIGGER delay_sealed_intent BEFORE UPDATE OF outcome ON dispatch_fences
           FOR EACH ROW WHEN (NEW.outcome='submitting') EXECUTE FUNCTION delay_sealed_intent();"
    ).await.unwrap();
    let observed = case
        .admission
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let intent = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: frame.account_id,
        device_id: frame.device_id,
        message_id: frame.message_id,
        attempt_id: frame.attempt_id,
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: observed,
        segment_index: None,
        segment_count: None,
    };
    let mut connection = case.admission.connect().await;
    // This isolated fault-injection write intentionally spans the 30s grant.
    connection
        .batch_execute("SET statement_timeout='45s'")
        .await
        .unwrap();
    let result = DeliveryStore::new(&mut connection)
        .record_radio_event(intent)
        .await;
    assert!(
        matches!(result, Err(zrotext_delivery_store::StoreError::StaleFence)),
        "{result:?}"
    );
    let row = case.admission.db.query_one(
        "SELECT state,(SELECT outcome FROM dispatch_fences),(SELECT count(*) FROM message_events WHERE id=$1) FROM messages WHERE id=$2",
        &[&intent.event_id, &case.message]
    ).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "claimed");
    assert_eq!(row.get::<_, String>(1), "granted");
    assert_eq!(row.get::<_, i64>(2), 0);
    case.cleanup().await;
}

struct Case {
    admission: TestCase,
    enrollment: SigningKey,
    session: SessionRecord,
    ready: Ready,
    policy: AlphaPolicy,
    message: Uuid,
    bytes: Vec<u8>,
}

impl Case {
    async fn new(limit: Option<u8>) -> Self {
        let admission = TestCase::new().await;
        admission
            .db
            .batch_execute("UPDATE deployment_authority SET dispatch_enabled=true")
            .await
            .unwrap();
        let enrollment = SigningKey::generate_from_rng(&mut rand::rng());
        let point = enrollment.verifying_key().to_sec1_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(point.as_bytes()).into();
        admission
            .db
            .execute(
                "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
                &[
                    &admission.device,
                    &point.as_bytes(),
                    &fingerprint.as_slice(),
                ],
            )
            .await
            .unwrap();
        let message = Uuid::new_v4();
        let bytes = admission.envelope(message).await;
        admit_candidate02_with_limit(
            &mut admission.connect().await,
            &admission.principal,
            &admission.hasher,
            admission.writer(),
            &bytes,
            limit,
        )
        .await
        .unwrap();
        let session = SessionRecord {
            account_id: admission.account,
            device_id: admission.device,
            site_id: "manifest-test".into(),
            instance_id: "fixture".into(),
            epoch: 1,
            deployment_epoch: 1,
        };
        let ready = Ready {
            grant_version: 1,
            connection_epoch: 1,
            line_id: admission.line,
            binding_generation: 1,
            reader_key_id: URL_SAFE_NO_PAD.encode(admission.readers[0].key_id),
        };
        let policy = AlphaPolicy::parse(
            Some("true"),
            Some(&admission.account.to_string()),
            Some("+12"),
        )
        .unwrap();
        Self {
            admission,
            enrollment,
            session,
            ready,
            policy,
            message,
            bytes,
        }
    }

    async fn grant(&self) -> Result<Option<GrantFrame>, Error> {
        grant(
            &mut self.admission.connect().await,
            &self.session,
            &self.ready,
            &self.policy,
        )
        .await
    }

    fn request(&self, grant: GrantFrame) -> Fetch {
        let signature: Signature = self
            .enrollment
            .sign(&wire::fetch_transcript(&grant).unwrap());
        Fetch {
            grant,
            signature_der: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        }
    }

    async fn fetch(&self, request: &Fetch) -> Result<Vec<u8>, Error> {
        fetch(
            &mut self.admission.connect().await,
            request,
            "manifest-test",
            1,
            &self.policy,
        )
        .await
    }

    async fn cleanup(self) {
        self.admission.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn exact_sealed_grant_fetch_and_one_use_intent_reuse_existing_recovery() {
    let case = Case::new(Some(2)).await;
    let frame = case.grant().await.unwrap().unwrap();
    assert_eq!(frame.segment_count, 2);
    assert_eq!(frame.message_id, case.message);
    assert_eq!(
        wire::digest(&frame.envelope_sha256).unwrap(),
        <[u8; 32]>::from(Sha256::digest(&case.bytes))
    );
    assert!(case.grant().await.unwrap().is_none());
    let request = case.request(frame.clone());
    assert_eq!(case.fetch(&request).await.unwrap(), case.bytes);
    assert_eq!(case.fetch(&request).await.unwrap(), case.bytes);
    let mut connection = case.admission.connect().await;
    let mut store = DeliveryStore::new(&mut connection);
    let observed = case
        .admission
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let intent = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: frame.account_id,
        device_id: frame.device_id,
        message_id: frame.message_id,
        attempt_id: frame.attempt_id,
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: observed,
        segment_index: None,
        segment_count: None,
    };
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        zrotext_domain::MessageState::Submitting
    );
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        zrotext_domain::MessageState::Submitting
    );
    assert!(case.fetch(&request).await.is_err());
    assert!(case.grant().await.unwrap().is_none());
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn missing_declaration_or_disabled_policy_never_creates_a_sealed_attempt() {
    let case = Case::new(None).await;
    assert!(case.grant().await.unwrap().is_none());
    let disabled = AlphaPolicy::parse(None, None, None).unwrap();
    assert!(
        grant(
            &mut case.admission.connect().await,
            &case.session,
            &case.ready,
            &disabled
        )
        .await
        .unwrap()
        .is_none()
    );
    let count: i64 = case
        .admission
        .db
        .query_one("SELECT count(*) FROM message_attempts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn fetch_refuses_resigned_scope_digest_epoch_and_reader_substitution() {
    let case = Case::new(Some(1)).await;
    let frame = case.grant().await.unwrap().unwrap();
    for index in 0..8 {
        let mut changed = frame.clone();
        match index {
            0 => changed.account_id = Uuid::new_v4(),
            1 => changed.device_id = Uuid::new_v4(),
            2 => changed.line_id = Uuid::new_v4(),
            3 => changed.message_id = Uuid::new_v4(),
            4 => changed.connection_epoch += 1,
            5 => changed.attempt_id = Uuid::new_v4(),
            6 => changed.reader_key_id = URL_SAFE_NO_PAD.encode([2; 32]),
            7 => changed.envelope_sha256 = URL_SAFE_NO_PAD.encode([3; 32]),
            _ => unreachable!(),
        }
        assert!(case.fetch(&case.request(changed)).await.is_err());
    }
    assert_eq!(case.fetch(&case.request(frame)).await.unwrap(), case.bytes);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn root_device_binding_and_reconnect_revocation_fence_retrieval() {
    for statement in [
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()",
        "UPDATE device_keys SET revoked_at=clock_timestamp()",
        "UPDATE device_sessions SET connection_epoch=connection_epoch+1",
        "UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second'",
        "UPDATE device_line_bindings SET state='revoked'",
    ] {
        let case = Case::new(Some(1)).await;
        let frame = case.grant().await.unwrap().unwrap();
        case.admission.db.batch_execute(statement).await.unwrap();
        assert!(case.fetch(&case.request(frame)).await.is_err());
        assert!(case.grant().await.is_err());
        case.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn cancel_that_wins_pre_grant_is_terminal_and_grant_that_wins_cannot_cancel() {
    let case = Case::new(Some(1)).await;
    let mut connection = case.admission.connect().await;
    let mut store = DeliveryStore::new(&mut connection);
    assert!(
        store
            .cancel(case.admission.account, case.message)
            .await
            .unwrap()
    );
    assert!(case.grant().await.unwrap().is_none());
    case.cleanup().await;
    let case = Case::new(Some(1)).await;
    let frame = case.grant().await.unwrap().unwrap();
    let mut connection = case.admission.connect().await;
    let mut store = DeliveryStore::new(&mut connection);
    assert!(
        store
            .cancel(case.admission.account, case.message)
            .await
            .is_err()
    );
    assert_eq!(case.fetch(&case.request(frame)).await.unwrap(), case.bytes);
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn concurrent_cancel_and_grant_have_one_atomic_winner() {
    for _ in 0..4 {
        let case = Case::new(Some(1)).await;
        let mut connection = case.admission.connect().await;
        let mut store = DeliveryStore::new(&mut connection);
        let (issued, cancelled) = tokio::join!(
            case.grant(),
            store.cancel(case.admission.account, case.message),
        );
        let issued = issued.unwrap();
        assert_ne!(issued.is_some(), cancelled.is_ok_and(|value| value));
        let row = case
            .admission
            .db
            .query_one(
                "SELECT (SELECT count(*) FROM dispatch_fences), \
             (SELECT count(*) FROM usage_ledger WHERE entry_kind='refund')",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), i64::from(issued.is_some()));
        assert_eq!(row.get::<_, i64>(1), i64::from(issued.is_none()));
        case.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn stale_authority_after_fetch_blocks_new_intent_but_preserves_prior_receipts() {
    for invalidation in [
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()",
        "UPDATE sealed_manifest_authorities SET last_verified_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+60000",
    ] {
        for revoke_before_intent in [true, false] {
            let case = Case::new(Some(1)).await;
            let frame = case.grant().await.unwrap().unwrap();
            assert_eq!(
                case.fetch(&case.request(frame.clone())).await.unwrap(),
                case.bytes
            );
            let observed = case
                .admission
                .db
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            let intent = RadioEvent {
                event_id: Uuid::new_v4(),
                account_id: frame.account_id,
                device_id: frame.device_id,
                message_id: frame.message_id,
                attempt_id: frame.attempt_id,
                evidence: Evidence::DurableSubmitIntent,
                observed_at_ms: observed,
                segment_index: None,
                segment_count: None,
            };
            let mut connection = case.admission.connect().await;
            let mut store = DeliveryStore::new(&mut connection);
            if !revoke_before_intent {
                store.record_radio_event(intent).await.unwrap();
            }
            case.admission.db.batch_execute(invalidation).await.unwrap();
            let result = store.record_radio_event(intent).await;
            if revoke_before_intent {
                assert!(result.is_err());
                let state: String = case
                    .admission
                    .db
                    .query_one("SELECT state FROM messages WHERE id=$1", &[&case.message])
                    .await
                    .unwrap()
                    .get(0);
                assert_eq!(state, "claimed");
            } else {
                assert_eq!(result.unwrap(), zrotext_domain::MessageState::Submitting);
                let callback = RadioEvent {
                    event_id: Uuid::new_v4(),
                    evidence: Evidence::SentCallbackOk,
                    segment_index: Some(0),
                    segment_count: Some(2),
                    ..intent
                };
                assert!(store.record_radio_event(callback).await.is_err());
                assert_eq!(
                    store
                        .record_radio_event(RadioEvent {
                            event_id: Uuid::new_v4(),
                            segment_count: Some(1),
                            ..callback
                        })
                        .await
                        .unwrap(),
                    zrotext_domain::MessageState::Submitted
                );
            }
            case.cleanup().await;
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn withdrawal_that_wins_account_lock_prevents_grant_and_refetch() {
    for before_grant in [true, false] {
        let case = Case::new(Some(1)).await;
        let frame = if before_grant {
            None
        } else {
            case.grant().await.unwrap()
        };
        let mut blocker = case.admission.connect().await;
        let lock = blocker.transaction().await.unwrap();
        lock.query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&case.admission.account],
        )
        .await
        .unwrap();
        let mut connection = case.admission.connect().await;
        let pid: i32 = connection
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let request = frame.map(|value| case.request(value));
        let operation = async {
            if let Some(request) = &request {
                fetch(&mut connection, request, "manifest-test", 1, &case.policy)
                    .await
                    .map(|_| ())
            } else {
                grant(&mut connection, &case.session, &case.ready, &case.policy)
                    .await
                    .map(|_| ())
            }
        };
        let withdraw = async {
            tokio::time::timeout(std::time::Duration::from_secs(10),async {
                loop {
                    let waiting:bool=case.admission.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM accounts%')",&[&pid]).await.unwrap().get(0);
                    if waiting { break; }
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            lock.execute("INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) VALUES($1,$2,'+12','email','opt_out',clock_timestamp(),$3)",
                &[&Uuid::new_v4(),&case.admission.account,&case.admission.user]).await.unwrap();
            lock.commit().await.unwrap();
        };
        let (result, ()) = tokio::join!(operation, withdraw);
        assert!(result.is_err());
        let count: i64 = case
            .admission
            .db
            .query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, i64::from(!before_grant));
        case.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn declaration_and_grant_provenance_are_immutable_and_require_reserved_usage() {
    let case = Case::new(Some(2)).await;
    for limit in [None, Some(1), Some(3)] {
        assert!(
            admit_candidate02_with_limit(
                &mut case.admission.connect().await,
                &case.admission.principal,
                &case.admission.hasher,
                case.admission.writer(),
                &case.bytes,
                limit
            )
            .await
            .is_err()
        );
    }
    let frame = case.grant().await.unwrap().unwrap();
    for sql in [
        "UPDATE messages SET sealed_segment_limit=3",
        "UPDATE sealed_grant_authorizations SET reader_key_id=decode(repeat('00',32),'hex')",
        "UPDATE dispatch_fences SET grant_expires_at=clock_timestamp()+interval '1 hour'",
        "UPDATE dispatch_fences SET session_epoch=session_epoch+1",
    ] {
        assert_eq!(
            case.admission
                .db
                .batch_execute(sql)
                .await
                .unwrap_err()
                .as_db_error()
                .unwrap()
                .code()
                .code(),
            "23514"
        );
    }
    assert_eq!(case.fetch(&case.request(frame)).await.unwrap(), case.bytes);
    case.cleanup().await;
    let case = Case::new(Some(1)).await;
    case.admission
        .db
        .batch_execute("DELETE FROM usage_ledger")
        .await
        .unwrap();
    assert!(case.grant().await.is_err());
    let row=case.admission.db.query_one("SELECT (SELECT count(*) FROM message_attempts),(SELECT count(*) FROM sealed_grant_authorizations),state FROM messages",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, String>(2), "queued");
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn expired_grant_becomes_unknown_without_automatic_resend() {
    let case = Case::new(Some(1)).await;
    let frame = case.grant().await.unwrap().unwrap();
    let observed: i64 = case
        .admission
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    tokio::time::sleep(std::time::Duration::from_millis(
        u64::try_from(frame.expires_at_ms - observed + 2).unwrap(),
    ))
    .await;
    assert!(case.fetch(&case.request(frame)).await.is_err());
    let mut connection = case.admission.connect().await;
    let mut store = DeliveryStore::new(&mut connection);
    assert_eq!(store.reconcile_silent_attempts(1).await.unwrap(), 1);
    assert!(case.grant().await.unwrap().is_none());
    let row=case.admission.db.query_one("SELECT (SELECT count(*) FROM message_attempts),state,(SELECT outcome FROM dispatch_fences) FROM messages",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, String>(1), "unknown");
    assert_eq!(row.get::<_, String>(2), "unknown");
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn reconnect_that_wins_session_lock_blocks_first_intent_after_fetch() {
    let case = Case::new(Some(1)).await;
    let frame = case.grant().await.unwrap().unwrap();
    case.fetch(&case.request(frame.clone())).await.unwrap();
    let mut blocker = case.admission.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one(
        "SELECT device_id FROM device_sessions WHERE device_id=$1 FOR UPDATE",
        &[&case.admission.device],
    )
    .await
    .unwrap();
    let mut connection = case.admission.connect().await;
    let pid: i32 = connection
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let observed = case
        .admission
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let intent = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: frame.account_id,
        device_id: frame.device_id,
        message_id: frame.message_id,
        attempt_id: frame.attempt_id,
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: observed,
        segment_index: None,
        segment_count: None,
    };
    let mut store = DeliveryStore::new(&mut connection);
    let reconnect = async {
        tokio::time::timeout(std::time::Duration::from_secs(10),async {
            loop {
                let waiting:bool=case.admission.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT g.attempt_id FROM sealed_grant_authorizations%')",&[&pid]).await.unwrap().get(0);
                if waiting { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        lock.execute(
            "UPDATE device_sessions SET connection_epoch=connection_epoch+1 WHERE device_id=$1",
            &[&case.admission.device],
        )
        .await
        .unwrap();
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(store.record_radio_event(intent), reconnect);
    assert!(result.is_err());
    let state: String = case
        .admission
        .db
        .query_one("SELECT state FROM messages WHERE id=$1", &[&case.message])
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "claimed");
    case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated disposable schema"]
async fn execution_candidate_preserves_ordinary_sealed_grant_fetch_and_intent() {
    let case = Case::new(Some(2)).await;
    for dependency in [
        include_str!("../../../../deploy/compose/migrations/064_owner_conversation_consent.sql"),
        include_str!("../../../../deploy/compose/migrations/065_conversation_activation.sql"),
        include_str!(
            "../../../../deploy/compose/migrations/072_conversation_confirmation_records.sql"
        ),
    ] {
        case.admission.db.batch_execute(dependency).await.unwrap();
    }
    case.admission
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migration-candidates/NNN_conversation_execution_records.sql"
        ))
        .await
        .unwrap();
    let frame = case.grant().await.unwrap().unwrap();
    assert_eq!(frame.segment_count, 2);
    assert_eq!(frame.message_id, case.message);
    assert_eq!(
        wire::digest(&frame.envelope_sha256).unwrap(),
        <[u8; 32]>::from(Sha256::digest(&case.bytes))
    );
    assert!(case.grant().await.unwrap().is_none());
    let request = case.request(frame.clone());
    assert_eq!(case.fetch(&request).await.unwrap(), case.bytes);
    assert_eq!(case.fetch(&request).await.unwrap(), case.bytes);
    let mut connection = case.admission.connect().await;
    let mut store = DeliveryStore::new(&mut connection);
    let observed = case
        .admission
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let intent = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: frame.account_id,
        device_id: frame.device_id,
        message_id: frame.message_id,
        attempt_id: frame.attempt_id,
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: observed,
        segment_index: None,
        segment_count: None,
    };
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        zrotext_domain::MessageState::Submitting
    );
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        zrotext_domain::MessageState::Submitting
    );
    assert!(case.fetch(&request).await.is_err());
    assert!(case.grant().await.unwrap().is_none());
    case.cleanup().await;
}
