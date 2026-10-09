// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::context::decisions::tests::Case;
use contracts::{AllocationMutation, Offer, OpeningMutation, Reserve, Source};
use futures_util::FutureExt;
use sha2::{Digest, Sha256};

async fn fixture() -> Case {
    Case::new().await
}
fn source(c: &Case) -> Source {
    Source {
        context_id: c.base.h.context,
        revision: c.base.h.revision,
        digest: Sha256::digest(c.base.bytes())
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect(),
    }
}
async fn opening(c: &Case, capacity: i16) -> Outcome {
    let now: i64 = c
        .base
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    create(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Create {
            request_id: Uuid::new_v4(),
            opening_id: Uuid::new_v4(),
            capacity,
            description: source(c),
            decision_deadline_ms: (now + 30000).min(c.base.h.expires_ms - 1000),
        },
    )
    .await
    .unwrap()
}
async fn offered(c: &Case, key: OpeningKey) -> Outcome {
    offered_source(c, key, source(c)).await
}
async fn offered_source(c: &Case, key: OpeningKey, selected: Source) -> Outcome {
    let deadline: i64 = c
        .base
        .f
        .db
        .query_one(
            "SELECT decision_deadline_ms FROM workflow_openings WHERE account_id=$1 AND id=$2",
            &[&c.base.f.account, &key.opening_id],
        )
        .await
        .unwrap()
        .get::<_, Option<i64>>(0)
        .unwrap();
    offer(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Offer {
            request_id: Uuid::new_v4(),
            opening: key,
            offer_id: Uuid::new_v4(),
            contact_id: c.contact,
            purpose: contracts::Purpose::Transactional,
            source: selected,
            expires_ms: deadline - 1000,
        },
    )
    .await
    .unwrap()
}

async fn independent_source(c: &Case) -> Source {
    let mut header = c.base.h.clone();
    header.context = Uuid::new_v4();
    header.expires_ms = c.base.s.expires_ms;
    let bytes = crate::http_owner_conversations::context::tests::Case::envelope(&header, 99);
    crate::http_owner_conversations::context::write(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        0,
        &bytes,
    )
    .await
    .unwrap();
    Source {
        context_id: header.context,
        revision: header.revision,
        digest: Sha256::digest(bytes)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect(),
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual current head and signed capture negatives"]
async fn wrong_source_head_digest_peer_or_signature_has_no_allocation_effect() {
    let c = fixture().await;
    for wrong_revision in [true, false] {
        let mut description = source(&c);
        if wrong_revision {
            description.revision += 1;
        } else {
            description.digest = "ab".repeat(32);
        }
        assert!(matches!(
            create(
                &mut c.base.f.connect().await,
                &c.base.owner,
                Create {
                    request_id: Uuid::new_v4(),
                    opening_id: Uuid::new_v4(),
                    capacity: 1,
                    description,
                    decision_deadline_ms: c.base.h.expires_ms - 1000
                }
            )
            .await,
            Err(ConversationError::Conflict)
        ));
    }
    assert_eq!(
        c.base
            .f
            .db
            .query_one("SELECT count(*) FROM workflow_openings", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let created = opening(&c, 1).await;
    let offered = offered(&c, created.receipt.opening).await;
    let wrong_event = Uuid::new_v4();
    // A second peer cannot acquire this active interval. Exercise an actually
    // signed wrong-peer packet through maintained capture admission instead.
    assert!(matches!(
        crate::http_owner_conversations::activation::tests::capture(
            &c.base.f,
            &c.base.s,
            wrong_event,
            1,
            b"+13",
        )
        .await,
        Err(crate::sealed_inbound::ingest::IngestError::Conversation(
            ConversationError::Forbidden
        ))
    ));
    assert_eq!(c.base.f.db.query_one(
        "SELECT count(*) FROM conversation_inbound_provenance WHERE account_id=$1 AND event_id=$2",
        &[&c.base.f.account, &wrong_event]
    ).await.unwrap().get::<_, i64>(0), 0);
    let wrong = Reserve {
        request_id: Uuid::new_v4(),
        opening: offered.receipt.opening,
        offer: offered.receipt.offer.unwrap(),
        allocation_id: Uuid::new_v4(),
        event_id: wrong_event,
        // Admission refused the signed packet, so no retained digest exists.
        // Any nonzero claimed digest must still fail exact event lookup.
        event_digest: "ab".repeat(32),
    };
    assert!(matches!(
        reserve(&mut c.base.f.connect().await, &c.base.owner, wrong).await,
        Err(ConversationError::NotFound)
    ));
    let event = Uuid::new_v4();
    let mut bytes = crate::http_owner_conversations::activation::tests::capture(
        &c.base.f,
        &c.base.s,
        event,
        2,
        c.base.s.peer.as_bytes(),
    )
    .await
    .unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(
        crate::sealed_inbound::ingest::ingest_conversation(
            &mut c.base.f.connect().await,
            c.base.f.session(),
            c.base.f.line,
            1,
            &c.base.f.bytes,
            &bytes,
            crate::http_owner_conversations::activation::CaptureInterval {
                interval: c.base.s.interval,
                activation_digest: c.base.s.activation_digest
            }
        )
        .await,
        Err(crate::sealed_inbound::ingest::IngestError::Verification(_))
    ));
    let wrong = Reserve {
        request_id: Uuid::new_v4(),
        opening: offered.receipt.opening,
        offer: offered.receipt.offer.unwrap(),
        allocation_id: Uuid::new_v4(),
        event_id: event,
        event_digest: Sha256::digest(bytes)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect(),
    };
    assert!(matches!(
        reserve(&mut c.base.f.connect().await, &c.base.owner, wrong).await,
        Err(ConversationError::Forbidden)
    ));
    let request = reservation(
        &c,
        offered.receipt.opening,
        offered.receipt.offer.unwrap(),
        3,
    )
    .await;
    let mut next = c.base.h.clone();
    next.revision += 1;
    let bytes = crate::http_owner_conversations::context::tests::Case::envelope(&next, 100);
    crate::http_owner_conversations::context::write(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        1,
        &bytes,
    )
    .await
    .unwrap();
    assert!(matches!(
        reserve(&mut c.base.f.connect().await, &c.base.owner, request).await,
        Err(ConversationError::Conflict)
    ));
    let row=c.base.f.db.query_one("SELECT (SELECT count(*) FROM workflow_opening_allocations),(SELECT count(*) FROM workflow_opening_requests)",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 2);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual source purge and deletion"]
async fn description_purge_cancels_dependent_pending_but_preserves_other_source_bindings_and_confirmed_units()
 {
    let mut c = fixture().await;
    let now: i64 = c
        .base
        .f
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    // Expiry is an immutable context binding: create a new real short-lived
    // source rather than rewriting the persisted deadline or its guard.
    c.base.h.context = Uuid::new_v4();
    c.base.h.expires_ms = now + 30000;
    crate::http_owner_conversations::context::write(
        &mut c.base.f.connect().await,
        &c.base.owner,
        Uuid::new_v4(),
        0,
        &c.base.bytes(),
    )
    .await
    .unwrap();
    let created = opening(&c, 3).await;
    let first = offered(&c, created.receipt.opening).await;
    let request = reservation(&c, first.receipt.opening, first.receipt.offer.unwrap(), 1).await;
    let reserved = reserve(&mut c.base.f.connect().await, &c.base.owner, request)
        .await
        .unwrap();
    let confirmed = confirm(
        &mut c.base.f.connect().await,
        &c.base.owner,
        allocation(&reserved),
    )
    .await
    .unwrap();
    let other = independent_source(&c).await;
    let second = offered_source(&c, confirmed.receipt.opening, other.clone()).await;
    let request = reservation(&c, second.receipt.opening, second.receipt.offer.unwrap(), 2).await;
    let pending = reserve(&mut c.base.f.connect().await, &c.base.owner, request)
        .await
        .unwrap();
    loop {
        let now: i64 = c
            .base
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        if now >= c.base.h.expires_ms {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        crate::http_owner_conversations::context::lifecycle::prune(
            &mut c.base.f.connect().await,
            0,
            500
        )
        .await
        .unwrap(),
        1
    );
    let state = status(
        &mut c.base.f.connect().await,
        &c.base.owner,
        created.receipt.opening.opening_id,
    )
    .await
    .unwrap();
    assert_eq!((state.pending, state.confirmed), (0, 1));
    let row=c.base.f.db.query_one("SELECT binding_scrubbed,context_id,contact_identity FROM workflow_opening_offers WHERE account_id=$1 AND id=$2", &[&c.base.f.account,&second.receipt.offer.unwrap().offer_id]).await.unwrap();
    assert!(!row.get::<_, bool>(0));
    assert_eq!(row.get::<_, Option<Uuid>>(1), Some(other.context_id));
    assert_eq!(row.get::<_, Option<Uuid>>(2), Some(c.contact));
    let row=c.base.f.db.query_one("SELECT phase,binding_scrubbed,offer_id FROM workflow_opening_allocations WHERE account_id=$1 AND id=$2", &[&c.base.f.account,&pending.receipt.allocation_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert!(!row.get::<_, bool>(1));
    assert_eq!(
        row.get::<_, Option<Uuid>>(2),
        Some(second.receipt.offer.unwrap().offer_id)
    );
    let fields=c.base.f.db.query_one("SELECT description_context_id,description_revision,description_digest,decision_deadline_ms,created_by_user,created_session,created_ms FROM workflow_openings WHERE account_id=$1 AND id=$2", &[&c.base.f.account,&created.receipt.opening.opening_id]).await.unwrap();
    for i in [0, 4, 5] {
        assert!(fields.get::<_, Option<Uuid>>(i).is_none());
    }
    for i in [1, 3, 6] {
        assert!(fields.get::<_, Option<i64>>(i).is_none());
    }
    assert!(fields.get::<_, Option<Vec<u8>>>(2).is_none());
    assert_eq!(
        crate::http_owner_conversations::context::lifecycle::prune(
            &mut c.base.f.connect().await,
            0,
            500
        )
        .await
        .unwrap(),
        1
    );
    assert!(
        c.base
            .f
            .db
            .query_opt(
                "SELECT id FROM workflow_contexts WHERE account_id=$1 AND id=$2",
                &[&c.base.f.account, &c.base.h.context]
            )
            .await
            .unwrap()
            .is_none()
    );
    let view = export::export(&mut c.base.f.connect().await, &c.base.owner, [None; 4])
        .await
        .unwrap();
    assert!(
        !serde_json::to_string(&view)
            .unwrap()
            .contains(&c.base.h.context.to_string())
    );
    let mut reduced = allocation(&confirmed);
    reduced.opening = state.opening;
    let released = release(&mut c.base.f.connect().await, &c.base.owner, reduced)
        .await
        .unwrap();
    assert_eq!(released.receipt.confirmed, 0);
    c.cleanup().await;
}
async fn reservation(
    c: &Case,
    key: OpeningKey,
    offered: contracts::OfferKey,
    sequence: u64,
) -> Reserve {
    let event = c.capture(sequence).await;
    let bytes: Vec<u8> = c
        .base
        .f
        .db
        .query_one(
            "SELECT envelope FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
            &[&c.base.f.account, &event],
        )
        .await
        .unwrap()
        .get::<_, Option<Vec<u8>>>(0)
        .unwrap();
    Reserve {
        request_id: Uuid::new_v4(),
        opening: key,
        offer: offered,
        allocation_id: Uuid::new_v4(),
        event_id: event,
        event_digest: Sha256::digest(bytes)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect(),
    }
}
fn allocation(out: &Outcome) -> AllocationMutation {
    AllocationMutation {
        request_id: Uuid::new_v4(),
        opening: out.receipt.opening,
        allocation_id: out.receipt.allocation_id.unwrap(),
        allocation_version: out.receipt.allocation_version.unwrap(),
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual isolated candidate schema"]
async fn provenance_mismatch_takeover_and_regrant_cannot_create_or_revive_capacity() {
    for takeover in [true, false] {
        let c = fixture().await;
        let created = opening(&c, 1).await;
        let offered = offered(&c, created.receipt.opening).await;
        let mut request = reservation(
            &c,
            offered.receipt.opening,
            offered.receipt.offer.unwrap(),
            1,
        )
        .await;
        let correct = request.event_digest.clone();
        request.event_digest = "ab".repeat(32);
        assert!(
            reserve(
                &mut c.base.f.connect().await,
                &c.base.owner,
                request.clone()
            )
            .await
            .is_err()
        );
        assert_eq!(
            status(
                &mut c.base.f.connect().await,
                &c.base.owner,
                created.receipt.opening.opening_id
            )
            .await
            .unwrap()
            .pending,
            0
        );
        request.request_id = Uuid::new_v4();
        request.event_digest = correct;
        let reserved = reserve(&mut c.base.f.connect().await, &c.base.owner, request)
            .await
            .unwrap();
        if takeover {
            crate::http_owner_conversations::context::decisions::responses::takeover(
                &mut c.base.f.connect().await,
                &c.base.owner,
                Uuid::new_v4(),
                c.base.h.context,
            )
            .await
            .unwrap();
        } else {
            let mut db = c.base.f.connect().await;
            let tx = db.transaction().await.unwrap();
            owner_context::lock_owner(&tx, &c.base.owner).await.unwrap();
            tx.query_one(
                "SELECT id FROM contacts WHERE account_id=$1 AND id=$2 FOR UPDATE",
                &[&c.base.f.account, &c.contact],
            )
            .await
            .unwrap();
            tx.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'transactional','withdraw','manual_entry',clock_timestamp(),$4)", &[&Uuid::new_v4(),&c.base.f.account,&c.contact,&c.base.owner.user_id]).await.unwrap();
            crate::workflow_runtime::lifecycle::consent::withdraw(
                &tx,
                c.base.f.account,
                c.contact,
                "transactional",
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            c.base.f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'transactional','grant','manual_entry',clock_timestamp(),$4)", &[&Uuid::new_v4(),&c.base.f.account,&c.contact,&c.base.owner.user_id]).await.unwrap();
        }
        assert!(
            confirm(
                &mut c.base.f.connect().await,
                &c.base.owner,
                allocation(&reserved)
            )
            .await
            .is_err()
        );
        let state = status(
            &mut c.base.f.connect().await,
            &c.base.owner,
            created.receipt.opening.opening_id,
        )
        .await
        .unwrap();
        assert_eq!((state.pending, state.confirmed), (0, 0));
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual isolated candidate schema"]
async fn owner_loss_during_observed_account_lock_wait_rolls_back_every_allocation() {
    for revoke in [true, false] {
        let c = fixture().await;
        let created = opening(&c, 1).await;
        let offered = offered(&c, created.receipt.opening).await;
        let request = reservation(
            &c,
            offered.receipt.opening,
            offered.receipt.offer.unwrap(),
            1,
        )
        .await;
        let mut blocker = c.base.f.connect().await;
        let hold = blocker.transaction().await.unwrap();
        hold.query_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[&c.base.f.account],
        )
        .await
        .unwrap();
        let mut waiting = c.base.f.connect().await;
        waiting
            .batch_execute("SET application_name='synthetic_opening_owner_wait'")
            .await
            .unwrap();
        let owner = c.base.owner.clone();
        let backend_pid: i32 = waiting
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let job = tokio::spawn(async move { reserve(&mut waiting, &owner, request).await });
        let observed=tokio::time::timeout(std::time::Duration::from_secs(2),async{
            loop {if c.base.f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=current_database() AND application_name='synthetic_opening_owner_wait' AND wait_event_type='Lock')", &[&backend_pid]).await.unwrap().get::<_,bool>(0){break;}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
        }).await;
        assert!(observed.is_ok(), "must observe the real authority wait");
        let sql = if revoke {
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1"
        } else {
            "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1"
        };
        c.base
            .f
            .db
            .execute(sql, &[&c.base.owner.session_id])
            .await
            .unwrap();
        hold.rollback().await.unwrap();
        assert!(
            matches!(job.await.unwrap(), Err(ConversationError::Forbidden)),
            "owner loss must fail authorization, not lock timeout/deadlock"
        );
        let row=c.base.f.db.query_one("SELECT (SELECT count(*) FROM workflow_opening_allocations),(SELECT count(*) FROM workflow_opening_requests)", &[]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 0);
        assert_eq!(row.get::<_, i64>(1), 2);
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual later receipt/scrub failures"]
async fn later_receipt_and_erasure_failures_roll_back_state_and_authority_scrubbing() {
    let c = fixture().await;
    let created = opening(&c, 1).await;
    let offered = offered(&c, created.receipt.opening).await;
    let request = reservation(
        &c,
        offered.receipt.opening,
        offered.receipt.offer.unwrap(),
        1,
    )
    .await;
    let role = format!("opening_fault_{}", Uuid::new_v4().simple());
    let schema = c.base.f.schema.clone();
    let admin = c.base.f.connect().await;
    let mut db = c.base.f.connect().await;
    let role_sql = admin.query_one("SELECT format('CREATE ROLE %I NOLOGIN', $1::text), format('SET ROLE %I', $1::text), format('SET LOCAL ROLE %I', $1::text), format('DROP ROLE %I', $1::text)", &[&role]).await.unwrap();
    let create_sql: String = role_sql.get(0);
    let set_role_sql: String = role_sql.get(1);
    let local_role_sql: String = role_sql.get(2);
    let drop_role_sql: String = role_sql.get(3);
    // The disposable hosted PostgreSQL fixture uses its bootstrap administrator.
    // A missing CREATE ROLE privilege is a test failure, never a skipped case.
    admin.batch_execute(&create_sql).await.unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let sql: String = admin.query_one("SELECT format('GRANT USAGE ON SCHEMA %I TO %I; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I', $1::text,$2::text,$1::text,$2::text)", &[&schema,&role]).await.unwrap().get(0);
        admin.batch_execute(&sql).await.unwrap();
        db.batch_execute(&set_role_sql).await.unwrap();
        let role_active: bool = db
            .query_one("SELECT current_user::text=$1::text", &[&role])
            .await
            .unwrap()
            .get(0);
        assert!(role_active, "fault injection must use the owned restricted role");

        let tx = db.transaction().await.unwrap();
        assert!(schema::installed(&tx).await.unwrap());
        tx.rollback().await.unwrap();
        let sql: String = c.base.f.db.query_one("SELECT format('REVOKE INSERT ON workflow_opening_requests FROM %I', $1::text)", &[&role]).await.unwrap().get(0);
        c.base.f.db.batch_execute(&sql).await.unwrap();
        let may_insert: bool = db.query_one("SELECT has_table_privilege(current_user,'workflow_opening_requests','INSERT')", &[]).await.unwrap().get(0);
        assert!(!may_insert);
        let error = reserve(&mut db, &c.base.owner, request.clone()).await.unwrap_err();
        let ConversationError::Database(error) = error else {
            panic!("receipt INSERT must fail with a database permission error");
        };
        let error = error.as_db_error().unwrap();
        assert_eq!(error.code().code(), "42501");
        assert_eq!(error.message(), "permission denied for table workflow_opening_requests");
        db.batch_execute("RESET ROLE").await.unwrap();
        let state = status(&mut db, &c.base.owner, created.receipt.opening.opening_id)
            .await
            .unwrap();
        assert_eq!(state.pending, 0);
        assert_eq!(state.opening.state_version, offered.receipt.opening.state_version);
        let row = c.base.f.db.query_one("SELECT (SELECT count(*) FROM workflow_opening_allocations WHERE account_id=$1),(SELECT count(*) FROM workflow_opening_requests WHERE account_id=$1 AND request_id=$2)", &[&c.base.f.account,&request.request_id]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 0);
        assert_eq!(row.get::<_, i64>(1), 0);
        // Restore the actual role's permission before retrying the identical request.
        let grant: String = c.base.f.db.query_one("SELECT format('GRANT INSERT ON workflow_opening_requests TO %I', $1::text)", &[&role]).await.unwrap().get(0);
        c.base.f.db.batch_execute(&grant).await.unwrap();
        // SET ROLE is scoped to this client, not the fixture administrator.
        db.batch_execute(&set_role_sql).await.unwrap();
        let reserved = reserve(&mut db, &c.base.owner, request).await.unwrap();
        let confirmed = confirm(&mut db, &c.base.owner, allocation(&reserved)).await.unwrap();
        db.batch_execute("RESET ROLE").await.unwrap();
        let snapshot_sql = "SELECT (SELECT jsonb_agg(to_jsonb(t) ORDER BY request_id)::text FROM workflow_opening_requests t WHERE account_id=$1),(SELECT to_jsonb(t)::text FROM workflow_opening_allocations t WHERE account_id=$1 AND id=$2),(SELECT to_jsonb(t)::text FROM workflow_opening_offers t WHERE account_id=$1 AND id=$3)";
        let offer_id = offered.receipt.offer.unwrap().offer_id;
        let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &c.base.f.account,
            &confirmed.receipt.allocation_id,
            &offer_id,
        ];
        let before = c.base.f.db.query_one(snapshot_sql, params).await.unwrap();
        let before: Vec<String> = (0..3).map(|i| before.get(i)).collect();
        let sql: String = c.base.f.db.query_one("SELECT format('REVOKE UPDATE ON workflow_opening_allocations FROM %I; GRANT UPDATE(phase,state_version) ON workflow_opening_allocations TO %I', $1::text,$1::text)", &[&role]).await.unwrap().get(0);
        c.base.f.db.batch_execute(&sql).await.unwrap();
        let tx = db.transaction().await.unwrap();
        tx.batch_execute(&local_role_sql).await.unwrap();
        let privileges = tx.query_one("SELECT has_table_privilege(current_user,'workflow_opening_allocations','SELECT'),has_column_privilege(current_user,'workflow_opening_allocations','phase','UPDATE'),has_column_privilege(current_user,'workflow_opening_allocations','state_version','UPDATE'),has_column_privilege(current_user,'workflow_opening_allocations','binding_scrubbed','UPDATE')", &[]).await.unwrap();
        assert!((0..3).all(|i| privileges.get::<_, bool>(i)));
        assert!(!privileges.get::<_, bool>(3));
        assert!(schema::installed(&tx).await.unwrap());
        owner_context::lock_owner(&tx, &c.base.owner).await.unwrap();
        let error =
            crate::workflow_runtime::lifecycle::erase_contact(&tx, c.base.f.account, c.contact)
                .await
                .unwrap_err();
        let error = error.as_db_error().unwrap();
        assert_eq!(error.code().code(), "42501");
        assert_eq!(error.message(), "permission denied for table workflow_opening_allocations");
        let aborted = tx.query_one("SELECT 1", &[]).await.unwrap_err();
        assert_eq!(aborted.as_db_error().unwrap().code().code(), "25P02");
        tx.rollback().await.unwrap();
        db.batch_execute("RESET ROLE").await.unwrap();
        let after = c.base.f.db.query_one(snapshot_sql, params).await.unwrap();
        let after: Vec<String> = (0..3).map(|i| after.get(i)).collect();
        assert_eq!(after, before, "later scrub failure rolls back complete receipts and bindings");
        let row=c.base.f.db.query_one("SELECT phase,binding_scrubbed,contact_identity,event_id FROM workflow_opening_allocations WHERE account_id=$1 AND id=$2", &[&c.base.f.account,&confirmed.receipt.allocation_id]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "confirmed");
        assert!(!row.get::<_, bool>(1));
        assert_eq!(row.get::<_, Option<Uuid>>(2), Some(c.contact));
        assert!(row.get::<_, Option<Uuid>>(3).is_some());
        assert!(
            c.base
                .f
                .db
                .query_opt(
                    "SELECT id FROM contacts WHERE account_id=$1 AND id=$2",
                    &[&c.base.f.account, &c.contact]
                )
                .await
                .unwrap()
                .is_some()
        );
    })
    .catch_unwind()
    .await;
    // Dropping a panicking borrowed transaction queues rollback on this client.
    // Retain both clients so teardown runs on success and assertion failure.
    let reset = db.batch_execute("ROLLBACK; RESET ROLE").await;
    drop(db);
    let cleanup = std::panic::AssertUnwindSafe(c.cleanup())
        .catch_unwind()
        .await;
    let drop_role = admin.batch_execute(&drop_role_sql).await;
    if let Err(payload) = result {
        if reset.is_err() || cleanup.is_err() || drop_role.is_err() {
            eprintln!("opening fault fixture teardown also failed");
        }
        std::panic::resume_unwind(payload);
    }
    reset.unwrap();
    if let Err(payload) = cleanup {
        std::panic::resume_unwind(payload);
    }
    drop_role.unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual expiry and replay fences"]
async fn expired_pending_capacity_is_reduced_without_reusing_a_consumed_response() {
    let c = fixture().await;
    let created = opening(&c, 1).await;
    let offered = offered(&c, created.receipt.opening).await;
    let request = reservation(
        &c,
        offered.receipt.opening,
        offered.receipt.offer.unwrap(),
        1,
    )
    .await;
    let reserved = reserve(
        &mut c.base.f.connect().await,
        &c.base.owner,
        request.clone(),
    )
    .await
    .unwrap();
    c.base.f.db.execute("UPDATE workflow_opening_allocations SET decision_deadline_ms=accepted_ms+1 WHERE account_id=$1 AND id=$2", &[&c.base.f.account,&reserved.receipt.allocation_id]).await.unwrap();
    let state = status(
        &mut c.base.f.connect().await,
        &c.base.owner,
        created.receipt.opening.opening_id,
    )
    .await
    .unwrap();
    assert_eq!((state.pending, state.confirmed), (0, 0));
    let mut retry = request;
    retry.request_id = Uuid::new_v4();
    retry.allocation_id = Uuid::new_v4();
    retry.opening = state.opening;
    assert!(
        reserve(&mut c.base.f.connect().await, &c.base.owner, retry)
            .await
            .is_err()
    );
    assert_eq!(
        status(
            &mut c.base.f.connect().await,
            &c.base.owner,
            created.receipt.opening.opening_id
        )
        .await
        .unwrap()
        .pending,
        0
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual isolated candidate schema"]
async fn competing_responses_have_one_capacity_winner_and_owner_confirmation_is_separate() {
    let c = fixture().await;
    let created = opening(&c, 1).await;
    let offered = offered(&c, created.receipt.opening).await;
    let first = reservation(
        &c,
        offered.receipt.opening,
        offered.receipt.offer.unwrap(),
        1,
    )
    .await;
    let second = reservation(
        &c,
        offered.receipt.opening,
        offered.receipt.offer.unwrap(),
        2,
    )
    .await;
    let mut a = c.base.f.connect().await;
    let mut b = c.base.f.connect().await;
    let (one, two) = tokio::join!(
        reserve(&mut a, &c.base.owner, first.clone()),
        reserve(&mut b, &c.base.owner, second.clone())
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    assert!(matches!(&one, Ok(_) | Err(ConversationError::Conflict)));
    assert!(matches!(&two, Ok(_) | Err(ConversationError::Conflict)));
    let winner = one.or(two).unwrap();
    assert_eq!((winner.receipt.pending, winner.receipt.confirmed), (1, 0));
    let mut full = if winner.receipt.allocation_id == Some(first.allocation_id) {
        second.clone()
    } else {
        first.clone()
    };
    full.request_id = Uuid::new_v4();
    full.opening = winner.receipt.opening;
    assert!(
        matches!(
            reserve(&mut c.base.f.connect().await, &c.base.owner, full).await,
            Err(ConversationError::Conflict)
        ),
        "a fresh current CAS cannot exceed pending capacity"
    );
    let confirmed = confirm(
        &mut c.base.f.connect().await,
        &c.base.owner,
        allocation(&winner),
    )
    .await
    .unwrap();
    assert_eq!(
        (confirmed.receipt.pending, confirmed.receipt.confirmed),
        (0, 1)
    );
    let replay = reserve(
        &mut c.base.f.connect().await,
        &c.base.owner,
        if winner.receipt.allocation_id == Some(first.allocation_id) {
            first
        } else {
            second
        },
    )
    .await
    .unwrap();
    assert!(!replay.applied && replay.recorded);
    let released = release(
        &mut c.base.f.connect().await,
        &c.base.owner,
        allocation(&confirmed),
    )
    .await
    .unwrap();
    assert_eq!(
        (released.receipt.pending, released.receipt.confirmed),
        (0, 0)
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual isolated candidate schema"]
async fn concurrent_cancellation_and_confirmation_of_one_pending_allocation_have_one_winner() {
    let c = fixture().await;
    let created = opening(&c, 1).await;
    let offered = offered(&c, created.receipt.opening).await;
    let reserved = reserve(
        &mut c.base.f.connect().await,
        &c.base.owner,
        reservation(
            &c,
            offered.receipt.opening,
            offered.receipt.offer.unwrap(),
            1,
        )
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        (reserved.receipt.pending, reserved.receipt.confirmed),
        (1, 0)
    );
    let confirmation = allocation(&reserved);
    let cancellation = OpeningMutation {
        request_id: Uuid::new_v4(),
        opening: reserved.receipt.opening,
    };
    let mut a = c.base.f.connect().await;
    let mut b = c.base.f.connect().await;
    let (confirmed, cancelled) = tokio::join!(
        confirm(&mut a, &c.base.owner, confirmation),
        cancel(&mut b, &c.base.owner, cancellation)
    );
    assert_eq!(
        usize::from(confirmed.is_ok()) + usize::from(cancelled.is_ok()),
        1,
        "exactly one of confirmation and cancellation may consume the pending unit"
    );
    assert!(matches!(
        &confirmed,
        Ok(_) | Err(ConversationError::Conflict)
    ));
    assert!(matches!(
        &cancelled,
        Ok(_) | Err(ConversationError::Conflict)
    ));
    let (winner, phase) = match (&confirmed, &cancelled) {
        (Ok(confirmed), Err(_)) => {
            assert_eq!(
                (confirmed.receipt.pending, confirmed.receipt.confirmed),
                (0, 1)
            );
            (confirmed, "confirmed")
        }
        (Err(_), Ok(cancelled)) => {
            assert_eq!(
                (cancelled.receipt.pending, cancelled.receipt.confirmed),
                (0, 0)
            );
            (cancelled, "cancelled")
        }
        _ => unreachable!("exactly one winner asserted above"),
    };
    assert!(winner.applied && winner.recorded);
    assert_eq!(winner.receipt.phase, phase);
    let state = status(
        &mut c.base.f.connect().await,
        &c.base.owner,
        created.receipt.opening.opening_id,
    )
    .await
    .unwrap();
    assert_eq!(
        (state.pending, state.confirmed),
        (0, winner.receipt.confirmed)
    );
    let row = c
        .base
        .f
        .db
        .query_one(
            "SELECT (SELECT count(*) FROM workflow_opening_allocations WHERE account_id=$1 AND opening_id=$2 AND phase=$3),(SELECT count(*) FROM workflow_opening_requests WHERE account_id=$1 AND opening_id=$2 AND operation IN (4,8))",
            &[&c.base.f.account, &created.receipt.opening.opening_id, &phase],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, i64>(0),
        1,
        "the single allocation ends in the winning phase"
    );
    assert_eq!(
        row.get::<_, i64>(1),
        1,
        "exactly one operation is recorded; the loser records nothing"
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual isolated candidate schema"]
async fn contact_erasure_scrubs_authority_and_receipts_without_freeing_confirmed_units() {
    let c = fixture().await;
    let created = opening(&c, 2).await;
    let offered = offered(&c, created.receipt.opening).await;
    let request = reservation(
        &c,
        offered.receipt.opening,
        offered.receipt.offer.unwrap(),
        1,
    )
    .await;
    let event = request.event_id;
    let reserved = reserve(&mut c.base.f.connect().await, &c.base.owner, request)
        .await
        .unwrap();
    let confirmed = confirm(
        &mut c.base.f.connect().await,
        &c.base.owner,
        allocation(&reserved),
    )
    .await
    .unwrap();
    let mut db = c.base.f.connect().await;
    let tx = db.transaction().await.unwrap();
    owner_context::lock_owner(&tx, &c.base.owner).await.unwrap();
    crate::workflow_runtime::lifecycle::erase_contact(&tx, c.base.f.account, c.contact)
        .await
        .unwrap();
    tx.execute(
        "DELETE FROM contacts WHERE account_id=$1 AND id=$2",
        &[&c.base.f.account, &c.contact],
    )
    .await
    .unwrap();
    owner_context::fresh_owner(&tx, &c.base.owner)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let row=c.base.f.db.query_one("SELECT phase,binding_scrubbed,offer_id,contact_identity,event_id,event_digest,observed_ms,accepted_ms,decision_deadline_ms,reserved_by_user,reserved_session,confirmed_by_user,confirmed_session,confirmed_ms,response_use_digest FROM workflow_opening_allocations WHERE account_id=$1 AND id=$2", &[&c.base.f.account,&confirmed.receipt.allocation_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "confirmed");
    assert!(row.get::<_, bool>(1));
    for i in [2, 3, 4, 9, 10, 11, 12] {
        assert!(row.get::<_, Option<Uuid>>(i).is_none());
    }
    assert!(row.get::<_, Option<Vec<u8>>>(5).is_none());
    for i in [6, 7, 8, 13] {
        assert!(row.get::<_, Option<i64>>(i).is_none());
    }
    assert_eq!(row.get::<_, Vec<u8>>(14).len(), 32);
    let view = export::export(&mut c.base.f.connect().await, &c.base.owner, [None; 4])
        .await
        .unwrap();
    let offer = &view.offers.items[0];
    for field in [
        "contact_identity",
        "current_contact_id",
        "purpose",
        "consent_episode_id",
        "context_id",
        "context_revision",
        "context_digest",
        "issued_ms",
        "expires_ms",
        "created_by_user",
        "created_session",
    ] {
        assert!(offer[field].is_null(), "erased offer field {field}");
    }
    let exported_allocation = &view.allocations.items[0];
    for field in [
        "offer_id",
        "offer_state_version",
        "contact_identity",
        "event_id",
        "event_digest",
        "observed_ms",
        "accepted_ms",
        "decision_deadline_ms",
        "reserved_by_user",
        "reserved_session",
        "confirmed_by_user",
        "confirmed_session",
        "confirmed_ms",
    ] {
        assert!(
            exported_allocation[field].is_null(),
            "erased allocation field {field}"
        );
    }
    for request in view
        .requests
        .items
        .iter()
        .filter(|row| row["redacted"] == serde_json::json!(true))
    {
        for field in [
            "subject_kind",
            "subject_id",
            "operation",
            "request_digest",
            "result",
            "actor_user_id",
            "actor_session_id",
            "committed_ms",
        ] {
            assert!(request[field].is_null(), "erased receipt field {field}");
        }
    }
    let bytes = serde_json::to_string(&view).unwrap();
    assert!(!bytes.contains(&c.contact.to_string()));
    assert!(!bytes.contains(&event.to_string()));
    let count:i64=c.base.f.db.query_one("SELECT count(*) FROM workflow_opening_requests WHERE account_id=$1 AND (subject_kind IN(2,3) OR (redacted AND (result IS NOT NULL OR request_digest IS NOT NULL OR actor_user_id IS NOT NULL)))", &[&c.base.f.account]).await.unwrap().get(0);
    assert_eq!(count, 0);
    let status = status(
        &mut c.base.f.connect().await,
        &c.base.owner,
        created.receipt.opening.opening_id,
    )
    .await
    .unwrap();
    assert_eq!(status.confirmed, 1);
    let released = release(
        &mut c.base.f.connect().await,
        &c.base.owner,
        allocation(&confirmed),
    )
    .await
    .unwrap();
    assert_eq!(released.receipt.confirmed, 0);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual isolated candidate schema"]
async fn full_admission_budget_and_max_versions_do_not_block_close_cancel_or_release() {
    let c = fixture().await;
    let created = opening(&c, 1).await;
    let offered = offered(&c, created.receipt.opening).await;
    let request = reservation(
        &c,
        offered.receipt.opening,
        offered.receipt.offer.unwrap(),
        1,
    )
    .await;
    let reserved = reserve(&mut c.base.f.connect().await, &c.base.owner, request)
        .await
        .unwrap();
    let confirmed = confirm(
        &mut c.base.f.connect().await,
        &c.base.owner,
        allocation(&reserved),
    )
    .await
    .unwrap();
    let second_created = opening(&c, 1).await;
    let second_offer = offered_source(&c, second_created.receipt.opening, source(&c)).await;
    let request = reservation(
        &c,
        second_offer.receipt.opening,
        second_offer.receipt.offer.unwrap(),
        2,
    )
    .await;
    let second_reserved = reserve(&mut c.base.f.connect().await, &c.base.owner, request)
        .await
        .unwrap();
    let second_confirmed = confirm(
        &mut c.base.f.connect().await,
        &c.base.owner,
        allocation(&second_reserved),
    )
    .await
    .unwrap();
    c.base.f.db.execute("INSERT INTO workflow_opening_requests(account_id,request_id,opening_id,subject_kind,subject_id,operation,request_digest,result,actor_user_id,actor_session_id,committed_ms) SELECT $1,md5('synthetic-opening-budget-'||n::text)::uuid,$2,1,$2,1,decode(repeat('ab',32),'hex'),convert_to('{}','UTF8'),$3,$4,1 FROM generate_series(1,8184) n", &[&c.base.f.account,&created.receipt.opening.opening_id,&c.base.owner.user_id,&c.base.owner.session_id]).await.unwrap();
    c.base
        .f
        .db
        .execute(
            "UPDATE workflow_openings SET state_version=9223372036854775807 WHERE account_id=$1",
            &[&c.base.f.account],
        )
        .await
        .unwrap();
    c.base.f.db.execute("UPDATE workflow_opening_allocations SET state_version=9223372036854775807 WHERE account_id=$1", &[&c.base.f.account]).await.unwrap();
    let key = OpeningKey {
        state_version: i64::MAX,
        ..confirmed.receipt.opening
    };
    let closed = close(
        &mut c.base.f.connect().await,
        &c.base.owner,
        OpeningMutation {
            request_id: Uuid::new_v4(),
            opening: key,
        },
    )
    .await
    .unwrap();
    assert_eq!(closed.receipt.confirmed, 1);
    assert_eq!(closed.receipt.opening.state_version, i64::MAX);
    let cancelled = cancel(
        &mut c.base.f.connect().await,
        &c.base.owner,
        OpeningMutation {
            request_id: Uuid::new_v4(),
            opening: key,
        },
    )
    .await
    .unwrap();
    assert_eq!(cancelled.receipt.confirmed, 0);
    let second_key = OpeningKey {
        state_version: i64::MAX,
        ..second_confirmed.receipt.opening
    };
    let closed = close(
        &mut c.base.f.connect().await,
        &c.base.owner,
        OpeningMutation {
            request_id: Uuid::new_v4(),
            opening: second_key,
        },
    )
    .await
    .unwrap();
    assert_eq!(closed.receipt.confirmed, 1);
    let mut reduction = allocation(&second_confirmed);
    reduction.opening = second_key;
    reduction.allocation_version = i64::MAX;
    let released = release(&mut c.base.f.connect().await, &c.base.owner, reduction)
        .await
        .unwrap();
    assert!(released.applied && released.recorded);
    assert_eq!(released.receipt.confirmed, 0);
    assert_eq!(released.receipt.allocation_version, Some(i64::MAX));
    let cancelled = cancel(
        &mut c.base.f.connect().await,
        &c.base.owner,
        OpeningMutation {
            request_id: Uuid::new_v4(),
            opening: second_key,
        },
    )
    .await
    .unwrap();
    assert!(cancelled.applied);
    assert_eq!(cancelled.receipt.confirmed, 0);
    let before: i64 = c
        .base
        .f
        .db
        .query_one(
            "SELECT count(*) FROM workflow_opening_requests WHERE account_id=$1",
            &[&c.base.f.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, 8197);
    for _ in 0..24 {
        let out = cancel(
            &mut c.base.f.connect().await,
            &c.base.owner,
            OpeningMutation {
                request_id: Uuid::new_v4(),
                opening: key,
            },
        )
        .await
        .unwrap();
        assert!(!out.applied && !out.recorded);
    }
    let after: i64 = c
        .base
        .f
        .db
        .query_one(
            "SELECT count(*) FROM workflow_opening_requests WHERE account_id=$1",
            &[&c.base.f.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, after);
    c.cleanup().await;
}
