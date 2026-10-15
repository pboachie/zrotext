// SPDX-License-Identifier: AGPL-3.0-only
//! Raw request bytes preserve duplicate JSON keys and refusal-side row checks.
use super::super::super::{authority, final_record, lifecycle, packet, store};
use super::*;
use crate::http_owner_conversations::{ConversationError, enable_conversation};
use std::{future::Future, pin::Pin, time::Duration};

async fn expiry(c: &GenuineCase, deadline: i64) {
    // A timeout is a failure, not evidence that any cancelled request settled.
    tokio::time::timeout(Duration::from_secs(8),c.f.db.query_one(
        "SELECT 1 FROM pg_sleep(GREATEST(0,($1::bigint-floor(extract(epoch FROM clock_timestamp())*1000)::bigint)::double precision/1000.0)+0.05)",
        &[&deadline])).await.expect("actual deadline wait exceeded fixed ceiling").unwrap();
    assert!(c.now().await >= deadline);
}
async fn observed_wait<F: Future>(c: &GenuineCase, blocker: i32, pending: Pin<&mut F>) -> i32 {
    let barrier = async {
        loop {
            if let Some(row)=c.f.db.query_opt("SELECT DISTINCT pid FROM pg_locks WHERE NOT granted AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1",
                &[&blocker]).await.unwrap() {
                break row.get::<_,i32>(0);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        _=pending=>panic!("operation finished before its intended observed blocker"),
        result=tokio::time::timeout(Duration::from_secs(2),barrier)=>result.expect("operation did not reach its observed blocker"),
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; authenticated HTTP slot and settled rollback"]
async fn authenticated_request_keeps_account_slot_through_expiring_consent_wait_and_settles() {
    use crate::http_auth::preauth::AccountSlot;
    // Leave 1.5 seconds of actual proposal lifetime, comfortably below the
    // unchanged HTTP pool's 3-second lock timeout. A 5-second lifetime made
    // that timeout win instead of reaching the final expired-consent fence.
    let (c, before, consent) = ceremonies::configured_at(120000, 298500).await;
    enable_conversation(&mut c.f.connect().await, &c.owner.principal, &consent)
        .await
        .unwrap();
    let account = c.owner.principal.tenant.account_id();
    let issued = u64::from_be_bytes(before[37..45].try_into().unwrap());
    let bytes = ceremonies::activation_packet(&c, &before, issued);
    let deadline = (issued + 300000) as i64;
    assert!(u64::from_be_bytes(before[45..53].try_into().unwrap()) as i64 > deadline + 60000);
    let mut blocker = c.f.connect().await;
    let hold = blocker.transaction().await.unwrap();
    let pid: i32 = hold
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    hold.query_one(
        "SELECT account_id FROM owner_conversation_consents WHERE account_id=$1 FOR UPDATE",
        &[&account],
    )
    .await
    .unwrap();
    let waiter;
    let result = {
        let pending = ceremonies::issue(&c, 4, &bytes);
        tokio::pin!(pending);
        waiter = observed_wait(&c, pid, pending.as_mut()).await;
        assert!(
            c.now().await < deadline,
            "consent blocker must be observed while the proposal is still live"
        );
        assert_eq!(AccountSlot::in_flight(account), 1);
        expiry(&c, deadline).await;
        hold.rollback().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .expect("HTTP request did not settle")
    };
    assert_eq!(result.0, StatusCode::FORBIDDEN);
    assert_eq!(AccountSlot::in_flight(account), 0);
    // The request pool resets asynchronously. Observe that exact waiting
    // backend's transaction ending before teardown; response alone is insufficient.
    tokio::time::timeout(Duration::from_secs(2),async {
        while c.f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND xact_start IS NOT NULL)",&[&waiter])
            .await.unwrap().get::<_,bool>(0) { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.expect("HTTP rollback/reset did not settle");
    assert!(c.rows().await.is_empty());
    let selected = packet::selection(4, &bytes).unwrap();
    let mut verify = c.f.connect().await;
    let tx = verify.transaction().await.unwrap();
    lifecycle::require_installed(&tx).await.unwrap();
    let current = authority::lock(&tx, &c.owner.principal, &selected)
        .await
        .unwrap();
    assert!(
        authority::fresh(&tx, &c.owner.principal, &selected, &current)
            .await
            .unwrap()
            >= deadline
    );
    tx.rollback().await.unwrap();
    drop(verify);
    drop(blocker);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; true retained proposal expiry"]
async fn original_registered_proposal_expiry_refuses_context_and_retry_without_renewal() {
    let c = GenuineCase::new().await;
    // Original bytes are genuinely live on registration, with five seconds
    // remaining. No proposal row time or deadline is rewritten by this test.
    let (bytes, phone, archive) = ceremonies::inputs(&c, c.now().await as u64 - 235000);
    let body = registration(&c, &bytes, &phone, &archive);
    let (status, receipt) = request(&c, PATH, &body).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(
        request(&c, CONTEXT_PATH, &context(&c, &bytes)).await.0,
        StatusCode::OK
    );
    let rows = c.rows().await;
    let deadline: i64 = receipt["expires_ms"].as_str().unwrap().parse().unwrap();
    expiry(&c, deadline).await;
    assert_eq!(
        request(&c, CONTEXT_PATH, &context(&c, &bytes)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(request(&c, PATH, &body).await.0, StatusCode::FORBIDDEN);
    assert_eq!(c.rows().await, rows);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; observed post-save final consent wait"]
async fn final_consent_wait_past_proposal_or_current_session_deadline_rolls_back_saved_record() {
    for session_deadline in [false, true] {
        let (c, before, consent) =
            ceremonies::configured_at(120000, if session_deadline { 0 } else { 295000 }).await;
        enable_conversation(&mut c.f.connect().await, &c.owner.principal, &consent)
            .await
            .unwrap();
        let deadline = if session_deadline {
            c.f.db.query_one("UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1 RETURNING floor(extract(epoch FROM expires_at)*1000)::bigint",
                &[&c.owner.principal.session_id]).await.unwrap().get::<_,i64>(0)
        } else {
            u64::from_be_bytes(before[37..45].try_into().unwrap()) as i64 + 300000
        };
        let bytes = ceremonies::activation_packet(
            &c,
            &before,
            u64::from_be_bytes(before[37..45].try_into().unwrap()),
        );
        let selected = packet::selection(4, &bytes).unwrap();
        let mut blocker = c.f.connect().await;
        let hold = blocker.transaction().await.unwrap();
        let pid: i32 = hold
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        hold.query_one(
            "SELECT account_id FROM owner_conversation_consents WHERE account_id=$1 FOR UPDATE",
            &[&c.owner.principal.tenant.account_id()],
        )
        .await
        .unwrap();
        let mut db = c.f.connect().await;
        let tx = db.transaction().await.unwrap();
        lifecycle::require_installed(&tx).await.unwrap();
        let current = authority::lock(&tx, &c.owner.principal, &selected)
            .await
            .unwrap();
        let now = authority::fresh(&tx, &c.owner.principal, &selected, &current)
            .await
            .unwrap();
        let record = packet::validate(
            4,
            packet::Context {
                p: &c.owner.principal,
                s: &selected,
                c: &current,
                origin: ORIGIN,
                now,
            },
            &bytes,
            None,
        )
        .unwrap();
        if !session_deadline {
            assert_eq!(record.expires, deadline);
            assert!(
                u64::from_be_bytes(before[45..53].try_into().unwrap()) as i64 > deadline + 60000
            );
        } else {
            assert!(record.expires > deadline + 60000);
        }
        store::save(&tx, &c.owner.principal, &selected, &current, &record)
            .await
            .unwrap();
        let count: i64 = tx
            .query_one(
                "SELECT count(*) FROM owner_android_proposals WHERE account_id=$1",
                &[&c.owner.principal.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
        assert!(c.rows().await.is_empty());
        let result = {
            let pending = final_record(
                &tx,
                &c.owner.principal,
                &selected,
                &current,
                ORIGIN,
                &record,
            );
            tokio::pin!(pending);
            observed_wait(&c, pid, pending.as_mut()).await;
            expiry(&c, deadline).await;
            hold.rollback().await.unwrap();
            // Settle the exact validation future before rollback or cleanup.
            tokio::time::timeout(Duration::from_secs(2), pending)
                .await
                .unwrap()
        };
        assert!(matches!(result, Err(ConversationError::Forbidden)));
        if !session_deadline {
            // Only the original proposal deadline expired. Recheck the same
            // transaction's still-live root/owner/session/phone authority.
            assert!(
                authority::fresh(&tx, &c.owner.principal, &selected, &current)
                    .await
                    .unwrap()
                    >= record.expires
            );
        }
        tx.rollback().await.unwrap();
        assert!(c.rows().await.is_empty());
        drop(db);
        drop(blocker);
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; observed creator deadline after interval wait"]
async fn final_interval_wait_rechecks_original_creator_deadline_for_another_live_owner_session() {
    let (mut c, before, consent) = ceremonies::configured(120000).await;
    enable_conversation(&mut c.f.connect().await, &c.owner.principal, &consent)
        .await
        .unwrap();
    let (before, interval) = ceremonies::activate(&c, &before, &consent, None).await;
    let creator = c.owner.principal.session_id;
    let login = c.f.connect().await;
    c.owner.credentials = auth::login(&login, &c.hasher, &c.owner.email, &c.owner.password)
        .await
        .unwrap();
    c.owner.principal = auth::authenticate_session(&login, &c.hasher, &c.owner.credentials.token)
        .await
        .unwrap();
    assert_ne!(creator, c.owner.principal.session_id);
    let deadline:i64=login.query_one("UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1 RETURNING floor(extract(epoch FROM expires_at)*1000)::bigint",&[&creator]).await.unwrap().get(0);
    let bytes = ceremonies::refresh_packet(&c, &before, interval, c.now().await as u64);
    let selected = packet::selection(5, &bytes).unwrap();
    let mut blocker = c.f.connect().await;
    let hold = blocker.transaction().await.unwrap();
    let pid: i32 = hold
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    hold.query_one(
        "SELECT id FROM conversation_intervals WHERE account_id=$1 AND id=$2 FOR UPDATE",
        &[&c.owner.principal.tenant.account_id(), &interval],
    )
    .await
    .unwrap();
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    lifecycle::require_installed(&tx).await.unwrap();
    let current = authority::lock(&tx, &c.owner.principal, &selected)
        .await
        .unwrap();
    let now = authority::fresh(&tx, &c.owner.principal, &selected, &current)
        .await
        .unwrap();
    let record = packet::validate(
        5,
        packet::Context {
            p: &c.owner.principal,
            s: &selected,
            c: &current,
            origin: ORIGIN,
            now,
        },
        &bytes,
        None,
    )
    .unwrap();
    store::save(&tx, &c.owner.principal, &selected, &current, &record)
        .await
        .unwrap();
    let result = {
        let pending = final_record(
            &tx,
            &c.owner.principal,
            &selected,
            &current,
            ORIGIN,
            &record,
        );
        tokio::pin!(pending);
        observed_wait(&c, pid, pending.as_mut()).await;
        expiry(&c, deadline).await;
        hold.rollback().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .unwrap()
    };
    assert!(matches!(result, Err(ConversationError::Forbidden)));
    tx.rollback().await.unwrap();
    assert!(c.rows().await.is_empty());
    assert!(
        auth::authenticate_session(&login, &c.hasher, &c.owner.credentials.token)
            .await
            .is_ok()
    );
    drop(db);
    drop(blocker);
    drop(login);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; captured transport and current owner drift"]
async fn context_refuses_replaced_transport_or_current_owner_without_pending_mutation() {
    for mutation in [
        "UPDATE device_sessions SET connection_epoch=connection_epoch+1 WHERE device_id=$1",
        "UPDATE device_sessions SET deployment_epoch=deployment_epoch+1 WHERE device_id=$1",
        "UPDATE device_sessions SET instance_id='replacement' WHERE device_id=$1",
        "UPDATE device_sessions SET site_id='replacement' WHERE device_id=$1",
        "UPDATE device_keys SET revoked_at=clock_timestamp() WHERE device_id=$1",
        "UPDATE devices SET revoked_at=clock_timestamp() WHERE id=$1",
    ] {
        let c = GenuineCase::new().await;
        let (bytes, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
        let body = registration(&c, &bytes, &phone, &archive);
        assert_eq!(request(&c, PATH, &body).await.0, StatusCode::OK);
        let rows = c.rows().await;
        c.f.db
            .execute("INSERT INTO sites(site_id) VALUES('replacement')", &[])
            .await
            .unwrap();
        c.f.db.execute(mutation, &[&c.device]).await.unwrap();
        assert_eq!(
            request(&c, CONTEXT_PATH, &context(&c, &bytes)).await.0,
            StatusCode::FORBIDDEN
        );
        assert!(request(&c, PATH, &body).await.0.is_client_error());
        assert_eq!(c.rows().await, rows);
        c.cleanup().await;
    }
    let c = GenuineCase::new().await;
    let (bytes, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
    assert_eq!(
        request(&c, PATH, &registration(&c, &bytes, &phone, &archive))
            .await
            .0,
        StatusCode::OK
    );
    let rows = c.rows().await;
    c.f.db
        .execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&c.owner.principal.tenant.account_id()],
        )
        .await
        .unwrap();
    assert_eq!(
        request(&c, CONTEXT_PATH, &context(&c, &bytes)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(c.rows().await, rows);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; independent immutable selected byte scope"]
async fn registration_refuses_changed_selected_metadata_bytes_without_replacing_original_slot() {
    let c = GenuineCase::new().await;
    let (bytes, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
    assert_eq!(
        request(&c, PATH, &registration(&c, &bytes, &phone, &archive))
            .await
            .0,
        StatusCode::OK
    );
    let rows = c.rows().await;
    for at in [
        5,
        21,
        37,
        53,
        69,
        101,
        110,
        115,
        115 + ORIGIN.len() + 32,
        115 + ORIGIN.len(),
    ] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(
            request(&c, PATH, &registration(&c, &changed, &phone, &archive))
                .await
                .0
                .is_client_error(),
            "offset{at}"
        );
        assert_eq!(c.rows().await, rows);
    }
    assert_eq!(
        request(&c, CONTEXT_PATH, &context(&c, &bytes)).await.0,
        StatusCode::OK
    );
    c.cleanup().await;
}

fn duplicate(value: &serde_json::Value, key: &str) -> Vec<u8> {
    let mut text = value.to_string();
    assert_eq!(text.pop(), Some('}'));
    text.push_str(&format!(
        ",{}:{}}}",
        serde_json::to_string(key).unwrap(),
        value[key]
    ));
    text.into_bytes()
}

fn escaped_duplicate(value: &serde_json::Value, key: &str) -> Vec<u8> {
    let escaped = format!("{}u{:04x}{}", '\\', key.as_bytes()[0], &key[1..]);
    let mut text = value.to_string();
    assert_eq!(text.pop(), Some('}'));
    text.push_str(&format!(",\"{escaped}\":{}}}", value[key]));
    text.into_bytes()
}
async fn typed_case(kind: i16) -> (GenuineCase, Vec<u8>, serde_json::Value) {
    if kind == 3 {
        let c = GenuineCase::new().await;
        let (bytes, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
        let body = registration(&c, &bytes, &phone, &archive);
        return (c, bytes, body);
    }
    let (c, mut before, consent) = ceremonies::configured(120000).await;
    enable_conversation(&mut c.f.connect().await, &c.owner.principal, &consent)
        .await
        .unwrap();
    let bytes = if kind == 4 {
        ceremonies::activation_packet(&c, &before, c.now().await as u64)
    } else {
        let (current, interval) = ceremonies::activate(&c, &before, &consent, None).await;
        before = current;
        ceremonies::refresh_packet(&c, &before, interval, c.now().await as u64)
    };
    let body = serde_json::json!({"kind":kind,"proposal_b64":STANDARD.encode(&bytes),
        "expected_session_id":c.owner.principal.session_id});
    (c, bytes, body)
}
fn typed_context(c: &GenuineCase, kind: i16, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({"kind":kind,"proposal_sha256_hex":hex_bytes(&Sha256::digest(bytes)),
        "expected_session_id":c.owner.principal.session_id})
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; streamed map-only authenticated requests"]
async fn positional_scalar_and_escaped_duplicate_bodies_refuse_after_valid_typed_objects() {
    for kind in [3, 4, 5] {
        let (c, bytes, body) = typed_case(kind).await;
        let authority_rows = c.authority_rows().await;
        assert_eq!(request(&c, PATH, &body).await.0, StatusCode::OK);
        assert_eq!(
            ceremonies::context_of(&c, kind, &bytes).await.0,
            StatusCode::OK
        );
        let rows = c.rows().await;
        let context = typed_context(&c, kind, &bytes);
        let sequence = if kind == 3 {
            serde_json::json!([
                kind,
                body["proposal_b64"],
                body["expected_session_id"],
                body["encrypted_archive_b64"],
                body["phone_export_b64"]
            ])
        } else {
            serde_json::json!([kind, body["proposal_b64"], body["expected_session_id"]])
        };
        for (path, object, sequence) in [
            (PATH, &body, sequence),
            (
                CONTEXT_PATH,
                &context,
                serde_json::json!([
                    kind,
                    context["proposal_sha256_hex"],
                    context["expected_session_id"]
                ]),
            ),
        ] {
            for wrong in [
                sequence,
                serde_json::Value::Null,
                serde_json::json!(true),
                serde_json::json!(kind),
                serde_json::json!("object"),
                serde_json::json!([]),
            ] {
                assert_eq!(
                    raw(
                        &c,
                        Some(&c.owner),
                        path,
                        serde_json::to_vec(&wrong).unwrap(),
                        Some(ORIGIN),
                        Some(&c.owner.credentials.csrf_token)
                    )
                    .await
                    .0,
                    StatusCode::BAD_REQUEST
                );
                assert_eq!(c.rows().await, rows);
                assert_eq!(c.authority_rows().await, authority_rows);
            }
            for key in object.as_object().unwrap().keys() {
                assert_eq!(
                    raw(
                        &c,
                        Some(&c.owner),
                        path,
                        escaped_duplicate(object, key),
                        Some(ORIGIN),
                        Some(&c.owner.credentials.csrf_token)
                    )
                    .await
                    .0,
                    StatusCode::BAD_REQUEST
                );
                assert_eq!(c.rows().await, rows);
                assert_eq!(c.authority_rows().await, authority_rows);
            }
        }
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; exact valid body boundary"]
async fn valid_objects_at_exact_body_limit_succeed_and_one_more_byte_refuses() {
    let (c, bytes, body) = typed_case(3).await;
    let authority_rows = c.authority_rows().await;
    assert_eq!(request(&c, PATH, &body).await.0, StatusCode::OK);
    assert_eq!(
        ceremonies::context_of(&c, 3, &bytes).await.0,
        StatusCode::OK
    );
    let rows = c.rows().await;
    for (path, object) in [(PATH, body), (CONTEXT_PATH, typed_context(&c, 3, &bytes))] {
        let mut padded = serde_json::to_vec(&object).unwrap();
        assert!(padded.len() < 32768);
        padded.resize(32768, b' ');
        assert_eq!(
            raw(
                &c,
                Some(&c.owner),
                path,
                padded.clone(),
                Some(ORIGIN),
                Some(&c.owner.credentials.csrf_token)
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(c.rows().await, rows);
        assert_eq!(c.authority_rows().await, authority_rows);
        padded.push(b' ');
        assert_eq!(padded.len(), 32769);
        assert_eq!(
            raw(
                &c,
                Some(&c.owner),
                path,
                padded,
                Some(ORIGIN),
                Some(&c.owner.credentials.csrf_token)
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(c.rows().await, rows);
        assert_eq!(c.authority_rows().await, authority_rows);
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; maintained observer invitation and current revocation"]
async fn genuine_observer_and_revoked_current_owner_refuse_before_polling_body() {
    use crate::auth::seats;
    use crate::http_auth::preauth::AccountSlot;
    let (c, bytes, body) = typed_case(3).await;
    assert_eq!(request(&c, PATH, &body).await.0, StatusCode::OK);
    assert_eq!(
        ceremonies::context_of(&c, 3, &bytes).await.0,
        StatusCode::OK
    );
    let rows = c.rows().await;
    let authority_rows = c.authority_rows().await;
    c.f.db
        .batch_execute(include_str!(
            "../../../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"
        ))
        .await
        .unwrap();
    let email = format!("{}@example.test", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    let mut db = c.f.connect().await;
    let invitation = seats::create_invitation_with_proof(
        &mut db,
        None,
        &c.hasher,
        &c.owner.principal,
        &c.owner.password,
        None,
        &email,
    )
    .await
    .unwrap();
    let accepted = seats::accept_invitation(&mut db, &c.hasher, &invitation.token, &password)
        .await
        .unwrap();
    assert_eq!(accepted.account_id, c.owner.principal.tenant.account_id());
    assert!(
        auth::verify_email_with_password(
            &mut db,
            &c.hasher,
            &accepted.verification_token,
            &password
        )
        .await
        .unwrap()
    );
    let credentials = auth::login(&db, &c.hasher, &email, &password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&db, &c.hasher, &credentials.token)
        .await
        .unwrap();
    assert_eq!(principal.user_id, accepted.user_id);
    assert_eq!(principal.role, auth::Role::Observer);
    let observer = SignedIn {
        principal,
        credentials,
        email,
        password,
    };
    // Owner routes deliberately hide the distinction between an observer and
    // an absent session. Revocation is a separate fixture action, not a status.
    for (who, status, revoke_owner) in [
        (&observer, StatusCode::UNAUTHORIZED, false),
        (&c.owner, StatusCode::UNAUTHORIZED, true),
    ] {
        if revoke_owner {
            assert!(
                auth::revoke_session(&db, &c.owner.principal, c.owner.principal.session_id)
                    .await
                    .unwrap()
            );
            assert!(matches!(
                auth::authenticate_session(&db, &c.hasher, &c.owner.credentials.token).await,
                Err(AuthError::Unauthorized)
            ));
        }
        for path in [PATH, CONTEXT_PATH] {
            let pending = Body::from_stream(futures_util::stream::pending::<
                Result<axum::body::Bytes, std::io::Error>,
            >());
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                router(c.state()).oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .header("cookie", who.cookie())
                        .header("origin", ORIGIN)
                        .header("x-zrotext-csrf", &who.credentials.csrf_token)
                        .body(pending)
                        .unwrap(),
                ),
            )
            .await
            .expect("prebody refusal must settle")
            .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert_eq!(
                AccountSlot::in_flight(c.owner.principal.tenant.account_id()),
                0
            );
            assert_eq!(c.rows().await, rows);
            assert_eq!(c.authority_rows().await, authority_rows);
        }
    }
    drop(db);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; independent first-issuance typed scope"]
async fn activation_and_refresh_selected_fields_refuse_with_empty_slots_and_positive_resets() {
    for kind in [4, 5] {
        let (c, bytes, body) = typed_case(kind).await;
        let authority_rows = c.authority_rows().await;
        let (status, receipt) = request(&c, PATH, &body).await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        let (status, original) = ceremonies::context_of(&c, kind, &bytes).await;
        assert_eq!(status, StatusCode::OK, "{original}");
        let rows = c.rows().await;
        let shift = if kind == 5 { 16 } else { 0 };
        let prefix = 5 + 16 * 4 + shift + 8 + 1 + 3 + 2 + ORIGIN.len();
        let mut cases = Vec::new();
        for (name, at) in [
            ("account", 5),
            ("session", 21),
            ("device", 37 + shift),
            ("line", 53 + shift),
            ("peer", 80 + shift),
            ("origin", prefix - 3),
            ("root fingerprint", prefix),
            ("predecessor digest", prefix + 40),
            ("phone reader", prefix + 72),
            ("archive reader", prefix + 104),
            ("signer", prefix + 136),
        ] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            cases.push((name, changed));
        }
        let mut generation = bytes.clone();
        generation[69 + shift..77 + shift].copy_from_slice(&2u64.to_be_bytes());
        cases.push(("generation", generation));
        let mut version = bytes.clone();
        let selected_version =
            u64::from_be_bytes(version[prefix + 32..prefix + 40].try_into().unwrap());
        version[prefix + 32..prefix + 40].copy_from_slice(&(selected_version + 1).to_be_bytes());
        cases.push(("predecessor version", version));
        let predecessor_at = if kind == 4 {
            prefix + 176
        } else {
            prefix + 241
        };
        let mut predecessor_root = bytes.clone();
        let other_root = SigningKey::generate_from_rng(&mut rand::rng());
        predecessor_root[predecessor_at + 2 + 85..predecessor_at + 2 + 150]
            .copy_from_slice(other_root.verifying_key().to_sec1_point(false).as_bytes());
        cases.push(("predecessor root pin", predecessor_root));
        if kind == 5 {
            let mut interval = bytes.clone();
            interval[37..53].copy_from_slice(Uuid::new_v4().as_bytes());
            cases.push(("different interval", interval));
            let mut until = bytes.clone();
            until[prefix + 233..prefix + 241]
                .copy_from_slice(&((c.now().await - 1) as u64).to_be_bytes());
            cases.push(("expired signer deadline", until));
            // A valid SEC1 point and matching role5 key ID remain forbidden
            // when they alias the current paired signing role history.
            let point = c.paired.verifying_key().to_sec1_point(false);
            let id =
                Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[1, 1], point.as_bytes()].concat());
            let mut alias = bytes.clone();
            alias[prefix + 136..prefix + 168].copy_from_slice(&id);
            alias[prefix + 168..prefix + 233].copy_from_slice(point.as_bytes());
            let n = u16::from_be_bytes(
                alias[predecessor_at..predecessor_at + 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let added = predecessor_at + 2 + n + 2 + 151 + 3 * 149;
            alias[added + 1..added + 33].copy_from_slice(&id);
            alias[added + 33..added + 98].copy_from_slice(point.as_bytes());
            cases.push(("known signing point alias", alias));
        }
        for (name, changed) in cases {
            assert_eq!(
                c.f.db
                    .execute(
                        "DELETE FROM owner_android_proposals WHERE account_id=$1 AND kind=$2",
                        &[&c.owner.principal.tenant.account_id(), &kind]
                    )
                    .await
                    .unwrap(),
                1
            );
            assert!(c.rows().await.is_empty());
            let mut wrong = body.clone();
            wrong["proposal_b64"] = serde_json::json!(STANDARD.encode(changed));
            assert!(
                request(&c, PATH, &wrong).await.0.is_client_error(),
                "{name}"
            );
            assert!(c.rows().await.is_empty(), "{name}");
            assert_eq!(c.authority_rows().await, authority_rows, "{name}");
            assert_eq!(
                request(&c, PATH, &body).await,
                (StatusCode::OK, receipt.clone()),
                "{name}"
            );
            let (status, got) = ceremonies::context_of(&c, kind, &bytes).await;
            assert_eq!(status, StatusCode::OK, "{name}: {got}");
            assert_eq!(
                got["expected_context"], original["expected_context"],
                "{name}"
            );
            assert_eq!(got["expires_ms"], original["expires_ms"], "{name}");
            assert_eq!(c.rows().await, rows, "{name}");
            assert_eq!(c.authority_rows().await, authority_rows, "{name}");
        }
        // Captured paired point/fingerprint drift is checked on the retained
        // original slot. The replacement is a valid synthetic public point,
        // so this cannot pass merely by rejecting malformed SEC1 framing.
        let replacement = SigningKey::generate_from_rng(&mut rand::rng());
        let replacement_point = replacement.verifying_key().to_sec1_point(false);
        c.f.db
            .execute(
                "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
                &[
                    &c.device,
                    &replacement_point.as_bytes(),
                    &Sha256::digest(replacement_point.as_bytes()).as_slice(),
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            ceremonies::context_of(&c, kind, &bytes).await.0,
            StatusCode::FORBIDDEN
        );
        assert!(request(&c, PATH, &body).await.0.is_client_error());
        assert_eq!(c.rows().await, rows);
        assert_eq!(c.authority_rows().await, authority_rows);
        let original_point = c.paired.verifying_key().to_sec1_point(false);
        c.f.db
            .execute(
                "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
                &[
                    &c.device,
                    &original_point.as_bytes(),
                    &Sha256::digest(original_point.as_bytes()).as_slice(),
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            ceremonies::context_of(&c, kind, &bytes).await.0,
            StatusCode::OK
        );
        // Wrong exact consent is independent of packet syntax and the
        // pending slot: the same original proposal/context was just live.
        c.f.db
            .execute(
                "UPDATE owner_conversation_consents SET peer='+13' WHERE account_id=$1",
                &[&c.owner.principal.tenant.account_id()],
            )
            .await
            .unwrap();
        let wrong_consent = c.authority_rows().await;
        assert_eq!(request(&c, PATH, &body).await.0, StatusCode::FORBIDDEN);
        assert_eq!(
            ceremonies::context_of(&c, kind, &bytes).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(c.rows().await, rows);
        assert_eq!(c.authority_rows().await, wrong_consent);
        c.f.db
            .execute(
                "UPDATE owner_conversation_consents SET peer='+12' WHERE account_id=$1",
                &[&c.owner.principal.tenant.account_id()],
            )
            .await
            .unwrap();
        assert_eq!(
            ceremonies::context_of(&c, kind, &bytes).await.0,
            StatusCode::OK
        );
        assert_eq!(c.authority_rows().await, authority_rows);
        if kind == 5 {
            c.f.db.execute("UPDATE conversation_intervals SET phase='history',closed_at=clock_timestamp() WHERE account_id=$1",
                &[&c.owner.principal.tenant.account_id()]).await.unwrap();
            let inactive = c.authority_rows().await;
            assert_eq!(request(&c, PATH, &body).await.0, StatusCode::FORBIDDEN);
            assert_eq!(
                ceremonies::context_of(&c, kind, &bytes).await.0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(c.rows().await, rows);
            assert_eq!(c.authority_rows().await, inactive);
            // History is irreversible under the maintained interval trigger;
            // teardown follows this negative, without reactivating the row.
        }
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner cookies"]
async fn raw_duplicate_unknown_and_oversized_bodies_refuse_without_pending_mutation() {
    let c = GenuineCase::new().await;
    let (packet, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
    let registration = registration(&c, &packet, &phone, &archive);
    let context = context(&c, &packet);
    let csrf = Some(c.owner.credentials.csrf_token.as_str());
    for (path, value) in [(PATH, &registration), (CONTEXT_PATH, &context)] {
        for key in value.as_object().unwrap().keys() {
            let before = c.rows().await;
            let (status, error) = raw(
                &c,
                Some(&c.owner),
                path,
                duplicate(value, key),
                Some(ORIGIN),
                csrf,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(error, serde_json::json!({"code":"invalid_request"}));
            assert_eq!(c.rows().await, before);
        }
        let mut unknown = value.clone();
        unknown["account_id"] = serde_json::json!(c.owner.principal.tenant.account_id());
        assert_eq!(request(&c, path, &unknown).await.0, StatusCode::BAD_REQUEST);
        assert!(c.rows().await.is_empty());
        assert_eq!(
            raw(
                &c,
                Some(&c.owner),
                path,
                vec![b' '; 32769],
                Some(ORIGIN),
                csrf
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(c.rows().await.is_empty());
    }
    assert_eq!(request(&c, PATH, &registration).await.0, StatusCode::OK);
    let rows = c.rows().await;
    for key in context.as_object().unwrap().keys() {
        assert_eq!(
            raw(
                &c,
                Some(&c.owner),
                CONTEXT_PATH,
                duplicate(&context, key),
                Some(ORIGIN),
                csrf
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(c.rows().await, rows);
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; origin and CSRF refusals"]
async fn missing_wrong_origin_and_wrong_csrf_refuse_both_routes_without_pending_mutation() {
    let c = GenuineCase::new().await;
    let (packet, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
    for (path, body) in [
        (PATH, registration(&c, &packet, &phone, &archive)),
        (CONTEXT_PATH, context(&c, &packet)),
    ] {
        for origin in [
            None,
            Some("https://other.example.test"),
            Some("https://owner.example.test/"),
        ] {
            assert_eq!(
                raw(
                    &c,
                    Some(&c.owner),
                    path,
                    serde_json::to_vec(&body).unwrap(),
                    origin,
                    Some(&c.owner.credentials.csrf_token)
                )
                .await
                .0,
                StatusCode::FORBIDDEN
            );
            assert!(c.rows().await.is_empty());
        }
        for csrf in [None, Some("incorrect")] {
            assert_eq!(
                raw(
                    &c,
                    Some(&c.owner),
                    path,
                    serde_json::to_vec(&body).unwrap(),
                    Some(ORIGIN),
                    csrf
                )
                .await
                .0,
                StatusCode::FORBIDDEN
            );
            assert!(c.rows().await.is_empty());
        }
        assert_eq!(
            raw(
                &c,
                None,
                path,
                serde_json::to_vec(&body).unwrap(),
                Some(ORIGIN),
                None
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert!(c.rows().await.is_empty());
    }
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original-principal scope"]
async fn other_registered_owner_and_other_login_session_cannot_reuse_original_proposal() {
    let c = GenuineCase::new().await;
    let (packet, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
    assert_eq!(
        request(&c, PATH, &registration(&c, &packet, &phone, &archive))
            .await
            .0,
        StatusCode::OK
    );
    let rows = c.rows().await;
    let stranger = SignedIn::register(&c.f, &c.hasher).await;
    let db = c.f.connect().await;
    let credentials = auth::login(&db, &c.hasher, &c.owner.email, &c.owner.password)
        .await
        .unwrap();
    let principal = auth::authenticate_session(&db, &c.hasher, &credentials.token)
        .await
        .unwrap();
    let secondary = SignedIn {
        principal,
        credentials,
        email: c.owner.email.clone(),
        password: c.owner.password.clone(),
    };
    for who in [&stranger, &secondary] {
        let mut body = context(&c, &packet);
        // Match the authenticated caller so refusal must check retained original ownership.
        body["expected_session_id"] = serde_json::json!(who.principal.session_id);
        assert_eq!(
            raw(
                &c,
                Some(who),
                CONTEXT_PATH,
                serde_json::to_vec(&body).unwrap(),
                Some(ORIGIN),
                Some(&who.credentials.csrf_token)
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(c.rows().await, rows);
        let mut issue = registration(&c, &packet, &phone, &archive);
        issue["expected_session_id"] = serde_json::json!(who.principal.session_id);
        assert!(
            raw(
                &c,
                Some(who),
                PATH,
                serde_json::to_vec(&issue).unwrap(),
                Some(ORIGIN),
                Some(&who.credentials.csrf_token)
            )
            .await
            .0
            .is_client_error()
        );
        assert_eq!(c.rows().await, rows);
    }
    let mut wrong = context(&c, &packet);
    wrong["expected_session_id"] = serde_json::json!(secondary.principal.session_id);
    assert_eq!(
        request(&c, CONTEXT_PATH, &wrong).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(c.rows().await, rows);
    drop(db);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; invalid kind and canonical encoding"]
async fn line_bridge_and_noncanonical_encodings_cannot_issue_or_select_typed_pending() {
    let c = GenuineCase::new().await;
    let (packet, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
    let good = registration(&c, &packet, &phone, &archive);
    for kind in [1, 2, 0, 6] {
        let mut wrong = good.clone();
        wrong["kind"] = serde_json::json!(kind);
        assert!(request(&c, PATH, &wrong).await.0.is_client_error());
        assert!(c.rows().await.is_empty());
    }
    let mut noncanonical = good.clone();
    noncanonical["proposal_b64"] = serde_json::json!(format!("{}\n", STANDARD.encode(&packet)));
    assert_eq!(
        request(&c, PATH, &noncanonical).await.0,
        StatusCode::BAD_REQUEST
    );
    assert!(c.rows().await.is_empty());
    assert_eq!(request(&c, PATH, &good).await.0, StatusCode::OK);
    let rows = c.rows().await;
    for kind in [1, 2, 0, 6] {
        let mut wrong = context(&c, &packet);
        wrong["kind"] = serde_json::json!(kind);
        assert!(request(&c, CONTEXT_PATH, &wrong).await.0.is_client_error());
        assert_eq!(c.rows().await, rows);
    }
    for hash in ["00".repeat(31), "gg".repeat(32), "AB".repeat(32)] {
        let mut wrong = context(&c, &packet);
        wrong["proposal_sha256_hex"] = serde_json::json!(hash);
        assert_eq!(
            request(&c, CONTEXT_PATH, &wrong).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(c.rows().await, rows);
    }
    let mut mismatch = context(&c, &packet);
    mismatch["proposal_sha256_hex"] = serde_json::json!("00".repeat(32));
    assert_eq!(
        request(&c, CONTEXT_PATH, &mismatch).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(c.rows().await, rows);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; expired current phone lease"]
async fn expired_current_phone_lease_refuses_context_and_preserves_original_deadline() {
    let c = GenuineCase::new().await;
    let (packet, phone, archive) = ceremonies::inputs(&c, c.now().await as u64);
    assert_eq!(
        request(&c, PATH, &registration(&c, &packet, &phone, &archive))
            .await
            .0,
        StatusCode::OK
    );
    let rows = c.rows().await;
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    tx.execute("UPDATE device_sessions SET lease_until=clock_timestamp() WHERE account_id=$1 AND device_id=$2",
        &[&c.owner.principal.tenant.account_id(),&c.device]).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        request(&c, CONTEXT_PATH, &context(&c, &packet)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(c.rows().await, rows);
    drop(db);
    c.cleanup().await;
}
