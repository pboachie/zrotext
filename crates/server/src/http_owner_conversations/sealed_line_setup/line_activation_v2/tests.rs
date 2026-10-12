// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::inbound::InboundSession;
use axum::{body::Body, http::Request};
use p256::ecdsa::{Signature, signature::Signer};
use tower::ServiceExt;

#[test]
fn raw_sealed_owner_bodies_are_objects_with_direct_duplicate_and_type_refusal() {
    assert!(serde_json::from_str::<Open>(r#"{"expected_session_id":"session","device_id":"device","registration_id":"registration"}"#).is_ok());
    assert!(serde_json::from_str::<Session>(r#"{"expected_session_id":"session"}"#).is_ok());
    assert!(
        serde_json::from_str::<Approve>(
            r#"{"expected_session_id":"session","owner_signature_der_b64url":"signature"}"#
        )
        .is_ok()
    );
    assert!(serde_json::from_str::<Open>(r#"["session","device","registration"]"#).is_err());
    assert!(serde_json::from_str::<Session>(r#"["session"]"#).is_err());
    assert!(serde_json::from_str::<Approve>(r#"["session","signature"]"#).is_err());
    for raw in [
        r#"{"expected_session_id":"a","\u0065xpected_session_id":"b"}"#,
        r#"{"expected_session_id":null}"#,
        r#"{"expected_session_id":2}"#,
        r#"{"expected_session_id":true}"#,
        r#"{"expected_session_id":[]}"#,
        r#"{"expected_session_id":{}}"#,
        r#"{}"#,
        r#"{"expected_session_id":"a","trusted":true}"#,
    ] {
        assert!(serde_json::from_str::<Session>(raw).is_err(), "{raw}");
    }
    for (field, value) in [
        ("expected_session_id", serde_json::json!(null)),
        ("device_id", serde_json::json!(false)),
        ("registration_id", serde_json::json!(2)),
    ] {
        let mut body = serde_json::json!({"expected_session_id":"session","device_id":"device","registration_id":"registration"});
        body[field] = value;
        assert!(serde_json::from_str::<Open>(&body.to_string()).is_err());
    }
    assert!(serde_json::from_str::<Open>(r#"{"expected_session_id":"s","device_id":"a","\u0064evice_id":"b","registration_id":"r"}"#).is_err());
    assert!(serde_json::from_str::<Approve>(r#"{"expected_session_id":"s","owner_signature_der_b64url":"a","\u006fwner_signature_der_b64url":"b"}"#).is_err());
    assert!(
        serde_json::from_str::<Approve>(
            r#"{"expected_session_id":"s","owner_signature_der_b64url":null}"#
        )
        .is_err()
    );
}

#[test]
fn registration_opening_body_is_closed_and_canonical() {
    let value = serde_json::json!({"expected_session_id":Uuid::new_v4(),"device_id":Uuid::new_v4(),"registration_id":Uuid::new_v4()});
    assert!(serde_json::from_value::<Open>(value.clone()).is_ok());
    for key in [
        "account_id",
        "protocol_version",
        "opening_id",
        "root_fingerprint",
        "trusted",
    ] {
        let mut v = value.clone();
        v[key] = serde_json::json!(true);
        assert!(serde_json::from_value::<Open>(v).is_err());
    }
    assert!(id(&Uuid::nil().to_string()).is_err());
    assert!(signature("AA==").is_err());
}
#[tokio::test]
async fn sealed_v2_requires_explicit_composition_and_owner_before_body() {
    let owner = OwnerConversationsState {
        database_url: "invalid".into(),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(93)).unwrap()),
        canonical_origin: "https://owner.example.test".into(),
    };
    let line = Uuid::new_v4();
    let challenge = Uuid::new_v4();
    for path in [
        format!("/v1/owner/conversation/sealed-line/{line}/challenges-v2"),
        format!("/v1/owner/conversation/sealed-line/{line}/challenges-v2/{challenge}/view"),
        format!("/v1/owner/conversation/sealed-line/{line}/challenges-v2/{challenge}/approve"),
    ] {
        assert_eq!(
            super::super::super::owner_host::router(owner.clone())
                .oneshot(Request::post(&path).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let body = Body::from_stream(futures_util::stream::pending::<
            std::result::Result<axum::body::Bytes, std::io::Error>,
        >());
        let app = super::super::router(SetupState {
            owner: owner.clone(),
            mfa_cipher: Arc::new(MfaCipher::new(crate::test_keys::key(92)).unwrap()),
        });
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app.oneshot(Request::post(&path).body(body).unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; seeded pinned root/MFA with real registration transaction"]
async fn seeded_root_registered_v2_receipt_is_atomic_and_exact_retry_survives_nonce_removal() {
    use super::super::tests::{Case, ORIGIN};
    use crate::sealed_inbound::line_activation::{v2, v2_runtime as run};
    let c = Case::new().await;
    let mut db = c.owner.f.connect().await;
    c.owner.f.db.execute("UPDATE device_sessions SET connection_epoch=2,line_activation_version=2 WHERE device_id=$1",&[&c.device]).await.unwrap();
    let mut selection = c.selection(1);
    selection.connection_epoch = 2;
    let statement = registration::issue(&mut db, &c.owner.principal, ORIGIN, selection)
        .await
        .unwrap();
    let registration_id = Uuid::from_bytes(statement.scope().challenge);
    let (bytes, root, approval) = c.signatures(&statement);
    let factor = c.factor().await;
    registration::complete(
        &mut db,
        &c.owner.principal,
        ORIGIN,
        &c.owner.hasher,
        &c.owner.cipher,
        registration_id,
        registration::Completion {
            unsigned: &bytes,
            root_signature: &root,
            approval_signature: &approval,
            factor: &factor,
        },
    )
    .await
    .unwrap();
    let session = InboundSession {
        connection_epoch: 2,
        ..c.session()
    };
    let challenge = run::open(
        &mut db,
        &c.owner.principal,
        c.line,
        c.device,
        Purpose::Sealed,
        registration_id,
        Some(registration_id),
    )
    .await
    .unwrap();
    let mut raw = [0u8; 121];
    raw[0..2].copy_from_slice(&35u16.to_be_bytes());
    raw[2..4].copy_from_slice(&2u16.to_be_bytes());
    raw[4..8].copy_from_slice(&7i32.to_be_bytes());
    raw[8] = 1;
    for offset in [9, 25, 49, 73] {
        raw[offset..offset + 16].copy_from_slice(Uuid::new_v4().as_bytes());
    }
    raw[65..73].copy_from_slice(&1i64.to_be_bytes());
    raw[89..121].fill(7);
    let observation = v2::ObservationV2::decode(&raw).unwrap();
    let unsigned =
        v2::device_statement(v2::PurposeV2::Sealed, &challenge.tuple, &observation).unwrap();
    let proof: Signature = c.paired.sign(&unsigned.bytes());
    assert!(
        run::record_device_proof(
            &mut db,
            session,
            Purpose::Sealed,
            challenge.tuple.id,
            &raw,
            proof.to_der().as_bytes()
        )
        .await
        .unwrap()
    );
    let view = run::view(
        &mut db,
        &c.owner.principal,
        c.line,
        challenge.tuple.id,
        Purpose::Sealed,
    )
    .await
    .unwrap();
    let approval: Signature = c.approval.sign(&view.owner_statement.unwrap());
    run::approve(
        &mut db,
        &c.owner.principal,
        c.line,
        challenge.tuple.id,
        Purpose::Sealed,
        approval.to_der().as_bytes(),
    )
    .await
    .unwrap();
    let ack = run::next_ack(&mut db, session, Purpose::Sealed, &[])
        .await
        .unwrap()
        .unwrap();
    let mut wrong = ack;
    wrong.device_signature_sha256[0] ^= 1;
    assert!(
        !run::confirm_sealed_install(&mut db, session, wrong)
            .await
            .unwrap()
    );
    assert!(c.owner.f.db.query_one("SELECT nonce IS NOT NULL AND installed_at IS NULL FROM line_activation_v2_pending WHERE challenge_id=$1",&[&ack.challenge_id]).await.unwrap().get::<_,bool>(0));
    assert!(
        run::confirm_sealed_install(&mut db, session, ack)
            .await
            .unwrap()
    );
    assert!(c.owner.f.db.query_one("SELECT nonce IS NULL AND installed_at IS NOT NULL FROM line_activation_v2_pending WHERE challenge_id=$1",&[&ack.challenge_id]).await.unwrap().get::<_,bool>(0));
    // Model a dropped outgoing install_ack: exact retry reads the committed
    // terminal tuple. It neither recreates a nonce nor renews the challenge.
    assert!(
        run::confirm_sealed_install(&mut db, session, ack)
            .await
            .unwrap()
    );
    c.owner
        .f
        .db
        .execute(
            "UPDATE device_sessions SET connection_epoch=3 WHERE device_id=$1",
            &[&c.device],
        )
        .await
        .unwrap();
    let renewed = InboundSession {
        connection_epoch: 3,
        ..session
    };
    assert!(
        !run::confirm_sealed_install(&mut db, session, ack)
            .await
            .unwrap()
    );
    assert!(
        run::confirm_sealed_install(&mut db, renewed, ack)
            .await
            .unwrap()
    );
    assert_eq!(
        c.owner
            .f
            .db
            .execute(
                "UPDATE line_activation_v2_pending SET nonce=$2 WHERE challenge_id=$1",
                &[&ack.challenge_id, &&challenge.tuple.nonce[..]]
            )
            .await
            .unwrap_err()
            .code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    drop(db);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual registered v2 proof blocked by MFA or receipt invalidation"]
async fn sealed_proof_rechecks_mfa_and_registration_after_observed_lock_wait() {
    use super::super::tests::{Case, ORIGIN};
    use crate::sealed_inbound::line_activation::{v2, v2_runtime as run};
    for case in ["mfa", "registration"] {
        let c = Case::new().await;
        let account = c.owner.principal.tenant.account_id();
        let mut db = c.owner.f.connect().await;
        c.owner.f.db.execute("UPDATE device_sessions SET connection_epoch=2,line_activation_version=2 WHERE device_id=$1",&[&c.device]).await.unwrap();
        let mut selection = c.selection(1);
        selection.connection_epoch = 2;
        let statement = registration::issue(&mut db, &c.owner.principal, ORIGIN, selection)
            .await
            .unwrap();
        let id = Uuid::from_bytes(statement.scope().challenge);
        let (bytes, root, approval) = c.signatures(&statement);
        let factor = c.factor().await;
        registration::complete(
            &mut db,
            &c.owner.principal,
            ORIGIN,
            &c.owner.hasher,
            &c.owner.cipher,
            id,
            registration::Completion {
                unsigned: &bytes,
                root_signature: &root,
                approval_signature: &approval,
                factor: &factor,
            },
        )
        .await
        .unwrap();
        let challenge = run::open(
            &mut db,
            &c.owner.principal,
            c.line,
            c.device,
            Purpose::Sealed,
            id,
            Some(id),
        )
        .await
        .unwrap();
        let session = InboundSession {
            connection_epoch: 2,
            ..c.session()
        };
        let mut raw = [0u8; 121];
        raw[..2].copy_from_slice(&35u16.to_be_bytes());
        raw[2..4].copy_from_slice(&2u16.to_be_bytes());
        raw[4..8].copy_from_slice(&7i32.to_be_bytes());
        raw[8] = 1;
        for offset in [9, 25, 49, 73] {
            raw[offset..offset + 16].copy_from_slice(Uuid::new_v4().as_bytes());
        }
        raw[65..73].copy_from_slice(&1i64.to_be_bytes());
        raw[89..121].fill(7);
        let observation = v2::ObservationV2::decode(&raw).unwrap();
        let unsigned =
            v2::device_statement(v2::PurposeV2::Sealed, &challenge.tuple, &observation).unwrap();
        let signature: Signature = c.paired.sign(&unsigned.bytes());
        let der = signature.to_der();
        let mut blocker = c.owner.f.connect().await;
        let tx = blocker.transaction().await.unwrap();
        if case == "mfa" {
            tx.query_one(
                "SELECT user_id FROM owner_mfa WHERE account_id=$1 AND user_id=$2 FOR UPDATE",
                &[&account, &c.owner.principal.user_id],
            )
            .await
            .unwrap();
        } else {
            tx.query_one("SELECT registration_id FROM sealed_line_key_receipts WHERE account_id=$1 AND registration_id=$2 FOR UPDATE",&[&account,&id]).await.unwrap();
        }
        let pid: i32 = db
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let mut proof = Box::pin(run::record_device_proof(
            &mut db,
            session,
            Purpose::Sealed,
            challenge.tuple.id,
            &raw,
            der.as_bytes(),
        ));
        let wait = async {
            loop {
                if c.owner
                    .f
                    .db
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)",
                        &[&pid],
                    )
                    .await
                    .unwrap()
                    .get::<_, bool>(0)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        tokio::select! {result=&mut proof=>panic!("{case}: proof completed before barrier: {}",matches!(result,Ok(true))),result=tokio::time::timeout(std::time::Duration::from_secs(2),wait)=>result.expect("actual sealed proof lock wait")}
        if case == "mfa" {
            // The owner_mfa checks pair a NULL enabled_at with a pending
            // re-enrollment, so removing the row is the schema-legal way to
            // represent MFA no longer being enabled for this account.
            tx.execute(
                "DELETE FROM owner_mfa WHERE account_id=$1 AND user_id=$2",
                &[&account, &c.owner.principal.user_id],
            )
            .await
            .unwrap();
        } else {
            tx.execute("UPDATE sealed_line_key_receipts SET retired_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE account_id=$1 AND registration_id=$2",&[&account,&id]).await.unwrap();
        }
        tx.commit().await.unwrap();
        assert!(
            !tokio::time::timeout(std::time::Duration::from_secs(5), &mut proof)
                .await
                .expect("known sealed proof completion")
                .expect("invalidated registration is a typed refusal, not a database error")
        );
        drop(proof);
        drop(db);
        drop(blocker);
        assert_eq!(
            c.owner
                .f
                .db
                .query_one(
                    "SELECT count(*) FROM line_activation_v2_observations WHERE challenge_id=$1",
                    &[&challenge.tuple.id]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        assert!(c.owner.f.db.query_one("SELECT c.consumed_at IS NULL AND p.approved_at IS NULL AND p.installed_at IS NULL AND p.nonce IS NOT NULL FROM line_activation_challenges c JOIN line_activation_v2_pending p ON p.challenge_id=c.id WHERE c.id=$1",&[&challenge.tuple.id]).await.unwrap().get::<_,bool>(0));
        c.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original registered owner activity expires behind unchanged binding"]
async fn registered_opening_retry_rechecks_owner_activity_after_binding_wait() {
    use super::super::tests::{Case, ORIGIN};
    use crate::sealed_inbound::line_activation::{LineActivationError, v2_runtime as run};
    let c = Case::new().await;
    let account = c.owner.principal.tenant.account_id();
    let mut db = c.owner.f.connect().await;
    c.owner.f.db.execute("UPDATE device_sessions SET connection_epoch=2,line_activation_version=2 WHERE device_id=$1",&[&c.device]).await.unwrap();
    let mut selection = c.selection(1);
    selection.connection_epoch = 2;
    let statement = registration::issue(&mut db, &c.owner.principal, ORIGIN, selection)
        .await
        .unwrap();
    let id = Uuid::from_bytes(statement.scope().challenge);
    let (bytes, root, approval) = c.signatures(&statement);
    let factor = c.factor().await;
    registration::complete(
        &mut db,
        &c.owner.principal,
        ORIGIN,
        &c.owner.hasher,
        &c.owner.cipher,
        id,
        registration::Completion {
            unsigned: &bytes,
            root_signature: &root,
            approval_signature: &approval,
            factor: &factor,
        },
    )
    .await
    .unwrap();
    let challenge = run::open(
        &mut db,
        &c.owner.principal,
        c.line,
        c.device,
        Purpose::Sealed,
        id,
        Some(id),
    )
    .await
    .unwrap();
    // The challenge has the registration's absolute cap, but the owner's
    // independent activity window can expire substantially earlier.
    assert!(c.owner.f.db.query_one("SELECT expires_at<=to_timestamp($2::bigint::double precision/1000) FROM line_activation_challenges WHERE id=$1",&[&challenge.tuple.id,&(statement.scope().expires_ms as i64)]).await.unwrap().get::<_,bool>(0));
    c.owner.f.db.execute("UPDATE sessions SET last_used_at=clock_timestamp()-interval '72 hours'+interval '5 seconds' WHERE id=$1",&[&c.owner.principal.session_id]).await.unwrap();
    const SNAPSHOT: &str = "SELECT jsonb_build_array(to_jsonb(p),to_jsonb(c),to_jsonb(b),to_jsonb(l),to_jsonb(r))::text FROM line_activation_v2_pending p JOIN line_activation_challenges c ON c.id=p.challenge_id JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(p.account_id,p.line_id,p.device_id,p.generation) JOIN phone_lines l ON (l.account_id,l.id)=(p.account_id,p.line_id) JOIN sealed_line_key_receipts r ON (r.account_id,r.registration_id)=(p.account_id,p.registration_id) WHERE p.challenge_id=$1";
    let before: String = c
        .owner
        .f
        .db
        .query_one(SNAPSHOT, &[&challenge.tuple.id])
        .await
        .unwrap()
        .get(0);
    let mut blocker = c.owner.f.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one(
        "SELECT generation FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 FOR UPDATE",
        &[&account, &c.line],
    )
    .await
    .unwrap();
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let mut retry = Box::pin(run::open(
        &mut db,
        &c.owner.principal,
        c.line,
        c.device,
        Purpose::Sealed,
        id,
        Some(id),
    ));
    let wait = async {
        loop {
            if c.owner
                .f
                .db
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)",
                    &[&pid],
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        result=&mut retry=>panic!("registered retry completed before binding wait: {}",result.is_ok()),
        result=tokio::time::timeout(std::time::Duration::from_secs(2),wait)=>result.expect("actual registered retry binding wait"),
    }
    tokio::time::timeout(std::time::Duration::from_secs(7),async {
        loop {
            if c.owner.f.db.query_one("SELECT COALESCE(last_used_at,created_at)<=clock_timestamp()-interval '72 hours' FROM sessions WHERE id=$1",&[&c.owner.principal.session_id]).await.unwrap().get::<_,bool>(0) {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("actual registered owner activity deadline");
    // Exclude challenge/session/phone absolute expiry as an alternative cause.
    assert!(c.owner.f.db.query_one("SELECT c.expires_at>clock_timestamp() AND o.expires_at>clock_timestamp() AND d.lease_until>clock_timestamp() FROM line_activation_challenges c JOIN sessions o ON o.account_id=c.account_id JOIN device_sessions d ON (d.account_id,d.device_id)=(c.account_id,c.device_id) WHERE c.id=$1 AND o.id=$2",&[&challenge.tuple.id,&c.owner.principal.session_id]).await.unwrap().get::<_,bool>(0));
    lock.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut retry)
            .await
            .expect("known registered retry completion"),
        Err(LineActivationError::Unavailable)
    ));
    drop(retry);
    let after: String = c
        .owner
        .f
        .db
        .query_one(SNAPSHOT, &[&challenge.tuple.id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        before, after,
        "expired registered retry changed provenance or pending state"
    );
    drop(db);
    drop(blocker);
    c.cleanup().await;
}
