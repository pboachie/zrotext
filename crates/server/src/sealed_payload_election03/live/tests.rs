// SPDX-License-Identifier: AGPL-3.0-only
//! Actual ordinary-runtime ceremonies and accepted-row integration. The lease
//! and local observation are synthetic; no phone/hardware/carrier claim.
use super::*;
use crate::auth::ordinary_owner03::{self, RequestSource, step_up};
use crate::sealed_inbound::line_activation::v2_runtime as run;
use crate::sealed_manifest03 as crypto;
use crate::sealed_payload_election03::activation_records::tests::fixture::Case;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use uuid::Uuid;
const ORIGIN: &str = "https://activation.example";
mod fixture;
mod manifest_cache_tests;
mod manifest_original_tests;
mod manifest_tests;
use fixture::{prepared, sign, source};

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary runtime election schema"]
async fn real_opening_burns_once_distinct_factors_commit_and_exact_retry_stays_historical() {
    let (mut c, successor) = prepared().await;
    let opening = Uuid::new_v4();
    let line = c.line;
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[2])
            .await
            .unwrap()
    else {
        panic!("actual factor refused")
    };
    let r = reserve(&tx, &mut proof, opening, line, &successor, ORIGIN)
        .await
        .unwrap();
    assert!(r.device_signature.is_none());
    assert_eq!(r.old_generation, 1);
    assert_eq!(r.new_generation, 2);
    let original_core = r.core;
    let challenge = r.challenge;
    let binding = r.new_binding;
    drop(proof);
    tx.commit().await.unwrap();
    let highwater: i64 = c
        .db
        .reader
        .query_one(
            "SELECT last_issued_generation FROM public.phone_lines WHERE account_id=$1 AND id=$2",
            &[&c.principal.tenant.account_id(), &line],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(highwater, 2);
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let retried = status(&tx, &mut owner, opening, line).await.unwrap();
    assert_eq!(retried.core, original_core);
    assert_eq!(retried.new_binding, binding);
    assert!(retried.matches_successor(&successor));
    let step_up::Outcome::Rejected(step_up::Rejection::InvalidCredentials) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[2])
            .await
            .unwrap()
    else {
        panic!("consumed factor became fresh")
    };
    tx.commit().await.unwrap();
    let device_signature = sign(
        &c.phone_key,
        b"ZTSE/line/payload-profile/device/v1\0",
        &original_core,
    );
    let tx = c.db.reader.transaction().await.unwrap();
    device_proof(
        &tx,
        SocketSelection03 {
            session: crate::device_socket::DeviceSession {
                account_id: c.principal.tenant.account_id(),
                device_id: c.device,
                connection_epoch: 1,
            },
            site: "activation-test",
            instance: "fixture",
            deployment: 1,
            origin: ORIGIN,
        },
        challenge,
        &device_signature,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let owner_payload = [original_core.as_slice(), &crypto::sha(&device_signature)].concat();
    let owner_signature = sign(
        &c.approval_key,
        b"ZTSE/line/payload-profile/owner/v1\0",
        &owner_payload,
    );
    let bundle = [
        original_core.as_slice(),
        &device_signature,
        &owner_signature,
    ]
    .concat();
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[3])
            .await
            .unwrap()
    else {
        panic!("distinct fresh factor refused")
    };
    let receipt = accept(
        &tx, &mut proof, opening, challenge, &successor, &bundle, ORIGIN,
    )
    .await
    .unwrap();
    assert_eq!(receipt["selection_epoch"], "1");
    assert_eq!(receipt["binding_id"], binding.to_string());
    drop(proof);
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let replay = historical_accept(&tx, &mut owner, opening, challenge, &successor, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt, replay);
    let mut changed = bundle.clone();
    changed[627] ^= 1;
    assert!(
        historical_accept(&tx, &mut owner, opening, challenge, &successor, &changed)
            .await
            .is_err()
    );
    drop(owner);
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let permission = current(&tx, &mut owner, c.line, ORIGIN).await.unwrap();
    assert_eq!(
        permission["owner_session_id"],
        c.principal.session_id.to_string()
    );
    assert!(permission.get("kind").is_none());
    assert!(permission.get("physical_selection").is_none());
    drop(owner);
    tx.rollback().await.unwrap();
    assert!(
        crate::auth::revoke_session(&c.db.reader, &c.principal, c.principal.session_id)
            .await
            .unwrap()
    );
    let socket = crate::device_socket::DeviceSession {
        account_id: c.principal.tenant.account_id(),
        device_id: c.device,
        connection_epoch: 1,
    };
    let tx = c.db.reader.transaction().await.unwrap();
    assert!(
        ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let selection = device_current(&tx, socket, "activation-test", "fixture", 1, c.line, ORIGIN)
        .await
        .unwrap();
    assert_eq!(selection["kind"], "device_selection03");
    assert_eq!(selection["physical_selection"]["kind"], "original_v2");
    for field in [
        "user_id",
        "owner_session_id",
        "owner_session_digest",
        "permission_expires_ms",
    ] {
        assert!(selection.get(field).is_none());
    }
    assert_eq!(
        selection["evidence"]["bundle"],
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bundle)
    );
    tx.rollback().await.unwrap();
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary runtime election schema"]
async fn wrong_owner_signature_rolls_back_new_factor_and_entire_epoch_transition() {
    let (mut c, successor) = prepared().await;
    let opening = Uuid::new_v4();
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[2])
            .await
            .unwrap()
    else {
        panic!("factor")
    };
    let r = reserve(&tx, &mut proof, opening, c.line, &successor, ORIGIN)
        .await
        .unwrap();
    drop(proof);
    tx.commit().await.unwrap();
    let device_signature = sign(
        &c.phone_key,
        b"ZTSE/line/payload-profile/device/v1\0",
        &r.core,
    );
    let tx = c.db.reader.transaction().await.unwrap();
    device_proof(
        &tx,
        SocketSelection03 {
            session: crate::device_socket::DeviceSession {
                account_id: c.principal.tenant.account_id(),
                device_id: c.device,
                connection_epoch: 1,
            },
            site: "activation-test",
            instance: "fixture",
            deployment: 1,
            origin: ORIGIN,
        },
        r.challenge,
        &device_signature,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let forged = sign(
        &c.phone_key,
        b"ZTSE/line/payload-profile/owner/v1\0",
        &[r.core.as_slice(), &crypto::sha(&device_signature)].concat(),
    );
    let bundle = [r.core.as_slice(), &device_signature, &forged].concat();
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[3])
            .await
            .unwrap()
    else {
        panic!("factor")
    };
    assert!(
        accept(
            &tx,
            &mut proof,
            opening,
            r.challenge,
            &successor,
            &bundle,
            ORIGIN
        )
        .await
        .is_err()
    );
    drop(proof);
    tx.rollback().await.unwrap();
    let row=c.db.reader.query_one("SELECT selection_epoch,(SELECT count(*) FROM public.payload_profile_elections WHERE account_id=$1) FROM public.payload_profile_account_anchors WHERE account_id=$1",&[&c.principal.tenant.account_id()]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[3])
            .await
            .unwrap(),
        step_up::Outcome::Verified(_)
    ));
    tx.rollback().await.unwrap();
    c.db.finish().await;
}
