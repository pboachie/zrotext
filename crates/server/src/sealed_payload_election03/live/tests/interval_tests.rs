// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine owner/root/v2/election/manifest/consent signatures and ordinary SQL.
//! The physical lease is synthetic; no phone hardware or carrier claim.
use super::manifest_tests::{elected, packet};
use super::*;
use crate::{
    conversation_interval03::{self as consent, live as intervals},
    manifest_install03::live as manifests,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

fn device(c: &Case) -> intervals::DeviceInterval03<'static> {
    intervals::DeviceInterval03 {
        session: crate::device_socket::DeviceSession {
            account_id: c.principal.tenant.account_id(),
            device_id: c.device,
            connection_epoch: 1,
        },
        site: "activation-test",
        instance: "fixture",
        deployment: 1,
        origin: ORIGIN,
    }
}
#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary runtime conversation schema"]
async fn genuine_owner_request_and_phone_install_activate_then_device_stop_preserves_originals() {
    let (mut c, _) = elected().await;
    let browser = SigningKey::generate_from_rng(&mut rand::rng());
    let (opening, statement, signed, signature) = packet(&mut c, &browser, false).await;
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[4])
            .await
            .unwrap()
    else {
        panic!("genuine manifest factor")
    };
    manifests::install(
        &tx,
        &mut proof,
        manifests::InstallCommand03 {
            opening,
            statement: &statement,
            successor: &signed,
            signature: &signature,
        },
        ORIGIN,
    )
    .await
    .unwrap();
    drop(proof);
    tx.commit().await.unwrap();
    let key = |role| -> [u8; 32] {
        signed[153..signed.len() - 64]
            .chunks_exact(149)
            .find(|r| r[0] == role && r[148] == 1)
            .unwrap()[1..33]
            .try_into()
            .unwrap()
    };
    let opening = Uuid::new_v4();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let now:i64=tx.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",&[]).await.unwrap().get(0);
    let (new, reserved) = intervals::reserve(
        &tx,
        &mut owner,
        intervals::Reserve03 {
            opening,
            line: c.line,
            peer: b"+12",
            archive: key(2),
            phone: key(4),
            browser: key(5),
            expires_ms: now as u64 + 300_000,
            integrations: &[],
        },
        ORIGIN,
    )
    .await
    .unwrap();
    assert!(new);
    assert_eq!(reserved["phase"], "reserved");
    drop(owner);
    tx.commit().await.unwrap();
    let id = Uuid::parse_str(reserved["interval_id"].as_str().unwrap()).unwrap();
    let bytes = B.decode(reserved["statement"].as_str().unwrap()).unwrap();
    let parsed = consent::Statement03::decode(&bytes).unwrap();
    let owner_sig = sign(&browser, b"zrotext/conversation/request03/v1\0", &bytes);
    let tx = c.db.reader.transaction().await.unwrap();
    assert!(
        intervals::device_challenge(&tx, device(&c))
            .await
            .unwrap()
            .is_none()
    );
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[5])
            .await
            .unwrap()
    else {
        panic!("fresh content request factor")
    };
    let (new, requested) =
        intervals::request(&tx, &mut proof, opening, id, &bytes, &owner_sig, ORIGIN)
            .await
            .unwrap();
    assert!(new);
    assert_eq!(requested["phase"], "requested");
    drop(proof);
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let challenge = intervals::device_challenge(&tx, device(&c))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(challenge["interval_permission"]["phase"], "requested");
    assert_eq!(challenge["current"]["kind"], "device_manifest_selection03");
    assert_eq!(challenge["statement"], reserved["statement"]);
    tx.rollback().await.unwrap();
    let phone_sig = sign(
        &c.phone_key,
        b"zrotext/conversation/approve03/v1\0",
        &[bytes.as_slice(), &crypto::sha(&owner_sig)].concat(),
    );
    let installed_sig = sign(
        &c.phone_key,
        b"zrotext/conversation/install03/v1\0",
        &[
            bytes.as_slice(),
            &crypto::sha(&owner_sig),
            &crypto::sha(&phone_sig),
        ]
        .concat(),
    );
    let tx = c.db.reader.transaction().await.unwrap();
    intervals::device_approve(&tx, device(&c), id, &parsed.digest(), &phone_sig)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let status = intervals::device_status(&tx, device(&c), id, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(status["interval_permission"]["phase"], "install_pending");
    assert!(status["interval_permission"]["installed_signature"].is_null());
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    intervals::device_install(&tx, device(&c), id, &parsed.digest(), &installed_sig)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let active = intervals::device_status(&tx, device(&c), id, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(active["interval_permission"]["phase"], "active");
    assert_eq!(
        active["interval_permission"]["installed_signature"],
        B.encode(&installed_sig)
    );
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let stopped = intervals::device_stop(&tx, device(&c), id, &parsed.digest())
        .await
        .unwrap();
    assert_eq!(stopped["type"], "conversation_interval_stopped03");
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let historical = intervals::owner_status(&tx, &mut owner, opening, id)
        .await
        .unwrap();
    assert_eq!(historical["phase"], "stopped");
    assert_eq!(historical["statement"], reserved["statement"]);
    assert_eq!(historical["owner_signature"], B.encode(&owner_sig));
    assert_eq!(historical["phone_signature"], B.encode(&phone_sig));
    assert_eq!(historical["installed_signature"], B.encode(&installed_sig));
    drop(owner);
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    assert!(matches!(
        intervals::device_status(&tx, device(&c), id, Uuid::new_v4()).await,
        Err(Error::Expired)
    ));
    tx.rollback().await.unwrap();
    c.db.finish().await;
}
