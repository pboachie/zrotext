// SPDX-License-Identifier: AGPL-3.0-only
//! Cold original-proof bootstrap reads are not physical or content authority.
use super::manifest_tests::{elected, packet};
use super::*;
use crate::manifest_install03::live as manifests;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary runtime manifest schema"]
async fn original_bootstrap_survives_tip_advance_and_reconnect_without_physical_permission() {
    let (mut c, original03) = elected().await;
    let browser = SigningKey::generate_from_rng(&mut rand::rng());
    let (opening, statement, successor, signature) = packet(&mut c, &browser, false).await;
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
            successor: &successor,
            signature: &signature,
        },
        ORIGIN,
    )
    .await
    .unwrap();
    drop(proof);
    tx.commit().await.unwrap();
    c.db.reader.execute("UPDATE public.device_sessions SET connection_epoch=2,lease_until=pg_catalog.clock_timestamp()+interval '5 minutes' WHERE account_id=$1 AND device_id=$2",&[&c.principal.tenant.account_id(),&c.device]).await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let original = manifests::original_owner(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    let fields = original.as_object().unwrap();
    assert_eq!(fields.len(), 5);
    assert_eq!(original["kind"], "manifest_original03");
    assert_eq!(
        original["evidence"]["accepted_manifest03"],
        B.encode(&original03)
    );
    assert_ne!(
        original["evidence"]["accepted_manifest03"],
        B.encode(&successor)
    );
    assert_eq!(original["evidence"].as_object().unwrap().len(), 10);
    assert!(
        manifests::current_owner(&tx, &mut owner, c.line, ORIGIN)
            .await
            .is_err()
    );
    drop(owner);
    tx.rollback().await.unwrap();
    let scope = SocketSelection03 {
        session: crate::device_socket::DeviceSession {
            account_id: c.principal.tenant.account_id(),
            device_id: c.device,
            connection_epoch: 2,
        },
        site: "activation-test",
        instance: "fixture",
        deployment: 1,
        origin: ORIGIN,
    };
    let tx = c.db.reader.transaction().await.unwrap();
    let phone = manifests::original_device(&tx, &scope, c.line)
        .await
        .unwrap();
    assert_eq!(phone.as_object().unwrap().len(), 3);
    assert_eq!(phone["binding_id"], original["binding_id"]);
    assert_eq!(phone["evidence"], original["evidence"]);
    assert!(
        manifests::current_device(&tx, &scope, c.line)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let stale = SocketSelection03 {
        session: crate::device_socket::DeviceSession {
            connection_epoch: 1,
            ..scope.session
        },
        ..scope
    };
    let tx = c.db.reader.transaction().await.unwrap();
    assert!(matches!(
        manifests::original_device(&tx, &stale, c.line).await,
        Err(Error::Authentication)
    ));
    tx.rollback().await.unwrap();
    c.db.reader.execute("UPDATE public.device_sessions SET lease_until=pg_catalog.clock_timestamp()-interval '1 second' WHERE account_id=$1 AND device_id=$2",&[&c.principal.tenant.account_id(),&c.device]).await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    assert!(
        manifests::original_device(&tx, &scope, c.line)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert_eq!(
        manifests::original_owner(&tx, &mut owner, c.line, ORIGIN)
            .await
            .unwrap(),
        original
    );
    drop(owner);
    tx.rollback().await.unwrap();
    c.db.finish().await;
}
