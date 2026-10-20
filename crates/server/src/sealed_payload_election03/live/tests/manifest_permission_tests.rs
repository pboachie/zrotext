// SPDX-License-Identifier: AGPL-3.0-only
//! Actual owner/ancestry/physical composition. No public projection is parsed
//! back into authentication or a typed current-content permission.
use super::manifest_tests::{elected, packet};
use super::*;
use crate::manifest_install03::live as manifests;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary runtime manifest schema"]
async fn held_message_selection_uses_complete_current_ancestry_and_refuses_owner_revocation() {
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
        panic!("genuine current manifest factor")
    };
    let receipt = manifests::install(
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
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    // Existing consumers keep their exact original contract and fail closed.
    assert!(current(&tx, &mut owner, c.line, ORIGIN).await.is_err());
    let mut held = hold_owner_selection(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    assert_eq!(
        held.authority().manifest_version.to_string(),
        receipt["successor_version"].as_str().unwrap()
    );
    assert_eq!(held.selected().session, c.principal.session_id);
    let projection = held.device_projection().unwrap();
    assert_eq!(projection["kind"], "device_manifest_selection03");
    assert_eq!(projection["current_manifest03"], B.encode(&successor));
    assert_eq!(
        projection["evidence"]["accepted_manifest03"],
        B.encode(&original03)
    );
    assert_eq!(
        projection["manifest_ancestry_sha256"],
        receipt["ancestry_sha256"]
    );
    assert_eq!(projection["physical_selection"]["kind"], "original_v2");
    assert_ne!(*held.physical_digest(), [0; 32]);
    // A retained verified manifest is not a retained owner permission. A
    // same-transaction revocation is visible even though public cache survives.
    assert_eq!(held.tx().execute(
        "UPDATE public.sessions SET revoked_at=pg_catalog.clock_timestamp() WHERE account_id=$1 AND id=$2",
        &[&c.principal.tenant.account_id(), &c.principal.session_id],
    ).await.unwrap(), 1);
    assert!(matches!(
        held.revalidate().await,
        Err(Error::Authentication)
    ));
    drop(held);
    drop(owner);
    tx.rollback().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let restored = hold_owner_selection(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    assert_eq!(
        restored.authority().manifest_version.to_string(),
        receipt["successor_version"].as_str().unwrap()
    );
    drop(restored);
    drop(owner);
    tx.rollback().await.unwrap();
    c.db.finish().await;
}
