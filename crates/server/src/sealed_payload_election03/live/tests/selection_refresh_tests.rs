// SPDX-License-Identifier: AGPL-3.0-only
//! Genuine account/root/registration/election and fresh two-factor restoration.
//! A synthetic full socket/observation is seeded; no hardware or carrier claim.
use super::manifest_tests::elected;
use super::*;
use crate::{manifest_install03::live as manifests, selection_refresh03::live as refresh};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual same-phone restoration"]
async fn reconnect_requires_distinct_owner_approval_and_installed_ack_without_rewriting_originals()
{
    let (mut c, _) = elected().await;
    c.db.reader.execute("UPDATE public.device_sessions SET connection_epoch=2,lease_until=pg_catalog.clock_timestamp()+interval '10 minutes' WHERE account_id=$1 AND device_id=$2", &[&c.principal.tenant.account_id(),&c.device]).await.unwrap();
    let account = c.principal.tenant.account_id();
    let socket = SocketSelection03 {
        session: crate::device_socket::DeviceSession {
            account_id: account,
            device_id: c.device,
            connection_epoch: 2,
        },
        site: "activation-test",
        instance: "fixture",
        deployment: 1,
        origin: ORIGIN,
    };
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(
        manifests::current_owner(&tx, &mut owner, c.line, ORIGIN)
            .await
            .is_err()
    );
    let original = manifests::original_owner(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    drop(owner);
    tx.rollback().await.unwrap();
    let opening = Uuid::new_v4();
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[4])
            .await
            .unwrap()
    else {
        panic!("fresh opening factor")
    };
    let (new, reserved) = refresh::reserve(&tx, &mut proof, opening, c.line, ORIGIN)
        .await
        .unwrap();
    assert!(new);
    assert_eq!(reserved["status"], "reserved");
    let id = Uuid::parse_str(reserved["refresh_id"].as_str().unwrap()).unwrap();
    let core = B.decode(reserved["core"].as_str().unwrap()).unwrap();
    assert_eq!(core.len(), 496);
    assert_eq!(crypto::number(&core[104..112]).unwrap(), 2);
    drop(proof);
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let offered = refresh::device_challenge(&tx, &socket)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(offered["evidence"], original["evidence"]);
    assert_eq!(offered["core"], reserved["core"]);
    tx.rollback().await.unwrap();
    let mut observation = c.device_statement[134..255].to_vec();
    observation[49..65].copy_from_slice(Uuid::new_v4().as_bytes());
    observation[65..73].copy_from_slice(&2_i64.to_be_bytes());
    observation[73..89].copy_from_slice(Uuid::new_v4().as_bytes());
    let device_signature = sign(
        &c.phone_key,
        b"ZTSE/line/payload-profile/selection-refresh/device/v1\0",
        &[core.as_slice(), &observation].concat(),
    );
    let tx = c.db.reader.transaction().await.unwrap();
    refresh::device_proof(&tx, &socket, id, &observation, &device_signature)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let owner_signature = sign(
        &c.approval_key,
        b"ZTSE/line/payload-profile/selection-refresh/owner/v1\0",
        &[
            core.as_slice(),
            &observation,
            &crypto::sha(&device_signature),
        ]
        .concat(),
    );
    let bundle = [
        core.as_slice(),
        &observation,
        &device_signature,
        &owner_signature,
    ]
    .concat();
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[4])
            .await
            .unwrap(),
        step_up::Outcome::Rejected(_)
    ));
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
        panic!("distinct approval factor")
    };
    let (new, accepted) = refresh::approve(&tx, &mut proof, opening, id, &bundle, ORIGIN)
        .await
        .unwrap();
    assert!(new);
    drop(proof);
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(
        manifests::current_owner(&tx, &mut owner, c.line, ORIGIN)
            .await
            .is_err()
    );
    assert!(matches!(
        refresh::installed(&tx, &mut owner, opening, id, ORIGIN).await,
        Err(Error::NotFound)
    ));
    drop(owner);
    tx.rollback().await.unwrap();
    let digest = crypto::sha(&bundle);
    let installed_signature = sign(
        &c.phone_key,
        b"ZTSE/line/payload-profile/selection-refresh/installed/v1\0",
        &[id.as_bytes().as_slice(), &digest, &core[344..376]].concat(),
    );
    let tx = c.db.reader.transaction().await.unwrap();
    let ack = refresh::device_installed(&tx, &socket, id, &digest, &installed_signature)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let repeated = refresh::device_installed(&tx, &socket, id, &digest, &installed_signature)
        .await
        .unwrap();
    assert_eq!(ack, repeated);
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let current = manifests::current_owner(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    assert_eq!(current["physical_selection"]["kind"], "owner_refresh03");
    assert_eq!(current["physical_selection"]["refresh_id"], id.to_string());
    assert_eq!(current["evidence"], original["evidence"]);
    assert_eq!(
        refresh::historical_approval(&tx, &mut owner, opening, id, &bundle, ORIGIN)
            .await
            .unwrap()
            .unwrap(),
        accepted
    );
    let status = refresh::status(&tx, &mut owner, opening, c.line, ORIGIN)
        .await
        .unwrap();
    assert_eq!(status["core"], reserved["core"]);
    assert_eq!(status["status"], "installed");
    assert_eq!(status["issued_ms"], reserved["issued_ms"]);
    assert_eq!(status["expires_ms"], reserved["expires_ms"]);
    drop(owner);
    tx.rollback().await.unwrap();
    c.db.finish().await;
}
