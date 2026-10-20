// SPDX-License-Identifier: AGPL-3.0-only
//! Real ordinary-role auth/registration/v2/election plus genuine root/browser
//! successor signatures. Socket lease and physical observation remain seeded;
//! this fixture claims no browser key-store, phone, hardware or carrier result.
use super::*;
use crate::manifest_install03::live as service;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
pub(super) async fn elected() -> (Case, Vec<u8>) {
    let (mut c, signed) = fixture::prepared_actual_genesis().await;
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
        panic!("genuine reserve factor")
    };
    let r = reserve(&tx, &mut proof, opening, c.line, &signed, ORIGIN)
        .await
        .unwrap();
    drop(proof);
    tx.commit().await.unwrap();
    let device = sign(
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
        &device,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let owner_sig = sign(
        &c.approval_key,
        b"ZTSE/line/payload-profile/owner/v1\0",
        &[r.core.as_slice(), &crypto::sha(&device)].concat(),
    );
    let bundle = [r.core.as_slice(), &device, &owner_sig].concat();
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[3])
            .await
            .unwrap()
    else {
        panic!("genuine commit factor")
    };
    accept(
        &tx,
        &mut proof,
        opening,
        r.challenge,
        &signed,
        &bundle,
        ORIGIN,
    )
    .await
    .unwrap();
    drop(proof);
    tx.commit().await.unwrap();
    (c, signed)
}
pub(super) async fn packet(
    c: &mut Case,
    key: &SigningKey,
    replace: bool,
) -> (Uuid, Vec<u8>, Vec<u8>, Vec<u8>) {
    let tx = c.db.reader.transaction().await.unwrap();
    let h = manifest_history::lock(&tx, c.principal.tenant.account_id(), c.line, ORIGIN)
        .await
        .unwrap();
    let now = h.checked_ms;
    let prior = &h.tip_signed;
    let expires = now + 3_600_000;
    let mut keys: Vec<Vec<u8>> = prior[153..prior.len() - 64]
        .chunks_exact(149)
        .map(|b| b.to_vec())
        .collect();
    let point = key.verifying_key().to_sec1_point(false);
    let browser_id = crate::sealed_manifest::key_id(5, point.as_bytes());
    let existing = keys.iter().any(|r| r[0] == 5 && r[148] == 1);
    for r in &mut keys {
        if replace && r[0] == 5 && r[148] == 1 {
            r[148] = 2;
        } else if r[148] == 1 {
            r[140..148].copy_from_slice(&expires.to_be_bytes());
        }
    }
    if !existing || replace {
        let mut r = vec![5];
        r.extend(browser_id);
        r.extend(point.as_bytes());
        r.extend(Uuid::nil().as_bytes());
        r.extend(c.line.as_bytes());
        r.extend(1u16.to_be_bytes());
        r.extend(now.to_be_bytes());
        r.extend(expires.to_be_bytes());
        r.push(1);
        keys.push(r);
    }
    keys.sort_by(|a, b| a[..33].cmp(&b[..33]));
    let mut unsigned = prior[..153].to_vec();
    unsigned[6] = 3;
    unsigned[31..39].copy_from_slice(&(h.tip_version + 1).to_be_bytes());
    unsigned[39..47].copy_from_slice(&now.to_be_bytes());
    unsigned[47..55].copy_from_slice(&expires.to_be_bytes());
    unsigned[55..87].copy_from_slice(&h.tip_digest);
    unsigned[152] = keys.len().try_into().unwrap();
    for key in keys {
        unsigned.extend(key);
    }
    let signed = [
        unsigned.as_slice(),
        &sign(&c.root_key, b"ZTSE/manifest/v3\0", &unsigned),
    ]
    .concat();
    let opening = Uuid::new_v4();
    let mut statement = b"ZTMS\x01\x03\x03\0".to_vec();
    for id in [
        h.account,
        c.principal.user_id,
        c.principal.session_id,
        h.device,
        h.line,
        h.binding,
        h.challenge,
        opening,
    ] {
        statement.extend(id.as_bytes());
    }
    for n in [
        h.generation,
        1,
        h.epoch,
        h.tip_version,
        h.tip_version + 1,
        now,
        now + 300_000,
    ] {
        statement.extend(n.to_be_bytes());
    }
    for digest in [
        h.accepted.root_fingerprint,
        h.accepted.election_commitment,
        h.accepted.election_bundle_sha256,
        crate::sealed_payload_election03::adapter_contract::origin_digest(ORIGIN).unwrap(),
        crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03 {
            account_id: *h.account.as_bytes(),
            user_id: *c.principal.user_id.as_bytes(),
            session_id: *c.principal.session_id.as_bytes(),
        }
        .digest()
        .unwrap(),
        h.tip_digest,
        crypto::sha(&signed),
        browser_id,
    ] {
        statement.extend(digest);
    }
    statement.extend(point.as_bytes());
    let signature = sign(
        key,
        b"ZTSE/line/payload-profile/manifest-install03/v1\0",
        &statement,
    );
    tx.rollback().await.unwrap();
    (opening, statement, signed, signature)
}
#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary runtime manifest schema"]
async fn real_four_role_setup_enrolls_renews_and_replaces_browser_without_rewriting_original_evidence()
 {
    let (mut c, first) = elected().await;
    assert_eq!(
        first[153..first.len() - 64]
            .chunks_exact(149)
            .map(|r| r[0])
            .collect::<Vec<_>>(),
        vec![1, 2, 4, 6]
    );
    let browser = SigningKey::generate_from_rng(&mut rand::rng());
    let replacement = SigningKey::generate_from_rng(&mut rand::rng());
    let mut first_receipt = None;
    for (step, mode, key, replace) in [
        (0, "enroll", &browser, false),
        (1, "renew", &browser, false),
        (2, "replace", &replacement, true),
    ] {
        let (opening, statement, successor, signature) = packet(&mut c, key, replace).await;
        let tx = c.db.reader.transaction().await.unwrap();
        let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
            .await
            .unwrap();
        let step_up::Outcome::Verified(mut proof) = step_up::verify(
            owner,
            &c.hasher,
            &c.cipher,
            &c.password,
            &c.recovery[4 + step],
        )
        .await
        .unwrap() else {
            panic!("fresh manifest factor")
        };
        let result = service::install(
            &tx,
            &mut proof,
            service::InstallCommand03 {
                opening,
                statement: &statement,
                successor: &successor,
                signature: &signature,
            },
            ORIGIN,
        )
        .await;
        let receipt = match result {
            Ok(value) => value,
            Err(error) => panic!(
                "{mode} manifest install refused: {error:?}; held factor recheck: {:?}",
                proof.revalidate().await
            ),
        };
        assert_eq!(receipt["operation"], mode);
        drop(proof);
        tx.commit().await.unwrap();
        if first_receipt.is_none() {
            first_receipt = Some((opening, receipt.clone()));
        }
        let tx = c.db.reader.transaction().await.unwrap();
        let mut owner =
            ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
                .await
                .unwrap();
        let before: String = tx
            .query_one(
                "SELECT xmin::text FROM public.payload_profile_account_anchors WHERE account_id=$1",
                &[&c.principal.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
        let again = service::exact_historical(
            &tx,
            &mut owner,
            &service::InstallCommand03 {
                opening,
                statement: &statement,
                successor: &successor,
                signature: &signature,
            },
            ORIGIN,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(again, receipt);
        let after: String = tx
            .query_one(
                "SELECT xmin::text FROM public.payload_profile_account_anchors WHERE account_id=$1",
                &[&c.principal.tenant.account_id()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(before, after);
        let current = service::current_owner(&tx, &mut owner, c.line, ORIGIN)
            .await
            .unwrap();
        assert_eq!(current["kind"], "owner_manifest_selection03");
        assert_eq!(current["physical_selection"]["kind"], "original_v2");
        assert_eq!(current["evidence"]["accepted_manifest03"], B.encode(&first));
        assert_eq!(current["current_manifest03"], B.encode(&successor));
        assert!(
            super::super::current(&tx, &mut owner, c.line, ORIGIN)
                .await
                .is_err()
        );
        drop(owner);
        tx.rollback().await.unwrap();
    }
    let (opening, original) = first_receipt.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert_eq!(
        service::historical(&tx, &mut owner, opening, ORIGIN)
            .await
            .unwrap()
            .unwrap(),
        original
    );
    drop(owner);
    tx.rollback().await.unwrap();
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual ordinary runtime manifest schema"]
async fn invalid_possession_rolls_back_consumed_factor_tip_claim_and_new_receipt() {
    let (mut c, _) = elected().await;
    let browser = SigningKey::generate_from_rng(&mut rand::rng());
    let (opening, statement, successor, mut signature) = packet(&mut c, &browser, false).await;
    signature[0] ^= 1;
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) =
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[4])
            .await
            .unwrap()
    else {
        panic!("genuine factor")
    };
    assert!(
        service::install(
            &tx,
            &mut proof,
            service::InstallCommand03 {
                opening,
                statement: &statement,
                successor: &successor,
                signature: &signature
            },
            ORIGIN
        )
        .await
        .is_err()
    );
    drop(proof);
    tx.rollback().await.unwrap();
    let row=c.db.reader.query_one("SELECT a.version,(SELECT count(*) FROM public.payload_profile_manifest_successors r WHERE r.account_id=a.account_id),(SELECT count(*) FROM public.known_signing_role_claims k WHERE k.account_id=a.account_id AND k.role='browser_content03') FROM public.sealed_manifest_authorities a WHERE a.account_id=$1",&[&c.principal.tenant.account_id()]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 2);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 0);
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(matches!(
        step_up::verify(owner, &c.hasher, &c.cipher, &c.password, &c.recovery[4])
            .await
            .unwrap(),
        step_up::Outcome::Verified(_)
    ));
    tx.rollback().await.unwrap();
    c.db.finish().await;
}
