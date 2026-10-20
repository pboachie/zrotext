// SPDX-License-Identifier: AGPL-3.0-only
//! Real retained multi-peer requests, not manually relabelled ledger phases.
use super::manifest_tests::{elected, packet};
use super::*;
use crate::{conversation_interval03::live as intervals, manifest_install03::live as manifests};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

async fn prepared() -> (Case, SigningKey, Vec<u8>) {
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
        panic!("fresh manifest factor")
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
    (c, browser, signed)
}
fn lease(c: &Case) -> intervals::DeviceInterval03<'static> {
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
struct Pending {
    opening: Uuid,
    id: Uuid,
    bytes: Vec<u8>,
    signature: Vec<u8>,
    expires: u64,
}
async fn request(
    c: &mut Case,
    browser: &SigningKey,
    signed: &[u8],
    peer: &[u8],
    lifetime: u64,
    factor: usize,
) -> Pending {
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
    let now: i64 = tx.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint", &[]).await.unwrap().get(0);
    let expires = now as u64 + lifetime;
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let (new, reply) = intervals::reserve(
        &tx,
        &mut owner,
        intervals::Reserve03 {
            opening,
            line: c.line,
            peer,
            archive: key(2),
            phone: key(4),
            browser: key(5),
            expires_ms: expires,
            integrations: &[],
        },
        ORIGIN,
    )
    .await
    .unwrap();
    assert!(new);
    let id = Uuid::parse_str(reply["interval_id"].as_str().unwrap()).unwrap();
    let bytes = B.decode(reply["statement"].as_str().unwrap()).unwrap();
    drop(owner);
    tx.commit().await.unwrap();
    let signature = sign(browser, b"zrotext/conversation/request03/v1\0", &bytes);
    let tx = c.db.reader.transaction().await.unwrap();
    let owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let step_up::Outcome::Verified(mut proof) = step_up::verify(
        owner,
        &c.hasher,
        &c.cipher,
        &c.password,
        &c.recovery[factor],
    )
    .await
    .unwrap() else {
        panic!("fresh content factor")
    };
    let (new, reply) = intervals::request(&tx, &mut proof, opening, id, &bytes, &signature, ORIGIN)
        .await
        .unwrap();
    assert!(new);
    assert_eq!(reply["phase"], "requested");
    drop(proof);
    tx.commit().await.unwrap();
    Pending {
        opening,
        id,
        bytes,
        signature,
        expires,
    }
}
async fn assert_retained(c: &mut Case, pending: &Pending, phase: &str) {
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let original = intervals::owner_status(&tx, &mut owner, pending.opening, pending.id)
        .await
        .unwrap();
    assert_eq!(original["phase"], phase);
    assert_eq!(original["statement"], B.encode(&pending.bytes));
    assert_eq!(original["owner_signature"], B.encode(&pending.signature));
    drop(owner);
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; real multi-peer conversation requests"]
async fn multiple_genuine_pending_peers_offer_oldest_then_next_after_explicit_stop() {
    let (mut c, browser, signed) = prepared().await;
    let device = lease(&c);
    let first = request(&mut c, &browser, &signed, b"+12", 300_000, 5).await;
    let second = request(&mut c, &browser, &signed, b"+13", 300_000, 6).await;
    let tx = c.db.reader.transaction().await.unwrap();
    let offered = intervals::device_challenge(&tx, device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(offered["interval_id"], first.id.to_string());
    assert_eq!(offered["statement"], B.encode(&first.bytes));
    tx.rollback().await.unwrap();
    assert_retained(&mut c, &first, "requested").await;
    assert_retained(&mut c, &second, "requested").await;
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    intervals::stop(&tx, &mut owner, first.id).await.unwrap();
    drop(owner);
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let offered = intervals::device_challenge(&tx, device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(offered["interval_id"], second.id.to_string());
    tx.rollback().await.unwrap();
    assert_retained(&mut c, &first, "stopped").await;
    assert_retained(&mut c, &second, "requested").await;
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; real expired-other-peer conversation request"]
async fn naturally_expired_other_peer_does_not_block_or_rewrite_live_request() {
    let (mut c, browser, signed) = prepared().await;
    let device = lease(&c);
    let expired = request(&mut c, &browser, &signed, b"+12", 30_000, 5).await;
    let live = request(&mut c, &browser, &signed, b"+13", 300_000, 6).await;
    // Observe actual primary expiry, with a monotonic test bound. Do not forge
    // timestamps or mutate the signed interval to simulate expiry.
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            let now: i64 = c.db.reader.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint", &[]).await.unwrap().get(0);
            if now as u64 >= expired.expires { break; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }).await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    let offered = intervals::device_challenge(&tx, device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(offered["interval_id"], live.id.to_string());
    assert_eq!(offered["statement"], B.encode(&live.bytes));
    tx.rollback().await.unwrap();
    assert_retained(&mut c, &expired, "requested").await;
    assert_retained(&mut c, &live, "requested").await;
    c.db.finish().await;
}
