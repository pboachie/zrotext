// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    http_owner_conversations::{
        ConversationConsent, enable_conversation, revoke_conversation, tests::prepared,
    },
    sealed_manifest_store::{self, tests::Fixture},
};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use sha2::{Digest, Sha256};
fn record(f: &Fixture, role: u8) -> ([u8; 32], [u8; 65], Vec<u8>) {
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let point: [u8; 65] = key
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let algorithm = if role == 1 { [0, 16] } else { [1, 1] };
    let id: [u8; 32] =
        Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &algorithm, &point].concat()).into();
    let mut out = vec![role];
    out.extend(id);
    out.extend(point);
    out.extend(if role == 1 {
        *f.device.as_bytes()
    } else {
        [0; 16]
    });
    out.extend(*f.line.as_bytes());
    out.extend(if role == 1 { 4u16 } else { 1u16 }.to_be_bytes());
    out.extend_from_slice(&f.bytes[37..45]);
    out.extend_from_slice(&f.bytes[45..53]);
    out.push(1);
    (id, point, out)
}
async fn candidate() -> (Fixture, SessionPrincipal, Enrollment, Vec<u8>) {
    let (mut f, owner) = prepared().await;
    let (phone, _, phone_record) = record(&f, 1);
    f.bytes.splice(151..151, phone_record);
    f.bytes[150] += 1;
    f.resign();
    let mut client = f.connect().await;
    let tx = client.transaction().await.unwrap();
    let mut admitted = sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
        .await
        .unwrap();
    admitted.context(&f.wanted()).await.unwrap();
    drop(admitted);
    tx.commit().await.unwrap();
    enable_conversation(
        &mut client,
        &owner,
        &ConversationConsent {
            device_id: f.device,
            line_id: f.line,
            binding_generation: 1,
            peer: "+12".into(),
            disclosure_version: "conversation-content-v1".into(),
            content_transfer_confirmed: true,
        },
    )
    .await
    .unwrap();
    let predecessor: [u8; 32] = Sha256::digest(&f.bytes[..f.bytes.len() - 64]).into();
    f.advance();
    let (signer, point, key) = record(&f, 5);
    let at = 151
        + f.bytes[151..f.bytes.len() - 64]
            .chunks_exact(149)
            .position(|r| r[0] == 6)
            .unwrap()
            * 149;
    f.bytes.splice(at..at, key);
    f.bytes[150] += 1;
    f.resign();
    let r = Enrollment {
        device: f.device,
        line: f.line,
        generation: 1,
        originating_session: owner.session_id,
        peer: "+12".into(),
        phone_reader: phone,
        archive_reader: f.readers[0].key_id,
        signer,
        public_point: point,
        predecessor,
    };
    let bytes = f.bytes.clone();
    (f, owner, r, bytes)
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn verified_successor_install_is_atomic_and_replay_cannot_advance() {
    let (f, owner, r, bytes) = candidate().await;
    let prior: i64 =
        f.db.query_one(
            "SELECT accepted_at_ms FROM sealed_manifest_authorities",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    install(&mut f.connect().await, &owner, &r, &bytes)
        .await
        .unwrap();
    assert!(
        install(&mut f.connect().await, &owner, &r, &bytes)
            .await
            .is_err()
    );
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    let stamp =
        f.db.query_one(
            "SELECT accepted_at_ms,last_verified_ms FROM sealed_manifest_authorities",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(stamp.get::<_, i64>(0), stamp.get::<_, i64>(1));
    assert!(stamp.get::<_, i64>(0) >= prior);
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn withdrawn_consent_cannot_install_signed_key() {
    let (f, owner, r, bytes) = candidate().await;
    revoke_conversation(&mut f.connect().await, &owner)
        .await
        .unwrap();
    assert!(
        install(&mut f.connect().await, &owner, &r, &bytes)
            .await
            .is_err()
    );
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expired_owner_cannot_install_signed_key() {
    let (f, owner, r, bytes) = candidate().await;
    f.db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        install(&mut f.connect().await, &owner, &r, &bytes)
            .await
            .is_err()
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn tampered_signature_and_foreign_reader_roll_back_authority() {
    let (f, owner, mut r, mut bytes) = candidate().await;
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    assert!(
        install(&mut f.connect().await, &owner, &r, &bytes)
            .await
            .is_err()
    );
    bytes[n - 1] ^= 1;
    r.phone_reader = [9; 32];
    assert!(
        install(&mut f.connect().await, &owner, &r, &bytes)
            .await
            .is_err()
    );
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expiry_at_final_commit_guard_rolls_back_verified_successor() {
    let (f, owner, r, bytes) = candidate().await;
    let mut client = f.connect().await;
    let tx = client.transaction().await.unwrap();
    let mut authority = lock_current(&tx, f.account).await.unwrap();
    lock_owner(&tx, &owner).await.unwrap();
    authority
        .install_browser_successor(&bytes, &r)
        .await
        .unwrap();
    authority
        .recheck_installed_successor(&bytes, &r)
        .await
        .unwrap();
    drop(authority);
    // Synthetic deadline transition after verification; no sleeps or permissive commit path.
    tx.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    assert!(commit_verified(tx, &owner).await.is_err());
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.cleanup().await;
}
