// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::ecdsa::{Signature, signature::Signer};
fn frame(
    s: &AuthenticatedChannelSession<'_>,
    kind: u8,
    statement: &activation::Statement,
    signature: &[u8],
) -> Vec<u8> {
    let bytes = statement.encode().unwrap();
    [
        header(s, kind, Uuid::new_v4()).unwrap(),
        (bytes.len() as u16).to_be_bytes().to_vec(),
        bytes,
        signature.to_vec(),
    ]
    .concat()
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn approve_ack_is_not_active_and_install_lease_is_exact_bound() {
    let (f, owner, statement) = activation::tests::pending().await;
    let s = AuthenticatedChannelSession {
        device: f.session(),
        phone_session: Uuid::new_v4(),
        origin_hash: [7; 32],
    };
    let sign = |domain: &[u8]| {
        let signature: Signature = f.event_signer.sign(&statement.transcript(domain).unwrap());
        signature.normalize_s().to_bytes().to_vec()
    };
    let approve = frame(
        &s,
        6,
        &statement,
        &sign(activation::statement::APPROVE_DOMAIN),
    );
    let ack = super::super::handle(&mut f.connect().await, &s, &approve)
        .await
        .unwrap();
    assert_eq!(ack[5], 7);
    assert_eq!(&ack[118..], scope(&statement).unwrap());
    assert_eq!(
        f.db.query_one("SELECT phase FROM conversation_intervals", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "install_pending"
    );
    assert!(
        activation::active_lease(
            &mut f.connect().await,
            f.session(),
            statement.interval,
            Uuid::new_v4()
        )
        .await
        .is_err()
    );
    let install = frame(
        &s,
        8,
        &statement,
        &sign(activation::statement::INSTALL_DOMAIN),
    );
    let lease = super::super::handle(&mut f.connect().await, &s, &install)
        .await
        .unwrap();
    assert_eq!(lease[5], 9);
    assert_eq!(&lease[102..118], &install[102..118]);
    assert_eq!(&lease[118..lease.len() - 8], scope(&statement).unwrap());
    let duration = i64::from_be_bytes(lease[lease.len() - 8..].try_into().unwrap());
    assert!((1..=60000).contains(&duration));
    let renew = [
        header(&s, 10, Uuid::new_v4()).unwrap(),
        scope(&statement).unwrap(),
    ]
    .concat();
    assert!(
        super::super::handle(&mut f.connect().await, &s, &renew)
            .await
            .is_ok()
    );
    activation::close(&mut f.connect().await, &owner, statement.interval, true)
        .await
        .unwrap();
    assert!(
        super::super::handle(&mut f.connect().await, &s, &renew)
            .await
            .is_err()
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn approval_transport_rejects_signature_scope_context_and_wrong_stage() {
    let (f, _, statement) = activation::tests::pending().await;
    let s = AuthenticatedChannelSession {
        device: f.session(),
        phone_session: Uuid::new_v4(),
        origin_hash: [7; 32],
    };
    let signature: Signature = f.event_signer.sign(
        &statement
            .transcript(activation::statement::APPROVE_DOMAIN)
            .unwrap(),
    );
    let valid = frame(&s, 6, &statement, &signature.normalize_s().to_bytes());
    for at in [6, 22, 38, 54, 62, 70, 118, 120, valid.len() - 1] {
        let mut bad = valid.clone();
        bad[at] ^= 1;
        assert!(
            super::super::handle(&mut f.connect().await, &s, &bad)
                .await
                .is_err()
        );
    }
    let wrong = frame(&s, 8, &statement, &signature.normalize_s().to_bytes());
    assert!(
        super::super::handle(&mut f.connect().await, &s, &wrong)
            .await
            .is_err()
    );
    assert_eq!(
        f.db.query_one("SELECT phase FROM conversation_intervals", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pending"
    );
    f.cleanup().await;
}
