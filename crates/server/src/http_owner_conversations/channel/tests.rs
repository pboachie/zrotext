// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
fn identity(
    f: &crate::sealed_manifest_store::tests::Fixture,
) -> AuthenticatedChannelSession<'static> {
    AuthenticatedChannelSession {
        device: f.session(),
        phone_session: Uuid::new_v4(),
        origin_hash: [9; 32],
    }
}
#[test]
fn header_matches_android_width_and_network_order() {
    let s = AuthenticatedChannelSession {
        device: InboundSession {
            account_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            site_id: "fixture",
            instance_id: "fixture",
            connection_epoch: 1,
            deployment_epoch: 2,
        },
        phone_session: Uuid::from_u128(3),
        origin_hash: [4; 32],
    };
    let bytes = header(&s, 1, Uuid::from_u128(5)).unwrap();
    assert_eq!(bytes.len(), 118);
    assert_eq!(&bytes[..6], b"ZTCW\x01\x01");
    assert_eq!(&bytes[54..62], &1i64.to_be_bytes());
    assert!(request(&s, &bytes).is_ok());
    let mut tampered = bytes.clone();
    tampered[7] ^= 1;
    assert!(request(&s, &tampered).is_err());
    assert!(request(&s, &[bytes, vec![0]].concat()).is_err());
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn time_and_committed_stop_are_exact_scoped_and_idempotent() {
    let (f, _, statement) = activation::tests::pending().await;
    activation::tests::activate(&f, &statement).await;
    let s = identity(&f);
    let challenge = Uuid::new_v4();
    let time = handle(
        &mut f.connect().await,
        &s,
        &header(&s, 1, challenge).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(&time[..118], header(&s, 2, challenge).unwrap());
    assert!(i64::from_be_bytes(time[118..].try_into().unwrap()) > 0);
    let close = [
        header(&s, 3, challenge).unwrap(),
        scope(&statement).unwrap(),
    ]
    .concat();
    let reply = handle(&mut f.connect().await, &s, &close).await.unwrap();
    assert_eq!(reply.last(), Some(&1));
    assert_eq!(&reply[118..reply.len() - 1], &close[118..]);
    assert_eq!(
        f.db.query_one("SELECT phase FROM conversation_intervals", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "history"
    );
    assert_eq!(
        handle(&mut f.connect().await, &s, &close).await.unwrap(),
        reply
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn closure_scope_tamper_cannot_change_state() {
    let (f, _, statement) = activation::tests::pending().await;
    activation::tests::activate(&f, &statement).await;
    let s = identity(&f);
    let close = [
        header(&s, 3, Uuid::new_v4()).unwrap(),
        scope(&statement).unwrap(),
    ]
    .concat();
    for at in [118, 134, 150, 182, 214, 238, 270, 302, 334, 369] {
        let mut changed = close.clone();
        changed[at] ^= 1;
        assert!(handle(&mut f.connect().await, &s, &changed).await.is_err());
    }
    assert_eq!(
        f.db.query_one("SELECT phase FROM conversation_intervals", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "active"
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expired_or_revoked_phone_cannot_get_authenticated_time() {
    let (f, _, _) = activation::tests::pending().await;
    let s = identity(&f);
    let bytes = header(&s, 1, Uuid::new_v4()).unwrap();
    f.db.execute(
        "UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second'",
        &[],
    )
    .await
    .unwrap();
    assert!(handle(&mut f.connect().await, &s, &bytes).await.is_err());
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_logout_still_allows_phone_stop_but_not_capture() {
    let (f, owner, statement) = activation::tests::pending().await;
    activation::tests::activate(&f, &statement).await;
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    let s = identity(&f);
    let bytes = [
        header(&s, 3, Uuid::new_v4()).unwrap(),
        scope(&statement).unwrap(),
    ]
    .concat();
    handle(&mut f.connect().await, &s, &bytes).await.unwrap();
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
    f.cleanup().await;
}
