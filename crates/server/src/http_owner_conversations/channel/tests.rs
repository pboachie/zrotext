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
fn recovery(
    s: &AuthenticatedChannelSession<'_>,
    statement: &activation::Statement,
    challenge: Uuid,
) -> Vec<u8> {
    let original = statement.encode().unwrap();
    [
        header(s, 5, challenge).unwrap(),
        (original.len() as u16).to_be_bytes().to_vec(),
        original,
    ]
    .concat()
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

#[test]
fn recovery_requires_an_exact_bounded_statement_length() {
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
    let bytes = [header(&s, 5, Uuid::from_u128(5)).unwrap(), vec![0; 382]].concat();
    for end in 0..bytes.len() {
        assert!(request(&s, &bytes[..end]).is_err());
    }
    assert!(request(&s, &bytes).is_err());
    let mut bounded = bytes;
    bounded[118..120].copy_from_slice(&380u16.to_be_bytes());
    assert!(request(&s, &bounded).is_ok());
    assert!(request(&s, &[bounded, vec![0]].concat()).is_err());
    let excessive = [header(&s, 5, Uuid::from_u128(5)).unwrap(), vec![0; 1027]].concat();
    assert!(request(&s, &excessive).is_err());
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn lost_pending_close_ack_recovers_from_original_without_restoring_statement() {
    let (f, _, statement) = activation::tests::pending().await;
    let s = identity(&f);
    let close = [
        header(&s, 3, Uuid::new_v4()).unwrap(),
        scope(&statement).unwrap(),
    ]
    .concat();
    handle(&mut f.connect().await, &s, &close).await.unwrap();
    assert!(handle(&mut f.connect().await, &s, &close).await.is_err());
    let before: String =
        f.db.query_one(
            "SELECT to_jsonb(c)::text FROM conversation_intervals c",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    for _ in 0..2 {
        let nonce = Uuid::new_v4();
        let reply = handle(&mut f.connect().await, &s, &recovery(&s, &statement, nonce))
            .await
            .unwrap();
        assert_eq!(&reply[..118], header(&s, 4, nonce).unwrap());
        assert_eq!(&reply[118..reply.len() - 1], scope(&statement).unwrap());
        assert_eq!(reply.last(), Some(&1));
        let after: String =
            f.db.query_one(
                "SELECT to_jsonb(c)::text FROM conversation_intervals c",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(after, before);
    }
    let decoded: serde_json::Value = serde_json::from_str(&before).unwrap();
    assert_eq!(decoded["phase"], "expired");
    assert!(decoded["statement"].is_null());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn recovery_rejects_tampered_original_peer_reader_and_authenticated_scope() {
    let (f, _, statement) = activation::tests::pending().await;
    let s = identity(&f);
    let close = [
        header(&s, 3, Uuid::new_v4()).unwrap(),
        scope(&statement).unwrap(),
    ]
    .concat();
    handle(&mut f.connect().await, &s, &close).await.unwrap();
    let mut variants = Vec::new();
    for field in 0..20 {
        let mut changed = statement.clone();
        match field {
            0 => changed.peer = "+13".into(),
            1 => changed.reader[0] ^= 1,
            2 => changed.signer[0] ^= 1,
            3 => changed.nonce[0] ^= 1,
            4 => changed.account = Uuid::new_v4(),
            5 => changed.device = Uuid::new_v4(),
            6 => changed.line = Uuid::new_v4(),
            7 => changed.interval = Uuid::new_v4(),
            8 => changed.receipt = Uuid::new_v4(),
            9 => changed.originating_session = Uuid::new_v4(),
            10 => changed.generation += 1,
            11 => changed.trust_generation += 1,
            12 => changed.expires_ms += 1,
            13 => {
                changed.predecessor_version += 1;
                changed.activation_version += 1;
            }
            14 => changed.predecessor_digest[0] ^= 1,
            15 => changed.activation_digest[0] ^= 1,
            16 => changed.site.push('x'),
            17 => changed.instance.push('x'),
            18 => changed.connection_epoch += 1,
            _ => changed.deployment_epoch += 1,
        }
        variants.push(changed);
    }
    for changed in variants {
        assert!(
            handle(
                &mut f.connect().await,
                &s,
                &recovery(&s, &changed, Uuid::new_v4())
            )
            .await
            .is_err()
        );
    }
    let bytes = recovery(&s, &statement, Uuid::new_v4());
    let mut wrong = identity(&f);
    assert!(
        handle(&mut f.connect().await, &wrong, &bytes)
            .await
            .is_err()
    );
    wrong.device.device_id = Uuid::new_v4();
    assert!(
        handle(
            &mut f.connect().await,
            &wrong,
            &recovery(&wrong, &statement, Uuid::new_v4())
        )
        .await
        .is_err()
    );
    let mut stale = identity(&f);
    stale.device.connection_epoch += 1;
    assert!(
        handle(
            &mut f.connect().await,
            &stale,
            &recovery(&stale, &statement, Uuid::new_v4())
        )
        .await
        .is_err()
    );
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
async fn recovery_refuses_open_intervals_and_preserves_closed_history_and_withdrawal() {
    let (f, owner, statement) = activation::tests::pending().await;
    let s = identity(&f);
    assert!(
        handle(
            &mut f.connect().await,
            &s,
            &recovery(&s, &statement, Uuid::new_v4())
        )
        .await
        .is_err()
    );
    activation::tests::activate(&f, &statement).await;
    let event = Uuid::new_v4();
    let observed: i64 =
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let saved =
        crate::http_owner_conversations::tests::envelope(&f, event, 1, observed as u64, b"+12");
    crate::sealed_inbound::ingest::ingest_conversation(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &f.bytes,
        &saved,
        activation::CaptureInterval {
            interval: statement.interval,
            activation_digest: statement.activation_digest,
        },
    )
    .await
    .unwrap();
    assert!(
        handle(
            &mut f.connect().await,
            &s,
            &recovery(&s, &statement, Uuid::new_v4())
        )
        .await
        .is_err()
    );
    let close = [
        header(&s, 3, Uuid::new_v4()).unwrap(),
        scope(&statement).unwrap(),
    ]
    .concat();
    handle(&mut f.connect().await, &s, &close).await.unwrap();
    let before: String =
        f.db.query_one(
            "SELECT to_jsonb(c)::text FROM conversation_intervals c",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    for _ in 0..2 {
        handle(
            &mut f.connect().await,
            &s,
            &recovery(&s, &statement, Uuid::new_v4()),
        )
        .await
        .unwrap();
    }
    let after: String =
        f.db.query_one(
            "SELECT to_jsonb(c)::text FROM conversation_intervals c",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, before);
    let decoded: serde_json::Value = serde_json::from_str(&after).unwrap();
    assert_eq!(decoded["phase"], "history");
    assert!(!decoded["statement"].is_null());
    assert_eq!(
        activation::read_history(&mut f.connect().await, &owner, event)
            .await
            .unwrap(),
        saved
    );
    activation::close(&mut f.connect().await, &owner, statement.interval, true)
        .await
        .unwrap();
    handle(
        &mut f.connect().await,
        &s,
        &recovery(&s, &statement, Uuid::new_v4()),
    )
    .await
    .unwrap();
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
    let row =
        f.db.query_one("SELECT phase,statement FROM conversation_intervals", &[])
            .await
            .unwrap();
    assert_eq!(row.get::<_, String>(0), "withdrawn");
    assert!(row.get::<_, Option<Vec<u8>>>(1).is_none());
    assert!(
        activation::read_history(&mut f.connect().await, &owner, event)
            .await
            .is_err()
    );
    f.cleanup().await;
}
