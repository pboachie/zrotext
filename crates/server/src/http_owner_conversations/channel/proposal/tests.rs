// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::activation::statement::APPROVE_DOMAIN;
use p256::ecdsa::{Signature, signature::Signer};
use p256::elliptic_curve::Generate;

fn identity(
    f: &crate::sealed_manifest_store::tests::Fixture,
) -> AuthenticatedChannelSession<'static> {
    AuthenticatedChannelSession {
        device: f.session(),
        phone_session: Uuid::new_v4(),
        origin_hash: [9; 32],
    }
}
fn frame(session: &AuthenticatedChannelSession<'_>, interval: Uuid, nonce: Uuid) -> Vec<u8> {
    [
        header(session, 16, nonce).unwrap(),
        interval.as_bytes().to_vec(),
    ]
    .concat()
}
async fn interval_snapshot(f: &crate::sealed_manifest_store::tests::Fixture) -> String {
    f.db.query_one(
        "SELECT to_jsonb(i)::text FROM conversation_intervals i",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}
#[test]
fn proposal_request_is_exact_bounded_and_authenticated() {
    let session = AuthenticatedChannelSession {
        device: InboundSession {
            account_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            site_id: "fixture",
            instance_id: "fixture",
            connection_epoch: 1,
            deployment_epoch: 1,
        },
        phone_session: Uuid::from_u128(3),
        origin_hash: [4; 32],
    };
    let bytes = frame(&session, Uuid::from_u128(5), Uuid::from_u128(6));
    assert_eq!(bytes.len(), 134);
    assert!(request(&session, &bytes).is_ok());
    for end in 0..bytes.len() {
        assert!(request(&session, &bytes[..end]).is_err());
    }
    assert!(request(&session, &[bytes.clone(), vec![0]].concat()).is_err());
    for at in [6, 22, 38, 54, 62, 70, 102] {
        let mut altered = bytes.clone();
        altered[at] ^= 1;
        // Nonce is selected by the sender, but must remain nonzero and echo-bound.
        if at != 102 {
            assert!(request(&session, &altered).is_err());
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn proposal_returns_stored_original_in_both_pending_phases_without_consent_transition() {
    let (f, _, statement) = activation::tests::pending().await;
    let session = identity(&f);
    for approved in [false, true] {
        if approved {
            let signed: Signature = f
                .event_signer
                .sign(&statement.transcript(APPROVE_DOMAIN).unwrap());
            activation::approve(
                &mut f.connect().await,
                f.session(),
                &statement.encode().unwrap(),
                &signed.normalize_s().to_bytes(),
            )
            .await
            .unwrap();
        }
        let before = interval_snapshot(&f).await;
        let original: Vec<u8> =
            f.db.query_one("SELECT statement FROM conversation_intervals", &[])
                .await
                .unwrap()
                .get(0);
        let manifest: Vec<u8> =
            f.db.query_one("SELECT manifest FROM conversation_intervals", &[])
                .await
                .unwrap()
                .get(0);
        let nonce = Uuid::new_v4();
        let bytes = frame(&session, statement.interval, nonce);
        for _ in 0..2 {
            let reply = super::super::handle(&mut f.connect().await, &session, &bytes)
                .await
                .unwrap();
            assert_eq!(&reply[..118], header(&session, 17, nonce).unwrap());
            assert_eq!(
                u16::from_be_bytes(reply[118..120].try_into().unwrap()) as usize,
                original.len()
            );
            let end = 120 + original.len();
            assert_eq!(&reply[120..end], original);
            assert_eq!(
                activation::Statement::decode(&reply[120..end]).unwrap(),
                statement
            );
            assert_eq!(
                u16::from_be_bytes(reply[end..end + 2].try_into().unwrap()) as usize,
                manifest.len()
            );
            assert_eq!(&reply[end + 2..], manifest);
            assert!(reply.len() <= 10897);
            assert_eq!(interval_snapshot(&f).await, before);
            assert_eq!(
                f.db.query_one("SELECT count(*) FROM sealed_inbound_events", &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                0
            );
        }
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn proposal_denies_foreign_selectors_tuple_changes_and_active_or_withdrawn_intervals() {
    let (f, owner, statement) = activation::tests::pending().await;
    let session = identity(&f);
    let bytes = frame(&session, statement.interval, Uuid::new_v4());
    let before = interval_snapshot(&f).await;
    assert!(matches!(
        super::super::handle(
            &mut f.connect().await,
            &session,
            &frame(&session, Uuid::new_v4(), Uuid::new_v4())
        )
        .await,
        Err(ConversationError::Forbidden)
    ));
    for at in [6, 22, 38, 54, 62, 70] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(matches!(
            super::super::handle(&mut f.connect().await, &session, &changed).await,
            Err(ConversationError::Forbidden)
        ));
    }
    for cause in 0..4 {
        let mut changed = identity(&f);
        match cause {
            0 => changed.device.device_id = Uuid::new_v4(),
            1 => changed.device.connection_epoch += 1,
            2 => changed.device.site_id = "absent",
            _ => changed.device.deployment_epoch += 1,
        }
        assert!(matches!(
            super::super::handle(
                &mut f.connect().await,
                &changed,
                &frame(&changed, statement.interval, Uuid::new_v4())
            )
            .await,
            Err(ConversationError::Forbidden)
        ));
        assert_eq!(interval_snapshot(&f).await, before);
    }
    activation::tests::activate(&f, &statement).await;
    let active = interval_snapshot(&f).await;
    assert!(matches!(
        super::super::handle(&mut f.connect().await, &session, &bytes).await,
        Err(ConversationError::Forbidden)
    ));
    assert_eq!(interval_snapshot(&f).await, active);
    activation::close(&mut f.connect().await, &owner, statement.interval, true)
        .await
        .unwrap();
    let withdrawn = interval_snapshot(&f).await;
    assert!(matches!(
        super::super::handle(&mut f.connect().await, &session, &bytes).await,
        Err(ConversationError::Forbidden)
    ));
    assert_eq!(interval_snapshot(&f).await, withdrawn);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn proposal_rejects_revoked_origin_line_and_manifest_authority_without_state_change() {
    for cause in 0..5 {
        let (f, owner, statement) = activation::tests::pending().await;
        let session = identity(&f);
        let bytes = frame(&session, statement.interval, Uuid::new_v4());
        let before = interval_snapshot(&f).await;
        match cause {
            0 => {
                f.db.execute(
                    "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
                    &[&owner.session_id],
                )
                .await
                .unwrap();
            }
            1 => {
                f.db.execute("UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",&[&owner.session_id]).await.unwrap();
            }
            2 => {
                f.db.execute("UPDATE device_line_bindings SET state='revoked'", &[])
                    .await
                    .unwrap();
            }
            3 => {
                f.db.execute(
                    "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp()",
                    &[],
                )
                .await
                .unwrap();
            }
            _ => {
                f.db.execute("UPDATE device_keys SET revoked_at=clock_timestamp()", &[])
                    .await
                    .unwrap();
            }
        }
        assert!(
            super::super::handle(&mut f.connect().await, &session, &bytes)
                .await
                .is_err()
        );
        assert_eq!(interval_snapshot(&f).await, before);
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn proposal_rechecks_origin_revocation_after_observed_session_lock_wait() {
    let (f, owner, statement) = activation::tests::pending().await;
    let session = identity(&f);
    let bytes = frame(&session, statement.interval, Uuid::new_v4());
    let before = interval_snapshot(&f).await;
    let mut blocker = f.connect().await;
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM sessions WHERE id=$1 FOR UPDATE",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    let blocker_pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let mut db = f.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let pending = super::super::handle(&mut db, &session, &bytes);
    tokio::pin!(pending);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            tokio::select! {
                result=&mut pending=>panic!("retrieval ended before session barrier: {result:?}"),
                row=async { f.db.query_one("SELECT $2=ANY(pg_blocking_pids($1))",&[&pid,&blocker_pid]).await }=>{
                    if row.unwrap().get::<_,bool>(0) {break;}
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("retrieval must reach the actual session blocker");
    tx.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(pending.await, Err(ConversationError::Forbidden)));
    assert_eq!(interval_snapshot(&f).await, before);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn proposal_rejects_root_signed_successor_without_selected_live_reader_or_phone_signer() {
    for (role, expired) in [(2, false), (4, false), (2, true), (4, true)] {
        let (mut f, owner) = crate::http_owner_conversations::tests::prepared().await;
        let mut db = f.connect().await;
        let tx = db.transaction().await.unwrap();
        let admitted = crate::sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
            .await
            .unwrap();
        drop(admitted);
        tx.commit().await.unwrap();
        f.advance();
        let at = 151
            + f.bytes[151..f.bytes.len() - 64]
                .chunks_exact(149)
                .position(|record| record[0] == role)
                .unwrap()
                * 149;
        if expired {
            let now: i64 =
                f.db.query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            f.bytes[at + 140..at + 148].copy_from_slice(&(now - 1).to_be_bytes());
        } else if role == 2 {
            // A manifest must retain one archive role. Replace its valid key,
            // so the signed successor lacks the original selected reader.
            let replacement = p256::ecdsa::SigningKey::generate_from_rng(&mut rand::rng());
            let point = replacement.verifying_key().to_sec1_point(false);
            f.bytes[at + 1..at + 33].copy_from_slice(&Sha256::digest(
                [b"ZTSE/key/v1\0".as_slice(), &[0, 0x10], point.as_bytes()].concat(),
            ));
            f.bytes[at + 33..at + 98].copy_from_slice(point.as_bytes());
        } else {
            f.bytes.drain(at..at + 149);
            f.bytes[150] -= 1;
        }
        f.resign();
        let statement = activation::begin(
            &mut db,
            &owner,
            &crate::http_owner_conversations::ConversationConsent {
                device_id: f.device,
                line_id: f.line,
                binding_generation: 1,
                peer: "+12".into(),
                disclosure_version: crate::http_owner_conversations::DISCLOSURE_VERSION.into(),
                content_transfer_confirmed: true,
            },
            &f.bytes,
        )
        .await
        .unwrap();
        let before = interval_snapshot(&f).await;
        let session = identity(&f);
        assert!(matches!(
            super::super::handle(
                &mut f.connect().await,
                &session,
                &frame(&session, statement.interval, Uuid::new_v4())
            )
            .await,
            Err(ConversationError::Forbidden)
        ));
        assert_eq!(interval_snapshot(&f).await, before);
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn proposal_rejects_current_reader_rotation_and_real_origin_expiry() {
    for rotation in [false, true] {
        let (mut f, owner, statement) = activation::tests::pending().await;
        let before = interval_snapshot(&f).await;
        let session = identity(&f);
        if rotation {
            let key = p256::ecdsa::SigningKey::generate_from_rng(&mut rand::rng());
            let point = key.verifying_key().to_sec1_point(false);
            let id: [u8; 32] =
                Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], point.as_bytes()].concat())
                    .into();
            let at = 151
                + f.bytes[151..f.bytes.len() - 64]
                    .chunks_exact(149)
                    .position(|r| r[0] == 2)
                    .unwrap()
                    * 149;
            f.bytes[at + 1..at + 33].copy_from_slice(&id);
            f.bytes[at + 33..at + 98].copy_from_slice(point.as_bytes());
            f.resign();
            let mut db = f.connect().await;
            let tx = db.transaction().await.unwrap();
            let admitted =
                crate::sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
                    .await
                    .unwrap();
            drop(admitted);
            tx.commit().await.unwrap();
        } else {
            f.db.execute("UPDATE sessions SET expires_at=clock_timestamp()+interval '100 milliseconds' WHERE id=$1",&[&owner.session_id]).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if f.db
                        .query_one(
                            "SELECT clock_timestamp()>=expires_at FROM sessions WHERE id=$1",
                            &[&owner.session_id],
                        )
                        .await
                        .unwrap()
                        .get::<_, bool>(0)
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
        assert!(matches!(
            super::super::handle(
                &mut f.connect().await,
                &session,
                &frame(&session, statement.interval, Uuid::new_v4())
            )
            .await,
            Err(ConversationError::Forbidden)
        ));
        assert_eq!(interval_snapshot(&f).await, before);
        f.cleanup().await;
    }
}
