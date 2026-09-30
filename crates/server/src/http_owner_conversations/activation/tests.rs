// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    http_owner_conversations::tests::{envelope, prepared},
    sealed_manifest_store::tests::Fixture,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::{Signature, signature::Signer};
use sha2::Sha256;

async fn fresh_session(f: &Fixture, owner: &SessionPrincipal) -> SessionPrincipal {
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
    mac.update(b"session-v1\0");
    mac.update(token.as_bytes());
    let hash = mac.finalize().into_bytes();
    let hasher = super::super::TokenHasher::new(crate::test_keys::key(84)).unwrap();
    f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
        &[&Uuid::new_v4(),&f.account,&owner.user_id,&hash.as_slice(),&vec![4u8;32]]).await.unwrap();
    crate::auth::authenticate_session(&f.db, &hasher, &token)
        .await
        .unwrap()
}

fn sign(f: &Fixture, s: &Statement, domain: &[u8]) -> Vec<u8> {
    let signature: Signature = f.event_signer.sign(&s.transcript(domain).unwrap());
    signature.normalize_s().to_bytes().to_vec()
}
async fn pending() -> (Fixture, SessionPrincipal, Statement) {
    let (mut f, owner) = prepared().await;
    let mut client = f.connect().await;
    let tx = client.transaction().await.unwrap();
    let mut admitted = sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
        .await
        .unwrap();
    admitted.context(&f.wanted()).await.unwrap();
    drop(admitted);
    tx.commit().await.unwrap();
    f.advance();
    let consent = ConversationConsent {
        device_id: f.device,
        line_id: f.line,
        binding_generation: 1,
        peer: "+12".into(),
        disclosure_version: super::super::DISCLOSURE_VERSION.into(),
        content_transfer_confirmed: true,
    };
    let s = begin(&mut client, &owner, &consent, &f.bytes)
        .await
        .unwrap();
    (f, owner, s)
}
async fn activate(f: &Fixture, s: &Statement) {
    approve(
        &mut f.connect().await,
        f.session(),
        &s.encode().unwrap(),
        &sign(f, s, statement::APPROVE_DOMAIN),
    )
    .await
    .unwrap();
    installed(
        &mut f.connect().await,
        f.session(),
        &s.encode().unwrap(),
        &sign(f, s, statement::INSTALL_DOMAIN),
    )
    .await
    .unwrap();
}
async fn capture(
    f: &Fixture,
    s: &Statement,
    event: Uuid,
    seq: u64,
    peer: &[u8],
) -> Result<Vec<u8>, crate::sealed_inbound::ingest::IngestError> {
    let observed: i64 =
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let bytes = envelope(f, event, seq, observed as u64, peer);
    crate::sealed_inbound::ingest::ingest_conversation(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &f.bytes,
        &bytes,
        CaptureInterval {
            interval: s.interval,
            activation_digest: s.activation_digest,
        },
    )
    .await?;
    Ok(bytes)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn acceptance_and_installation_are_both_required_with_exact_replay_domains() {
    let (f, owner, s) = pending().await;
    let bytes = s.encode().unwrap();
    assert_eq!(Statement::decode(&bytes).unwrap(), s);
    let mut client = f.connect().await;
    assert!(
        active_lease(&mut client, f.session(), s.interval, Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(
        installed(
            &mut client,
            f.session(),
            &bytes,
            &sign(&f, &s, statement::INSTALL_DOMAIN)
        )
        .await
        .is_err()
    );
    assert!(capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.is_err());
    assert_eq!(
        f.db.query_one(
            "SELECT version FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&f.account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let approval = sign(&f, &s, statement::APPROVE_DOMAIN);
    let mut wrong = s.clone();
    wrong.peer = "+13".into();
    assert!(
        approve(
            &mut client,
            f.session(),
            &wrong.encode().unwrap(),
            &approval
        )
        .await
        .is_err()
    );
    approve(&mut client, f.session(), &bytes, &approval)
        .await
        .unwrap();
    approve(&mut client, f.session(), &bytes, &approval)
        .await
        .unwrap();
    assert!(
        active_lease(&mut client, f.session(), s.interval, Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(capture(&f, &s, Uuid::new_v4(), 1, b"+12").await.is_err());
    assert!(
        installed(&mut client, f.session(), &bytes, &approval)
            .await
            .is_err()
    );
    let installation = sign(&f, &s, statement::INSTALL_DOMAIN);
    installed(&mut client, f.session(), &bytes, &installation)
        .await
        .unwrap();
    installed(&mut client, f.session(), &bytes, &installation)
        .await
        .unwrap();
    let lease = active_lease(&mut client, f.session(), s.interval, Uuid::new_v4())
        .await
        .unwrap();
    assert!(lease.valid_for_ms > 0 && lease.valid_for_ms <= 60_000);
    let event = Uuid::new_v4();
    let saved = capture(&f, &s, event, 1, b"+12").await.unwrap();
    assert_eq!(
        read_history(&mut client, &owner, event).await.unwrap(),
        saved
    );
    assert!(capture(&f, &s, Uuid::new_v4(), 2, b"+13").await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn original_provenance_survives_renewal_and_fresh_session_without_rewriting_ciphertext() {
    let (mut f, owner, s) = pending().await;
    activate(&f, &s).await;
    let old = Uuid::new_v4();
    let old_bytes = capture(&f, &s, old, 1, b"+12").await.unwrap();
    let provenance=f.db.query_one("SELECT manifest_version,manifest_digest,verified_manifest,accepted_at_ms FROM conversation_inbound_provenance WHERE event_id=$1", &[&old]).await.unwrap();
    f.advance();
    let new = Uuid::new_v4();
    capture(&f, &s, new, 2, b"+12").await.unwrap();
    assert_eq!(
        read_history(&mut f.connect().await, &owner, old)
            .await
            .unwrap(),
        old_bytes
    );
    assert_eq!(provenance.get::<_, i64>(0), 2);
    let after=f.db.query_one("SELECT manifest_version,manifest_digest,verified_manifest,accepted_at_ms FROM conversation_inbound_provenance WHERE event_id=$1", &[&old]).await.unwrap();
    for i in [1, 2] {
        assert_eq!(provenance.get::<_, Vec<u8>>(i), after.get::<_, Vec<u8>>(i));
    }
    assert_eq!(provenance.get::<_, i64>(3), after.get::<_, i64>(3));
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    assert!(capture(&f, &s, Uuid::new_v4(), 3, b"+12").await.is_err());
    assert!(
        active_lease(
            &mut f.connect().await,
            f.session(),
            s.interval,
            Uuid::new_v4()
        )
        .await
        .is_err()
    );
    let fresh = fresh_session(&f, &owner).await;
    assert_eq!(
        read_history(&mut f.connect().await, &fresh, old)
            .await
            .unwrap(),
        old_bytes
    );
    f.advance();
    let consent = ConversationConsent {
        device_id: f.device,
        line_id: f.line,
        binding_generation: 1,
        peer: "+12".into(),
        disclosure_version: super::super::DISCLOSURE_VERSION.into(),
        content_transfer_confirmed: true,
    };
    let replacement = begin(&mut f.connect().await, &fresh, &consent, &f.bytes)
        .await
        .unwrap();
    assert_ne!(replacement.interval, s.interval);
    assert_eq!(
        f.db.query_one(
            "SELECT phase FROM conversation_intervals WHERE id=$1",
            &[&s.interval]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "history"
    );
    activate(&f, &replacement).await;
    assert_eq!(
        read_history(&mut f.connect().await, &fresh, old)
            .await
            .unwrap(),
        old_bytes
    );
    close(&mut f.connect().await, &fresh, s.interval, true)
        .await
        .unwrap();
    assert!(
        read_history(&mut f.connect().await, &fresh, old)
            .await
            .is_err()
    );
    assert!(
        f.db.query_one(
            "SELECT statement IS NULL FROM conversation_intervals WHERE id=$1",
            &[&s.interval]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn scoped_replay_cannot_create_provenance_for_legacy_or_purged_storage() {
    let (f, owner, s) = pending().await;
    activate(&f, &s).await;
    let event = Uuid::new_v4();
    let bytes = capture(&f, &s, event, 1, b"+12").await.unwrap();
    let selector = CaptureInterval {
        interval: s.interval,
        activation_digest: s.activation_digest,
    };
    assert!(
        !crate::sealed_inbound::ingest::ingest_conversation(
            &mut f.connect().await,
            f.session(),
            f.line,
            1,
            &f.bytes,
            &bytes,
            selector
        )
        .await
        .unwrap()
        .created
    );
    f.db.execute(
        "UPDATE sealed_inbound_events SET envelope=NULL WHERE id=$1",
        &[&event],
    )
    .await
    .unwrap();
    f.db.execute(
        "DELETE FROM conversation_inbound_provenance WHERE event_id=$1",
        &[&event],
    )
    .await
    .unwrap();
    assert!(
        crate::sealed_inbound::ingest::ingest_conversation(
            &mut f.connect().await,
            f.session(),
            f.line,
            1,
            &f.bytes,
            &bytes,
            selector
        )
        .await
        .is_err()
    );
    assert!(
        read_history(&mut f.connect().await, &owner, event)
            .await
            .is_err()
    );
    assert_eq!(
        f.db.query_one("SELECT COUNT(*) FROM conversation_inbound_provenance", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn legacy_reader_cannot_bypass_interval_withdrawal_and_inventory_reports_provenance() {
    let (f, owner, s) = pending().await;
    let consent = ConversationConsent {
        device_id: f.device,
        line_id: f.line,
        binding_generation: 1,
        peer: "+12".into(),
        disclosure_version: super::super::DISCLOSURE_VERSION.into(),
        content_transfer_confirmed: true,
    };
    super::super::enable_conversation(&mut f.connect().await, &owner, &consent)
        .await
        .unwrap();
    activate(&f, &s).await;
    let event = Uuid::new_v4();
    capture(&f, &s, event, 1, b"+12").await.unwrap();
    let view = super::super::lifecycle::inventory(&mut f.connect().await, &owner, None, None)
        .await
        .unwrap();
    assert_eq!(view.intervals.len(), 1);
    assert_eq!(view.intervals[0].interval_id, s.interval);
    assert_eq!(view.sealed_events[0].interval_id, Some(s.interval));
    assert_eq!(view.sealed_events[0].verified_manifest_version, Some(2));
    assert!(
        super::super::read_event(&mut f.connect().await, &owner, event)
            .await
            .is_err()
    );
    close(&mut f.connect().await, &owner, s.interval, true)
        .await
        .unwrap();
    assert!(
        super::super::read_event(&mut f.connect().await, &owner, event)
            .await
            .is_err()
    );
    assert!(
        read_history(&mut f.connect().await, &owner, event)
            .await
            .is_err()
    );
    // Retention deletes provenance after body purge, preserving replay identity.
    f.db.execute(
        "UPDATE sealed_inbound_events SET envelope=NULL WHERE id=$1",
        &[&event],
    )
    .await
    .unwrap();
    let (_, provenance, _) =
        super::super::lifecycle::activation::prune(&mut f.connect().await, 30, 1)
            .await
            .unwrap();
    assert_eq!(provenance, 1);
    assert_eq!(
        f.db.query_one(
            "SELECT COUNT(*) FROM sealed_inbound_events WHERE id=$1",
            &[&event]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn approval_and_installation_refuse_a_replacement_signed_lease_but_active_recovery_allows_renewal()
 {
    let (f, _owner, s) = pending().await;
    let mut replacement = f.session();
    replacement.connection_epoch += 1;
    f.db.execute(
        "UPDATE device_sessions SET connection_epoch=$2 WHERE device_id=$1",
        &[&f.device, &replacement.connection_epoch],
    )
    .await
    .unwrap();
    assert!(
        approve(
            &mut f.connect().await,
            replacement,
            &s.encode().unwrap(),
            &sign(&f, &s, statement::APPROVE_DOMAIN)
        )
        .await
        .is_err()
    );
    f.db.execute(
        "UPDATE device_sessions SET connection_epoch=$2 WHERE device_id=$1",
        &[&f.device, &s.connection_epoch],
    )
    .await
    .unwrap();
    approve(
        &mut f.connect().await,
        f.session(),
        &s.encode().unwrap(),
        &sign(&f, &s, statement::APPROVE_DOMAIN),
    )
    .await
    .unwrap();
    f.db.execute(
        "UPDATE device_sessions SET connection_epoch=$2 WHERE device_id=$1",
        &[&f.device, &replacement.connection_epoch],
    )
    .await
    .unwrap();
    assert!(
        installed(
            &mut f.connect().await,
            replacement,
            &s.encode().unwrap(),
            &sign(&f, &s, statement::INSTALL_DOMAIN)
        )
        .await
        .is_err()
    );
    f.db.execute(
        "UPDATE device_sessions SET connection_epoch=$2 WHERE device_id=$1",
        &[&f.device, &s.connection_epoch],
    )
    .await
    .unwrap();
    installed(
        &mut f.connect().await,
        f.session(),
        &s.encode().unwrap(),
        &sign(&f, &s, statement::INSTALL_DOMAIN),
    )
    .await
    .unwrap();
    f.db.execute(
        "UPDATE device_sessions SET connection_epoch=$2 WHERE device_id=$1",
        &[&f.device, &replacement.connection_epoch],
    )
    .await
    .unwrap();
    assert!(
        active_lease(
            &mut f.connect().await,
            replacement,
            s.interval,
            Uuid::new_v4()
        )
        .await
        .is_ok()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expired_origin_is_closed_by_retention_without_erasing_retained_history() {
    let (f, owner, s) = pending().await;
    activate(&f, &s).await;
    let event = Uuid::new_v4();
    let bytes = capture(&f, &s, event, 1, b"+12").await.unwrap();
    f.db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    let (closed, provenance, intervals) =
        super::super::lifecycle::activation::prune(&mut f.connect().await, 30, 1)
            .await
            .unwrap();
    assert_eq!((closed, provenance, intervals), (1, 0, 0));
    assert!(
        active_lease(
            &mut f.connect().await,
            f.session(),
            s.interval,
            Uuid::new_v4()
        )
        .await
        .is_err()
    );
    let fresh = fresh_session(&f, &owner).await;
    assert_eq!(
        read_history(&mut f.connect().await, &fresh, event)
            .await
            .unwrap(),
        bytes
    );
    f.db.execute(
        "UPDATE sealed_inbound_events SET envelope=NULL WHERE id=$1",
        &[&event],
    )
    .await
    .unwrap();
    let counts = super::super::lifecycle::activation::prune(&mut f.connect().await, 0, 1)
        .await
        .unwrap();
    assert_eq!(counts, (0, 1, 1));
    assert_eq!(
        f.db.query_one(
            "SELECT COUNT(*) FROM sealed_inbound_events WHERE id=$1",
            &[&event]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn origin_expiry_while_provenance_insert_waits_rolls_back_content() {
    let (f, owner, s) = pending().await;
    activate(&f, &s).await;
    let event = Uuid::new_v4();
    let observed: i64 =
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let bytes = envelope(&f, event, 1, observed as u64, b"+12");
    let mut blocker = f.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.batch_execute("LOCK TABLE conversation_inbound_provenance IN SHARE MODE")
        .await
        .unwrap();
    f.db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    let mut client = f.connect().await;
    let pid: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let session = f.session();
    let line = f.line;
    let manifest = f.bytes.clone();
    let task = tokio::spawn(async move {
        crate::sealed_inbound::ingest::ingest_conversation(
            &mut client,
            session,
            line,
            1,
            &manifest,
            &bytes,
            CaptureInterval {
                interval: s.interval,
                activation_digest: s.activation_digest,
            },
        )
        .await
    });
    let mut waiting = false;
    for _ in 0..100 {
        waiting=f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",&[&pid]).await.unwrap().get(0);
        if waiting {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(waiting, "ingest must reach the post-check storage wait");
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    lock.commit().await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert_eq!(
        f.db.query_one(
            "SELECT COUNT(*) FROM sealed_inbound_events WHERE id=$1",
            &[&event]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        f.db.query_one("SELECT COUNT(*) FROM conversation_inbound_provenance", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}
