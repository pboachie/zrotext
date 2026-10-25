// SPDX-License-Identifier: AGPL-3.0-only
//! Real public-schema stock-runtime containment, not an extracted SQL sketch.
//! Legacy identities/payloads are synthetic;03 has actual signed ceremonies and
//! admission. No real phone, HPKE open, platform invocation or carrier is used.
use super::grant_tests::{queue, ready};
use super::interval_queue_tests::lease;
use super::reviewed_send_tests::{active, packet_with_lifetime};
use super::*;
use tokio_postgres::Client;
use zrotext_delivery_store::{DeliveryStore, NewMessage, RadioEvent, StoreError};
use zrotext_domain::{Evidence, MessageState};

async fn now(db: &Client) -> i64 {
    db.query_one(
        "SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}
async fn legacy(db: &mut Client) -> (Uuid, Uuid) {
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let tx = crate::runtime_db::begin_native(db).await.unwrap();
    tx.execute("INSERT INTO public.accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    tx.execute("INSERT INTO public.devices(id,account_id,display_name) VALUES($1,$2,'synthetic legacy device')",&[&device,&account]).await.unwrap();
    tx.commit().await.unwrap();
    (account, device)
}
async fn enqueue(db: &mut Client, account: Uuid, device: Uuid, expiry: i64) -> Uuid {
    let message = Uuid::new_v4();
    let idempotency = Uuid::new_v4().to_string();
    assert!(
        DeliveryStore::new(db)
            .accept(NewMessage {
                account_id: account,
                client_message_id: message,
                device_id: device,
                idempotency_key: &idempotency,
                recipient_e164: "+14",
                synthetic_payload: b"synthetic legacy payload",
                expires_at_ms: expiry
            })
            .await
            .unwrap()
            .created
    );
    message
}
async fn guarded_snapshot(db: &Client, account: Uuid, message: Uuid) -> (String, i64, i64, i64) {
    let row=db.query_one("SELECT m.state,(SELECT count(*) FROM public.usage_ledger u WHERE u.account_id=m.account_id AND u.message_id=m.id AND u.entry_kind='reserve'),(SELECT count(*) FROM public.usage_ledger u WHERE u.account_id=m.account_id AND u.message_id=m.id AND u.entry_kind='refund'),(SELECT count(*) FROM public.message_attempts a WHERE a.account_id=m.account_id AND a.message_id=m.id) FROM public.messages m WHERE m.account_id=$1 AND m.id=$2",&[&account,&message]).await.unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; full current stock runtime mixed legacy and profile03 queue"]
async fn actual_expiry_and_recipient_cancellation_preserve_profile03_originals_and_legacy_progress()
{
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    // Current admission validates the full writer graph. Give this positive
    // containment control a finite initial window, then observe its REAL signed
    // expiry below. The separate short-window control still proves refusal.
    let packet = packet_with_lifetime(&mut c, &browser, &statement, 60_000).await;
    let signed_expiry = crate::reviewed_intent03::v2::Intent03V2::decode(&packet.intent)
        .unwrap()
        .message_expires_ms();
    let tx = crate::runtime_db::begin_native(&mut c.db.reader)
        .await
        .unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    crate::reviewed_intent03::live::admit(
        &tx,
        &mut owner,
        &packet.intent,
        &packet.signature,
        &packet.envelope,
        ORIGIN,
    )
    .await
    .unwrap();
    drop(owner);
    tx.commit().await.unwrap();
    let stored = c.db.reader.query_one(
        "SELECT floor(extract(epoch FROM m.expires_at)*1000)::bigint,row_to_json(m)::text FROM public.messages m WHERE account_id=$1 AND id=$2",
        &[&account, &packet.message],
    ).await.unwrap();
    let stored_expiry: i64 = stored.get(0);
    let original_message: String = stored.get(1);
    assert_eq!(stored_expiry as u64, signed_expiry);
    let (old_account, old_device) = legacy(&mut c.db.reader).await;
    let expiry = now(&c.db.reader).await + 5000;
    let expired = enqueue(&mut c.db.reader, old_account, old_device, expiry).await;
    let pending = enqueue(&mut c.db.reader, old_account, old_device, expiry + 60000).await;
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            let primary = now(&c.db.reader).await;
            if primary >= expiry && primary >= stored_expiry {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual expiry of both original profile03 and legacy messages");
    let primary = now(&c.db.reader).await;
    assert!(primary >= expiry && primary >= stored_expiry);
    assert_eq!(
        DeliveryStore::new(&mut c.db.reader)
            .expire_due(100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        guarded_snapshot(&c.db.reader, account, packet.message).await,
        ("queued".into(), 1, 0, 0)
    );
    assert_eq!(
        DeliveryStore::new(&mut c.db.reader)
            .status(old_account, expired)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Expired
    );
    assert!(matches!(
        DeliveryStore::new(&mut c.db.reader)
            .cancel(account, packet.message)
            .await,
        Err(StoreError::InvalidTransition)
    ));
    let tx = crate::runtime_db::begin_native(&mut c.db.reader)
        .await
        .unwrap();
    tx.batch_execute("SET LOCAL search_path TO pg_catalog,public,pg_temp")
        .await
        .unwrap();
    assert_eq!(
        zrotext_delivery_store::cancel_pending_recipient(&tx, account, "+12")
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        zrotext_delivery_store::cancel_pending_recipient(&tx, old_account, "+14")
            .await
            .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    assert_eq!(
        DeliveryStore::new(&mut c.db.reader)
            .status(old_account, pending)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Cancelled
    );
    assert_eq!(
        guarded_snapshot(&c.db.reader, account, packet.message).await,
        ("queued".into(), 1, 0, 0)
    );
    let retained_message: String =
        c.db.reader
            .query_one(
                "SELECT row_to_json(m)::text FROM public.messages m WHERE account_id=$1 AND id=$2",
                &[&account, &packet.message],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(retained_message, original_message);
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual independent03 grant and unchanged legacy radio evidence"]
async fn actual_legacy_events_cannot_change_profile03_grant_and_do_not_poison_other_message() {
    let (mut c, browser, statement) = super::reviewed_send_tests::active_claimed().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let packet = queue(&mut c, &browser, &statement).await;
    let published = ready(&mut c).await;
    let actor = lease(&c);
    let socket = c.socket_actor();
    let grant =
        crate::conversation_grant03::issue_next(&mut c.db.reader, socket, actor, &published)
            .await
            .unwrap()
            .unwrap();
    let claims = grant.frame().claims();
    let attempt = claims.attempt_id;
    let before = guarded_snapshot(&c.db.reader, account, packet.message).await;
    let (old_account, old_device) = legacy(&mut c.db.reader).await;
    let expiry = now(&c.db.reader).await + 60000;
    let message = enqueue(&mut c.db.reader, old_account, old_device, expiry).await;
    // This is only disposable test configuration. No live dispatch gate changes.
    c.db.owner
        .batch_execute(
            "UPDATE public.deployment_authority SET dispatch_enabled=TRUE WHERE singleton",
        )
        .await
        .unwrap();
    let session = DeliveryStore::new(&mut c.db.reader)
        .connect_session(
            old_account,
            old_device,
            "activation-test",
            "synthetic-legacy-worker",
            60,
        )
        .await
        .unwrap();
    let claim = DeliveryStore::new(&mut c.db.reader)
        .claim_due_for_device("synthetic-worker", old_account, old_device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.message_id, message);
    let old_attempt = Uuid::new_v4();
    DeliveryStore::new(&mut c.db.reader)
        .issue_grant(&claim, &session, old_attempt)
        .await
        .unwrap();
    for evidence in [
        Evidence::DurableSubmitIntent,
        Evidence::ProvenNoSubmit,
        Evidence::CrashWithoutCallback,
        Evidence::SentCallbackOk,
    ] {
        let sent = matches!(evidence, Evidence::SentCallbackOk);
        let observed = now(&c.db.reader).await;
        let event = RadioEvent {
            event_id: Uuid::new_v4(),
            account_id: account,
            device_id: c.device,
            message_id: packet.message,
            attempt_id: attempt,
            evidence,
            observed_at_ms: observed,
            segment_index: sent.then_some(0),
            segment_count: sent.then_some(1),
        };
        assert!(matches!(
            DeliveryStore::new(&mut c.db.reader)
                .record_radio_event(event)
                .await,
            Err(StoreError::InvalidTransition)
        ));
        assert_eq!(
            guarded_snapshot(&c.db.reader, account, packet.message).await,
            before
        );
    }
    let observed = now(&c.db.reader).await;
    let event = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: old_account,
        device_id: old_device,
        message_id: message,
        attempt_id: old_attempt,
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: observed,
        segment_index: None,
        segment_count: None,
    };
    assert_eq!(
        DeliveryStore::new(&mut c.db.reader)
            .record_radio_event(event)
            .await
            .unwrap(),
        MessageState::Submitting
    );
    let sent = RadioEvent {
        event_id: Uuid::new_v4(),
        evidence: Evidence::SentCallbackOk,
        segment_index: Some(0),
        segment_count: Some(1),
        ..event
    };
    assert_eq!(
        DeliveryStore::new(&mut c.db.reader)
            .record_radio_event(sent)
            .await
            .unwrap(),
        MessageState::Submitted
    );
    assert_eq!(
        guarded_snapshot(&c.db.reader, account, packet.message).await,
        before
    );
    assert_eq!(
        c.db.reader
            .query_one(
                "SELECT outcome FROM public.dispatch_fences WHERE account_id=$1 AND attempt_id=$2",
                &[&account, &attempt]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "granted"
    );
    assert_eq!(
        c.db.reader
            .query_one(
                "SELECT count(*) FROM public.message_events WHERE account_id=$1 AND attempt_id=$2",
                &[&account, &attempt]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; original short message expiry refuses admission without mutation"]
async fn original_short_message_expiry_refuses_admission_without_queue_or_reservation() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')", &[&account]).await.unwrap();
    let packet = packet_with_lifetime(&mut c, &browser, &statement, 5000).await;
    let signed = crate::reviewed_intent03::v2::Intent03V2::decode(&packet.intent).unwrap();
    assert_eq!(signed.message_expires_ms() - signed.observed_ms(), 5000);
    assert!((now(&c.db.reader).await as u64) < signed.message_expires_ms());
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while (now(&c.db.reader).await as u64) < signed.message_expires_ms() {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("original five-second signed message expires naturally");
    let tx = crate::runtime_db::begin_native(&mut c.db.reader)
        .await
        .unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(matches!(
        crate::reviewed_intent03::live::admit(
            &tx,
            &mut owner,
            &packet.intent,
            &packet.signature,
            &packet.envelope,
            ORIGIN
        )
        .await,
        Err(Error::Unsupported)
    ));
    drop(owner);
    tx.rollback().await.unwrap();
    let counts = c.db.reader.query_one(
        "SELECT (SELECT count(*) FROM public.messages WHERE account_id=$1),(SELECT count(*) FROM public.conversation_reviewed_sends03 WHERE account_id=$1),(SELECT count(*) FROM public.usage_ledger WHERE account_id=$1),(SELECT count(*) FROM public.message_attempts WHERE account_id=$1)",
        &[&account],
    ).await.unwrap();
    assert_eq!(
        (
            counts.get::<_, i64>(0),
            counts.get::<_, i64>(1),
            counts.get::<_, i64>(2),
            counts.get::<_, i64>(3)
        ),
        (0, 0, 0, 0)
    );
    c.db.finish().await;
}
