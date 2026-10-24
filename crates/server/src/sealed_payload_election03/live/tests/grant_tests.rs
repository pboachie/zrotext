// SPDX-License-Identifier: AGPL-3.0-only
//! Actual independently signed originals, ordinary runtime and one real quota
//! reservation. Opaque synthetic ciphertext proves no HPKE open or radio send.
use super::interval_queue_tests::{lease, request};
use super::reviewed_send_tests::{Packet, active, packet};
use super::*;
use crate::conversation_grant03::{self as grants, FetchServing03};
use crate::sealed_dispatch::wire03::{Fetch03, GrantFrame03, ReadyFrame03};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

async fn queue(
    c: &mut Case,
    browser: &SigningKey,
    statement: &crate::conversation_interval03::Statement03,
) -> Packet {
    let p = packet(c, browser, statement).await;
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    assert!(
        crate::reviewed_intent03::live::admit(
            &tx,
            &mut owner,
            &p.intent,
            &p.signature,
            &p.envelope,
            ORIGIN
        )
        .await
        .unwrap()
        .0
    );
    drop(owner);
    tx.commit().await.unwrap();
    p
}
async fn ready(c: &mut Case) -> ReadyFrame03 {
    let tx = c.db.reader.transaction().await.unwrap();
    let mut owner = ordinary_owner03::authenticate(&tx, &c.hasher, ORIGIN, source(&c.credentials))
        .await
        .unwrap();
    let held = hold_owner_selection(&tx, &mut owner, c.line, ORIGIN)
        .await
        .unwrap();
    let a = held.authority();
    let raw = serde_json::json!({"v":1,"type":"sealed_ready","grant_version":3,"envelope_profile":3,"manifest_profile":3,
        "connection_epoch":1,"deployment_epoch":1,"binding_generation":a.binding_generation,
        "trust_generation":1,"manifest_version":a.manifest_version,"line_id":Uuid::from_bytes(a.line_id),
        "reader_key_id":B.encode(a.selected_reader_key_id),"manifest_digest":B.encode(a.manifest_digest),
        "root_fingerprint":B.encode(a.root_fingerprint),"election_digest":B.encode(a.election_commitment)});
    let value = ReadyFrame03::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
    drop(held);
    drop(owner);
    tx.rollback().await.unwrap();
    value
}
fn fetch(c: &Case, frame: &GrantFrame03) -> Fetch03 {
    let signature: Signature = c.phone_key.sign(&frame.fetch_transcript());
    let raw = serde_json::json!({"grant":serde_json::from_slice::<serde_json::Value>(&frame.to_json().unwrap()).unwrap(),
        "signature_der":B.encode(signature.normalize_s().to_der().as_bytes())});
    Fetch03::parse(&serde_json::to_vec(&raw).unwrap()).unwrap()
}
fn serving() -> FetchServing03<'static> {
    FetchServing03 {
        site: "activation-test",
        deployment: 1,
        origin: ORIGIN,
    }
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; genuine typed grant and signed full-current fetch"]
async fn actual_grant_fetch_preserves_originals_one_attempt_and_refuses_owner_withdrawal() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let p = queue(&mut c, &browser, &statement).await;
    let ready = ready(&mut c).await;
    let actor = lease(&c);
    let grant = grants::issue_next(&mut c.db.reader, actor, &ready)
        .await
        .unwrap()
        .unwrap();
    let claims = grant.frame().claims();
    assert_eq!(claims.message_id, p.message);
    assert_eq!(claims.segment_count, 1);
    let request = fetch(&c, grant.frame());
    let first = grants::fetch(&mut c.db.reader, serving(), &request)
        .await
        .unwrap();
    assert_eq!(first.as_object().unwrap().len(), 10);
    assert_eq!(
        B.decode(first["envelope"].as_str().unwrap()).unwrap(),
        p.envelope
    );
    assert_eq!(first["current"]["kind"], "message_manifest_permission03");
    assert_eq!(
        first["current"]["request_id"],
        claims.attempt_id.to_string()
    );
    assert_eq!(
        first["current"]["fetch_transcript_sha256"],
        B.encode(crypto::sha(grant.frame().fetch_transcript().as_slice()))
    );
    assert_eq!(
        first["current"]["permission_expires_ms"],
        claims.expires_at_ms.to_string()
    );
    assert_eq!(
        first["interval_permission"]["permission_expires_ms"],
        claims.expires_at_ms.to_string()
    );
    assert_eq!(
        first["current"]["compared_ms"],
        first["interval_permission"]["compared_ms"]
    );
    let repeat = grants::fetch(&mut c.db.reader, serving(), &request)
        .await
        .unwrap();
    assert_eq!(repeat["envelope"], first["envelope"]);
    assert_eq!(repeat["accepted_ms"], first["accepted_ms"]);
    assert!(
        grants::issue_next(&mut c.db.reader, actor, &ready)
            .await
            .unwrap()
            .is_none()
    );
    let original=c.db.reader.query_one("SELECT(SELECT count(*) FROM public.message_attempts WHERE account_id=$1),(SELECT count(*) FROM public.usage_ledger WHERE account_id=$1 AND entry_kind='reserve'),(SELECT expires_at_ms FROM public.conversation_profile03_grants WHERE account_id=$1 AND message_id=$2)",&[&account,&p.message]).await.unwrap();
    assert_eq!(original.get::<_, i64>(0), 1);
    assert_eq!(original.get::<_, i64>(1), 1);
    assert_eq!(original.get::<_, i64>(2), claims.expires_at_ms);
    assert!(
        crate::auth::revoke_session(&c.db.reader, &c.principal, c.principal.session_id)
            .await
            .unwrap()
    );
    assert!(
        grants::fetch(&mut c.db.reader, serving(), &request)
            .await
            .is_err()
    );
    let row=c.db.reader.query_one("SELECT expires_at_ms FROM public.conversation_profile03_grants WHERE account_id=$1 AND message_id=$2",&[&account,&p.message]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), claims.expires_at_ms);
    c.db.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; genuine fresh-owner pending grant selection"]
async fn old_revoked_owner_message_cannot_starve_fresh_owner_queue_or_gain_an_attempt() {
    let (mut c, browser, statement) = active().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let old = queue(&mut c, &browser, &statement).await;
    assert!(
        crate::auth::revoke_session(&c.db.reader, &c.principal, c.principal.session_id)
            .await
            .unwrap()
    );
    let challenge = crate::auth::mfa::begin_login_challenge(
        &c.db.reader,
        &c.hasher,
        account,
        c.principal.user_id,
        &c.password,
    )
    .await
    .unwrap();
    c.credentials = crate::auth::mfa::complete_login(
        &mut c.db.reader,
        Some(&c.cipher),
        &c.hasher,
        &challenge,
        &c.recovery[6],
    )
    .await
    .unwrap();
    c.principal = crate::auth::authenticate_session(&c.db.reader, &c.hasher, &c.credentials.token)
        .await
        .unwrap();
    let signed: Vec<u8> =
        c.db.reader
            .query_one(
                "SELECT manifest FROM public.sealed_manifest_authorities WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
    let pending = request(&mut c, &browser, &signed, b"+13", 300_000, 7).await;
    let s = crate::conversation_interval03::Statement03::decode(&pending.bytes).unwrap();
    let phone = sign(
        &c.phone_key,
        b"zrotext/conversation/approve03/v1\0",
        &[pending.bytes.as_slice(), &crypto::sha(&pending.signature)].concat(),
    );
    let installed = sign(
        &c.phone_key,
        b"zrotext/conversation/install03/v1\0",
        &[
            pending.bytes.as_slice(),
            &crypto::sha(&pending.signature),
            &crypto::sha(&phone),
        ]
        .concat(),
    );
    let actor = lease(&c);
    let tx = c.db.reader.transaction().await.unwrap();
    crate::conversation_interval03::live::device_approve(
        &tx,
        actor,
        pending.id,
        &s.digest(),
        &phone,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let tx = c.db.reader.transaction().await.unwrap();
    crate::conversation_interval03::live::device_install(
        &tx,
        actor,
        pending.id,
        &s.digest(),
        &installed,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let fresh = queue(&mut c, &browser, &s).await;
    let ready = ready(&mut c).await;
    let grant = grants::issue_next(&mut c.db.reader, actor, &ready)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.frame().claims().message_id, fresh.message);
    let row=c.db.reader.query_one("SELECT m.state,(SELECT count(*) FROM public.message_attempts a WHERE a.account_id=m.account_id AND a.message_id=m.id) FROM public.messages m WHERE m.account_id=$1 AND m.id=$2",&[&account,&old.message]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "queued");
    assert_eq!(row.get::<_, i64>(1), 0);
    c.db.finish().await;
}
