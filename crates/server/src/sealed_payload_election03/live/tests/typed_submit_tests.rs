// SPDX-License-Identifier: AGPL-3.0-only
//! Actual server/native adapters and committed typed receipts on stock grants.
//! The signed closure is a synthetic device report, not proof of Android/OS entry.
use super::*;
use crate::conversation_effect03::{NoSubmitRecord03, history_clock, wire};
use crate::conversation_grant03::{self as grants, effects};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use p256::ecdsa::{Signature, signature::Signer};
use serde_json::{Value, json};

async fn apply(c: &mut Case, raw: &Value) -> Value {
    let request = wire::Request03::parse(&raw.to_string()).unwrap().unwrap();
    let state = c.socket_state();
    let actor = c.socket_actor();
    let admitted = effects::admit(&mut c.db.reader, actor, &state, request.kind().admission())
        .await
        .unwrap();
    effects::apply(&mut c.db.reader, admitted, &state, Some(ORIGIN), request)
        .await
        .unwrap()
}

async fn liabilities(c: &Case, message: Uuid) -> (String, String, i64, i64, i64) {
    let row=c.db.reader.query_one(
        "SELECT m.state,f.outcome,(SELECT count(*) FROM public.message_attempts a WHERE(a.account_id,a.message_id)=(m.account_id,m.id)),(SELECT count(*) FROM public.usage_ledger u WHERE(u.account_id,u.message_id)=(m.account_id,m.id) AND u.entry_kind='reserve'),(SELECT count(*) FROM public.usage_ledger u WHERE(u.account_id,u.message_id)=(m.account_id,m.id) AND u.entry_kind='refund') FROM public.messages m JOIN public.conversation_profile03_grants g ON(g.account_id,g.message_id)=(m.account_id,m.id) JOIN public.dispatch_fences f ON(f.account_id,f.attempt_id)=(g.account_id,g.attempt_id) WHERE m.account_id=$1 AND m.id=$2",
        &[&c.principal.tenant.account_id(),&message],
    ).await.unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual typed commit and signed no-rearm closure"]
async fn first_submit_commit_is_once_and_signed_closure_releases_only_busy_without_rearming() {
    let (mut c, browser, statement) = super::reviewed_send_tests::active_claimed().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let packet = super::grant_tests::queue(&mut c, &browser, &statement).await;
    let ready = super::grant_tests::ready(&mut c).await;
    let socket = c.socket_actor();
    let device = super::interval_queue_tests::lease(&c);
    let grant = grants::issue_next(&mut c.db.reader, socket, device, &ready)
        .await
        .unwrap()
        .unwrap();
    let claim = grant.frame().claims();
    let event = Uuid::new_v4();
    let fetch = crypto::sha(&grant.frame().fetch_transcript());
    let actor=c.db.reader.query_one("SELECT original_device_session_digest FROM public.conversation_profile03_effect_actors WHERE account_id=$1 AND attempt_id=$2",&[&account,&claim.attempt_id]).await.unwrap();
    let session: [u8; 32] = actor.get::<_, Vec<u8>>(0).try_into().unwrap();
    let observed: i64 =
        c.db.reader
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    let submit = json!({"v":1,"type":"payload_profile_submit03",
        "connection_epoch":socket.session().connection_epoch,"event_id":event,
        "message_id":packet.message,"attempt_id":claim.attempt_id,
        "fetch_transcript_sha256":B.encode(fetch),"segment_count":1,
        "observed_ms":observed.to_string()});
    let accepted = apply(&mut c, &submit).await;
    assert_eq!(accepted["disposition"], "submit_once");
    assert!(accepted["current"].is_object());
    assert!(accepted["interval_permission"].is_object());
    assert_eq!(
        liabilities(&c, packet.message).await,
        ("submitting".into(), "submitting".into(), 1, 1, 0)
    );

    let duplicate = apply(&mut c, &submit).await;
    assert_eq!(duplicate["disposition"], "history_only");
    assert!(duplicate["current"].is_null());
    assert!(duplicate["interval_permission"].is_null());
    assert_eq!(duplicate["accepted_ms"], accepted["accepted_ms"]);
    assert_eq!(
        liabilities(&c, packet.message).await,
        ("submitting".into(), "submitting".into(), 1, 1, 0)
    );

    // The final closure's fresh diagnostic comes from the distinct actual
    // passive primary clock. No wall clock, old status timestamp or effect
    // projection supplies it. This test makes no phone Room-barrier claim.
    c.heartbeat().await;
    let state = c.socket_state();
    let clock = history_clock::Request03::parse(
        &json!({"v":1,
        "type":"payload_profile_history_clock03_request",
        "connection_epoch":socket.session().connection_epoch,
        "request_id":Uuid::new_v4(),"message_id":packet.message,
        "attempt_id":claim.attempt_id})
        .to_string(),
    )
    .unwrap()
    .unwrap();
    let admitted = effects::admit(
        &mut c.db.reader,
        socket,
        &state,
        wire::OrdinaryAdmission03::Read,
    )
    .await
    .unwrap();
    let clock = effects::history_clock(&mut c.db.reader, admitted, &state, clock)
        .await
        .unwrap();
    let closed = clock["server_time_ms"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(closed >= observed as u64);
    let closure = Uuid::new_v4();
    let proof_request = Uuid::new_v4();
    let submit_hash: [u8; 32] = B
        .decode(accepted["submit_command_sha256"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut record = Vec::with_capacity(210);
    for id in [
        account,
        socket.session().device_id,
        event,
        packet.message,
        claim.attempt_id,
        closure,
    ] {
        record.extend(id.as_bytes());
    }
    record.extend(fetch);
    record.extend(submit_hash);
    record.extend(session);
    record.push(1);
    record.extend((observed as u64).to_be_bytes());
    record.push(1); // Genuine prior committed submit, ACK-authorized report.
    record.extend(closed.to_be_bytes());
    let record = NoSubmitRecord03::decode(&record).unwrap();
    let challenge_request = json!({"v":1,"type":"payload_profile_no_submit_challenge03_request",
        "connection_epoch":socket.session().connection_epoch,"proof_request_id":proof_request,
        "closure_id":closure,"event_id":event,"message_id":packet.message,
        "attempt_id":claim.attempt_id,"submit_command_sha256":B.encode(submit_hash),
        "fetch_transcript_sha256":B.encode(fetch),"segment_count":1,
        "submit_observed_ms":observed.to_string(),"closed_from":"ack_authorized",
        "closed_ms":closed.to_string(),"closure_record_sha256":B.encode(record.digest().unwrap()),
        "previous_challenge_id":null});
    let challenge = apply(&mut c, &challenge_request).await;
    assert_eq!(
        liabilities(&c, packet.message).await,
        ("unknown".into(), "unknown".into(), 1, 1, 0)
    );
    let core = B.decode(challenge["core"].as_str().unwrap()).unwrap();
    let signature: Signature = c
        .phone_key
        .sign(&crypto::framed(b"ZTSE/conversation/no-submit-proof03/v1\0", &core).unwrap());
    let proof = json!({"v":1,"type":"payload_profile_no_submit_proof03",
        "connection_epoch":socket.session().connection_epoch,"proof_request_id":proof_request,
        "closure_id":closure,"challenge_id":challenge["challenge_id"],
        "core":B.encode(core),"signature":B.encode(signature.normalize_s().unwrap_or(signature).to_bytes())});
    let closed = apply(&mut c, &proof).await;
    assert_eq!(closed["disposition"], "closed_no_rearm");
    assert_eq!(
        liabilities(&c, packet.message).await,
        ("failed".into(), "failed".into(), 1, 1, 0)
    );
    let retry = apply(&mut c, &proof).await;
    assert_eq!(retry["accepted_ms"], closed["accepted_ms"]);
    let retry = apply(&mut c, &submit).await;
    assert_eq!(retry["disposition"], "history_only");
    assert!(retry["current"].is_null());
    assert!(retry["interval_permission"].is_null());
    assert_eq!(
        liabilities(&c, packet.message).await,
        ("failed".into(), "failed".into(), 1, 1, 0)
    );
    c.db.finish().await;
}
