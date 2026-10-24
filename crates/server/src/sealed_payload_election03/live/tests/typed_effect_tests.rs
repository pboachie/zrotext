// SPDX-License-Identifier: AGPL-3.0-only
//! Real ordinary-role native adapter checks with genuine signed socket claim.
//! Synthetic ciphertext is opaque; no platform entry or radio result is claimed.
use super::*;
use crate::conversation_effect03::{history_clock, wire::OrdinaryAdmission03};
use crate::conversation_grant03::{self as grants, effects};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};

async fn retained(c: &Case, message: Uuid) -> String {
    c.db.reader.query_one(
        "SELECT pg_catalog.json_build_array(g.expires_at_ms,m.state,f.outcome,(SELECT count(*) FROM public.message_attempts a WHERE(a.account_id,a.message_id)=(g.account_id,g.message_id)),(SELECT count(*) FROM public.usage_ledger u WHERE(u.account_id,u.message_id)=(g.account_id,g.message_id) AND u.entry_kind='reserve'),(SELECT count(*) FROM public.usage_ledger u WHERE(u.account_id,u.message_id)=(g.account_id,g.message_id) AND u.entry_kind='refund'),anchor.xmin::text)::text FROM public.conversation_profile03_grants g JOIN public.messages m ON(m.account_id,m.id)=(g.account_id,g.message_id) JOIN public.dispatch_fences f ON(f.account_id,f.attempt_id)=(g.account_id,g.attempt_id) JOIN public.payload_profile_account_anchors anchor ON anchor.account_id=g.account_id WHERE g.account_id=$1 AND g.message_id=$2",
        &[&c.principal.tenant.account_id(),&message],
    ).await.unwrap().get(0)
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual typed original actor and passive clock"]
async fn original_actor_clock_survives_owner_withdrawal_without_content_or_effect_mutation() {
    let (mut c, browser, statement) = super::reviewed_send_tests::active_claimed().await;
    let account = c.principal.tenant.account_id();
    c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
    let packet = super::grant_tests::queue(&mut c, &browser, &statement).await;
    let ready = super::grant_tests::ready(&mut c).await;
    let socket = c.socket_actor();
    let state = c.socket_state();
    let device = super::interval_queue_tests::lease(&c);
    let grant = grants::issue_next(&mut c.db.reader, socket, device, &ready)
        .await
        .unwrap()
        .unwrap();
    let claim = grant.frame().claims();
    assert!(
        crate::auth::revoke_session(&c.db.reader, &c.principal, c.principal.session_id)
            .await
            .unwrap()
    );
    let before = retained(&c, packet.message).await;
    let nonce = Uuid::new_v4();
    let raw = serde_json::json!({"v":1,"type":"payload_profile_history_clock03_request","connection_epoch":socket.session().connection_epoch,"request_id":nonce,"message_id":claim.message_id,"attempt_id":claim.attempt_id});
    let request = history_clock::Request03::parse(&raw.to_string())
        .unwrap()
        .unwrap();
    let admitted = effects::admit(&mut c.db.reader, socket, &state, OrdinaryAdmission03::Read)
        .await
        .unwrap();
    let reply = effects::history_clock(&mut c.db.reader, admitted, &state, request)
        .await
        .unwrap();
    assert_eq!(reply.as_object().unwrap().len(), 11);
    assert_eq!(reply["lease"].as_object().unwrap().len(), 7);
    assert_eq!(reply["request_id"], nonce.to_string());
    assert_eq!(reply["attempt_id"], claim.attempt_id.to_string());
    assert_eq!(
        reply["lease"]["enrolled_signing_key_id"],
        B.encode(socket.proof().signing_key_id())
    );
    assert_eq!(reply["lease"]["line_activation_version"], 2);
    let now = reply["server_time_ms"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let end = reply["sample_expires_ms"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let lease = reply["lease"]["expires_ms"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(now < end && end <= now + 30_000 && end <= lease);
    for key in [
        "current",
        "interval_permission",
        "submit_once",
        "disposition",
    ] {
        assert!(reply.get(key).is_none());
    }
    assert_eq!(retained(&c, packet.message).await, before);
    let counts=c.db.reader.query_one("SELECT(SELECT count(*) FROM public.conversation_profile03_submits WHERE account_id=$1),(SELECT count(*) FROM public.conversation_profile03_outcomes WHERE account_id=$1)",&[&account]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 0);

    // A retained actor does not permit changing the correlated original message.
    let mut wrong = raw;
    wrong["message_id"] = serde_json::json!(Uuid::new_v4());
    let request = history_clock::Request03::parse(&wrong.to_string())
        .unwrap()
        .unwrap();
    let admitted = effects::admit(&mut c.db.reader, socket, &state, OrdinaryAdmission03::Read)
        .await
        .unwrap();
    assert!(matches!(
        effects::history_clock(&mut c.db.reader, admitted, &state, request).await,
        Err(Error::Conflict)
    ));
    assert_eq!(retained(&c, packet.message).await, before);
    c.db.finish().await;
}
