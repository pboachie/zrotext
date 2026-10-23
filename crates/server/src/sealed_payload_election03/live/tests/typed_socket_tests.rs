// SPDX-License-Identifier: AGPL-3.0-only
//! Actual manual ordinary-runtime socket, never a phone or platform invocation.
use super::*;
use crate::conversation_effect03::wire;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use futures_util::FutureExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin};

type TestIo<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
type ActiveSocket = (
    Case,
    SigningKey,
    crate::conversation_interval03::Statement03,
);

fn active_socket() -> TestIo<'static, ActiveSocket> {
    Box::pin(async {
        let original = Box::pin(fixture::prepared_socket_genesis()).await;
        let elected = Box::pin(super::manifest_tests::elected_case(original)).await;
        let prepared = Box::pin(super::interval_queue_tests::prepared_case(elected.0)).await;
        Box::pin(super::reviewed_send_tests::active_case(prepared)).await
    })
}

struct Saved {
    request: Value,
    original: Vec<u8>,
    session: [u8; 32],
    accepted: String,
    message: Uuid,
    point: Vec<u8>,
    key_id: Vec<u8>,
}

fn first<'a>(
    c: &'a mut Case,
    browser: &'a SigningKey,
    statement: &'a crate::conversation_interval03::Statement03,
) -> TestIo<'a, Saved> {
    Box::pin(async move {
        c.loopback().sample_profile().await;
        let account = c.principal.tenant.account_id();
        c.db.owner.execute("INSERT INTO public.usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',10,'operator')",&[&account]).await.unwrap();
        // Build readiness before the short signed message window begins.
        let ready = super::grant_tests::ready(c).await;
        let packet = super::grant_tests::queue(c, browser, statement).await;
        let grant = c.loopback().grant(&ready).await;
        let claim = grant.claims();
        assert_eq!(claim.message_id, packet.message);
        assert_eq!(claim.connection_epoch, c.loopback().epoch().await);
        let fetched = c.loopback().fetch(&grant, &c.phone_key).await;
        assert_eq!(
            B.decode(fetched["reviewed_intent"].as_str().unwrap())
                .unwrap(),
            packet.intent
        );
        assert_eq!(
            B.decode(fetched["envelope"].as_str().unwrap()).unwrap(),
            packet.envelope
        );
        let session: [u8; 32] = B
            .decode(
                fetched["current"]["device_session_digest"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let actor = c.db.reader.query_one("SELECT original_enrolled_point,original_enrolled_key_id,original_device_session_digest FROM public.conversation_profile03_effect_actors WHERE account_id=$1 AND attempt_id=$2",&[&account,&claim.attempt_id]).await.unwrap();
        let point: Vec<u8> = actor.get(0);
        let key_id: Vec<u8> = actor.get(1);
        assert_eq!(
            point,
            c.phone_key.verifying_key().to_sec1_point(false).as_bytes()
        );
        let mut hash = Sha256::new();
        hash.update(b"ZTSE/key/v1\0");
        hash.update([1, 1]);
        hash.update(&point);
        assert_eq!(key_id, hash.finalize().to_vec());
        assert_eq!(actor.get::<_, Vec<u8>>(2), session);
        let event = Uuid::new_v4();
        let request = json!({"v":1,"type":"payload_profile_submit03",
            "connection_epoch":c.loopback().epoch().await,"event_id":event,
            "message_id":packet.message,"attempt_id":claim.attempt_id,
            "fetch_transcript_sha256":B.encode(crypto::sha(&grant.fetch_transcript())),
            "segment_count":1,"observed_ms":fetched["current"]["compared_ms"]});
        let wire::Request03::Submit(local) = wire::Request03::parse(&request.to_string())
            .unwrap()
            .unwrap()
        else {
            panic!("original submit")
        };
        let command = local
            .candidate_command(account, c.device, &session)
            .unwrap();
        let original = command.bytes().to_vec();
        let expected = B.encode(command.digest().unwrap());
        // The original command is retained before this first socket I/O.
        let ack = c
            .loopback()
            .exchange(&request, "payload_profile_submit_ack03")
            .await;
        assert_eq!(ack.as_object().unwrap().len(), 15);
        assert_eq!(ack["disposition"], "submit_once");
        assert_eq!(ack["submit_command_sha256"], expected);
        assert_eq!(ack["current"].as_object().unwrap().len(), 40);
        assert_eq!(ack["current"]["kind"], "submit_manifest_permission03");
        assert_eq!(ack["current"]["request_kind"], "submit");
        assert_eq!(ack["current"]["request_id"], event.to_string());
        assert_eq!(
            ack["current"]["compared_ms"],
            ack["interval_permission"]["compared_ms"]
        );
        let accepted = ack["accepted_ms"].as_str().unwrap().to_owned();
        let compared = ack["current"]["compared_ms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(accepted.parse::<u64>().unwrap() <= compared);
        for name in ["current", "interval_permission"] {
            assert_eq!(
                ack[name]["permission_expires_ms"],
                claim.expires_at_ms.to_string()
            );
        }
        let retained: Vec<u8> = c.db.reader.query_one("SELECT command FROM public.conversation_profile03_submits WHERE account_id=$1 AND attempt_id=$2",&[&account,&claim.attempt_id]).await.unwrap().get(0);
        assert_eq!(retained, original);
        assert_eq!(
            super::typed_submit_tests::liabilities(c, packet.message).await,
            ("submitting".into(), "submitting".into(), 1, 1, 0)
        );
        Saved {
            request,
            original,
            session,
            accepted,
            message: packet.message,
            point,
            key_id,
        }
    })
}

fn retry<'a>(c: &'a Case, saved: &'a Saved, request: Value) -> TestIo<'a, ()> {
    Box::pin(async move {
        let wire::Request03::Submit(candidate) = wire::Request03::parse(&request.to_string())
            .unwrap()
            .unwrap()
        else {
            panic!("original history request")
        };
        let command = candidate
            .candidate_command(c.principal.tenant.account_id(), c.device, &saved.session)
            .unwrap();
        assert_eq!(command.bytes().as_slice(), saved.original);
        let before = super::typed_submit_tests::retained(c).await;
        let ack = c
            .loopback()
            .exchange(&request, "payload_profile_submit_ack03")
            .await;
        assert_eq!(ack["connection_epoch"], c.loopback().epoch().await);
        assert_eq!(ack["disposition"], "history_only");
        assert_eq!(ack["accepted_ms"], saved.accepted);
        assert_eq!(
            ack["submit_command_sha256"],
            B.encode(command.digest().unwrap())
        );
        assert!(ack["current"].is_null());
        assert!(ack["interval_permission"].is_null());
        assert_eq!(super::typed_submit_tests::retained(c).await, before);
        assert_eq!(
            super::typed_submit_tests::liabilities(c, saved.message).await,
            ("submitting".into(), "submitting".into(), 1, 1, 0)
        );
    })
}

fn exercise(reconnect: bool) -> TestIo<'static, ()> {
    Box::pin(async move {
        let (mut c, browser, statement) = active_socket().await;
        let outcome = AssertUnwindSafe(async {
            let saved = first(&mut c,&browser,&statement).await;
            let mut request = saved.request.clone();
            if reconnect {
                let before = c.loopback().epoch().await;
                c.loopback().reconnect_ordinary(&c.phone_key).await;
                assert!(c.loopback().epoch().await > before);
                c.loopback().assert_claim(&c.db.reader,&c.phone_key).await;
                let actor = c.db.reader.query_one("SELECT original_enrolled_point,original_enrolled_key_id FROM public.conversation_profile03_effect_actors WHERE account_id=$1 AND message_id=$2",&[&c.principal.tenant.account_id(),&saved.message]).await.unwrap();
                assert_eq!(actor.get::<_,Vec<u8>>(0),saved.point);
                assert_eq!(actor.get::<_,Vec<u8>>(1),saved.key_id);
                request["connection_epoch"] = c.loopback().epoch().await.into();
                // No profile sample, Ready, new grant or current projection on
                // this ordinary connection: only the original153 history.
            }
            retry(&c,&saved,request).await;
        }).catch_unwind().await;
        c.close_loopback().await;
        c.db.finish().await;
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
    })
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; real manual-runtime socket submit and passive retry"]
async fn actual_socket_first_submit_and_exact_retry_keep_one_attempt_and_reserve() {
    exercise(false).await;
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL administrator; actual later ordinary socket claim retains original typed history"]
async fn actual_ordinary_reconnect_retries_original_submit_without_current_permission() {
    exercise(true).await;
}
