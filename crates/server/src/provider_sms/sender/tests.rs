// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::provider_sms::Content;
use crate::provider_sms::dispatch::{self, tests::Fixture};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Scripted transport: exists only in test builds, counts calls and never
/// touches a network. Production wiring cannot construct this.
struct FakeTransport {
    outcomes: Mutex<Vec<TransportOutcome>>,
    calls: AtomicUsize,
}
impl FakeTransport {
    fn new(outcomes: Vec<TransportOutcome>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes),
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl SubmitTransport for FakeTransport {
    async fn submit(&self, _key: &ApiKey, _body: &[u8]) -> TransportOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcomes
            .lock()
            .unwrap()
            .pop()
            .unwrap_or(TransportOutcome::Lost)
    }
}

fn key() -> ApiKey {
    ApiKey::new("sk-test-0123456789abcdef0123456789abcdef").unwrap()
}

fn material<'a>(request: &'a Request, recipient: &'a str, body: &'a str) -> Material<'a> {
    Material {
        request,
        recipient,
        content: Content::ProviderPlaintext(body),
    }
}

#[test]
fn classify_maps_provider_answers_to_the_three_outcomes() {
    let id = Uuid::new_v4();
    let accepted = format!("{{\"data\":{{\"id\":\"{id}\"}}}}");
    assert_eq!(
        classify(201, accepted.as_bytes()),
        TransportOutcome::Accepted { message_id: id }
    );
    assert_eq!(
        classify(200, b"{\"data\":{\"id\":\"not-a-uuid\"}}"),
        TransportOutcome::Lost
    );
    assert_eq!(classify(200, b"not json"), TransportOutcome::Lost);
    assert_eq!(
        classify(422, b"{\"errors\":[{\"code\":\"100\"}]}"),
        TransportOutcome::Refused { status: 422 }
    );
    assert_eq!(classify(503, b"upstream"), TransportOutcome::Lost);
    assert_eq!(classify(200, &vec![b'x'; 65_537]), TransportOutcome::Lost);
}

#[test]
fn api_keys_are_bounded_graphic_ascii_and_configs_default_off() {
    assert!(ApiKey::new("short").is_err());
    assert!(ApiKey::new(&"x".repeat(257)).is_err());
    assert!(ApiKey::new("has space padding-0123456789abcdef").is_err());
    // The default configuration carries no credential, so the only path to
    // the network boundary (an ApiKey) does not exist until enable() is
    // called with a valid key.
    assert!(matches!(
        SenderConfig::default().authorize(),
        Err(SenderError::Disabled)
    ));
    assert!(SenderConfig::default().enable(key()).authorize().is_ok());
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn sender_tick_accepts_binds_and_never_resends() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    dispatch::commit_submit_intent(
        &mut f.db().await,
        &f.permit(),
        &f.action,
        f.reservation,
        attempt,
        &f.request,
        "+15551234567",
    )
    .await
    .unwrap();
    let message_id = Uuid::new_v4();
    let transport = FakeTransport::new(vec![TransportOutcome::Accepted { message_id }]);
    let m = material(&f.request, "+15551234567", "synthetic dispatch fixture");
    let tick = send_one(
        &mut f.db().await,
        &f.permit(),
        &key(),
        &transport,
        f.action.account_id,
        &m,
    )
    .await
    .unwrap();
    assert_eq!(
        tick,
        Tick::Accepted {
            attempt,
            message_id
        }
    );
    assert_eq!(transport.calls(), 1);
    assert_eq!(f.state(attempt).await, "accepted");
    // Nothing is claimable after a terminal outcome.
    let again = send_one(
        &mut f.db().await,
        &f.permit(),
        &key(),
        &transport,
        f.action.account_id,
        &m,
    )
    .await
    .unwrap();
    assert_eq!(again, Tick::Idle);
    assert_eq!(transport.calls(), 1);
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn lost_response_records_conservative_unknown_liability() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    dispatch::commit_submit_intent(
        &mut f.db().await,
        &f.permit(),
        &f.action,
        f.reservation,
        attempt,
        &f.request,
        "+15551234567",
    )
    .await
    .unwrap();
    let transport = FakeTransport::new(vec![TransportOutcome::Lost]);
    let m = material(&f.request, "+15551234567", "synthetic dispatch fixture");
    let tick = send_one(
        &mut f.db().await,
        &f.permit(),
        &key(),
        &transport,
        f.action.account_id,
        &m,
    )
    .await
    .unwrap();
    assert_eq!(tick, Tick::Lost { attempt });
    assert_eq!(f.state(attempt).await, "unknown");
    assert_eq!(
        send_one(
            &mut f.db().await,
            &f.permit(),
            &key(),
            &transport,
            f.action.account_id,
            &m,
        )
        .await
        .unwrap(),
        Tick::Idle
    );
    assert_eq!(transport.calls(), 1);
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn provider_refusal_and_suppression_release_without_transmission() {
    let f = Fixture::new().await;
    // A definitive 4xx refusal releases without transmission.
    let refused_attempt = Uuid::new_v4();
    dispatch::commit_submit_intent(
        &mut f.db().await,
        &f.permit(),
        &f.action,
        f.reservation,
        refused_attempt,
        &f.request,
        "+15551234567",
    )
    .await
    .unwrap();
    let transport = FakeTransport::new(vec![TransportOutcome::Refused { status: 422 }]);
    let m = material(&f.request, "+15551234567", "synthetic dispatch fixture");
    assert_eq!(
        send_one(
            &mut f.db().await,
            &f.permit(),
            &key(),
            &transport,
            f.action.account_id,
            &m,
        )
        .await
        .unwrap(),
        Tick::Refused {
            attempt: refused_attempt,
            status: 422,
        }
    );
    assert_eq!(f.state(refused_attempt).await, "released");
    assert_eq!(transport.calls(), 1);
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn stop_before_dispatch_releases_at_preflight_without_a_call() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    dispatch::commit_submit_intent(
        &mut f.db().await,
        &f.permit(),
        &f.action,
        f.reservation,
        attempt,
        &f.request,
        "+15551234567",
    )
    .await
    .unwrap();
    // The STOP lands after the intent but before the worker claims it.
    f.stop().await;
    let transport = FakeTransport::new(vec![TransportOutcome::Accepted {
        message_id: Uuid::new_v4(),
    }]);
    let m = material(&f.request, "+15551234567", "synthetic dispatch fixture");
    let tick = send_one(
        &mut f.db().await,
        &f.permit(),
        &key(),
        &transport,
        f.action.account_id,
        &m,
    )
    .await
    .unwrap();
    assert_eq!(tick, Tick::Released { attempt });
    assert_eq!(f.state(attempt).await, "released");
    assert_eq!(transport.calls(), 0, "pre-flight refusal must not transmit");
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn wrong_material_fails_the_commitment_check_before_transmission() {
    let f = Fixture::new().await;
    let attempt = Uuid::new_v4();
    dispatch::commit_submit_intent(
        &mut f.db().await,
        &f.permit(),
        &f.action,
        f.reservation,
        attempt,
        &f.request,
        "+15551234567",
    )
    .await
    .unwrap();
    let transport = FakeTransport::new(vec![TransportOutcome::Accepted {
        message_id: Uuid::new_v4(),
    }]);
    // Neither the recipient nor the body matches the committed request.
    let m = material(&f.request, "+15557654321", "different synthetic commitment");
    let error = send_one(
        &mut f.db().await,
        &f.permit(),
        &key(),
        &transport,
        f.action.account_id,
        &m,
    )
    .await
    .unwrap_err();
    assert_eq!(error, SenderError::Material);
    assert_eq!(transport.calls(), 0);
    f.case.cleanup().await;
}
