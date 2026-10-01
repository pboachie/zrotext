// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
mod resource_pagination;
use crate::sealed_envelope::ExpectedRecipient;

// Ordinary-CI layer of the issue #632 downgrade/leakage acceptance harness:
// the stateless boundary, which needs no PostgreSQL and runs in every build.
mod boundary_guard;
use crate::sealed_manifest_store::tests::Fixture;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

#[test]
fn sealed_segment_declaration_rejects_ambiguous_or_unbounded_headers() {
    let mut headers = HeaderMap::new();
    assert_eq!(segment_limit(&headers).unwrap(), None);
    for value in ["1", "6"] {
        headers.insert("x-zrotext-sealed-segment-limit", value.parse().unwrap());
        assert!(segment_limit(&headers).unwrap().is_some());
    }
    for value in ["0", "7", "01", "1 ", "-1", "1,2"] {
        headers.insert("x-zrotext-sealed-segment-limit", value.parse().unwrap());
        assert!(segment_limit(&headers).is_err());
    }
    headers.insert("x-zrotext-sealed-segment-limit", "1".parse().unwrap());
    headers.append("x-zrotext-sealed-segment-limit", "1".parse().unwrap());
    assert!(segment_limit(&headers).is_err());
}

/// A database URL that is never contacted: every stateless refusal test fails
/// before the extractor takes a pooled connection.
const UNREACHABLE_DATABASE_URL: &str = "postgresql://sealed-route-refusal.invalid/db";

fn hasher() -> Arc<TokenHasher> {
    Arc::new(TokenHasher::new(crate::test_keys::key(76)).unwrap())
}

fn enabled_state() -> SealedHttpState {
    SealedHttpState::new(
        UNREACHABLE_DATABASE_URL.into(),
        hasher(),
        "refusal-test".into(),
        1,
        true,
    )
    .unwrap()
}

fn sealed_request(
    token: Option<&str>,
    content_type: Option<&str>,
    duplicate_content_type: bool,
    idempotency_key: Option<&str>,
    duplicate_authorization: bool,
    body: Vec<u8>,
) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri("/messages");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if duplicate_authorization {
        builder = builder.header(header::AUTHORIZATION, "Bearer ztk_duplicate");
    }
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if duplicate_content_type {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(key) = idempotency_key {
        builder = builder.header(IDEMPOTENCY_HEADER, key);
    }
    builder.body(Body::from(body)).unwrap()
}

async fn code(response: axum::response::Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    #[derive(serde::Deserialize)]
    struct Body {
        code: String,
    }
    (status, serde_json::from_slice::<Body>(&bytes).unwrap().code)
}

#[tokio::test]
async fn disabled_state_answers_not_found_before_any_other_check() {
    let app = router(SealedHttpState::disabled(
        UNREACHABLE_DATABASE_URL.into(),
        hasher(),
    ));
    let response = app
        .clone()
        .oneshot(sealed_request(
            Some("ztk_example"),
            Some(SEALED_CONTENT_TYPE),
            false,
            None,
            false,
            vec![7; 500],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(code(response).await.1, "not_found");
}

#[tokio::test]
async fn missing_content_type_is_refused_before_authentication() {
    let app = router(enabled_state());
    let response = app
        .clone()
        .oneshot(sealed_request(
            Some("ztk_example"),
            None,
            false,
            None,
            false,
            vec![7; 500],
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type".into()
        )
    );
}

#[tokio::test]
async fn json_content_type_is_refused_before_authentication() {
    let app = router(enabled_state());
    let response = app
        .clone()
        .oneshot(sealed_request(
            Some("ztk_example"),
            Some("application/json"),
            false,
            None,
            false,
            vec![7; 500],
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type".into()
        )
    );
}

#[tokio::test]
async fn parameterized_sealed_content_type_is_refused() {
    let app = router(enabled_state());
    let response = app
        .clone()
        .oneshot(sealed_request(
            Some("ztk_example"),
            Some("application/vnd.zrotext.sealed.v1; charset=binary"),
            false,
            None,
            false,
            vec![7; 500],
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type".into()
        )
    );
}

#[tokio::test]
async fn duplicate_content_type_headers_are_refused() {
    let app = router(enabled_state());
    let response = app
        .clone()
        .oneshot(sealed_request(
            Some("ztk_example"),
            Some(SEALED_CONTENT_TYPE),
            true,
            None,
            false,
            vec![7; 500],
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type".into()
        )
    );
}

#[tokio::test]
async fn caller_idempotency_key_is_refused() {
    let app = router(enabled_state());
    let response = app
        .clone()
        .oneshot(sealed_request(
            Some("ztk_example"),
            Some(SEALED_CONTENT_TYPE),
            false,
            Some("caller-key-1"),
            false,
            vec![7; 500],
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
}

#[tokio::test]
async fn duplicate_authorization_headers_are_refused() {
    let app = router(enabled_state());
    let response = app
        .clone()
        .oneshot(sealed_request(
            Some("ztk_example"),
            Some(SEALED_CONTENT_TYPE),
            false,
            None,
            true,
            vec![7; 500],
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::UNAUTHORIZED, "unauthorized".into())
    );
}

#[tokio::test]
async fn non_bearer_authorization_is_refused() {
    let app = router(enabled_state());
    let mut request = sealed_request(
        None,
        Some(SEALED_CONTENT_TYPE),
        false,
        None,
        false,
        vec![7; 500],
    );
    request.headers_mut().insert(
        header::AUTHORIZATION,
        axum::http::HeaderValue::from_str("Token ztk_example").unwrap(),
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::UNAUTHORIZED, "unauthorized".into())
    );
}

/// One complete signed outbound envelope fixture over the shared manifest
/// authority fixture: the same SQL-composition shape the admission corpus
/// uses; not a decryption claim.
struct RouteCase {
    fixture: Fixture,
    token: String,
    user: Uuid,
    url: String,
}

impl RouteCase {
    async fn new() -> Self {
        let mut f = Fixture::new().await;
        let now = route_now(&f.db).await;
        f.bytes.truncate(150);
        f.bytes[37..45].copy_from_slice(&((now - 1000) as u64).to_be_bytes());
        f.bytes[45..53].copy_from_slice(&((now + 120_000) as u64).to_be_bytes());
        f.bytes.push(4);
        f.readers.clear();
        for (role, scope) in [(1, 4u16), (2, 12), (5, 1), (6, 0)] {
            let key = SigningKey::generate_from_rng(&mut rand::rng());
            let point = if role == 6 {
                f.root.verifying_key().to_sec1_point(false)
            } else {
                key.verifying_key().to_sec1_point(false)
            };
            let algorithm = if role <= 2 { [0u8, 16] } else { [1, 1] };
            let id: [u8; 32] = Sha256::digest(
                [b"ZTSE/key/v1\0".as_slice(), &algorithm, point.as_bytes()].concat(),
            )
            .into();
            f.bytes.push(role);
            f.bytes.extend(id);
            f.bytes.extend(point.as_bytes());
            f.bytes.extend(if role == 1 {
                *f.device.as_bytes()
            } else {
                [0; 16]
            });
            f.bytes.extend(if role == 1 || role == 5 {
                *f.line.as_bytes()
            } else {
                [0; 16]
            });
            f.bytes.extend(scope.to_be_bytes());
            f.bytes.extend(((now - 1000) as u64).to_be_bytes());
            f.bytes.extend(((now + 240_000) as u64).to_be_bytes());
            f.bytes.push(1);
            if role <= 2 {
                f.readers.push(ExpectedRecipient { role, key_id: id });
            }
            if role == 5 {
                f.signer = id;
                f.event_signer = key;
            }
        }
        f.bytes.extend([0; 64]);
        f.resign();
        let digest = Sha256::digest(&f.bytes[..f.bytes.len() - 64]);
        f.db.execute("UPDATE sealed_manifest_authorities SET version=1,semantic_digest=$2,manifest=$3,accepted_at_ms=$4,last_verified_ms=$4 WHERE account_id=$1",
            &[&f.account,&digest.as_slice(),&f.bytes,&now]).await.unwrap();
        let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let user = insert_owner(&mut f).await;
        insert_api_key(&mut f, &token, "messages:send", user).await;
        f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1000)",&[&f.account]).await.unwrap();
        let url = format!("{}?options=-csearch_path%3D{}", f.url, f.schema);
        Self {
            fixture: f,
            token,
            user,
            url,
        }
    }

    fn state(&self) -> SealedHttpState {
        SealedHttpState::new(self.url.clone(), hasher(), "manifest-test".into(), 1, true).unwrap()
    }

    fn submit(&self, token: &str, bytes: Vec<u8>) -> Request<Body> {
        sealed_request(
            Some(token),
            Some(SEALED_CONTENT_TYPE),
            false,
            None,
            false,
            bytes,
        )
    }

    async fn envelope(&self, id: Uuid, observed: i64, lifetime: i64) -> Vec<u8> {
        let f = &self.fixture;
        let mut b = b"ZTSE\x02\x01\0\0".to_vec();
        b.extend(157u16.to_be_bytes());
        b.extend(f.account.as_bytes());
        b.extend(id.as_bytes());
        b.extend(f.device.as_bytes());
        b.extend(f.line.as_bytes());
        b.extend(1u64.to_be_bytes());
        b.extend(Sha256::digest(&f.bytes[..f.bytes.len() - 64]));
        b.extend(f.signer);
        b.extend((observed as u64).to_be_bytes());
        b.extend(((observed + lifetime) as u64).to_be_bytes());
        b.extend([1, 3]);
        b.extend(b"+12");
        b.extend([4; 12]);
        b.extend(17u32.to_be_bytes());
        b.extend([7; 17]);
        b.push(2);
        for r in &f.readers {
            b.push(r.role);
            b.extend(r.key_id);
            b.extend(f.root.verifying_key().to_sec1_point(false).as_bytes());
            b.extend([9; 48]);
        }
        b.extend([0; 64]);
        let end = b.len() - 64;
        let signature: Signature = f.event_signer.sign(
            &[
                b"ZTSE/sign/v2\x00".as_slice(),
                &(end as u32).to_be_bytes(),
                &b[..end],
            ]
            .concat(),
        );
        b[end..].copy_from_slice(&signature.normalize_s().to_bytes());
        b
    }
}

/// One owner per account: additional API keys reuse the owner's membership.
async fn insert_owner(f: &mut Fixture) -> Uuid {
    let user = Uuid::new_v4();
    f.db.execute(
        "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,'unused',now())",
        &[&user, &format!("{}@example.invalid", user.simple())],
    )
    .await
    .unwrap();
    f.db.execute(
        "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
        &[&f.account, &user],
    )
    .await
    .unwrap();
    user
}

async fn insert_api_key(f: &mut Fixture, token: &str, scope: &str, user: Uuid) -> Uuid {
    let key = Uuid::new_v4();
    let pepper = crate::test_keys::key(76);
    let mut mac = Hmac::<Sha256>::new_from_slice(&pepper).unwrap();
    mac.update(b"api-key-v1\0");
    mac.update(token.as_bytes());
    let token_hash = mac.finalize().into_bytes().to_vec();
    f.db.execute("INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id) VALUES($1,$2,$3,$4,$5,ARRAY[$6],$7)",
        &[&key,&f.account,&user,&&token[4..16],&token_hash,&scope,&f.device]).await.unwrap();
    key
}

async fn route_now(db: &tokio_postgres::Client) -> i64 {
    db.query_one(
        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn sealed_submission_is_accepted_then_replayed_as_created_false() {
    let case = RouteCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let envelope = case.envelope(Uuid::new_v4(), now, 60_000).await;
    let first = app
        .clone()
        .oneshot(case.submit(&case.token, envelope.clone()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let bytes = to_bytes(first.into_body(), usize::MAX).await.unwrap();
    #[derive(serde::Deserialize)]
    struct Accepted {
        message_id: Uuid,
        created: bool,
    }
    let accepted: Accepted = serde_json::from_slice(&bytes).unwrap();
    assert!(accepted.created);
    let second = app
        .oneshot(case.submit(&case.token, envelope))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    let bytes = to_bytes(second.into_body(), usize::MAX).await.unwrap();
    let replay: Accepted = serde_json::from_slice(&bytes).unwrap();
    assert!(!replay.created);
    assert_eq!(replay.message_id, accepted.message_id);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn same_message_identity_under_a_different_digest_conflicts() {
    let case = RouteCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let id = Uuid::new_v4();
    let first = app
        .clone()
        .oneshot(case.submit(&case.token, case.envelope(id, now, 60_000).await))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let second = app
        .oneshot(case.submit(&case.token, case.envelope(id, now + 1000, 60_000).await))
        .await
        .unwrap();
    assert_eq!(
        code(second).await,
        (StatusCode::CONFLICT, "idempotency_conflict".into())
    );
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn tampered_signature_is_invalid_request() {
    let case = RouteCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let mut envelope = case.envelope(Uuid::new_v4(), now, 60_000).await;
    let last = envelope.len() - 1;
    envelope[last] ^= 0xff;
    let response = app
        .clone()
        .oneshot(case.submit(&case.token, envelope))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn undersized_body_is_invalid_request() {
    let case = RouteCase::new().await;
    let app = router(case.state());
    let response = app
        .clone()
        .oneshot(case.submit(&case.token, vec![7; 100]))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn oversized_body_hits_the_request_limit() {
    let case = RouteCase::new().await;
    let app = router(case.state());
    let response = app
        .clone()
        .oneshot(case.submit(&case.token, vec![7; 36_885]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn read_only_scope_cannot_submit_sealed_messages() {
    let mut case = RouteCase::new().await;
    let read_token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    insert_api_key(&mut case.fixture, &read_token, "messages:read", case.user).await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let envelope = case.envelope(Uuid::new_v4(), now, 60_000).await;
    let response = app
        .clone()
        .oneshot(case.submit(&read_token, envelope))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::FORBIDDEN, "forbidden".into())
    );
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn disabled_state_refuses_valid_credentials() {
    let case = RouteCase::new().await;
    let app = router(SealedHttpState::disabled(case.url.clone(), hasher()));
    let now = route_now(&case.fixture.db).await;
    let envelope = case.envelope(Uuid::new_v4(), now, 60_000).await;
    let response = app
        .clone()
        .oneshot(case.submit(&case.token, envelope))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::NOT_FOUND, "not_found".into())
    );
    case.fixture.cleanup().await;
}

// ---------------------------------------------------------------------------
// POST /v1/sealed/inbound-events (#538): the HTTP upload path stores kind-02
// envelopes through the same sealed_inbound_events replay fences as the
// device-socket pilot, with the stored current manifest as authority.
// ---------------------------------------------------------------------------

struct InboundCase {
    fixture: Fixture,
    token: String,
    user: Uuid,
    url: String,
}

impl InboundCase {
    async fn new() -> Self {
        let mut f = Fixture::new().await;
        let now = route_now(&f.db).await;
        // The fixture's manifest already carries the inbound role set (an
        // archive reader and the device-bound event signer); publish it as
        // the current chain so the stored-authority lock accepts it.
        let digest = Sha256::digest(&f.bytes[..f.bytes.len() - 64]);
        f.db.execute("UPDATE sealed_manifest_authorities SET version=1,semantic_digest=$2,manifest=$3,accepted_at_ms=$4,last_verified_ms=$4 WHERE account_id=$1",
            &[&f.account,&digest.as_slice(),&f.bytes,&now]).await.unwrap();
        let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let user = insert_owner(&mut f).await;
        insert_api_key(&mut f, &token, "messages:send", user).await;
        let url = format!("{}?options=-csearch_path%3D{}", f.url, f.schema);
        Self {
            fixture: f,
            token,
            user,
            url,
        }
    }

    fn state(&self) -> SealedHttpState {
        SealedHttpState::new(self.url.clone(), hasher(), "manifest-test".into(), 1, true).unwrap()
    }

    async fn envelope(
        &self,
        event: Uuid,
        sequence: u64,
        observed: i64,
        body_length: usize,
    ) -> Vec<u8> {
        let f = &self.fixture;
        let mut bytes = b"ZTSE\x00\x00".to_vec();
        bytes.extend(172u16.to_be_bytes());
        bytes.extend(f.account.as_bytes());
        bytes.extend(event.as_bytes());
        bytes.extend(f.device.as_bytes());
        bytes.extend(f.line.as_bytes());
        bytes.extend(&f.bytes[29..37]);
        bytes.extend(Sha256::digest(&f.bytes[..f.bytes.len() - 64]));
        bytes.extend(f.signer);
        bytes.extend((observed as u64).to_be_bytes());
        bytes.extend(event.as_bytes());
        bytes.extend(sequence.to_be_bytes());
        bytes.push(3);
        bytes.extend(b"+12");
        bytes.extend([3; 12]);
        bytes.extend((body_length as u32).to_be_bytes());
        bytes.extend(vec![7; body_length]);
        bytes.push(1);
        bytes.push(2);
        bytes.extend(f.readers[0].key_id);
        bytes.extend(f.root.verifying_key().to_sec1_point(false).as_bytes());
        bytes.extend([9; 48]);
        bytes.extend([0; 64]);
        let end = bytes.len() - 64;
        let signature: Signature = f.event_signer.sign(
            &[
                b"ZTSE/sign/v2\x00".as_slice(),
                &(end as u32).to_be_bytes(),
                &bytes[..end],
            ]
            .concat(),
        );
        bytes[end..].copy_from_slice(&signature.normalize_s().to_bytes());
        bytes
    }

    async fn count(&self) -> i64 {
        self.fixture
            .db
            .query_one("SELECT count(*) FROM sealed_inbound_events", &[])
            .await
            .unwrap()
            .get(0)
    }
}

fn inbound_post(token: &str, bytes: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/inbound-events")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, SEALED_CONTENT_TYPE)
        .body(Body::from(bytes))
        .unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn inbound_upload_is_accepted_then_replayed_as_created_false() {
    let case = InboundCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let event = Uuid::new_v4();
    let envelope = case.envelope(event, 1, now - 1_000, 200).await;
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, envelope.clone()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    #[derive(serde::Deserialize)]
    struct Accepted {
        event_id: Uuid,
        created: bool,
    }
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let accepted: Accepted = serde_json::from_slice(&body).unwrap();
    assert_eq!(accepted.event_id, event);
    assert!(accepted.created);
    // Exact replay of the same envelope bytes is a no-op.
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, envelope))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let replayed: Accepted = serde_json::from_slice(&body).unwrap();
    assert_eq!(replayed.event_id, event);
    assert!(!replayed.created);
    assert_eq!(case.count().await, 1);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn inbound_upload_accepts_out_of_order_sequences_inside_the_window() {
    let case = InboundCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let higher = case.envelope(Uuid::new_v4(), 9, now - 1_000, 200).await;
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, higher))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let lower = case.envelope(Uuid::new_v4(), 4, now - 60_000, 200).await;
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, lower))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(case.count().await, 2);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn inbound_upload_rejects_event_forks_and_sequence_reuse() {
    let case = InboundCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let event = Uuid::new_v4();
    let first = case.envelope(event, 2, now - 1_000, 200).await;
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, first))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    // Same event identity, different unsigned bytes.
    let fork = case.envelope(event, 2, now - 1_000, 240).await;
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, fork))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::CONFLICT, "event_id_conflict".into())
    );
    // Different event, reused device sequence.
    let reuse = case.envelope(Uuid::new_v4(), 2, now - 1_000, 200).await;
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, reuse))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::CONFLICT, "sequence_conflict".into())
    );
    assert_eq!(case.count().await, 1);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn inbound_upload_rejects_stale_observed_time_outside_the_window() {
    let case = InboundCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let stale = case
        .envelope(Uuid::new_v4(), 1, now - 8 * 24 * 60 * 60 * 1000, 200)
        .await;
    let response = app.oneshot(inbound_post(&case.token, stale)).await.unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "stale_event".into())
    );
    assert_eq!(case.count().await, 0);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn inbound_upload_rejects_a_tampered_signature_without_storing() {
    let case = InboundCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let mut envelope = case.envelope(Uuid::new_v4(), 1, now - 1_000, 200).await;
    let end = envelope.len() - 64;
    envelope[end] ^= 1;
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, envelope))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
    assert_eq!(case.count().await, 0);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn inbound_upload_requires_the_message_scope_on_the_uploading_device() {
    let mut case = InboundCase::new().await;
    // One owner per account: reuse the case's owner membership for the
    // wrong-scoped key instead of inserting a second owner.
    let wrong = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    insert_api_key(&mut case.fixture, &wrong, "devices:read", case.user).await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    let envelope = case.envelope(Uuid::new_v4(), 1, now - 1_000, 200).await;
    let response = app.oneshot(inbound_post(&wrong, envelope)).await.unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::FORBIDDEN, "forbidden".into())
    );
    assert_eq!(case.count().await, 0);
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn inbound_upload_refuses_an_oversized_envelope_before_any_work() {
    let case = InboundCase::new().await;
    let app = router(case.state());
    let now = route_now(&case.fixture.db).await;
    // Body 33_000 exceeds the kind-02 envelope bound of 34_082 total bytes.
    let oversized = case.envelope(Uuid::new_v4(), 1, now - 1_000, 33_000).await;
    let response = app
        .clone()
        .oneshot(inbound_post(&case.token, oversized))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
    assert_eq!(case.count().await, 0);
    case.fixture.cleanup().await;
}

// ---------------------------------------------------------------------------
// Slice-2 read-only resource groups (#538): devices, webhooks and usage on
// the API-key plane behind the same default-off flag.
// ---------------------------------------------------------------------------

async fn resource_case(scope: &str) -> (InboundCase, String) {
    let case = InboundCase::new().await;
    let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    // Resource groups are account-level reads: an unbound key. A device-bound
    // key stays confined to its device by `require`, including for reads.
    let key = Uuid::new_v4();
    let pepper = crate::test_keys::key(76);
    let mut mac = Hmac::<Sha256>::new_from_slice(&pepper).unwrap();
    mac.update(b"api-key-v1\x00");
    mac.update(token.as_bytes());
    let token_hash = mac.finalize().into_bytes().to_vec();
    case.fixture
        .db
        .execute(
            "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id) VALUES($1,$2,$3,$4,$5,ARRAY[$6],NULL)",
            &[&key, &case.fixture.account, &case.user, &&token[4..16], &token_hash, &scope],
        )
        .await
        .unwrap();
    (case, token)
}

fn get_request(token: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn devices_list_returns_sealed_bindings_and_404s_foreign_ids() {
    let (case, token) = resource_case("devices:read").await;
    let app = router(case.state());
    let response = app
        .clone()
        .oneshot(get_request(&token, "/devices"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    #[derive(serde::Deserialize)]
    struct Line {
        line_id: Uuid,
        binding_generation: i64,
        state: String,
    }
    #[derive(serde::Deserialize)]
    #[expect(
        dead_code,
        reason = "projection contract fields are asserted selectively"
    )]
    struct Device {
        device_id: Uuid,
        display_name: String,
        revoked: bool,
        active_socket_lease: bool,
        lines: Vec<Line>,
    }
    #[derive(serde::Deserialize)]
    struct Page {
        devices: Vec<Device>,
        next_cursor: Option<Uuid>,
    }
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: Page = serde_json::from_slice(&body).unwrap();
    assert_eq!(page.devices.len(), 1);
    let device = &page.devices[0];
    assert_eq!(device.device_id, case.fixture.device);
    assert_eq!(device.display_name, "synthetic");
    assert!(!device.revoked);
    assert_eq!(device.lines.len(), 1);
    assert_eq!(device.lines[0].line_id, case.fixture.line);
    assert_eq!(device.lines[0].binding_generation, 1);
    assert_eq!(device.lines[0].state, "active");
    assert!(page.next_cursor.is_none());
    // The fixture's own device resolves; a foreign id is a bare 404.
    let response = app
        .clone()
        .oneshot(get_request(
            &token,
            &format!("/devices/{}", case.fixture.device),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(get_request(
            &token,
            "/devices/00000000-0000-0000-0000-000000000000",
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::NOT_FOUND, "not_found".into())
    );
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn resource_groups_require_their_scopes() {
    let (case, token) = resource_case("messages:send").await;
    let app = router(case.state());
    for path in ["/devices", "/webhooks", "/usage"] {
        let response = app
            .clone()
            .oneshot(get_request(&token, path))
            .await
            .unwrap();
        assert_eq!(
            code(response).await,
            (StatusCode::FORBIDDEN, "forbidden".into()),
            "{path} must require its read scope"
        );
    }
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn disabled_state_hides_the_resource_groups_before_any_check() {
    let (case, token) = resource_case("devices:read").await;
    let app = router(SealedHttpState::disabled(case.url.clone(), hasher()));
    for path in ["/devices", "/webhooks", "/usage"] {
        let response = app
            .clone()
            .oneshot(get_request(&token, path))
            .await
            .unwrap();
        assert_eq!(
            code(response).await,
            (StatusCode::NOT_FOUND, "not_found".into()),
            "{path} must be absent while disabled"
        );
    }
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn usage_reports_the_current_period_without_currency() {
    let (case, token) = resource_case("billing:read").await;
    let f = &case.fixture;
    f.db.execute(
        "INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units,reserved_units,refunded_units)          VALUES($1,'outbound_message',date_trunc('month',current_date AT TIME ZONE 'UTC')::date,(date_trunc('month',current_date AT TIME ZONE 'UTC')+interval '1 month')::date,100,7,2)",
        &[&f.account],
    ).await.unwrap();
    let app = router(case.state());
    let response = app.oneshot(get_request(&token, "/usage")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    #[derive(serde::Deserialize)]
    #[expect(
        dead_code,
        reason = "projection contract fields are asserted selectively"
    )]
    struct Usage {
        metric: String,
        period_start: String,
        period_end: String,
        limit_units: i64,
        reserved_units: i64,
        refunded_units: i64,
        used_units: i64,
    }
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let usage: Usage = serde_json::from_slice(&body).unwrap();
    assert_eq!(usage.metric, "outbound_message");
    assert_eq!(usage.limit_units, 100);
    assert_eq!(usage.reserved_units, 7);
    assert_eq!(usage.refunded_units, 2);
    assert_eq!(usage.used_units, 5);
    assert!(usage.period_start.ends_with("-01"));
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn usage_without_a_period_row_is_not_found() {
    let (case, token) = resource_case("billing:read").await;
    let app = router(case.state());
    let response = app.oneshot(get_request(&token, "/usage")).await.unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::NOT_FOUND, "not_found".into())
    );
    case.fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn webhooks_list_and_deliveries_never_expose_secrets() {
    let (case, token) = resource_case("webhooks:read").await;
    let f = &case.fixture;
    let endpoint = Uuid::new_v4();
    f.db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version,enabled)          VALUES($1,$2,'https://hooks.example.test/seo',$3,1,true)",
        &[&endpoint, &f.account, &vec![6u8; 32]],
    ).await.unwrap();
    let app = router(case.state());
    let response = app
        .clone()
        .oneshot(get_request(&token, "/webhooks"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(!text.contains("signing_secret"), "no secret fields");
    assert!(text.contains(&endpoint.to_string()));
    // Deliveries for a foreign endpoint are a bare 404.
    let response = app
        .clone()
        .oneshot(get_request(
            &token,
            "/webhooks/00000000-0000-0000-0000-000000000000/deliveries",
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::NOT_FOUND, "not_found".into())
    );
    // Owned endpoint: empty page, valid bound.
    let response = app
        .clone()
        .oneshot(get_request(
            &token,
            &format!("/webhooks/{endpoint}/deliveries?limit=20"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(text.contains("\"deliveries\": []") || text.contains("\"deliveries\":[]"));
    // Out-of-range limit is invalid_request.
    let response = app
        .clone()
        .oneshot(get_request(
            &token,
            &format!("/webhooks/{endpoint}/deliveries?limit=21"),
        ))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
    case.fixture.cleanup().await;
}

#[path = "lifecycle_tests.rs"]
mod lifecycle;
