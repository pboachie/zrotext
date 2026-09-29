// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_envelope::ExpectedRecipient;
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
                b"ZTSE/sign/v2\0".as_slice(),
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
        .oneshot(case.submit(&case.token, envelope))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::NOT_FOUND, "not_found".into())
    );
    case.fixture.cleanup().await;
}
