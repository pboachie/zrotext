// SPDX-License-Identifier: AGPL-3.0-only
// Ordinary-CI layer of the sealed downgrade and leakage acceptance harness
// (issue #632): the stateless admission boundary of the strict sealed route.
// Every request here is refused before the extractor takes a pooled
// connection, so no PostgreSQL, Node or Android dependency exists. The
// integrated PostgreSQL and Android legs live in
// sealed_outbound::tests::sealed_boundary_acceptance behind the
// sealed-interop-tests feature. A synthetic marker planted in each request
// body proves the refusals never echo request bytes back: error bodies carry
// a code and nothing else.
use super::*;
use crate::sealed_marker::Marker;
use tower::ServiceExt;

/// A database URL that is never contacted: every stateless refusal test fails
/// before the extractor takes a pooled connection. Distinct from the parent
/// module's constant so this layer's independence stays visible in failures.
const UNCONTACTED_DATABASE_URL: &str = "postgresql://sealed-boundary-refusal.invalid/db";

fn hasher() -> Arc<TokenHasher> {
    Arc::new(TokenHasher::new(crate::test_keys::key(76)).unwrap())
}

/// Every downgrade shape the stateless boundary must refuse, with a synthetic
/// marker planted in each body so non-echo is checked on real request bytes.
struct DowngradeShape {
    name: &'static str,
    content_type: Option<&'static str>,
    duplicate_content_type: bool,
    idempotency_key: Option<&'static str>,
    duplicate_authorization: bool,
    body: Vec<u8>,
}

fn shapes(marker: &Marker) -> Vec<DowngradeShape> {
    let raw_plaintext = pad_to_minimum(&[marker.as_bytes(), b" sealed fallback body"].concat());
    vec![
        DowngradeShape {
            name: "missing content type",
            content_type: None,
            duplicate_content_type: false,
            idempotency_key: None,
            duplicate_authorization: false,
            body: raw_plaintext.clone(),
        },
        DowngradeShape {
            name: "json fallback content type",
            content_type: Some("application/json"),
            duplicate_content_type: false,
            idempotency_key: None,
            duplicate_authorization: false,
            body: json_fallback_body(marker),
        },
        DowngradeShape {
            name: "text fallback content type",
            content_type: Some("text/plain"),
            duplicate_content_type: false,
            idempotency_key: None,
            duplicate_authorization: false,
            body: raw_plaintext.clone(),
        },
        DowngradeShape {
            name: "parameterized sealed content type",
            content_type: Some("application/vnd.zrotext.sealed.v1; charset=binary"),
            duplicate_content_type: false,
            idempotency_key: None,
            duplicate_authorization: false,
            body: raw_plaintext.clone(),
        },
        DowngradeShape {
            name: "duplicate content type headers",
            content_type: Some(SEALED_CONTENT_TYPE),
            duplicate_content_type: true,
            idempotency_key: None,
            duplicate_authorization: false,
            body: raw_plaintext.clone(),
        },
        DowngradeShape {
            name: "caller idempotency key",
            content_type: Some(SEALED_CONTENT_TYPE),
            duplicate_content_type: false,
            idempotency_key: Some("caller-key-1"),
            duplicate_authorization: false,
            body: raw_plaintext.clone(),
        },
        DowngradeShape {
            name: "missing bearer",
            content_type: Some(SEALED_CONTENT_TYPE),
            duplicate_content_type: false,
            idempotency_key: None,
            duplicate_authorization: false,
            body: raw_plaintext.clone(),
        },
        DowngradeShape {
            name: "duplicate authorization headers",
            content_type: Some(SEALED_CONTENT_TYPE),
            duplicate_content_type: false,
            idempotency_key: None,
            duplicate_authorization: true,
            body: raw_plaintext.clone(),
        },
        DowngradeShape {
            name: "oversized body",
            content_type: Some(SEALED_CONTENT_TYPE),
            duplicate_content_type: false,
            idempotency_key: None,
            duplicate_authorization: false,
            body: vec![7u8; 36_885],
        },
    ]
}

fn pad_to_minimum(body: &[u8]) -> Vec<u8> {
    // Wrong-media-type refusals never read the body; the padding keeps the
    // plaintext shapes past the route's minimum envelope bound anyway so the
    // same bodies cannot accidentally become valid in a future refactor.
    let mut padded = body.to_vec();
    padded.resize(500, b' ');
    padded
}

fn json_fallback_body(marker: &Marker) -> Vec<u8> {
    let mut body = br#"{"text":""#.to_vec();
    body.extend_from_slice(marker.as_bytes());
    body.extend_from_slice(b"}");
    pad_to_minimum(&body)
}

async fn refusal(app: Router, shape: &DowngradeShape, marker: &Marker) -> (StatusCode, Vec<u8>) {
    let token = if shape.name == "missing bearer" {
        None
    } else {
        // A shape-only credential: authentication is never reached because
        // every shape here is refused before the database is contacted.
        Some("ztk_shape-only")
    };
    let request = sealed_request(
        token,
        shape.content_type,
        shape.duplicate_content_type,
        shape.idempotency_key,
        shape.duplicate_authorization,
        shape.body.clone(),
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store",
        "{}: every boundary response is no-store",
        shape.name
    );
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    assert!(
        !crate::sealed_marker::present(&bytes, marker.as_bytes()),
        "{name}: refusal echoed the planted marker",
        name = shape.name
    );
    (status, bytes)
}

fn assert_code_only(name: &str, bytes: &[u8], code: &str) {
    let mut expected = br#"{"code":""#.to_vec();
    expected.extend_from_slice(code.as_bytes());
    expected.extend_from_slice(br#""}"#);
    assert_eq!(
        bytes, expected,
        "{name}: the boundary speaks stable codes only"
    );
}

#[tokio::test]
async fn unmounted_route_fails_closed_for_every_downgrade_shape() {
    let marker = Marker::generate("route-off");
    let app = router(SealedHttpState::disabled(
        UNCONTACTED_DATABASE_URL.into(),
        hasher(),
    ));
    for shape in shapes(&marker) {
        let (status, bytes) = refusal(app.clone(), &shape, &marker).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}", shape.name);
        assert_code_only(shape.name, &bytes, "not_found");
    }
}

#[tokio::test]
async fn mounted_route_refuses_media_type_and_auth_downgrades_without_echo() {
    let marker = Marker::generate("route-on");
    let app = router(
        SealedHttpState::new(
            UNCONTACTED_DATABASE_URL.into(),
            hasher(),
            "boundary-guard".into(),
            1,
            true,
        )
        .unwrap(),
    );
    for shape in shapes(&marker) {
        // The body-size limit is enforced while the handler buffers the body,
        // after the authenticator has taken a pooled connection, so that one
        // shape belongs to the PostgreSQL-backed layer; every shape below is
        // refused before any database work.
        if shape.name == "oversized body" {
            continue;
        }
        let expected = match shape.name {
            "missing content type"
            | "json fallback content type"
            | "text fallback content type"
            | "parameterized sealed content type"
            | "duplicate content type headers" => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
            "caller idempotency key" => (StatusCode::BAD_REQUEST, "invalid_request"),
            "missing bearer" | "duplicate authorization headers" => {
                (StatusCode::UNAUTHORIZED, "unauthorized")
            }
            other => unreachable!("unclassified shape {other}"),
        };
        let (status, bytes) = refusal(app.clone(), &shape, &marker).await;
        assert_eq!(status, expected.0, "{}", shape.name);
        assert_code_only(shape.name, &bytes, expected.1);
    }
}

#[tokio::test]
async fn wrong_route_method_and_path_do_not_reach_admission() {
    let marker = Marker::generate("route-path");
    let app = router(
        SealedHttpState::new(
            UNCONTACTED_DATABASE_URL.into(),
            hasher(),
            "boundary-guard".into(),
            1,
            true,
        )
        .unwrap(),
    );
    for (method, uri) in [
        ("GET", "/messages"),
        ("POST", "/messages/other"),
        ("POST", "/"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, SEALED_CONTENT_TYPE)
            .body(Body::from(pad_to_minimum(marker.as_bytes())))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert!(
            response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::NOT_FOUND,
            "{method} {uri} reached admission"
        );
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        assert!(
            !crate::sealed_marker::present(&bytes, marker.as_bytes()),
            "{method} {uri} echoed the planted marker"
        );
    }
}

#[test]
fn plaintext_fallback_bodies_fail_envelope_parsing_before_any_database_work() {
    let marker = Marker::generate("parse");
    // The parser is the first act of admission and is a pure function, so the
    // plaintext-fallback rejection is provable here without PostgreSQL. Any
    // plaintext shape must fail closed at the magic/profile fence, whatever
    // the feature-flag state around the route is.
    for body in [
        pad_to_minimum(marker.as_bytes()),
        json_fallback_body(&marker),
        // Right magic family, wrong protocol bytes: still the magic/profile
        // fence, never a plaintext or profile-negotiation path.
        pad_to_minimum(&[b'Z', b'T', b'C', 2, 1, 0, 0]),
    ] {
        assert_eq!(
            crate::sealed_envelope::parse(&body, crate::sealed_envelope::Profile::Draft02Candidate)
                .map(|parsed| parsed.unsigned.len())
                .unwrap_err(),
            "magic/profile"
        );
    }
}
