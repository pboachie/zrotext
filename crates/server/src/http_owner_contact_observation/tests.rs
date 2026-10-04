// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::http::Request;
use http_body::Frame;
use std::{
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tower::ServiceExt;

fn state(url: String) -> OwnerContactObservationState {
    OwnerContactObservationState {
        database_url: url,
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(94)).unwrap()),
    }
}

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static(
            "__Host-zrotext_session=zts_fixture; __Host-zrotext_csrf=ztc_fixture",
        ),
    );
    headers.insert("x-zrotext-csrf", HeaderValue::from_static("ztc_fixture"));
    headers.insert(
        READER_HEADER,
        HeaderValue::from_str(&STANDARD.encode([7; 32])).unwrap(),
    );
    headers.insert(
        ROOT_HEADER,
        HeaderValue::from_str(&STANDARD.encode([8; 32])).unwrap(),
    );
    headers
}

#[test]
fn selection_rejects_duplicate_zero_alias_and_unbounded_values() {
    let good = headers();
    assert!(ingress(&good, None).is_ok());
    assert!(ingress(&good, Some("")).is_err());
    for name in [READER_HEADER, ROOT_HEADER] {
        for value in [
            STANDARD.encode([0; 32]),
            STANDARD.encode([1; 31]),
            STANDARD.encode([1; 33]),
            "A".repeat(2048),
            STANDARD.encode([1; 32]).trim_end_matches('=').into(),
        ] {
            let mut h = good.clone();
            h.insert(name, HeaderValue::from_str(&value).unwrap());
            assert!(ingress(&h, None).is_err());
        }
        let mut h = good.clone();
        h.append(name, h[name].clone());
        assert!(ingress(&h, None).is_err());
        // Change unused low pad bits without changing decoded bytes.
        let mut alias = STANDARD.encode([1; 32]).into_bytes();
        alias[42] = b'F';
        let mut h = good.clone();
        h.insert(name, HeaderValue::from_bytes(&alias).unwrap());
        assert!(ingress(&h, None).is_err());
    }
}

#[test]
fn ingress_refuses_bearer_framing_and_noncanonical_body_lengths() {
    let good = headers();
    for (name, value) in [
        (header::AUTHORIZATION, "Bearer ignored"),
        (header::TRANSFER_ENCODING, "chunked"),
        (header::CONTENT_LENGTH, "1"),
        (header::CONTENT_LENGTH, "00"),
        (header::CONTENT_LENGTH, "0,0"),
        (header::CONTENT_LENGTH, "invalid"),
    ] {
        let mut h = good.clone();
        h.insert(name, HeaderValue::from_static(value));
        assert!(ingress(&h, None).is_err());
    }
    let mut h = good.clone();
    h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    assert!(ingress(&h, None).is_ok());
    h.append(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    assert!(ingress(&h, None).is_err());
}

struct PendingBody(Arc<AtomicUsize>);
impl http_body::Body for PendingBody {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn absent_body_is_accepted_bytes_and_unfinished_body_are_refused() {
    assert!(empty_body(Body::empty()).await.is_ok());
    assert!(empty_body(Body::from("x")).await.is_err());
    let polls = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    assert!(
        empty_body(Body::new(PendingBody(polls.clone())))
            .await
            .is_err()
    );
    assert_eq!(Instant::now() - start, BODY_LIMIT);
    assert!(polls.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn missing_cookie_or_csrf_refuses_before_database_or_body_poll() {
    for cookie in [false, true] {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut request = Request::get(PATH)
            .body(Body::new(PendingBody(polls.clone())))
            .unwrap();
        if cookie {
            request.headers_mut().insert(
                header::COOKIE,
                HeaderValue::from_static("__Host-zrotext_session=zts_fixture"),
            );
        }
        let response = router(state("not a database url".into()))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if cookie {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn invalid_selection_refuses_before_database_and_methods_are_no_store() {
    for method in ["GET", "HEAD", "POST", "OPTIONS"] {
        let mut request = Request::builder()
            .method(method)
            .uri(PATH)
            .body(Body::empty())
            .unwrap();
        *request.headers_mut() = headers();
        request
            .headers_mut()
            .append(READER_HEADER, HeaderValue::from_static("invalid"));
        let response = router(state("not a database url".into()))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if method == "GET" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::METHOD_NOT_ALLOWED
            }
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}

#[tokio::test(start_paused = true)]
async fn outward_deadline_discards_unfinished_and_exact_deadline_success() {
    let deadline = Instant::now() + OUTWARD_LIMIT;
    let response = bounded_response(deadline, std::future::pending()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(Instant::now(), deadline);
    let deadline = Instant::now() + OUTWARD_LIMIT;
    // The timeout polls its operation first. Even completion at this boundary
    // must not publish a success. This proves policy, not backend settlement.
    let response = bounded_response(deadline, async {
        tokio::time::sleep_until(deadline).await;
        Ok(StatusCode::OK.into_response())
    })
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let response = bounded_response(Instant::now() + OUTWARD_LIMIT, async {
        Ok(StatusCode::OK.into_response())
    })
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

fn projection() -> ObservationView {
    ObservationView {
        account_id: Uuid::from_bytes([1; 16]),
        root_pin_b64: STANDARD.encode([1; 94]),
        root_fingerprint_b64: STANDARD.encode([2; 32]),
        trust_generation: "1",
        manifest_version: "1".into(),
        manifest_digest_b64: STANDARD.encode([3; 32]),
        manifest_b64: STANDARD.encode([4; 364]),
        observed_ms: "2".into(),
        manifest_issued_ms: "1".into(),
        manifest_expires_ms: "9".into(),
        signed_until_ms: "8".into(),
        reader: KeyView {
            key_id_b64: STANDARD.encode([5; 32]),
            public_point_b64: STANDARD.encode([6; 65]),
            from_ms: "0".into(),
            until_ms: "8".into(),
        },
        root_writer: KeyView {
            key_id_b64: STANDARD.encode([7; 32]),
            public_point_b64: STANDARD.encode([8; 65]),
            from_ms: "1".into(),
            until_ms: "9".into(),
        },
    }
}

#[test]
fn actual_serializer_is_closed_ascii_bounded_and_uses_decimal_strings() {
    let view = projection();
    let raw = encode(&view).unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(decoded.as_object().unwrap().len(), 13);
    assert_eq!(decoded["reader"].as_object().unwrap().len(), 4);
    assert_eq!(decoded["root_writer"].as_object().unwrap().len(), 4);
    assert_eq!(decoded["trust_generation"], "1");
    assert_eq!(decoded["observed_ms"], "2");
    assert_eq!(decoded["reader"]["from_ms"], "0");
    assert!(raw.is_ascii());
    assert!(raw.starts_with(b"{\"account_id\":"));
    assert!(raw.windows(9).any(|w| w == b"\"reader\":"));
    assert_eq!(positive(i64::MAX as u64).unwrap(), i64::MAX.to_string());
    assert!(positive(0).is_err());
    assert!(positive(i64::MAX as u64 + 1).is_err());
    let mut oversized = projection();
    oversized.manifest_b64 = "A".repeat(MAX_RESPONSE);
    assert!(encode(&oversized).is_err());
    let mut maximum = projection();
    maximum.manifest_b64 = STANDARD.encode(vec![0; MAX_MANIFEST]);
    assert!(encode(&maximum).unwrap().len() <= MAX_RESPONSE);
}

fn parts() -> (PublicCandidate, AccountArchiveStatementRecords) {
    let mut point = [1; 65];
    point[0] = 4;
    (
        PublicCandidate {
            pin: vec![1; 94],
            fingerprint: [2; 32],
            snapshot: crate::sealed_manifest_store::outbound::ManifestSnapshot {
                generation: 1,
                version: 1,
                digest: [3; 32],
                bytes: vec![4; 364],
                accepted_ms: 5,
            },
        },
        AccountArchiveStatementRecords {
            account: [1; 16],
            generation: 1,
            version: 1,
            digest: [3; 32],
            issued: 1,
            expires: 10,
            root_point: point,
            root_id: [6; 32],
            root_from: 0,
            root_until: 8,
            reader_point: point,
            reader_from: 0,
            reader_until: 9,
        },
    )
}

#[test]
fn projection_cannot_mix_account_tuple_or_extend_signed_deadline() {
    let (c, r) = parts();
    let v = view(Uuid::from_bytes([1; 16]), &[5; 32], c, r).unwrap();
    assert_eq!(v.signed_until_ms, "8");
    let (c, r) = parts();
    assert!(view(Uuid::from_bytes([2; 16]), &[5; 32], c, r).is_err());
    let (mut c, r) = parts();
    c.snapshot.digest = [9; 32];
    assert!(view(Uuid::from_bytes([1; 16]), &[5; 32], c, r).is_err());
    let (mut c, r) = parts();
    c.snapshot.version = 2;
    assert!(view(Uuid::from_bytes([1; 16]), &[5; 32], c, r).is_err());
    let (mut c, r) = parts();
    c.snapshot.accepted_ms = 8;
    assert!(view(Uuid::from_bytes([1; 16]), &[5; 32], c, r).is_err());
    let (mut c, r) = parts();
    c.snapshot.bytes = vec![0; MAX_MANIFEST + 1];
    assert!(view(Uuid::from_bytes([1; 16]), &[5; 32], c, r).is_err());
}

// Uses existing maintained schema/teardown, genuine registration, password-backed
// email verification and login. Only already-enrolled synthetic root state is
// modeled in SQL; this fixture does not prove an enrollment or signing ceremony.
struct OwnerFixture {
    schema: crate::sealed_manifest_store::tests::Fixture,
    signup: auth::Signup,
    credentials: auth::SessionCredentials,
    pin: Vec<u8>,
    bytes: Vec<u8>,
    reader: [u8; 32],
    fingerprint: [u8; 32],
}

impl OwnerFixture {
    async fn new() -> Self {
        Self::build(true, false).await
    }

    async fn build(current: bool, expired: bool) -> Self {
        use p256::ecdsa::{Signature, signature::Signer};
        use sha2::{Digest, Sha256};
        let schema = crate::sealed_manifest_store::tests::Fixture::without_authority().await;
        let hasher = state(String::new()).auth_hasher;
        let email = format!("observation-{}@example.test", Uuid::new_v4());
        let mut db = schema.connect().await;
        let signup = auth::register(&mut db, &hasher, &email, "synthetic observation password")
            .await
            .unwrap();
        assert!(
            auth::verify_email_with_password(
                &mut db,
                &hasher,
                &signup.verification_token,
                "synthetic observation password"
            )
            .await
            .unwrap()
        );
        let credentials = auth::login(&db, &hasher, &email, "synthetic observation password")
            .await
            .unwrap();
        let now: i64 = db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let mut pin = schema.pin.clone();
        pin[5..21].copy_from_slice(signup.account_id.as_bytes());
        let mut bytes = schema.bytes[..151].to_vec();
        bytes[5..21].copy_from_slice(signup.account_id.as_bytes());
        bytes[37..45].copy_from_slice(&(now as u64 - 1000).to_be_bytes());
        let expiry = if expired {
            now as u64 - 1
        } else {
            now as u64 + 600_000
        };
        bytes[45..53].copy_from_slice(&expiry.to_be_bytes());
        bytes[150] = 2;
        for role in schema.bytes[151..schema.bytes.len() - 64]
            .chunks_exact(149)
            .filter(|r| r[0] == 2 || r[0] == 6)
        {
            let mut role = role.to_vec();
            role[132..140].copy_from_slice(&(now as u64 - 1000).to_be_bytes());
            role[140..148].copy_from_slice(&expiry.to_be_bytes());
            bytes.extend(role);
        }
        let signature: Signature = schema.root.sign(
            &[
                b"ZTSE/manifest/v2\0".as_slice(),
                &(bytes.len() as u32).to_be_bytes(),
                &bytes,
            ]
            .concat(),
        );
        let digest: Vec<u8> = Sha256::digest(&bytes).to_vec();
        bytes.extend(signature.normalize_s().to_bytes());
        let fingerprint: [u8; 32] =
            Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), &pin].concat()).into();
        let reader = schema.readers[0].key_id;
        if current {
            let accepted_ms = if expired { now - 500 } else { now };
            db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest,version,semantic_digest,manifest,accepted_at_ms,last_verified_ms) VALUES($1,$2,$3,1,$4,1,$5,$6,$7,$7)",
                &[&signup.account_id,&pin,&&fingerprint[..],&vec![0u8;32],&digest,&bytes,&accepted_ms]).await.unwrap();
        }
        Self {
            schema,
            signup,
            credentials,
            pin,
            bytes,
            reader,
            fingerprint,
        }
    }
    fn app(&self) -> Router {
        let separator = if self.schema.url.contains('?') {
            '&'
        } else {
            '?'
        };
        router(state(format!(
            "{}{separator}options=-csearch_path%3D{}",
            self.schema.url, self.schema.schema
        )))
    }
    fn request(&self) -> Request<Body> {
        Request::get(PATH)
            .header(
                header::COOKIE,
                format!(
                    "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                    self.credentials.token, self.credentials.csrf_token
                ),
            )
            .header("x-zrotext-csrf", &self.credentials.csrf_token)
            .header(READER_HEADER, STANDARD.encode(self.reader))
            .header(ROOT_HEADER, STANDARD.encode(self.fingerprint))
            .body(Body::empty())
            .unwrap()
    }
    async fn get(&self) -> Response {
        self.app().oneshot(self.request()).await.unwrap()
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner and isolated synthetic current root"]
async fn real_owner_observes_exact_signed_records_without_advancing_high_water() {
    let f = OwnerFixture::new().await;
    let prior: i64 = f
        .schema
        .db
        .query_one(
            "SELECT last_verified_ms FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&f.signup.account_id],
        )
        .await
        .unwrap()
        .get(0);
    let response = f.get().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body = to_bytes(response.into_body(), MAX_RESPONSE).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["account_id"], f.signup.account_id.to_string());
    assert_eq!(v["root_pin_b64"], STANDARD.encode(&f.pin));
    assert_eq!(v["manifest_b64"], STANDARD.encode(&f.bytes));
    assert_eq!(v["reader"]["key_id_b64"], STANDARD.encode(f.reader));
    assert_eq!(v.as_object().unwrap().len(), 13);
    let after: i64 = f
        .schema
        .db
        .query_one(
            "SELECT last_verified_ms FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&f.signup.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(prior, after);
    assert_eq!(AccountSlot::in_flight(f.signup.account_id), 0);
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner and isolated synthetic current root"]
async fn real_owner_selection_csrf_account_disable_and_session_revocation_fail_closed() {
    let f = OwnerFixture::new().await;
    for name in [READER_HEADER, ROOT_HEADER] {
        let mut request = f.request();
        request.headers_mut().insert(
            name,
            HeaderValue::from_str(&STANDARD.encode([9; 32])).unwrap(),
        );
        assert_eq!(
            f.app().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    let mut request = f.request();
    request
        .headers_mut()
        .insert("x-zrotext-csrf", HeaderValue::from_static("ztc_other"));
    assert_eq!(
        f.app().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    // Another genuinely issued session's matching token still fails this hash.
    let email: String = f
        .schema
        .db
        .query_one("SELECT email FROM users WHERE id=$1", &[&f.signup.user_id])
        .await
        .unwrap()
        .get(0);
    let other = auth::login(
        &f.schema.db,
        &state(String::new()).auth_hasher,
        &email,
        "synthetic observation password",
    )
    .await
    .unwrap();
    let mut request = f.request();
    request.headers_mut().insert(
        "x-zrotext-csrf",
        HeaderValue::from_str(&other.csrf_token).unwrap(),
    );
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
            f.credentials.token, other.csrf_token
        ))
        .unwrap(),
    );
    assert_eq!(
        f.app().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    f.schema
        .db
        .execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&f.signup.account_id],
        )
        .await
        .unwrap();
    assert_eq!(f.get().await.status(), StatusCode::UNAUTHORIZED);
    f.schema
        .db
        .execute(
            "UPDATE accounts SET disabled_at=NULL WHERE id=$1",
            &[&f.signup.account_id],
        )
        .await
        .unwrap();
    let owner = auth::authenticate_session(
        &f.schema.db,
        &state(String::new()).auth_hasher,
        &f.credentials.token,
    )
    .await
    .unwrap();
    assert!(
        auth::revoke_session(&f.schema.db, &owner, f.credentials.id)
            .await
            .unwrap()
    );
    assert_eq!(f.get().await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(AccountSlot::in_flight(f.signup.account_id), 0);
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner and isolated synthetic current root"]
async fn current_authority_time_regression_and_revocation_are_refused() {
    let f = OwnerFixture::new().await;
    let clock: i64 = f
        .schema
        .db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    f.schema
        .db
        .execute(
            "UPDATE sealed_manifest_authorities SET last_verified_ms=$2 WHERE account_id=$1",
            &[&f.signup.account_id, &(clock + 600_000)],
        )
        .await
        .unwrap();
    assert_eq!(f.get().await.status(), StatusCode::FORBIDDEN);
    f.schema.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",&[&f.signup.account_id]).await.unwrap();
    assert_eq!(f.get().await.status(), StatusCode::FORBIDDEN);
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner and isolated synthetic current root"]
async fn absent_uninstalled_and_expired_current_manifests_never_observe() {
    let f = OwnerFixture::build(false, false).await;
    assert_eq!(f.get().await.status(), StatusCode::FORBIDDEN);
    f.schema.db.execute("INSERT INTO sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest) VALUES($1,$2,$3,1,$4)",
        &[&f.signup.account_id,&f.pin,&&f.fingerprint[..],&vec![0u8;32]]).await.unwrap();
    assert_eq!(f.get().await.status(), StatusCode::FORBIDDEN);
    f.schema.cleanup().await;
    let expired = OwnerFixture::build(true, true).await;
    assert_eq!(expired.get().await.status(), StatusCode::FORBIDDEN);
    expired.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner and isolated synthetic current root"]
async fn stale_real_owner_and_same_transaction_source_change_cannot_publish() {
    let f = OwnerFixture::new().await;
    let owner = auth::authenticate_session(
        &f.schema.db,
        &state(String::new()).auth_hasher,
        &f.credentials.token,
    )
    .await
    .unwrap();
    f.schema
        .db
        .execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&f.signup.account_id],
        )
        .await
        .unwrap();
    let mut db = f.schema.connect().await;
    let selection = Selection {
        reader: f.reader,
        fingerprint: f.fingerprint,
    };
    assert!(matches!(
        store(&mut db, &owner, &selection).await,
        Err(AuthHttpError::Unauthorized)
    ));
    f.schema
        .db
        .execute(
            "UPDATE accounts SET disabled_at=NULL WHERE id=$1",
            &[&f.signup.account_id],
        )
        .await
        .unwrap();
    let tx = db.transaction().await.unwrap();
    let mut current = lock_current(&tx, f.signup.account_id).await.unwrap();
    current
        .account_contact_observation(&f.reader, &f.fingerprint)
        .await
        .unwrap();
    tx.execute(
        "UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",
        &[&f.signup.account_id],
    )
    .await
    .unwrap();
    assert!(
        current
            .account_contact_observation(&f.reader, &f.fingerprint)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(f.get().await.status(), StatusCode::OK);
    f.schema.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine owner and isolated synthetic current root"]
async fn genuine_observer_is_refused_and_request_slot_errors_release_their_guard() {
    let f = OwnerFixture::new().await;
    assert_eq!(
        f.schema
            .db
            .query_one("SELECT current_schema()", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        f.schema.schema
    );
    f.schema
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"
        ))
        .await
        .unwrap();
    assert!(
        f.schema
            .db
            .query_one("SELECT to_regclass('seat_invitations') IS NOT NULL", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let hasher = state(String::new()).auth_hasher;
    let owner = auth::authenticate_session(&f.schema.db, &hasher, &f.credentials.token)
        .await
        .unwrap();
    let email = format!("observer-{}@example.test", Uuid::new_v4());
    let mut db = f.schema.connect().await;
    let invite = auth::seats::create_invitation_with_proof(
        &mut db,
        None,
        &hasher,
        &owner,
        "synthetic observation password",
        None,
        &email,
    )
    .await
    .unwrap();
    let accepted = auth::seats::accept_invitation(
        &mut db,
        &hasher,
        &invite.token,
        "synthetic observer password",
    )
    .await
    .unwrap();
    assert!(
        auth::verify_email_with_password(
            &mut db,
            &hasher,
            &accepted.verification_token,
            "synthetic observer password"
        )
        .await
        .unwrap()
    );
    let credentials = auth::login(&db, &hasher, &email, "synthetic observer password")
        .await
        .unwrap();
    let mut request = f.request();
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
            credentials.token, credentials.csrf_token
        ))
        .unwrap(),
    );
    request.headers_mut().insert(
        "x-zrotext-csrf",
        HeaderValue::from_str(&credentials.csrf_token).unwrap(),
    );
    assert_eq!(
        f.app().oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let guards: Vec<_> = (0..4)
        .map(|_| AccountSlot::try_acquire(f.signup.account_id).unwrap())
        .collect();
    let response = f.get().await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(AccountSlot::in_flight(f.signup.account_id), 4);
    drop(guards);
    let mut request = f.request();
    *request.body_mut() = Body::from("x");
    assert_eq!(
        f.app().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(AccountSlot::in_flight(f.signup.account_id), 0);
    f.schema.cleanup().await;
}
