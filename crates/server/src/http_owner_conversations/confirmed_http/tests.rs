// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::SessionPrincipal, http_owner_conversations::activation,
    sealed_envelope::ExpectedRecipient, sealed_manifest_store::tests::Fixture,
};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;
const SCHEMA: &str = include_str!(
    "../../../../../deploy/compose/migrations/072_conversation_confirmation_records.sql"
);
struct Case {
    f: Fixture,
    owner: SessionPrincipal,
    interval: activation::Statement,
    browser: SigningKey,
    browser_id: [u8; 32],
    phone_reader: ExpectedRecipient,
}
impl Case {
    async fn new() -> Self {
        let (mut f, owner, interval) = activation::tests::pending().await;
        activation::tests::activate(&f, &interval).await;
        f.advance();
        let old_entries = f.bytes[151..f.bytes.len() - 64].to_vec();
        let browser = SigningKey::generate_from_rng(&mut rand::rng());
        let kem = SigningKey::generate_from_rng(&mut rand::rng());
        let now: i64 =
            f.db.query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let entry = |role: u8, key: &SigningKey| {
            let point = key.verifying_key().to_sec1_point(false);
            let algorithm = if role == 1 { [0, 16] } else { [1, 1] };
            let id: [u8; 32] = Sha256::digest(
                [b"ZTSE/key/v1\0".as_slice(), &algorithm, point.as_bytes()].concat(),
            )
            .into();
            let mut bytes = vec![role];
            bytes.extend(id);
            bytes.extend(point.as_bytes());
            bytes.extend(if role == 1 {
                *f.device.as_bytes()
            } else {
                [0; 16]
            });
            bytes.extend(f.line.as_bytes());
            bytes.extend(if role == 1 { 4u16 } else { 1u16 }.to_be_bytes());
            bytes.extend((now - 1000).to_be_bytes());
            bytes.extend((now + 240_000).to_be_bytes());
            bytes.push(1);
            (bytes, id)
        };
        let (phone, phone_id) = entry(1, &kem);
        let (signer, browser_id) = entry(5, &browser);
        f.bytes.truncate(150);
        f.bytes.push(5);
        f.bytes.extend(phone);
        f.bytes.extend(&old_entries[..298]);
        f.bytes.extend(signer);
        f.bytes.extend(&old_entries[298..]);
        f.bytes.extend([0; 64]);
        f.resign();
        let mut db = f.connect().await;
        let tx = db.transaction().await.unwrap();
        let mut admitted =
            crate::sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
                .await
                .unwrap();
        admitted.context(&f.wanted()).await.unwrap();
        drop(admitted);
        tx.commit().await.unwrap();
        if !queue::lifecycle::installed(&f.db).await.unwrap() {
            f.db.batch_execute(SCHEMA).await.unwrap();
        }
        f.db.execute("INSERT INTO usage_quota_policies(account_id,metric,limit_units) VALUES($1,'outbound_message',1000)",&[&f.account]).await.unwrap();
        Self {
            f,
            owner,
            interval,
            browser,
            browser_id,
            phone_reader: ExpectedRecipient {
                role: 1,
                key_id: phone_id,
            },
        }
    }
    async fn packet(&self, message: Uuid, lifetime: i64) -> (Vec<u8>, Confirmation, Vec<u8>) {
        let now: i64 = self
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let digest: [u8; 32] = Sha256::digest(&self.f.bytes[..self.f.bytes.len() - 64]).into();
        let mut b = b"ZTSE\x02\x01\0\0".to_vec();
        b.extend(157u16.to_be_bytes());
        for id in [self.f.account, message, self.f.device, self.f.line] {
            b.extend(id.as_bytes());
        }
        b.extend(3u64.to_be_bytes());
        b.extend(digest);
        b.extend(self.browser_id);
        b.extend(now.to_be_bytes());
        b.extend((now + lifetime).to_be_bytes());
        b.extend([1, 3]);
        b.extend(b"+12");
        b.extend([4; 12]);
        b.extend(17u32.to_be_bytes());
        b.extend([7; 17]);
        b.push(2);
        for reader in [&self.phone_reader, &self.f.readers[0]] {
            b.push(reader.role);
            b.extend(reader.key_id);
            b.extend(self.f.root.verifying_key().to_sec1_point(false).as_bytes());
            b.extend([9; 48]);
        }
        let signature: Signature = self.browser.sign(
            &[
                b"ZTSE/sign/v2\0".as_slice(),
                &(b.len() as u32).to_be_bytes(),
                &b,
            ]
            .concat(),
        );
        b.extend(signature.normalize_s().to_bytes());
        let c = Confirmation {
            account: self.f.account,
            device: self.f.device,
            line: self.f.line,
            interval: self.interval.interval,
            session: self.owner.session_id,
            message,
            generation: 1,
            trust_generation: 1,
            version: 3,
            expires_ms: now + lifetime,
            peer: "+12".into(),
            signer: self.browser_id,
            reader: self.interval.reader,
            manifest: digest,
            envelope_digest: Sha256::digest(&b).into(),
            body_digest: [8; 32],
        };
        let signature: Signature = self.browser.sign(&c.transcript().unwrap());
        (b, c, signature.normalize_s().to_bytes().to_vec())
    }
}

impl Case {
    async fn credentials(&self, owner: &SessionPrincipal) -> (String, String) {
        let token = format!(
            "zts_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
        );
        let csrf = format!(
            "ztc_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
        );
        let hash = |domain: &[u8], value: &str| {
            let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
            mac.update(domain);
            mac.update(value.as_bytes());
            mac.finalize().into_bytes().to_vec()
        };
        self.f
            .db
            .execute(
                "UPDATE sessions SET token_hash=$1,csrf_hash=$2 WHERE id=$3",
                &[
                    &hash(b"session-v1\0", &token),
                    &hash(b"csrf-v1\0", &csrf),
                    &owner.session_id,
                ],
            )
            .await
            .unwrap();
        (token, csrf)
    }
    fn app(&self) -> Router {
        let sep = if self.f.url.contains('?') { '&' } else { '?' };
        let url = format!(
            "{}{sep}options=-csearch_path%3D{}",
            self.f.url, self.f.schema
        );
        test_router(url)
    }
    async fn post(&self, credentials: &(String, String), body: Value) -> Response {
        self.app()
            .oneshot(
                Request::post("/v1/owner/conversation/send")
                    .header("content-type", "application/json")
                    .header("origin", "https://test.example")
                    .header(
                        "cookie",
                        format!(
                            "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                            credentials.0, credentials.1
                        ),
                    )
                    .header("x-zrotext-csrf", &credentials.1)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    async fn body(&self, message: Uuid) -> Value {
        let (b, c, s) = self.packet(message, 30_000).await;
        json!({"envelope":STANDARD.encode(b),"confirmation":STANDARD.encode(c.encode().unwrap()),"signature":STANDARD.encode(s)})
    }
    async fn count(&self) -> i64 {
        self.f
            .db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get(0)
    }
}

#[test]
fn base64_requires_exact_canonical_encoding_and_size() {
    assert!(decode("YQ==", 1, 1).is_ok());
    for bad in ["YQ", "YQ==\n", "YR==", "YQ==="] {
        assert!(decode(bad, 1, 1).is_err());
    }
    assert!(decode("YWE=", 1, 1).is_err());
    assert!(
        serde_json::from_value::<Packet>(
            json!({"envelope":"","confirmation":"","signature":"","site_id":"untrusted"})
        )
        .is_err()
    );
}

#[tokio::test]
async fn unauthenticated_body_is_not_polled_and_bearer_is_rejected() {
    // No database connection or body work is needed to reject missing cookies.
    let body = Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >());
    let app = test_router("invalid".into());
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        app.oneshot(
            Request::post("/v1/owner/conversation/send")
                .body(body)
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = test_router("invalid".into())
        .oneshot(
            Request::post("/v1/owner/conversation/send")
                .header("authorization", "Bearer invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authenticated_submit_commits_proof_and_replays_exact_message_once() {
    let case = Case::new().await;
    let credentials = case.credentials(&case.owner).await;
    let message = Uuid::new_v4();
    let body = case.body(message).await;
    let response = case.post(&credentials, body.clone()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let result: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(result["state"], "queued");
    assert_eq!(result["created"], true);
    let replay = case.post(&credentials, body.clone()).await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    let result: Value =
        serde_json::from_slice(&to_bytes(replay.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(result["created"], false);
    let mut c = Confirmation::decode(
        &STANDARD
            .decode(body["confirmation"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    c.body_digest[0] ^= 1;
    let sig: Signature = case.browser.sign(&c.transcript().unwrap());
    let mut changed = body;
    changed["confirmation"] = json!(STANDARD.encode(c.encode().unwrap()));
    changed["signature"] = json!(STANDARD.encode(sig.normalize_s().to_bytes()));
    assert_eq!(
        case.post(&credentials, changed).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(case.count().await, 1);
    let row=case.f.db.query_one("SELECT (SELECT count(*) FROM dispatch_jobs),(SELECT count(*) FROM conversation_confirmation_records),(SELECT count(*) FROM usage_ledger WHERE entry_kind='reserve')",&[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (1, 1, 1)
    );
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authenticated_submit_rejects_csrf_unknown_fields_and_other_account() {
    let case = Case::new().await;
    let credentials = case.credentials(&case.owner).await;
    let mut bad = credentials.clone();
    bad.1 = format!(
        "ztc_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32])
    );
    assert_eq!(
        case.post(&bad, json!({})).await.status(),
        StatusCode::FORBIDDEN
    );
    let response = case
        .app()
        .oneshot(
            Request::post("/v1/owner/conversation/send")
                .header("content-type", "application/json")
                .header("origin", "https://other.example")
                .header(
                    "cookie",
                    format!(
                        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                        credentials.0, credentials.1
                    ),
                )
                .header("x-zrotext-csrf", &credentials.1)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = case
        .app()
        .oneshot(
            Request::post("/v1/owner/conversation/send")
                .header("content-type", "application/json")
                .header("origin", "https://test.example")
                .header(
                    "cookie",
                    format!(
                        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                        credentials.0, credentials.1
                    ),
                )
                .header("x-zrotext-csrf", &credentials.1)
                .body(Body::from(" ".repeat(48 * 1024 + 1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let mut body = case.body(Uuid::new_v4()).await;
    body["site_id"] = json!("untrusted");
    assert_eq!(
        case.post(&credentials, body).await.status(),
        StatusCode::BAD_REQUEST
    );
    let other = Uuid::new_v4();
    case.f
        .db
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&other])
        .await
        .unwrap();
    let principal = super::super::tests::owner_for(&case.f, other).await;
    let other_credentials = case.credentials(&principal).await;
    assert_eq!(
        case.post(&other_credentials, case.body(Uuid::new_v4()).await)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(case.count().await, 0);
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authenticated_submit_refuses_expired_revoked_phone_and_missing_proof_schema() {
    let case = Case::new().await;
    let credentials = case.credentials(&case.owner).await;
    case.f
        .db
        .execute(
            "UPDATE device_sessions SET lease_until=clock_timestamp()-interval '1 second'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        case.post(&credentials, case.body(Uuid::new_v4()).await)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    case.f
        .db
        .execute(
            "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '10 minutes'",
            &[],
        )
        .await
        .unwrap();
    case.f
        .db
        .execute("UPDATE devices SET revoked_at=clock_timestamp()", &[])
        .await
        .unwrap();
    assert_eq!(
        case.post(&credentials, case.body(Uuid::new_v4()).await)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(case.count().await, 0);
    let case = Case::new().await;
    let credentials = case.credentials(&case.owner).await;
    case.f
        .db
        .batch_execute("DROP TABLE conversation_confirmation_records")
        .await
        .unwrap();
    assert_eq!(
        case.post(&credentials, case.body(Uuid::new_v4()).await)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(case.count().await, 0);
}

fn test_router(url: String) -> Router {
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap());
    let owner = OwnerConversationsState {
        database_url: url.clone(),
        auth_hasher: hasher.clone(),
        canonical_origin: "https://test.example".into(),
    };
    let socket = DeviceSocketState {
        database_url: url,
        site_id: "manifest-test".into(),
        instance_id: "fixture".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(
            crate::enrollment::EnrollmentHasher::new(crate::test_keys::key(77)).unwrap(),
        ),
        auth_hasher: hasher,
        alpha_policy: Arc::new(crate::alpha_policy::AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        mms_spike_policy: Arc::new(
            crate::device_socket::MmsSpikePolicy::parse(None, None, None).unwrap(),
        ),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        drain_notify: Arc::new(tokio::sync::Notify::new()),
    };
    router(owner, socket, true)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn authenticated_submit_refuses_expired_confirmation_and_owner_session() {
    let case = Case::new().await;
    let credentials = case.credentials(&case.owner).await;
    let (mut b, c, s) = case.packet(Uuid::new_v4(), 30_000).await;
    let mut expired = c;
    expired.expires_ms -= 60_000;
    b[146..154].copy_from_slice(&(expired.expires_ms - 30_000).to_be_bytes());
    b[154..162].copy_from_slice(&expired.expires_ms.to_be_bytes());
    b.truncate(b.len() - 64);
    let envelope_signature: Signature = case.browser.sign(
        &[
            b"ZTSE/sign/v2\0".as_slice(),
            &(b.len() as u32).to_be_bytes(),
            &b,
        ]
        .concat(),
    );
    b.extend(envelope_signature.normalize_s().to_bytes());
    expired.envelope_digest = Sha256::digest(&b).into();
    let sig: Signature = case.browser.sign(&expired.transcript().unwrap());
    let body = json!({"envelope":STANDARD.encode(&b),"confirmation":STANDARD.encode(expired.encode().unwrap()),"signature":STANDARD.encode(sig.normalize_s().to_bytes())});
    assert_eq!(
        case.post(&credentials, body).await.status(),
        StatusCode::FORBIDDEN
    );
    case.f
        .db
        .execute(
            "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
            &[&case.owner.session_id],
        )
        .await
        .unwrap();
    let body = json!({"envelope":STANDARD.encode(b),"confirmation":STANDARD.encode(expired.encode().unwrap()),"signature":STANDARD.encode(s)});
    assert_eq!(
        case.post(&credentials, body).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(case.count().await, 0);
}
