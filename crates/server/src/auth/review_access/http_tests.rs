// SPDX-License-Identifier: AGPL-3.0-only
//! Actual unmounted Axum + numbered PostgreSQL ordinary-role + Argon2/P-256
//! journey. The synthetic in-process HTTPS Origin does not prove TLS/hosting,
//! native custody, carrier delivery or Google acceptance.
use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tower::ServiceExt;
use zeroize::Zeroizing;
use zrotext_root_material::{
    recovery_kit::encode_public_card,
    root_backup::{self, RecoverySecret, RootSecret},
};

struct BrowserClient {
    app: Router,
    cookies: BTreeMap<String, String>,
    commitment: String,
    held_csrf: BTreeMap<String, String>,
}
impl BrowserClient {
    fn new(access: Arc<ReviewAccess>) -> Self {
        Self {
            app: crate::http_review_access::unmounted_router(access),
            cookies: BTreeMap::new(),
            commitment: String::new(),
            held_csrf: BTreeMap::new(),
        }
    }
    async fn request(&self, path: &str, body: Value) -> (StatusCode, HeaderMap, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::ORIGIN, "https://review.invalid")
            .header(header::CONTENT_TYPE, "application/json");
        if !self.cookies.is_empty() {
            builder = builder.header(
                header::COOKIE,
                self.cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        let staged_csrf = self
            .cookies
            .iter()
            .find(|(k, _)| k.starts_with("__Host-ztrw-c-"))
            .map(|(_, v)| v.as_str());
        let original = body
            .get("preparation_id")
            .and_then(Value::as_str)
            .map(|id| id.replace('-', ""));
        let csrf = staged_csrf
            .or_else(|| {
                if matches!(
                    path,
                    "/v1/review/session/confirm" | "/v1/review/preparations/status"
                ) {
                    original
                        .as_ref()
                        .and_then(|id| self.held_csrf.get(id))
                        .map(String::as_str)
                } else {
                    None
                }
            })
            .unwrap_or(&self.commitment);
        if !csrf.is_empty() {
            builder = builder.header("x-ztrw-prepared-csrf", csrf);
        }
        for (cookie, header) in [
            ("__Host-ztrw-broker-csrf", "x-ztrw-broker-csrf"),
            ("__Host-ztrw-owner-csrf", "x-ztrw-owner-csrf"),
        ] {
            if let Some(value) = self.cookies.get(cookie) {
                builder = builder.header(header, value);
            }
        }
        let response = self
            .app
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 32_768).await.unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("non-JSON bounded fixture response, status {status}"));
        (status, headers, value)
    }
    fn apply(&mut self, headers: &HeaderMap) {
        for header in headers.get_all(header::SET_COOKIE) {
            let value = header.to_str().unwrap();
            let pair = value.split(';').next().unwrap();
            let (key, value) = pair.split_once('=').unwrap();
            assert!(key.starts_with("__Host-ztrw-"));
            assert!(header.to_str().unwrap().contains("SameSite=Strict"));
            if value.is_empty() {
                self.cookies.remove(key);
            } else {
                if let Some(id) = key.strip_prefix("__Host-ztrw-c-") {
                    self.held_csrf.insert(id.into(), value.into());
                }
                self.cookies.insert(key.into(), value.into());
            }
        }
    }
    async fn post(&mut self, path: &str, body: Value) -> Value {
        let (status, headers, value) = self.request(path, body).await;
        assert_eq!(status, StatusCode::OK, "{path}: {value}");
        self.apply(&headers);
        value
    }
}
fn request() -> Value {
    json!({"version":1,"request_id":Uuid::new_v4().to_string()})
}
fn identity(value: &Value) -> Value {
    json!({"version":1,"request_id":value["request_id"],"preparation_id":value["preparation_id"],"generation":value["generation"]})
}
fn b64(value: &Value, key: &str) -> Vec<u8> {
    STANDARD.decode(value[key].as_str().unwrap()).unwrap()
}
fn sign(key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(bytes);
    signature.normalize_s().to_bytes().to_vec()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; genuine ordinary LOGIN HTTP/root journey"]
async fn original_http_workspace_and_genuine_root_custody_complete_without_ordinary_auth() {
    let f = Fixture::create().await;
    let mut browser = BrowserClient::new(f.access.clone());
    let first = browser.post("/v1/review/browser/prepare", request()).await;
    browser.commitment = first["browser_context_commitment_b64"]
        .as_str()
        .unwrap()
        .into();
    assert!(!first["owner_session_issued"].as_bool().unwrap());
    browser.post("/v1/review/browser/confirm",json!({"version":1,"request_id":Uuid::new_v4(),"browser_context_commitment_b64":browser.commitment})).await;
    let prep=browser.post("/v1/review/preparations",json!({"version":1,"request_id":Uuid::new_v4(),"operation":{"kind":"initial_bootstrap","alias":"pilot"}})).await;
    let login = identity(&prep);
    browser
        .post("/v1/review/preparations/confirm", login.clone())
        .await;
    let mut body = login.clone();
    body["alias"] = json!("pilot");
    body["password"] = json!("synthetic-review-password");
    browser.post("/v1/review/login/bootstrap", body).await;
    let (_, headers, _) = browser
        .request("/v1/review/login/status", login.clone())
        .await;
    assert_eq!(headers.get_all(header::SET_COOKIE).iter().count(), 2);
    browser.apply(&headers);
    assert!(!browser.cookies.contains_key("__Host-ztrw-owner"));
    browser
        .post("/v1/review/workspace/status", login.clone())
        .await;
    let context = browser.post("/v1/review/session/context", request()).await;
    assert_eq!(context["root_state"]["kind"], "no_root_history");
    assert!(!context["locator_retained"].as_bool().unwrap());
    let account = Uuid::parse_str(context["account"].as_str().unwrap()).unwrap();
    let (status, headers, _) = browser
        .request("/v1/review/session/confirm", login.clone())
        .await;
    assert_eq!(status, StatusCode::OK);
    browser.apply(&headers); // Cookie headers arrived; original ACK body was lost.
    browser
        .post("/v1/review/session/confirm", login.clone())
        .await;
    let selector = browser
        .cookies
        .iter()
        .find(|(name, _)| name.starts_with("__Host-ztrw-l-"))
        .unwrap()
        .1
        .clone();
    let selector_hash = STANDARD.encode(Sha256::digest(selector.as_bytes()));
    let ack = json!({"version":1,"request_id":Uuid::new_v4(),"preparation_id":login["preparation_id"],"selector_cookie_sha256_b64":selector_hash});
    let (status, headers, value) = browser
        .request("/v1/review/locator/context", ack.clone())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(value["retained"], false);
    // Native owns actual consent/SAF. This fixture only checks exact private
    // record byte readback and server association; no JNI/device claim.
    let record = serde_json::to_vec(
        &json!({"version":1,"origin":"https://review.invalid","cookie_value":selector}),
    )
    .unwrap();
    let reread: Value = serde_json::from_slice(&record).unwrap();
    assert_eq!(reread["cookie_value"], selector);
    let (status, _, _) = browser
        .request("/v1/review/locator/retention-confirm", ack.clone())
        .await;
    assert_eq!(status, StatusCode::OK); // Deliberately drop actual L clearing ACK.
    browser
        .post("/v1/review/locator/retention-status", ack.clone())
        .await;
    assert!(
        !browser
            .cookies
            .keys()
            .any(|key| key.starts_with("__Host-ztrw-l-"))
    );
    browser
        .post("/v1/review/locator/retention-status", ack)
        .await;
    let original_browser = browser.cookies.remove("__Host-ztrw-browser").unwrap();
    let guards = f.count("review_access_preparations").await;
    let (status, headers, _) = browser
        .request("/v1/review/browser/prepare", request())
        .await;
    assert!(!status.is_success());
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(f.count("review_access_preparations").await, guards);
    assert_eq!(f.count("accounts").await, 1);
    browser
        .cookies
        .insert("__Host-ztrw-browser".into(), "invalid".into());
    assert!(
        !browser
            .request("/v1/review/browser/prepare", request())
            .await
            .0
            .is_success()
    );
    browser
        .cookies
        .insert("__Host-ztrw-browser".into(), original_browser);

    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let pin: [u8; 94] = [
        b"ZTRP\x02".as_slice(),
        account.as_bytes(),
        &1u64.to_be_bytes(),
        key.verifying_key().to_sec1_point(false).as_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap();
    let compared =
        crate::sealed_root_enrollment::root_fingerprint(&pin, account.as_bytes()).unwrap();
    let expected = root_backup::ExpectedIdentity {
        account_id: *account.as_bytes(),
        origin: "https://review.invalid".into(),
        root_fingerprint: compared,
    };
    let secret = RootSecret::new(Zeroizing::new(key.to_bytes().into())).unwrap();
    let recovery = RecoverySecret::new(Zeroizing::new(rand::random()));
    let backup = root_backup::seal(&secret, &recovery, &expected).unwrap();
    let card = encode_public_card(&pin, &expected, &Sha256::digest(&backup).into()).unwrap();
    let recovered = root_backup::open(&backup, &recovery, &expected).unwrap();
    let recovered_key = SigningKey::from_slice(recovered.as_bytes()).unwrap();
    assert_eq!(
        recovered_key.verifying_key().to_sec1_point(false),
        key.verifying_key().to_sec1_point(false)
    );
    let material = json!({"root_pin_b64":STANDARD.encode(pin),"independently_compared_fingerprint_b64":STANDARD.encode(compared),"encrypted_backup_b64":STANDARD.encode(&backup),"public_card_b64":STANDARD.encode(&card)});
    let mut issue_op = material.clone();
    issue_op["kind"] = json!("root_issue");
    let prep = browser
        .post(
            "/v1/review/preparations",
            json!({"version":1,"request_id":Uuid::new_v4(),"operation":issue_op}),
        )
        .await;
    let issue_id = identity(&prep);
    browser
        .post("/v1/review/preparations/confirm", issue_id.clone())
        .await;
    let mut issue_body = issue_id.clone();
    issue_body
        .as_object_mut()
        .unwrap()
        .extend(material.as_object().unwrap().clone());
    let issued = browser.post("/v1/review/root/issue", issue_body).await;
    let repeated = browser
        .post("/v1/review/root/issue-status", issue_id.clone())
        .await;
    for key in [
        "root_challenge_id",
        "reauth_challenge_id",
        "reauth_nonce_b64",
        "unsigned_enrollment_b64",
        "custody_statement_b64",
        "expires_ms",
    ] {
        assert_eq!(repeated[key], issued[key], "{key}");
    }
    let pending = browser.post("/v1/review/session/context", request()).await;
    assert_eq!(pending["root_state"]["kind"], "pending_enrollment");
    browser.post("/v1/review/session/confirm", issue_id).await;
    let unsigned = b64(&issued, "unsigned_enrollment_b64");
    let challenge = crate::sealed_root_enrollment::parse(&unsigned).unwrap();
    assert_eq!(challenge.account_id, *account.as_bytes());
    assert_eq!(
        Uuid::from_bytes(challenge.user_id).to_string(),
        context["owner_user"].as_str().unwrap()
    );
    assert_eq!(
        Uuid::from_bytes(challenge.session_id).to_string(),
        context["review_owner_session"].as_str().unwrap()
    );
    let enrollment = sign(
        &key,
        &crate::sealed_root_enrollment::transcript(&unsigned).unwrap(),
    );
    let custody = sign(
        &key,
        &[
            b"ZTSE/root-custody/v1\0".as_slice(),
            &(unsigned.len() as u32).to_be_bytes(),
            &unsigned,
            &Sha256::digest(&backup),
            &Sha256::digest(&card),
            &compared,
        ]
        .concat(),
    );
    let completion = json!({"root_challenge_id":issued["root_challenge_id"],"reauth_challenge_id":issued["reauth_challenge_id"],"reauth_nonce_b64":issued["reauth_nonce_b64"],
        "unsigned_enrollment_b64":STANDARD.encode(&unsigned),"enrollment_signature_b64":STANDARD.encode(enrollment),"custody_signature_b64":STANDARD.encode(&custody),
        "independently_compared_fingerprint_b64":STANDARD.encode(compared),"encrypted_backup_b64":STANDARD.encode(&backup),"public_card_b64":STANDARD.encode(&card)});
    let mut wrong_kit = completion.clone();
    wrong_kit["kind"] = json!("root_complete");
    wrong_kit["independently_compared_fingerprint_b64"] = json!(STANDARD.encode([99u8; 32]));
    assert!(
        !browser
            .request(
                "/v1/review/preparations",
                json!({"version":1,"request_id":Uuid::new_v4(),"operation":wrong_kit})
            )
            .await
            .0
            .is_success()
    );
    let mut wrong_domain = completion.clone();
    wrong_domain["enrollment_signature_b64"] =
        json!(STANDARD.encode(sign(&key, b"synthetic separate signature domain")));
    for (candidate, password) in [
        (&completion, "incorrect synthetic password"),
        (&wrong_domain, "synthetic-review-password"),
    ] {
        let mut operation = candidate.clone();
        operation["kind"] = json!("root_complete");
        let prepared = browser
            .post(
                "/v1/review/preparations",
                json!({"version":1,"request_id":Uuid::new_v4(),"operation":operation}),
            )
            .await;
        let original = identity(&prepared);
        browser
            .post("/v1/review/preparations/confirm", original.clone())
            .await;
        let mut body = original.clone();
        body.as_object_mut()
            .unwrap()
            .extend(candidate.as_object().unwrap().clone());
        body["password"] = json!(password);
        assert!(
            !browser
                .request("/v1/review/root/complete", body)
                .await
                .0
                .is_success()
        );
        for table in [
            "sealed_manifest_authorities",
            "sealed_root_receipts",
            "sealed_root_custody",
        ] {
            assert_eq!(f.count(table).await, 0, "{table}");
        }
        assert_eq!(
            f.owner
                .query_one("SELECT state FROM public.review_access_root_reauth", &[])
                .await
                .unwrap()
                .get::<_, String>(0),
            "pending"
        );
        let terminal = browser
            .post("/v1/review/preparations/cancel", original)
            .await;
        assert_eq!(terminal["state"], "rejected_no_effect");
    }
    let mut complete_op = completion.clone();
    complete_op["kind"] = json!("root_complete");
    let prep = browser
        .post(
            "/v1/review/preparations",
            json!({"version":1,"request_id":Uuid::new_v4(),"operation":complete_op}),
        )
        .await;
    let complete_id = identity(&prep);
    browser
        .post("/v1/review/preparations/confirm", complete_id.clone())
        .await;
    let mut complete = complete_id.clone();
    complete
        .as_object_mut()
        .unwrap()
        .extend(completion.as_object().unwrap().clone());
    complete["password"] = json!("synthetic-review-password");
    let counter = crate::auth::tests::PASSWORD_VERIFICATIONS.with(Arc::clone);
    let before = counter.load(std::sync::atomic::Ordering::SeqCst);
    let (first, second) = tokio::join!(
        browser.request("/v1/review/root/complete", complete.clone()),
        browser.request("/v1/review/root/complete", complete.clone())
    );
    assert_eq!(
        [first.0, second.0]
            .iter()
            .filter(|status| status.is_success())
            .count(),
        1,
        "one exact completion must win"
    );
    let receipt = if first.0.is_success() {
        first.2
    } else {
        second.2
    };
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::SeqCst),
        before + 1,
        "duplicate Checking must not run another password worker"
    );
    assert_eq!(receipt["actor_owner_user"], context["owner_user"]);
    assert_eq!(
        receipt["actor_review_owner_session"],
        context["review_owner_session"]
    );
    assert!(
        !browser
            .request("/v1/review/root/complete", complete)
            .await
            .0
            .is_success()
    );
    let mut read = request();
    read["independently_compared_fingerprint_b64"] = json!(STANDARD.encode(compared));
    let (status, headers, observed) = browser
        .request("/v1/review/root/result", read.clone())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert_eq!(observed["request_id"], read["request_id"]);
    assert_eq!(observed["actor_owner_user"], receipt["actor_owner_user"]);
    assert_eq!(
        observed["actor_review_owner_session"],
        receipt["actor_review_owner_session"]
    );
    let export = browser.post("/v1/review/root/custody-export", read).await;
    assert_eq!(b64(&export, "encrypted_backup_b64"), backup);
    assert_eq!(b64(&export, "public_card_b64"), card);
    assert_eq!(b64(&export, "unsigned_enrollment_b64"), unsigned);
    assert_eq!(b64(&export, "custody_signature_b64"), custody);
    let (status, headers, _) = browser
        .request("/v1/review/session/confirm", complete_id.clone())
        .await;
    assert_eq!(status, StatusCode::OK);
    browser.apply(&headers); // Lose completion ACK body too.
    browser
        .post("/v1/review/session/confirm", complete_id)
        .await;
    assert_eq!(
        browser.post("/v1/review/session/context", request()).await["root_state"]["kind"],
        "enrolled"
    );
    for table in [
        "sealed_manifest_authorities",
        "sealed_root_enrollments",
        "sealed_root_receipts",
        "sealed_root_custody",
    ] {
        assert_eq!(f.count(table).await, 1, "{table}");
    }
    for table in ["sessions", "owner_mfa"] {
        assert_eq!(f.count(table).await, 0, "{table}");
    }
    // Real config A->B->A is revision3, never revival of revision1 credentials.
    f.owner.execute("UPDATE public.review_realm_installation SET active_config_digest=$1,active_config_revision=2",&[&&[8u8;32][..]]).await.unwrap();
    f.owner.execute("UPDATE public.review_realm_installation SET active_config_digest=$1,active_config_revision=3",&[&&f.access.scope.config[..]]).await.unwrap();
    let (status, headers, _) = browser
        .request("/v1/review/session/context", request())
        .await;
    assert!(!status.is_success());
    assert!(!headers.contains_key(header::SET_COOKIE));
    drop(browser);
    f.cleanup().await;
}
