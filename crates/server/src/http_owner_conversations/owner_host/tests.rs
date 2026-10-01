// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::{SessionPrincipal, TokenHasher},
    sealed_manifest_store::{self, tests::Fixture},
};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn app(url: String) -> Router {
    router(OwnerConversationsState {
        database_url: url,
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        canonical_origin: "https://test.example".into(),
    })
}
fn fixture_app(f: &Fixture) -> Router {
    let sep = if f.url.contains('?') { '&' } else { '?' };
    app(format!(
        "{}{sep}options=-csearch_path%3D{}",
        f.url, f.schema
    ))
}
async fn credentials(f: &Fixture, owner: &SessionPrincipal) -> (String, String) {
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let hash = |domain: &[u8], value: &str| {
        let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(84)).unwrap();
        mac.update(domain);
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    f.db.execute(
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
async fn post(f: &Fixture, credentials: &(String, String), path: &str, body: Value) -> Response {
    fixture_app(f)
        .oneshot(
            Request::post(path)
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
async fn admit(f: &Fixture) {
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let admitted = sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
        .await
        .unwrap();
    drop(admitted);
    tx.commit().await.unwrap();
}
fn activation_body(f: &Fixture) -> Value {
    json!({"consent":{"device_id":f.device,"line_id":f.line,"binding_generation":1,"peer":"+12",
        "disclosure_version":"conversation-content-v1","content_transfer_confirmed":true},
        "next_manifest":STANDARD.encode(&f.bytes)})
}
fn record(f: &Fixture, role: u8) -> ([u8; 32], [u8; 65], Vec<u8>) {
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let point: [u8; 65] = key
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let algorithm = if role == 1 { [0, 16] } else { [1, 1] };
    let id: [u8; 32] =
        Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &algorithm, &point].concat()).into();
    let mut bytes = vec![role];
    bytes.extend(id);
    bytes.extend(point);
    bytes.extend(if role == 1 {
        *f.device.as_bytes()
    } else {
        [0; 16]
    });
    bytes.extend(f.line.as_bytes());
    bytes.extend(if role == 1 { 4u16 } else { 1u16 }.to_be_bytes());
    bytes.extend(&f.bytes[37..53]);
    bytes.push(1);
    (id, point, bytes)
}
async fn enrollment_case() -> (Fixture, SessionPrincipal, Value) {
    let (mut f, owner) = super::super::tests::prepared().await;
    let (phone, _, phone_record) = record(&f, 1);
    f.bytes.splice(151..151, phone_record);
    f.bytes[150] += 1;
    f.resign();
    admit(&f).await;
    super::super::enable_conversation(
        &mut f.connect().await,
        &owner,
        &serde_json::from_value::<ConversationConsent>(activation_body(&f)["consent"].clone())
            .unwrap(),
    )
    .await
    .unwrap();
    let predecessor: [u8; 32] = Sha256::digest(&f.bytes[..f.bytes.len() - 64]).into();
    f.advance();
    let (signer, point, signer_record) = record(&f, 5);
    let at = 151
        + f.bytes[151..f.bytes.len() - 64]
            .chunks_exact(149)
            .position(|r| r[0] == 6)
            .unwrap()
            * 149;
    f.bytes.splice(at..at, signer_record);
    f.bytes[150] += 1;
    f.resign();
    let body = json!({"device_id":f.device,"line_id":f.line,"binding_generation":1,"peer":"+12",
        "phone_reader":STANDARD.encode(phone),"archive_reader":STANDARD.encode(f.readers[0].key_id),
        "signer":STANDARD.encode(signer),"public_point":STANDARD.encode(point),
        "predecessor":STANDARD.encode(predecessor),"signed_successor":STANDARD.encode(&f.bytes)});
    (f, owner, body)
}

#[test]
fn owner_host_accepts_only_canonical_bounded_encodings_and_derived_identity() {
    assert_eq!(decode("YQ==", 1, 1).unwrap(), b"a");
    for value in ["YQ", "YQ==\n", "YR==", "YQ==="] {
        assert!(decode(value, 1, 1).is_err());
    }
    assert!(fixed::<32>(&STANDARD.encode([0; 31])).is_err());
    assert!(
        serde_json::from_value::<ActivationRequest>(
            json!({"account_id":Uuid::new_v4(),"consent":{},"next_manifest":""})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<EnrollmentRequest>(json!({"originating_session":Uuid::new_v4()}))
            .is_err()
    );
}
#[tokio::test]
async fn owner_host_rejects_missing_cookie_and_bearer_before_polling_body() {
    for path in [
        "/v1/owner/conversation/activation",
        "/v1/owner/conversation/enrollment",
        "/v1/owner/conversation/bootstrap",
    ] {
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            app("invalid".into()).oneshot(Request::post(path).body(body).unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app("invalid".into())
            .oneshot(
                Request::post(path)
                    .header("authorization", "Bearer invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}

fn selection(f: &Fixture) -> Value {
    json!({"device_id":f.device,"line_id":f.line,"binding_generation":1,"peer":"+12"})
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_bootstrap_projects_only_public_candidates_and_never_advances_manifest_or_consent() {
    let (f, owner, _) = enrollment_case().await;
    let creds = credentials(&f, &owner).await;
    let before: String =
        f.db.query_one(
            "SELECT to_jsonb(a)::text FROM sealed_manifest_authorities a",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let consent: String =
        f.db.query_one(
            "SELECT to_jsonb(c)::text FROM owner_conversation_consents c",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let response = post(
        &f,
        &creds,
        "/v1/owner/conversation/bootstrap",
        selection(&f),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 20 * 1024).await.unwrap()).unwrap();
    assert_eq!(value["trust_candidate"], true);
    assert_eq!(value["owner_session_live"], true);
    assert_eq!(value["consent_live"], true);
    assert_eq!(value["account_id"], f.account.to_string());
    assert_eq!(value["session_id"], owner.session_id.to_string());
    assert_eq!(value["phase"], "unprepared");
    assert!(value["interval_id"].is_null());
    assert_eq!(value["manifest_version"], "1");
    assert_eq!(
        decode(value["phone_reader_point"].as_str().unwrap(), 65, 65)
            .unwrap()
            .len(),
        65
    );
    let manifest = decode(value["current_manifest"].as_str().unwrap(), 364, 9751).unwrap();
    assert_eq!(
        manifest,
        f.db.query_one("SELECT manifest FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0)
    );
    assert_eq!(
        before,
        f.db.query_one(
            "SELECT to_jsonb(a)::text FROM sealed_manifest_authorities a",
            &[]
        )
        .await
        .unwrap()
        .get::<_, String>(0)
    );
    assert_eq!(
        consent,
        f.db.query_one(
            "SELECT to_jsonb(c)::text FROM owner_conversation_consents c",
            &[]
        )
        .await
        .unwrap()
        .get::<_, String>(0)
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM conversation_intervals", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_bootstrap_checks_selected_interval_consent_and_live_device_before_projection() {
    let (f, owner, _) = enrollment_case().await;
    let creds = credentials(&f, &owner).await;
    let statement = activation::begin(
        &mut f.connect().await,
        &owner,
        &serde_json::from_value::<ConversationConsent>(activation_body(&f)["consent"].clone())
            .unwrap(),
        &f.bytes,
    )
    .await
    .unwrap();
    activation::tests::activate(&f, &statement).await;
    let response = post(
        &f,
        &creds,
        "/v1/owner/conversation/bootstrap",
        selection(&f),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 20 * 1024).await.unwrap()).unwrap();
    assert_eq!(value["phase"], "active");
    assert_eq!(value["interval_id"], statement.interval.to_string());
    assert_eq!(value["manifest_version"], "2");
    super::super::revoke_conversation(&mut f.connect().await, &owner)
        .await
        .unwrap();
    let response = post(
        &f,
        &creds,
        "/v1/owner/conversation/bootstrap",
        selection(&f),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 20 * 1024).await.unwrap()).unwrap();
    assert_eq!(value["consent_live"], false);
    f.db.execute("UPDATE sites SET draining=TRUE", &[])
        .await
        .unwrap();
    assert_eq!(
        post(
            &f,
            &creds,
            "/v1/owner/conversation/bootstrap",
            selection(&f)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_bootstrap_denies_foreign_selection_clock_rollback_and_revoked_roles() {
    let (f, owner, _) = enrollment_case().await;
    let creds = credentials(&f, &owner).await;
    for field in ["device_id", "line_id"] {
        let mut changed = selection(&f);
        changed[field] = json!(Uuid::new_v4());
        assert_eq!(
            post(&f, &creds, "/v1/owner/conversation/bootstrap", changed)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    f.db.execute("UPDATE sealed_manifest_authorities SET last_verified_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+60000",&[]).await.unwrap();
    assert_eq!(
        post(
            &f,
            &creds,
            "/v1/owner/conversation/bootstrap",
            selection(&f)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    f.cleanup().await;
    // A durable high-water mark cannot be rolled back, including by a fixture.
    let (f, owner, _) = enrollment_case().await;
    let creds = credentials(&f, &owner).await;
    f.db.execute("UPDATE device_keys SET revoked_at=clock_timestamp()", &[])
        .await
        .unwrap();
    assert_eq!(
        post(
            &f,
            &creds,
            "/v1/owner/conversation/bootstrap",
            selection(&f)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_activation_returns_canonical_original_derived_from_actual_session_without_phone_consent()
 {
    let (mut f, owner) = super::super::tests::prepared().await;
    admit(&f).await;
    f.advance();
    let creds = credentials(&f, &owner).await;
    let response = post(
        &f,
        &creds,
        "/v1/owner/conversation/activation",
        activation_body(&f),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        STATEMENT_CONTENT_TYPE
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    let statement = activation::Statement::decode(&bytes).unwrap();
    assert_eq!(statement.account, f.account);
    assert_eq!(statement.device, f.device);
    assert_eq!(statement.originating_session, owner.session_id);
    assert_eq!(statement.connection_epoch, 1);
    assert_eq!(statement.site, "manifest-test");
    let row=f.db.query_one("SELECT statement,phase,approval_signature IS NULL,installation_signature IS NULL FROM conversation_intervals",&[]).await.unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), bytes);
    assert_eq!(row.get::<_, String>(1), "pending");
    assert!(row.get::<_, bool>(2) && row.get::<_, bool>(3));
    let duplicate = post(
        &f,
        &creds,
        "/v1/owner/conversation/activation",
        activation_body(&f),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_bootstrap_rechecks_phone_lease_after_observed_consent_lock_wait() {
    let (f, owner, _) = enrollment_case().await;
    let creds = credentials(&f, &owner).await;
    f.db.execute(
        // Expire before the existing three-second runtime lock deadline, which
        // must remain enabled. The observed barrier below proves it was live.
        "UPDATE device_sessions SET lease_until=clock_timestamp()+interval '2 seconds'",
        &[],
    )
    .await
    .unwrap();
    let mut blocker = f.connect().await;
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT account_id FROM owner_conversation_consents FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    let blocker_pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    {
        let response = post(
            &f,
            &creds,
            "/v1/owner/conversation/bootstrap",
            selection(&f),
        );
        tokio::pin!(response);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            tokio::select! {
                ended=&mut response=>panic!("bootstrap ended before consent barrier: {}", ended.status()),
                row=async { f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", &[&blocker_pid]).await }=>{
                    if row.unwrap().get::<_,bool>(0) { break; }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(f.db.query_one("SELECT lease_until>clock_timestamp() FROM device_sessions", &[]).await.unwrap().get::<_,bool>(0), "phone lease must still be live at the observed barrier");
        // Keep polling the request while waiting for the actual database lease expiry.
        loop {
            tokio::select! {
                ended=&mut response=>panic!("bootstrap passed a held consent barrier: {}", ended.status()),
                row=async { f.db.query_one("SELECT lease_until<=clock_timestamp() FROM device_sessions", &[]).await }=>{
                    if row.unwrap().get::<_,bool>(0) { break; }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("bootstrap must block while its actual phone lease expires");
        tx.commit().await.unwrap();
        assert_eq!(response.await.status(), StatusCode::FORBIDDEN);
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_activation_rejects_forged_scope_manifest_csrf_and_revoked_owner_without_interval() {
    let (mut f, owner) = super::super::tests::prepared().await;
    admit(&f).await;
    f.advance();
    let creds = credentials(&f, &owner).await;
    let valid = activation_body(&f);
    let mut bad_csrf = creds.clone();
    bad_csrf.1 = "ztc_invalid".into();
    assert_eq!(
        post(
            &f,
            &bad_csrf,
            "/v1/owner/conversation/activation",
            valid.clone()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    for field in ["device_id", "line_id"] {
        let mut body = valid.clone();
        body["consent"][field] = json!(Uuid::new_v4());
        assert_eq!(
            post(&f, &creds, "/v1/owner/conversation/activation", body)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let mut altered = f.bytes.clone();
    let n = altered.len();
    altered[n - 1] ^= 1;
    let mut body = valid.clone();
    body["next_manifest"] = json!(STANDARD.encode(altered));
    assert_eq!(
        post(&f, &creds, "/v1/owner/conversation/activation", body)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    assert_eq!(
        post(&f, &creds, "/v1/owner/conversation/activation", valid)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM conversation_intervals", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn owner_enrollment_installs_exact_root_signed_successor_once_and_rejects_scope_or_point_tampering()
 {
    let (f, owner, body) = enrollment_case().await;
    let creds = credentials(&f, &owner).await;
    for field in ["device_id", "line_id"] {
        let mut changed = body.clone();
        changed[field] = json!(Uuid::new_v4());
        assert_eq!(
            post(&f, &creds, "/v1/owner/conversation/enrollment", changed)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    for field in ["phone_reader", "archive_reader", "signer", "predecessor"] {
        let mut changed = body.clone();
        changed[field] = json!(STANDARD.encode([7; 32]));
        assert_eq!(
            post(&f, &creds, "/v1/owner/conversation/enrollment", changed)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let mut changed = body.clone();
    changed["public_point"] = json!(STANDARD.encode([0; 65]));
    assert_eq!(
        post(&f, &creds, "/v1/owner/conversation/enrollment", changed)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.db.query_one("SELECT version FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        post(
            &f,
            &creds,
            "/v1/owner/conversation/enrollment",
            body.clone()
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&f, &creds, "/v1/owner/conversation/enrollment", body)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.db.query_one("SELECT manifest FROM sealed_manifest_authorities", &[])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0),
        f.bytes
    );
    f.cleanup().await;
}
