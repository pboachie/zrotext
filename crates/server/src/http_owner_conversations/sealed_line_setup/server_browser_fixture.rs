// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit test-only ordinary HTTP composition; never included in a server binary.
use super::{tests::Case, *};
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::HeaderMap,
    middleware::Next,
};
use p256::ecdsa::{Signature, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write};
use tokio::sync::{Mutex, Notify};

struct Fixture {
    case: Mutex<Option<Case>>,
    origin: String,
    token: String,
    roots: Mutex<BTreeMap<Uuid, crate::sealed_root_enrollment::Challenge>>,
    done: Arc<Notify>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    version: u8,
    operation: String,
    challenge_id: Option<Uuid>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Capture only the real server-issued nonce, independently of the caller's
// downloaded signing packet. Forward exactly the actual handler response.
async fn capture(State(f): State<Arc<Fixture>>, request: Request, next: Next) -> Response {
    let selected = request.method() == axum::http::Method::POST
        && request.uri().path() == "/v1/auth/sealed-root/challenge";
    let response = next.run(request).await;
    if !selected || !response.status().is_success() {
        return response;
    }
    let (parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, 8192).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let challenge = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("unsigned_enrollment_b64")
                .and_then(Value::as_str)
                .and_then(|s| B.decode(s).ok())
        })
        .and_then(|b| crate::sealed_root_enrollment::parse(&b).ok());
    let Some(challenge) = challenge else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut roots = f.roots.lock().await;
    roots.clear();
    roots.insert(Uuid::from_bytes(challenge.challenge_id), challenge);
    Response::from_parts(parts, Body::from(bytes))
}

async fn control(
    State(f): State<Arc<Fixture>>,
    headers: HeaderMap,
    Json(command): Json<Command>,
) -> Response {
    if headers
        .get("x-zrotext-fixture-token")
        .and_then(|h| h.to_str().ok())
        != Some(f.token.as_str())
        || command.version != 1
        || command.operation.len() > 32
    {
        return fail();
    }
    let guard = f.case.lock().await;
    let Some(c) = guard.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let p = &c.owner.principal;
    let account = p.tenant.account_id();
    let mut db = c.owner.f.connect().await;
    db.batch_execute("SET statement_timeout='5s'; SET lock_timeout='3s'")
        .await
        .unwrap();
    let base = json!({"version":1,"synthetic":true,"operation":command.operation});
    let mut response = base;
    match command.operation.as_str() {
        "snapshot" if command.challenge_id.is_none() => {
            let r = db.query_one("SELECT (SELECT count(*) FROM sealed_root_receipts WHERE account_id=$1),(SELECT count(*) FROM sealed_line_key_receipts WHERE account_id=$1),(SELECT count(*) FROM sealed_line_key_receipts WHERE account_id=$1 AND activated_ms IS NOT NULL),(SELECT count(*) FROM sealed_line_activation_exchanges WHERE account_id=$1 AND ack_sent_at IS NOT NULL)", &[&account]).await.unwrap();
            response["counters"] = json!({"rootCompletions":r.get::<_,i64>(0),"lineRegistrations":r.get::<_,i64>(1),"lineApprovals":r.get::<_,i64>(2),"phoneAcknowledgments":r.get::<_,i64>(3)});
        }
        "root_sign_scope" => {
            let Some(id) = command.challenge_id else {
                return fail();
            };
            let roots = f.roots.lock().await;
            let Some(issued) = roots.get(&id) else {
                return fail();
            };
            let Some(r) = db.query_opt("SELECT root_fingerprint,nonce_digest,issued_ms,expires_ms FROM sealed_root_challenges WHERE account_id=$1 AND user_id=$2 AND session_id=$3 AND challenge_id=$4 AND origin=$5 AND consumed_ms IS NULL AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint", &[&account,&p.user_id,&p.session_id,&id,&f.origin]).await.unwrap() else { return fail(); };
            if issued.account_id != *account.as_bytes()
                || issued.user_id != *p.user_id.as_bytes()
                || issued.session_id != *p.session_id.as_bytes()
                || issued.origin != f.origin
                || r.get::<_, Vec<u8>>(0) != issued.root_fingerprint
                || r.get::<_, Vec<u8>>(1) != Sha256::digest(issued.nonce).as_slice()
                || r.get::<_, i64>(2) as u64 != issued.issued_ms
                || r.get::<_, i64>(3) as u64 != issued.expires_ms
            {
                return fail();
            }
            response["expected"] = json!({"account":account,"origin":f.origin,"rootFingerprint":hex(&issued.root_fingerprint),"user":p.user_id,"session":p.session_id,"challenge":id,"nonce":hex(&issued.nonce),"issued":issued.issued_ms.to_string(),"expires":issued.expires_ms.to_string()});
        }
        "line_sign_scope" => {
            let Some(id) = command.challenge_id else {
                return fail();
            };
            let Some(r) = db.query_opt("SELECT transcript FROM sealed_line_key_challenges WHERE account_id=$1 AND user_id=$2 AND session_id=$3 AND device_id=$4 AND line_id=$5 AND challenge_id=$6 AND completed_ms IS NULL AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint", &[&account,&p.user_id,&p.session_id,&c.device,&c.line,&id]).await.unwrap() else { return fail(); };
            let statement =
                zrotext_root_material::line_key_registration::decode(&r.get::<_, Vec<u8>>(0))
                    .unwrap();
            let s = statement.scope();
            let Some(lease) = db.query_opt("SELECT connection_epoch,deployment_epoch,site_id,instance_id FROM device_sessions WHERE account_id=$1 AND device_id=$2 AND lease_until>clock_timestamp()", &[&account,&c.device]).await.unwrap() else { return fail(); };
            if s.connection_epoch != lease.get::<_, i64>(0) as u64
                || s.deployment_epoch != lease.get::<_, i64>(1) as u64
                || s.site_id != lease.get::<_, String>(2)
                || s.instance_id != lease.get::<_, String>(3)
            {
                return fail();
            }
            response["expected"] = json!({"account":account,"origin":f.origin,"rootFingerprint":hex(statement.root_fingerprint()),"user":p.user_id,"session":p.session_id,"device":c.device,"line":c.line,"generation":s.next_generation.to_string(),"challenge":id,"nonce":hex(&s.nonce),"issued":s.issued_ms.to_string(),"expires":s.expires_ms.to_string(),"approvalFingerprint":hex(&s.approval_fingerprint),"pairedSigningFingerprint":hex(&s.paired_signing_fingerprint),"connectionEpoch":s.connection_epoch.to_string(),"deploymentEpoch":s.deployment_epoch.to_string(),"site":s.site_id,"instance":s.instance_id});
        }
        "submit_phone_proof" => {
            let Some(id) = command.challenge_id else {
                return fail();
            };
            let Some(ch) = exchange::next_challenge(&mut db, c.session())
                .await
                .unwrap()
            else {
                return fail();
            };
            if ch.challenge_id != id || ch.line_id != c.line || ch.generation != 1 {
                return fail();
            }
            let observation = crate::sealed_inbound::line_activation::SimObservation {
                android_api_level: 31,
                active_subscription_count: 1,
                selected_subscription_id: 7,
            };
            let selected = crate::sealed_inbound::line_activation::LineChallenge {
                id,
                account_id: account,
                line_id: c.line,
                device_id: c.device,
                generation: ch.generation,
                nonce: ch.nonce,
            };
            let statement = crate::sealed_inbound::line_activation::device_line_statement(
                &selected,
                observation,
            )
            .unwrap();
            let signature: Signature = c.paired.sign(&statement);
            let der = signature.to_der();
            if !exchange::record_device_proof(
                &mut db,
                c.session(),
                exchange::DeviceProof {
                    challenge_id: id,
                    observation,
                    signature_der: der.as_bytes(),
                },
            )
            .await
            .unwrap()
            {
                return fail();
            }
            response["ok"] = json!(true);
        }
        "acknowledge_phone" => {
            let Some(id) = command.challenge_id else {
                return fail();
            };
            let Some(ack) = exchange::next_ack(&mut db, c.session(), &[]).await.unwrap() else {
                return fail();
            };
            if ack.challenge_id != id
                || ack.line_id != c.line
                || !exchange::confirm_ack(&mut db, c.session(), ack)
                    .await
                    .unwrap()
            {
                return fail();
            }
            response["ok"] = json!(true);
        }
        "finish" if command.challenge_id.is_none() => {
            response["ok"] = json!(true);
            f.done.notify_one();
        }
        _ => return StatusCode::BAD_REQUEST.into_response(),
    }
    Json(response).into_response()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL, selected reserved HTTPS frontend and compiled browser package; explicit fixture consumer only"]
async fn ordinary_setup_server_browser_fixture() {
    let origin = std::env::var("ZT_OWNER_SETUP_FIXTURE_ORIGIN").expect("selected fixture origin");
    let selected = url::Url::parse(&origin).unwrap();
    assert_eq!(selected.host_str(), Some("owner.example.test"));
    assert!(crate::sealed_root_enrollment::canonical_origin(&origin));
    assert!(selected.port().is_some_and(|port| port > 0 && port != 443));
    let package = std::env::var_os("ZT_OWNER_SETUP_BROWSER_ASSETS")
        .expect("checked synthetic browser package");
    let assets =
        super::super::browser_assets::BrowserAssets::load(std::path::Path::new(&package)).unwrap();
    assets.require_owner_setup().unwrap();
    let mut c = Case::without_root().await;
    let p = &c.owner.principal;
    let account = p.tenant.account_id();
    // Start genuinely unenrolled. Never erase protected enrollment history to
    // manufacture eligibility for another first-root ceremony.
    c.owner
        .f
        .db
        .batch_execute(include_str!(
            "../../../../../deploy/compose/migrations/069_sealed_root_custody.sql"
        ))
        .await
        .unwrap();
    let root_factor = c.factor().await;
    let line_factor = c.factor().await;
    let mut setup = c.state();
    setup.mfa_cipher = Arc::new(std::mem::replace(
        &mut c.owner.cipher,
        MfaCipher::new(crate::test_keys::key(92)).unwrap(),
    ));
    setup.owner.canonical_origin = origin.clone();
    let auth = crate::http_auth::AuthHttpState::new(
        setup.owner.database_url.clone(),
        setup.owner.auth_hasher.clone(),
        origin.clone(),
        Arc::new(crate::http_auth::DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_mfa_cipher(setup.mfa_cipher.clone())
    .with_root_custody_enabled();
    let app = Router::new()
        .nest("/v1/auth", crate::http_auth::router(auth))
        .merge(super::router(setup.clone()))
        .merge(super::super::router_with_browser_sdk(setup.owner, assets))
        .merge(crate::owner_ui::conversation_router());
    let point = c
        .paired
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    let baseline = json!({"accountId":account,"userId":p.user_id,"sessionId":p.session_id,"deviceId":c.device,"lineId":c.line,"nextGeneration":"1","pairedPoint":hex(&point),"pairedFingerprintHex":hex(&Sha256::digest(&point)),"rootFactor":root_factor,"lineFactor":line_factor,"cookies":[{"name":"__Host-zrotext_session","value":c.owner.token},{"name":"__Host-zrotext_csrf","value":c.owner.csrf}],"lease":{"connectionEpoch":"1","deploymentEpoch":"1","siteId":"manifest-test","instanceId":"fixture"}});
    let token = hex(&rand::random::<[u8; 32]>());
    let done = Arc::new(Notify::new());
    let f = Arc::new(Fixture {
        case: Mutex::new(Some(c)),
        origin: origin.clone(),
        token: token.clone(),
        roots: Mutex::new(BTreeMap::new()),
        done: done.clone(),
    });
    let app = app
        .layer(middleware::from_fn_with_state(f.clone(), capture))
        .merge(
            Router::new()
                .route("/__fixture/owner-setup", post(control))
                .layer(DefaultBodyLimit::max(2048))
                .with_state(f.clone()),
        );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { done.notified().await })
            .await
            .unwrap();
    });
    println!(
        "ZT_OWNER_SETUP_READY {}",
        json!({"version":1,"synthetic":true,"port":port,"controlToken":token,"origin":origin,"baseline":baseline})
    );
    std::io::stdout().flush().unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(600), &mut server).await;
    if result.is_err() {
        server.abort();
        let _ = server.await;
    }
    // In-flight HTTP tasks can retain state after the listener is aborted.
    // Invalidate control admission and clean the owned schema independently of
    // Arc ownership, before reporting timeout/failure to the fixture consumer.
    let case = f.case.lock().await.take().expect("owned fixture case");
    case.cleanup().await;
    result
        .expect("fixture consumer did not complete")
        .expect("fixture failed");
}

#[test]
fn setup_fixture_control_refuses_unselected_fields_and_private_material() {
    for command in [
        json!({"version":1,"operation":"snapshot","account":"caller-selected"}),
        json!({"version":1,"operation":"root_sign_scope","private_key":"synthetic-canary"}),
        json!({"version":1,"operation":"submit_phone_proof","signature":"caller-selected"}),
        json!({"version":1,"operation":"finish","challenge_id":"not-a-uuid"}),
    ] {
        assert!(serde_json::from_value::<Command>(command).is_err());
    }
    assert!(serde_json::from_value::<Command>(json!({"version":1,"operation":"snapshot"})).is_ok());
}
