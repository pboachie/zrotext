// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{auth, sealed_outbound::tests::TestCase};
use argon2::{Argon2, PasswordHasher};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
    response::Response,
};
use serde_json::{Value, json};
use totp_rs::{Builder, Secret};
use tower::ServiceExt;

async fn request(
    router: &Router,
    path: &str,
    credentials: &auth::SessionCredentials,
    body: Value,
    csrf: bool,
) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("origin", "https://owner.example.test")
        .header("content-type", "application/json")
        .header(
            "cookie",
            format!(
                "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                credentials.token, credentials.csrf_token
            ),
        );
    if csrf {
        builder = builder.header("x-zrotext-csrf", &credentials.csrf_token);
    }
    router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses signed isolated fixtures"]
async fn owner_session_expiry_during_grant_or_approval_insert_rolls_back_authority() {
    let mut outcomes = Vec::new();
    for approval in [false, true] {
        let (case, connector, connector_key) = TestCase::with_agent_connector().await;
        let db = case.connect().await;
        db.batch_execute(include_str!(
            "../../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"
        ))
        .await
        .unwrap();
        let password = Uuid::new_v4().to_string();
        let hash = Argon2::default()
            .hash_password(password.as_bytes())
            .unwrap()
            .to_string();
        db.execute(
            "UPDATE users SET password_hash=$2 WHERE id=$1",
            &[&case.user, &hash],
        )
        .await
        .unwrap();
        let credentials = auth::login(
            &db,
            &case.hasher,
            &format!("{}@example.invalid", case.user.simple()),
            &password,
        )
        .await
        .unwrap();
        let separator = if case.url.contains('?') { '&' } else { '?' };
        let state = AuthHttpState::new(
            format!(
                "{}{separator}options=-csearch_path%3D{}",
                case.url, case.schema
            ),
            Arc::new(auth::TokenHasher::new(crate::test_keys::key(76)).unwrap()),
            "https://owner.example.test".into(),
            Arc::new(super::super::DisabledVerificationDispatcher),
        )
        .unwrap()
        .with_agent_grants_enabled();
        let router = super::super::router(state);
        let now: i64 = db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let body = json!({"current_password":password,"grant":{"connector_id":connector,"connector_key_id":connector_key,"signer_key_id":case.signer,"device_id":case.device,"line_id":case.line,"binding_generation":1,"recipient":"+12","metadata_allowed":true,"content_allowed":false,"draft_allowed":false,"send_allowed":true,"reader_identity":null,"model_provider_identity":null,"model_reads_content":false,"owner_self_notification":true,"expires_ms":now+90_000,"message_limit":3,"turn_limit":2}});
        let (route, body) = if approval {
            let created = request(&router, "/agent-grants", &credentials, body, true).await;
            assert_eq!(created.status(), StatusCode::CREATED);
            let created = json_body(created).await;
            (
                format!(
                    "/agent-grants/{}/approvals",
                    created["grant_id"].as_str().unwrap()
                ),
                json!({"current_password":password,"action_id":Uuid::new_v4(),"envelope_b64":STANDARD.encode(case.envelope(Uuid::new_v4()).await),"not_before_ms":now}),
            )
        } else {
            ("/agent-grants".to_owned(), body)
        };
        let before: i64 = db
            .query_one("SELECT count(*) FROM api_keys", &[])
            .await
            .unwrap()
            .get(0);
        let table = if approval {
            "agent_authority_approvals"
        } else {
            "agent_authority_grants"
        };
        db.batch_execute(&format!("CREATE SEQUENCE owner_insert_delays; CREATE FUNCTION delay_agent_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('owner_insert_delays'); PERFORM pg_sleep(6); RETURN NEW; END $$; CREATE TRIGGER delay_agent_insert BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION delay_agent_insert();")).await.unwrap();
        db.execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1",
            &[&credentials.id],
        )
        .await
        .unwrap();
        let status = request(&router, &route, &credentials, body, true)
            .await
            .status();
        assert!(
            db.query_one("SELECT is_called FROM owner_insert_delays", &[])
                .await
                .unwrap()
                .get::<_, bool>(0),
            "must reach the actual final insert delay"
        );
        let after: i64 = db
            .query_one("SELECT count(*) FROM api_keys", &[])
            .await
            .unwrap()
            .get(0);
        let rows: i64 = db
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        outcomes.push((approval, status, before == after, rows));
        case.cleanup().await;
    }
    assert!(
        outcomes.iter().all(
            |(_, status, unchanged, rows)| *status == StatusCode::UNAUTHORIZED
                && *unchanged
                && *rows == 0
        ),
        "expired owner writes must roll back authority: {outcomes:?}"
    );
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses a signed fixture and isolated disposable schema"]
async fn owner_http_grant_mfa_csrf_exact_approval_and_revocation_are_enforced() {
    let (case, connector, connector_key) = TestCase::with_agent_connector().await;
    let mut db = case.connect().await;
    db.batch_execute(include_str!(
        "../../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"
    ))
    .await
    .unwrap();
    let password = Uuid::new_v4().to_string();
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .unwrap()
        .to_string();
    db.execute(
        "UPDATE users SET password_hash=$2 WHERE id=$1",
        &[&case.user, &hash],
    )
    .await
    .unwrap();
    let email = format!("{}@example.invalid", case.user.simple());
    let credentials = auth::login(&db, &case.hasher, &email, &password)
        .await
        .unwrap();
    let owner = auth::authenticate_session(&db, &case.hasher, &credentials.token)
        .await
        .unwrap();
    let cipher = Arc::new(auth::mfa::MfaCipher::new(vec![5; 32]).unwrap());
    let enrollment = auth::mfa::begin_enrollment(&mut db, &cipher, &owner, &password)
        .await
        .unwrap();
    let factor = Builder::new()
        .with_secret(Secret::try_from_base32(&enrollment.secret_base32).unwrap())
        .build()
        .unwrap();
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let recovery = auth::mfa::confirm_enrollment(
        &mut db,
        &cipher,
        &case.hasher,
        &owner,
        &factor.generate(seconds).to_string(),
    )
    .await
    .unwrap();
    let base = &case.url;
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{}", case.schema);
    let state = AuthHttpState::new(
        url,
        Arc::new(auth::TokenHasher::new(crate::test_keys::key(76)).unwrap()),
        "https://owner.example.test".into(),
        Arc::new(super::super::DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_mfa_cipher(cipher)
    .with_agent_grants_enabled();
    let router = super::super::router(state);
    let now: i64 = db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let grant = json!({"connector_id":connector,"connector_key_id":connector_key,"signer_key_id":case.signer,"device_id":case.device,"line_id":case.line,"binding_generation":1,"recipient":"+12","metadata_allowed":true,"content_allowed":true,"draft_allowed":false,"send_allowed":true,"reader_identity":connector,"model_provider_identity":null,"model_reads_content":false,"owner_self_notification":true,"expires_ms":now+90_000,"message_limit":3,"turn_limit":2});
    let body = json!({"current_password":password,"code":recovery.codes[0],"grant":grant});
    assert_eq!(
        request(&router, "/agent-grants", &credentials, body.clone(), false)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut missing = body.clone();
    missing["code"] = Value::Null;
    assert_eq!(
        request(&router, "/agent-grants", &credentials, missing, true)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut bad_password = body.clone();
    bad_password["current_password"] = json!("wrong-synthetic-password");
    assert_eq!(
        request(&router, "/agent-grants", &credentials, bad_password, true)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = request(&router, "/agent-grants", &credentials, body.clone(), true).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;
    let grant_id = Uuid::parse_str(created["grant_id"].as_str().unwrap()).unwrap();
    let token = created["token"].as_str().unwrap();
    assert!(
        auth::authenticate_api_key(&db, &case.hasher, token)
            .await
            .is_err()
    );
    let agent = auth::agent_grants::authenticate_agent(&db, &case.hasher, token)
        .await
        .unwrap();
    assert!(
        agent
            .require(crate::agent_authority::Operation::Send)
            .is_ok()
    );
    assert!(
        agent
            .require(crate::agent_authority::Operation::Draft)
            .is_err()
    );
    assert_eq!(
        request(&router, "/agent-grants", &credentials, body, true)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let message = Uuid::new_v4();
    let envelope = case.envelope(message).await;
    let action = Uuid::new_v4();
    let approval = json!({"current_password":password,"code":recovery.codes[1],"action_id":action,"envelope_b64":STANDARD.encode(&envelope),"not_before_ms":now});
    let route = format!("/agent-grants/{grant_id}/approvals");
    let response = request(&router, &route, &credentials, approval.clone(), true).await;
    assert_eq!(response.status(), StatusCode::OK);
    let result = json_body(response).await;
    assert_eq!(
        STANDARD
            .decode(result["action_digest_b64"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    let row=db.query_one("SELECT message_id,line_id,device_id,unsigned_digest,approved_by_user,approved_session FROM agent_authority_approvals WHERE account_id=$1 AND action_id=$2",&[&case.account,&action]).await.unwrap();
    assert_eq!(row.get::<_, Uuid>(0), message);
    assert_eq!(row.get::<_, Uuid>(1), case.line);
    assert_eq!(row.get::<_, Uuid>(2), case.device);
    assert_eq!(row.get::<_, Vec<u8>>(3).len(), 32);
    assert_eq!(row.get::<_, Uuid>(4), case.user);
    assert_eq!(row.get::<_, Uuid>(5), credentials.id);
    let mut edited = approval;
    edited["code"] = json!(recovery.codes[2]);
    edited["not_before_ms"] = json!(now + 1);
    assert_eq!(
        request(&router, &route, &credentials, edited, true)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let proof = json!({"current_password":password,"code":recovery.codes[2]});
    assert_eq!(
        request(
            &router,
            &format!("/agent-grants/{grant_id}/revoke"),
            &credentials,
            proof,
            true
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        auth::agent_grants::authenticate_agent(&db, &case.hasher, token)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_api_key(&db, &case.hasher, token)
            .await
            .is_err()
    );
    let read = Request::builder()
        .uri("/agent-grants")
        .header(
            "cookie",
            format!("__Host-zrotext_session={}", credentials.token),
        )
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(read).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = json_body(response).await;
    assert!(listed["grants"][0]["revoked_ms"].is_number());
    assert_eq!(listed["grants"][0]["reader_identity"], json!(connector));
    assert_eq!(listed["grants"][0]["model_provider_identity"], Value::Null);
    assert_eq!(listed["grants"][0]["model_reads_content"], json!(false));
    assert!(listed["grants"][0].get("token").is_none());
    assert!(listed["grants"][0].get("recipient").is_none());
    assert_eq!(listed["truncated"], json!(false));
    assert_eq!(listed["next_cursor"], Value::Null);
    let missing_cursor = Request::builder()
        .uri(format!("/agent-grants?before={}", Uuid::new_v4()))
        .header(
            "cookie",
            format!("__Host-zrotext_session={}", credentials.token),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.oneshot(missing_cursor).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    drop(db);
    case.cleanup().await;
}
