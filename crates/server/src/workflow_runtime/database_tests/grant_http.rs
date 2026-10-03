// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_auth::{self, AuthHttpState, DisabledVerificationDispatcher};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable real owner workflow grant setup"]
async fn owner_http_setup_requires_csrf_real_factor_and_exact_scope_then_issues_and_revokes_dedicated_credential()
 {
    let case = Case::new().await;
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let session = Uuid::new_v4();
    case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')",
        &[&session,&case.f.account,&case.owner.user_id,&digest(b"session-v1",&token).as_slice(),&digest(b"csrf-v1",&csrf).as_slice()]).await.unwrap();
    let separator = if case.f.url.contains('?') { '&' } else { '?' };
    let state = AuthHttpState::new(
        format!(
            "{}{separator}options=-csearch_path%3D{}",
            case.f.url, case.f.schema
        ),
        Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        "https://owner.example.test".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_workflow_grants_enabled(true)
    .with_mfa_cipher(Arc::new(
        mfa::MfaCipher::new(crate::test_keys::key(89)).unwrap(),
    ));
    let body = json!({"current_password":case.password.as_str(),"code":case.factor,
        "connector_id":case.request.connector,"context_id":case.request.context,"contact_id":case.request.contact,
        "purpose":"operational","permissions":["context_metadata"],"expires_at_ms":case.request.expires_ms});
    let request = |method: &str, path: &str, body: Option<Value>, with_csrf: bool| {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("origin", "https://owner.example.test")
            .header(
                "cookie",
                format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),
            );
        if with_csrf {
            req = req.header("x-zrotext-csrf", &csrf);
        }
        if let Some(body) = body {
            req.header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        } else {
            req.body(Body::empty()).unwrap()
        }
    };
    let app = http_auth::router(state);
    assert_eq!(
        app.clone()
            .oneshot(request(
                "POST",
                "/workflow-grants",
                Some(body.clone()),
                false
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut wrong = body.clone();
    wrong["code"] = json!("invalid-factor");
    assert_ne!(
        app.clone()
            .oneshot(request("POST", "/workflow-grants", Some(wrong), true))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    let mut foreign = body.clone();
    foreign["context_id"] = json!(Uuid::new_v4());
    assert_ne!(
        app.clone()
            .oneshot(request("POST", "/workflow-grants", Some(foreign), true))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    for patch in [json!({"permissions":["send"]}), json!({"expires_at_ms":0})] {
        let mut invalid = body.clone();
        for (name, value) in patch.as_object().unwrap() {
            invalid[name] = value.clone();
        }
        assert_ne!(
            app.clone()
                .oneshot(request("POST", "/workflow-grants", Some(invalid), true))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
    }
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM workflow_integration_grants", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/workflow-grants",
            Some(body.clone()),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    let issued = value["token"].as_str().unwrap();
    let principal = authenticate(&case.f.db, &case.hasher, issued)
        .await
        .unwrap();
    assert!(
        read_context_metadata(
            &mut case.f.connect().await,
            &principal,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_ok()
    );
    assert!(
        propose_action(
            &mut case.f.connect().await,
            &principal,
            Uuid::new_v4(),
            case.descriptor().await
        )
        .await
        .is_err()
    );
    let other_email = format!("{}@example.test", Uuid::new_v4().simple());
    let other_password = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let other = auth::register(
        &mut case.f.connect().await,
        &case.hasher,
        &other_email,
        &other_password,
    )
    .await
    .unwrap();
    assert!(
        auth::verify_email_with_password(
            &mut case.f.connect().await,
            &case.hasher,
            &other.verification_token,
            &other_password
        )
        .await
        .unwrap()
    );
    let other_session = auth::login(&case.f.db, &case.hasher, &other_email, &other_password)
        .await
        .unwrap();
    let foreign_request = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/workflow-grants/{}",
            value["grant_id"].as_str().unwrap()
        ))
        .header("origin", "https://owner.example.test")
        .header(
            "cookie",
            format!(
                "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                other_session.token, other_session.csrf_token
            ),
        )
        .header("x-zrotext-csrf", other_session.csrf_token)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(foreign_request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                "DELETE",
                &format!("/workflow-grants/{}", Uuid::new_v4()),
                None,
                true
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                "DELETE",
                &format!("/workflow-grants/{}", value["grant_id"].as_str().unwrap()),
                None,
                true
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        authenticate(&case.f.db, &case.hasher, issued)
            .await
            .is_err()
    );
    case.f.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",&[&case.f.account]).await.unwrap();
    // Current manifest refusal precedes MFA consumption; this must not merely
    // fail because the successful issuance already consumed the recovery code.
    assert_eq!(
        app.oneshot(request("POST", "/workflow-grants", Some(body), true))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    case.f.cleanup().await;
}
