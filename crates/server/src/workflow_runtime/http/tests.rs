// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::workflow_runtime::{Operation, Permissions, database_tests::Case};
use axum::{body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

mod recipe_service;

fn state(case: &Case) -> WorkflowHttpState {
    let separator = if case.f.url.contains('?') { '&' } else { '?' };
    WorkflowHttpState {
        database_url: format!(
            "{}{separator}options=-csearch_path%3D{}",
            case.f.url, case.f.schema
        ),
        hasher: Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
    }
}
fn request(token: &str, body: Option<Value>) -> Request<Body> {
    let mut request = Request::builder()
        .uri("/v1/workflow/tools")
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(body) = body {
        request = request
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json");
        request
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    } else {
        request.body(Body::empty()).unwrap()
    }
}
async fn json_body(response: Response) -> Value {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    serde_json::from_slice(
        &to_bytes(response.into_body(), RESPONSE_LIMIT)
            .await
            .unwrap(),
    )
    .unwrap()
}
fn metadata(context: Uuid, request: Uuid) -> Value {
    json!({"method":"workflow.context.metadata","params":{"context_id":context,"request_id":request}})
}

#[tokio::test]
async fn off_mount_and_wrong_authentication_realms_never_access_database() {
    let state = WorkflowHttpState {
        database_url: "unavailable".into(),
        hasher: Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
    };
    assert_eq!(
        router(state.clone(), false)
            .oneshot(request("", None))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    for token in ["", "ztk_secret", "ztd_secret", "zts_secret", "ztw_bad"] {
        let response = router(state.clone(), true)
            .oneshot(request(token, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_body(response).await,
            json!({"error":{"code":"unauthorized"}})
        );
    }
    for field in [header::COOKIE, header::ORIGIN] {
        let mut request = request(&format!("ztw_{}", "A".repeat(43)), None);
        request
            .headers_mut()
            .insert(field, "synthetic".parse().unwrap());
        assert_eq!(
            router(state.clone(), true)
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let mut duplicate = request(&format!("ztw_{}", "A".repeat(43)), None);
    duplicate
        .headers_mut()
        .append(header::AUTHORIZATION, "Bearer synthetic".parse().unwrap());
    assert_eq!(
        router(state, true)
            .oneshot(duplicate)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn authenticated_http_calls_real_metadata_proposal_and_exact_status_without_queue_effects() {
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions = Permissions::new(&[
        Operation::ContextMetadata,
        Operation::Propose,
        Operation::Status,
    ])
    .unwrap();
    let descriptor = case.descriptor().await;
    let issued = case.issue().await.unwrap();
    let app = router(state(&case), true);
    let response = app
        .clone()
        .oneshot(request(&issued.token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let ready = json_body(response).await;
    assert_eq!(ready["available"], true);
    assert_eq!(
        ready["scope"]["context_id"],
        case.header.context.to_string()
    );
    assert_eq!(ready["scope"]["line_id"], case.header.line.to_string());
    assert_eq!(ready["send_semantics"], "owner_bound_prepared_only");
    let methods = ready["methods"].as_array().unwrap();
    assert_eq!(methods.len(), 8);
    assert!(methods.iter().all(|m| m["transport_mounted"] == true));
    assert_eq!(
        methods
            .iter()
            .filter(|m| m["permission_granted"] == true)
            .count(),
        3
    );
    let metadata_id = Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(request(
            &issued.token,
            Some(metadata(case.header.context, metadata_id)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = json_body(response).await;
    assert_eq!(metadata["kind"], "context_metadata");
    assert_eq!(
        metadata["result"]["source_content_digest"],
        descriptor.content_digest
    );
    let changed = json!({"method":"workflow.action.propose","params":{"request_id":metadata_id,"descriptor":descriptor}});
    assert_eq!(
        app.clone()
            .oneshot(request(&issued.token, Some(changed)))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let proposal = json!({"method":"workflow.action.propose","params":{"request_id":Uuid::new_v4(),"descriptor":descriptor}});
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(proposal.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let first = json_body(response).await;
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(proposal)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await, first);
    let status = json!({"method":"workflow.action.status","params":{"request_id":Uuid::new_v4(),"context_id":case.header.context,"action_id":descriptor.key().unwrap().action_id}});
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(status)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await, first);
    let send = json!({"method":"workflow.action.send","params":{"request_id":Uuid::new_v4(),"key":descriptor.key().unwrap(),"occurrence_id":null}});
    assert_eq!(
        app.oneshot(request(&issued.token, Some(send)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let counts=case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_actions),(SELECT count(*) FROM messages),(SELECT count(*) FROM workflow_schedule_occurrences)",&[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 1);
    assert_eq!(counts.get::<_, i64>(1), 0);
    assert_eq!(counts.get::<_, i64>(2), 0);
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn http_foreign_scope_malformed_body_identity_reuse_and_revocation_fail_closed() {
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::ContextMetadata]).unwrap();
    let issued = case.issue().await.unwrap();
    let app = router(state(&case), true);
    let response = app
        .clone()
        .oneshot(request(
            &issued.token,
            Some(metadata(Uuid::new_v4(), Uuid::new_v4())),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    for body in [
        json!({"method":"workflow.action.approve","params":{}}),
        json!({"method":"workflow.context.metadata","params":{"request_id":Uuid::new_v4(),"context_id":case.header.context,"authorized":true}}),
    ] {
        let response = app
            .clone()
            .oneshot(request(&issued.token, Some(body)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await,
            json!({"error":{"code":"invalid_request"}})
        );
    }
    let id = Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(request(
            &issued.token,
            Some(metadata(case.header.context, id)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let changed = json!({"method":"workflow.contact.read","params":{"request_id":id,"context_id":case.header.context}});
    assert_eq!(
        app.clone()
            .oneshot(request(&issued.token, Some(changed)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    crate::workflow_runtime::revoke_grant(
        &mut case.f.connect().await,
        &case.owner,
        issued.grant_id,
    )
    .await
    .unwrap();
    for body in [None, Some(metadata(case.header.context, Uuid::new_v4()))] {
        assert_eq!(
            app.clone()
                .oneshot(request(&issued.token, body))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn http_schedule_and_send_require_actual_owner_binding_and_replay_prepared_metadata_only() {
    use crate::encrypted_schedule::policy::WindowPolicy;
    use crate::http_owner_conversations::context::decisions::{self, model::Decision};
    let mut case = Case::with_signer(Some(120000)).await;
    case.request.permissions = Permissions::new(&[Operation::Schedule, Operation::Send]).unwrap();
    let issued = case.issue().await.unwrap();
    let row = case.f.db.query_one("SELECT to_char(t,'YYYY-MM-DD'),extract(hour FROM t)::int*60+extract(minute FROM t)::int FROM (SELECT (clock_timestamp() AT TIME ZONE 'UTC')-interval '2 minutes' t) v", &[]).await.unwrap();
    let opens: i32 = row.get(1);
    let policy = WindowPolicy {
        timezone: Some("UTC".into()),
        first_local_date: row.get(0),
        opens_minute: opens as u16,
        closes_minute: ((opens + 60) % 1440) as u16,
        repeat_every_days: None,
        max_occurrences: 1,
        pacing_seconds: 60,
    };
    let mut descriptor = case.descriptor().await;
    descriptor.window_id = policy.identity().unwrap();
    let proposed = decisions::register(
        &mut case.f.connect().await,
        &case.owner,
        Uuid::new_v4(),
        descriptor,
    )
    .await
    .unwrap();
    let app = router(state(&case), true);
    let schedule = json!({"method":"workflow.action.schedule","params":{"request_id":Uuid::new_v4(),"key":proposed.key,"policy":policy,"series_id":Uuid::new_v4(),"ordinal":0}});
    assert_eq!(
        app.clone()
            .oneshot(request(&issued.token, Some(schedule.clone())))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let approved = decisions::decide(
        &mut case.f.connect().await,
        &case.owner,
        Uuid::new_v4(),
        proposed.record_version,
        proposed.key,
        Decision::Approve,
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(schedule.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let occurrence = json_body(response).await;
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(schedule)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await, occurrence);
    let occurrence_id: Uuid =
        serde_json::from_value(occurrence["result"]["occurrence_id"].clone()).unwrap();
    let waiting = json!({"method":"workflow.action.send","params":{"request_id":Uuid::new_v4(),"key":approved.key,"occurrence_id":occurrence_id}});
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(waiting.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let waiting_result = json_body(response).await;
    assert_eq!(waiting_result["result"]["state"], "waiting_owner_binding");
    let dispatch: Uuid = case
        .f
        .db
        .query_one(
            "SELECT dispatch_id FROM workflow_schedule_occurrences WHERE id=$1",
            &[&occurrence_id],
        )
        .await
        .unwrap()
        .get(0);
    let (bound, message) = case.bind_message(approved, dispatch).await;
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(waiting)))
        .await
        .unwrap();
    assert_eq!(
        json_body(response).await,
        waiting_result,
        "old waiting identity cannot adopt a later owner binding"
    );
    let send = json!({"method":"workflow.action.send","params":{"request_id":Uuid::new_v4(),"key":bound.key,"occurrence_id":occurrence_id}});
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(send.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let prepared = json_body(response).await;
    assert_eq!(prepared["result"]["state"], "prepared");
    assert_eq!(prepared["result"]["message_id"], message.to_string());
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(send.clone())))
        .await
        .unwrap();
    assert_eq!(json_body(response).await, prepared);
    let cancel = json!({"method":"workflow.action.cancel","params":{"request_id":Uuid::new_v4(),"key":bound.key}});
    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(request(&issued.token, Some(cancel.clone())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            json!({"kind":"cancel","result":{"key":bound.key,"message_id":message,"state":"cancelled"}})
        );
    }
    let forged = json!({"method":"workflow.action.cancel","params":{"request_id":Uuid::new_v4(),"key":bound.key,"message_id":message}});
    assert_eq!(
        app.clone()
            .oneshot(request(&issued.token, Some(forged)))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let refund: i64 = case
        .f
        .db
        .query_one(
            "SELECT count(*) FROM usage_ledger WHERE entry_kind='refund'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(refund, 1);
    let count: i64 = case
        .f
        .db
        .query_one("SELECT count(*) FROM messages", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count, 1,
        "MCP/service send never materializes another message"
    );
    crate::workflow_runtime::revoke_grant(
        &mut case.f.connect().await,
        &case.owner,
        issued.grant_id,
    )
    .await
    .unwrap();
    assert_eq!(
        app.oneshot(request(&issued.token, Some(send)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable workflow schema"]
async fn http_content_returns_only_selected_ciphertext_and_rejects_oversized_authenticated_requests()
 {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut case = Case::new().await;
    case.request.permissions = Permissions::new(&[Operation::ContextContent]).unwrap();
    let projection = case.projection().await;
    case.request.content_envelope = Some(projection.clone());
    let issued = case.issue().await.unwrap();
    let app = router(state(&case), true);
    let body = json!({"method":"workflow.context.content","params":{"request_id":Uuid::new_v4(),"context_id":case.header.context}});
    let response = app
        .clone()
        .oneshot(request(&issued.token, Some(body)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content = json_body(response).await;
    assert_eq!(content["kind"], "context_content");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(content["result"]["envelope_base64url"].as_str().unwrap())
            .unwrap(),
        projection
    );
    assert_eq!(
        content["result"].as_object().unwrap().len(),
        3,
        "no plaintext/archive/credential fields"
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                &issued.token,
                Some(metadata(case.header.context, Uuid::new_v4()))
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let oversized = Request::builder()
        .method("POST")
        .uri("/v1/workflow/tools")
        .header(header::AUTHORIZATION, format!("Bearer {}", *issued.token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(vec![b' '; BODY_LIMIT + 1]))
        .unwrap();
    let response = app.clone().oneshot(oversized).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await,
        json!({"error":{"code":"invalid_request"}})
    );
    case.f
        .db
        .execute(
            "UPDATE workflow_connector_context_envelopes SET envelope=NULL WHERE grant_id=$1",
            &[&issued.grant_id],
        )
        .await
        .unwrap();
    let body = json!({"method":"workflow.context.content","params":{"request_id":Uuid::new_v4(),"context_id":case.header.context}});
    assert_eq!(
        app.oneshot(request(&issued.token, Some(body)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN,
        "no archive fallback after selected content disappears"
    );
    case.f.cleanup().await;
}
