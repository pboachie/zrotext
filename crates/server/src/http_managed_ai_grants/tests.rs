// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{body::Body, http::Request};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
mod database;
mod support;
use support::*;

#[test]
fn wrappers_reject_unknown_duplicate_missing_and_mistyped_fields() {
    let scope = request_scope();
    let body = create_body(&scope).to_string();
    assert!(serde_json::from_str::<Create>(&body).is_ok());
    let mut unknown = create_body(&scope);
    unknown["authority"] = json!(true);
    assert!(serde_json::from_value::<Create>(unknown).is_err());
    let duplicate = format!("{{\"password\":\"synthetic password\",{}", &body[1..]);
    assert!(serde_json::from_str::<Create>(&duplicate).is_err());
    let nested_duplicate = body.replace("\"max_calls\":8", "\"max_calls\":8,\"max_calls\":8");
    assert_ne!(nested_duplicate, body);
    assert!(serde_json::from_str::<Create>(&nested_duplicate).is_err());
    let mut nested_unknown = create_body(&scope);
    nested_unknown["request"]["policy"]["trusted"] = json!(true);
    assert!(serde_json::from_value::<Create>(nested_unknown).is_err());
    for name in ["password", "factor", "request"] {
        let mut missing = create_body(&scope);
        missing.as_object_mut().unwrap().remove(name);
        assert!(serde_json::from_value::<Create>(missing).is_err());
    }
    assert!(serde_json::from_str::<Revoke>("{}").is_ok());
    assert!(serde_json::from_str::<Revoke>("[]").is_ok());
    for invalid in ["null", "[1]", "{\"password\":\"synthetic password\"}"] {
        assert!(serde_json::from_str::<Revoke>(invalid).is_err());
    }
    for invalid in [
        json!(0),
        json!(128),
        json!(-1),
        json!(true),
        json!(1.5),
        json!("1"),
        Value::Null,
    ] {
        assert!(
            serde_json::from_value::<Narrow>(json!({"expected_version":invalid,"request":scope}))
                .is_err()
        );
    }
    for valid in [1, 127] {
        assert!(
            serde_json::from_value::<Narrow>(json!({"expected_version":valid,"request":scope}))
                .is_ok()
        );
    }
    let mut replacement = create_body(&scope);
    replacement["expected_version"] = json!(1);
    assert!(serde_json::from_value::<Replace>(replacement.clone()).is_ok());
    replacement["code"] = json!("synthetic factor");
    assert!(serde_json::from_value::<Replace>(replacement).is_err());
}

#[test]
fn positional_compatibility_preserves_typed_order_counts_and_raw_integers() {
    let scope = request_scope();
    let policy = json!([
        scope.policy.id,
        scope.policy.version,
        scope.policy.digest,
        scope.policy.reader,
        scope.policy.reader_generation
    ]);
    let source = &scope.selections[0];
    let selection = json!([
        {"workflow_context_v1": null},
        source.id,
        source.version,
        source.digest
    ]);
    let positional = json!([
        policy,
        scope.contact,
        {"operational": null},
        scope.instruction_digest,
        scope.expires_ms,
        scope.max_calls,
        scope.max_input_bytes,
        scope.max_cost_microunits,
        [selection]
    ]);
    let parsed =
        serde_json::from_str::<crate::managed_ai::GrantRequest>(&positional.to_string()).unwrap();
    assert_eq!(parsed, scope);
    assert!(parsed.validate().is_ok());
    let create = json!(["synthetic password", "synthetic factor", positional]);
    let parsed = serde_json::from_str::<Create>(&create.to_string()).unwrap();
    assert_eq!(parsed.request, scope);
    let replacement = json!([1, "synthetic password", "synthetic factor", positional]);
    assert_eq!(
        serde_json::from_str::<Replace>(&replacement.to_string())
            .unwrap()
            .request,
        scope
    );
    let narrow = json!([127, positional]);
    assert_eq!(
        serde_json::from_str::<Narrow>(&narrow.to_string())
            .unwrap()
            .request,
        scope
    );
    for extra in [false, true] {
        let mut wrong = create.clone();
        let fields = wrong.as_array_mut().unwrap();
        if extra {
            fields.push(json!("extra"));
        } else {
            fields.pop();
        }
        assert!(serde_json::from_str::<Create>(&wrong.to_string()).is_err());
    }
    let mut wrong = create;
    wrong.as_array_mut().unwrap().swap(0, 2);
    assert!(serde_json::from_str::<Create>(&wrong.to_string()).is_err());
    let raw = json!({"expected_version":1,"request":scope}).to_string();
    for token in ["1.0", "1e0", "true", "\"1\""] {
        let wrong = raw.replace(
            "\"expected_version\":1",
            &format!("\"expected_version\":{token}"),
        );
        assert_ne!(wrong, raw);
        assert!(serde_json::from_str::<Narrow>(&wrong).is_err());
    }
    let negative_zero = raw.replace("\"max_calls\":8", "\"max_calls\":-0");
    assert_ne!(negative_zero, raw);
    assert!(serde_json::from_str::<Narrow>(&negative_zero).is_err());
    let id = Uuid::from_u128(0xabcdef0123456789abcdef0123456789);
    for alias in [
        id.simple().to_string(),
        id.to_string().to_uppercase(),
        format!("{{{id}}}"),
        format!("urn:uuid:{id}"),
    ] {
        let mut wire = serde_json::to_value(&scope).unwrap();
        wire["policy"]["id"] = json!(alias);
        assert_eq!(
            serde_json::from_str::<crate::managed_ai::GrantRequest>(&wire.to_string())
                .unwrap()
                .policy
                .id,
            id
        );
        assert!(grant_id(&alias).is_err());
    }
}

#[test]
fn secret_limits_count_decoded_utf8_bytes_and_uuid_paths_have_one_spelling() {
    for (text, accepted) in [
        ("x".repeat(11), false),
        ("x".repeat(12), true),
        ("x".repeat(1024), true),
        ("x".repeat(1025), false),
        ("é".repeat(6), true),
        ("é".repeat(513), false),
    ] {
        assert_eq!(
            serde_json::from_value::<requests::Secret<12, 1024>>(json!(text)).is_ok(),
            accepted
        );
    }
    for (text, accepted) in [
        (String::new(), false),
        ("x".repeat(1), true),
        ("x".repeat(256), true),
        ("x".repeat(257), false),
    ] {
        assert_eq!(
            serde_json::from_value::<requests::Secret<1, 256>>(json!(text)).is_ok(),
            accepted
        );
    }
    let id = Uuid::from_u128(0xabcdef0123456789abcdef0123456789);
    assert_eq!(grant_id(&id.to_string()), Ok(id));
    for invalid in [
        id.to_string().to_uppercase(),
        id.simple().to_string(),
        format!("{{{id}}}"),
        Uuid::nil().to_string(),
    ] {
        assert!(grant_id(&invalid).is_err());
    }
}

#[test]
fn local_auth_and_observable_core_error_statuses_preserve_public_variants() {
    for (auth, status) in [
        (AuthError::InvalidInput, 400),
        (AuthError::InvalidCredentials, 401),
        (AuthError::Unauthorized, 401),
        (AuthError::EmailNotVerified, 403),
        (AuthError::Forbidden, 403),
        (AuthError::Conflict, 409),
        (AuthError::SmsOwnerKeyActive, 409),
        (AuthError::Crypto, 503),
        (AuthError::Password, 500),
        (AuthError::RateLimited, 429),
        (
            AuthError::MfaRequired {
                account_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
            },
            401,
        ),
    ] {
        assert_eq!(authentication(auth).status().as_u16(), status);
    }
    for (core, status) in [
        (Error::Invalid, 400),
        (Error::Conflict, 409),
        (Error::Forbidden, 403),
        (Error::NotFound, 404),
        (Error::Unavailable, 503),
        (Error::Archive(ConversationError::Invalid), 400),
        (Error::Archive(ConversationError::Unavailable), 503),
    ] {
        assert_eq!(error(core).status().as_u16(), status);
    }
}

#[test]
fn maintained_scope_validation_rejects_overflow_and_noncanonical_selections() {
    let mut scope = request_scope();
    assert!(scope.validate().is_ok());
    scope.selections.clear();
    assert!(scope.validate().is_ok()); // Empty reduction remains legitimate.
    for n in 1..=32 {
        scope.selections.push(crate::managed_ai::Selection {
            kind: crate::managed_ai::SourceKind::WorkflowContextV1,
            id: Uuid::from_u128(n),
            version: 128,
            digest: [3; 32],
        });
    }
    assert!(scope.validate().is_ok());
    let thirty_two = scope.clone();
    scope.selections.push(crate::managed_ai::Selection {
        kind: crate::managed_ai::SourceKind::WorkflowContextV1,
        id: Uuid::from_u128(33),
        version: 1,
        digest: [3; 32],
    });
    assert!(scope.validate().is_err());
    for field in [
        "max_calls",
        "max_input_bytes",
        "max_cost_microunits",
        "expires_ms",
    ] {
        let mut wire = serde_json::to_value(&thirty_two).unwrap();
        wire[field] = json!(-1);
        assert!(
            serde_json::from_value::<crate::managed_ai::GrantRequest>(wire)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for mutation in 0..4 {
        let mut bad = thirty_two.clone();
        match mutation {
            0 => bad.selections.swap(0, 1),
            1 => bad.selections[1] = bad.selections[0].clone(),
            2 => bad.selections[0].version = 129,
            _ => bad.selections[0].digest = [0; 32],
        }
        assert!(bad.validate().is_err());
    }
}

#[tokio::test]
async fn disabled_router_is_empty_and_enabled_router_authenticates_before_body() {
    let absent = router(unreachable_owner(), None, false)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(COLLECTION)
                .body(stalled_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    let app = router(unreachable_owner(), None, true);
    for path in [
        COLLECTION.to_owned(),
        format!("{COLLECTION}/{}/replace", Uuid::new_v4()),
        format!("{COLLECTION}/{}/narrow", Uuid::new_v4()),
        format!("{COLLECTION}/{}/revoke", Uuid::new_v4()),
    ] {
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            app.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(stalled_body())
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_private(&response);
    }
    for request in [
        Request::builder()
            .method("POST")
            .uri(COLLECTION)
            .header(header::AUTHORIZATION, "synthetic")
            .body(stalled_body())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri(format!("{COLLECTION}?request=synthetic"))
            .body(stalled_body())
            .unwrap(),
    ] {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_private(&response);
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(COLLECTION)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_private(&response);
}

// Parser isolation is deliberate: these controls do not stand in for OwnerMutation.
#[tokio::test]
async fn actual_api_json_refuses_raw_duplicates_utf8_and_oversize_without_echo() {
    async fn parse(ApiJson(_body): ApiJson<Create>) -> StatusCode {
        StatusCode::NO_CONTENT
    }
    let app = Router::new()
        .route("/", post(parse))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(DEADLINE, boundary));
    let valid = create_body(&request_scope()).to_string();
    let duplicate = format!("{{\"factor\":\"synthetic factor\",{}", &valid[1..]);
    for (raw, status) in [
        (valid.into_bytes(), 204),
        (duplicate.into_bytes(), 400),
        (vec![0xff, 0xfe], 400),
        (vec![b' '; BODY_LIMIT + 1], 413),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(raw))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_private(&response);
        if status == 400 {
            assert_eq!(
                json_response(response).await,
                json!({"code":"invalid_request"})
            );
        }
    }
}

#[tokio::test]
async fn operation_deadline_cancels_a_stalled_future_and_seals_the_response() {
    let app = Router::new()
        .route(
            "/",
            post(|| async { futures_util::future::pending::<StatusCode>().await }),
        )
        .layer(middleware::from_fn_with_state(
            Duration::from_millis(20),
            boundary,
        ));
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_private(&response);
    assert_eq!(json_response(response).await, json!({"code":"unavailable"}));
}
