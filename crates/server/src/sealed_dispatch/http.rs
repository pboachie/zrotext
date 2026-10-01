// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded device-signed opaque retrieval; owner API tokens confer no access.
use super::{Error, fetch, wire::Fetch};
use crate::{alpha_policy::AlphaPolicy, runtime_db};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
struct FetchState {
    database_url: String,
    site: String,
    epoch: i64,
    policy: Arc<AlphaPolicy>,
    capacity: Arc<Semaphore>,
}

/// Mount only after the explicit sealed dispatch and alpha policy gates pass.
pub fn router(database_url: String, site: String, epoch: i64, policy: Arc<AlphaPolicy>) -> Router {
    Router::new()
        .route("/v1/sealed/dispatch/envelope", post(retrieve))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn(no_store))
        .with_state(FetchState {
            database_url,
            site,
            epoch,
            policy,
            capacity: Arc::new(Semaphore::new(8)),
        })
}

async fn retrieve(State(state): State<FetchState>, Json(request): Json<Fetch>) -> Response {
    if !state.policy.allows_account(request.grant.account_id)
        || super::wire::fetch_transcript(&request.grant).is_err()
        || !(11..=107).contains(&request.signature_der.len())
    {
        return refusal(StatusCode::NOT_FOUND);
    }
    let Ok(_permit) = state.capacity.try_acquire() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(mut client) = runtime_db::connect_device(&state.database_url).await else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE);
    };
    match fetch(
        &mut client,
        &request,
        &state.site,
        state.epoch,
        &state.policy,
    )
    .await
    {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/vnd.zrotext.sealed.v1"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            bytes,
        )
            .into_response(),
        Err(Error::Database(_)) => refusal(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => refusal(StatusCode::NOT_FOUND),
    }
}

fn refusal(status: StatusCode) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        "sealed execution unavailable",
    )
        .into_response()
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn malformed_or_unbounded_fetch_fails_before_storage_and_never_caches() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/vectors/sealed-dispatch-01.json"
        ))
        .unwrap();
        let policy = Arc::new(
            AlphaPolicy::parse(
                Some("true"),
                vector["grant"]["account_id"].as_str(),
                Some("+12"),
            )
            .unwrap(),
        );
        let app = router(
            "postgresql://fetch-refusal.invalid/db".into(),
            "fetch-test".into(),
            1,
            policy,
        );
        let mut bad = serde_json::json!({"grant":vector["grant"],"signature_der":"A".repeat(96)});
        bad["grant"]["envelope_sha256"] = "invalid".into();
        for (body, status) in [
            (vec![b' '; 4097], StatusCode::PAYLOAD_TOO_LARGE),
            (serde_json::to_vec(&bad).unwrap(), StatusCode::NOT_FOUND),
            (b"{}".to_vec(), StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/sealed/dispatch/envelope")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }
}
