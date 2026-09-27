// SPDX-License-Identifier: AGPL-3.0-only
//! JSON request bodies for the API routers.
//!
//! `axum::Json` rejects a malformed body, a missing or wrong `Content-Type`,
//! a type mismatch, a missing field or a `deny_unknown_fields` violation with
//! a plain-text 400, 415 or 422 carrying serde's message. [`ApiJson`] maps
//! each of those to the documented `400 {"code":"invalid_request"}` envelope
//! with `Cache-Control: no-store`, and never echoes the parser message, which
//! would reveal internal field names. A body that cannot be read (for example
//! one over the router's `DefaultBodyLimit`, 413) keeps axum's response.

use axum::{
    Json,
    extract::{FromRequest, Request, rejection::JsonRejection},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;

/// Drop-in replacement for `axum::Json` as a request extractor.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiJsonRejection;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(ApiJsonRejection)
    }
}

/// The rejection keeps axum's detail private; only the status class leaves.
#[derive(Debug)]
pub struct ApiJsonRejection(JsonRejection);

impl IntoResponse for ApiJsonRejection {
    fn into_response(self) -> Response {
        if let JsonRejection::BytesRejection(rejection) = self.0 {
            // A body that could not be read (such as the router's length limit)
            // is not a JSON error; keep axum's status for it.
            let mut response = rejection.into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            return response;
        }
        (
            StatusCode::BAD_REQUEST,
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "code": "invalid_request" })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests;
