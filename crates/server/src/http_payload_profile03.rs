// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit profile03 owner router. Startup must opt in after the matching
//! socket/current/effect composition is qualified; existing runtime defaults
//! do not mount it. Neither API bearers nor received owner selectors are used.
use crate::{
    auth::{
        self, TokenHasher,
        mfa::MfaCipher,
        ordinary_owner03::{self, step_up},
    },
    sealed_payload_election03::live,
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use std::{sync::Arc, time::Duration};
use tokio_postgres::IsolationLevel;

mod conversation;
mod request;
pub use conversation::router as conversation_router;
pub use conversation::send_router as reviewed_send_router;
use request::{Body, Operation};

#[derive(Clone)]
pub struct ProfileHttpState {
    database_url: String,
    hasher: Arc<TokenHasher>,
    cipher: Arc<MfaCipher>,
    origin: String,
}
impl ProfileHttpState {
    /// Inputs come from checked startup configuration independently of HTTP.
    /// No endpoint, factor or environment toggle is enabled by this constructor.
    pub fn new(
        database_url: String,
        hasher: Arc<TokenHasher>,
        cipher: Arc<MfaCipher>,
        origin: String,
    ) -> Result<Self, &'static str> {
        if database_url.is_empty() {
            return Err("profile database required");
        }
        crate::sealed_payload_election03::adapter_contract::origin_digest(&origin)?;
        Ok(Self {
            database_url,
            hasher,
            cipher,
            origin,
        })
    }
}

/// Explicit library composition only. A partial/missing schema or elevated
/// database caller refuses startup rather than downgrading the protocol.
pub async fn router(state: ProfileHttpState) -> Result<Router, &'static str> {
    let db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| "profile database unavailable")?;
    crate::payload_profile_elections::require(&*db)
        .await
        .map_err(|_| "profile schema unavailable")?;
    Ok(Router::new()
        .route(
            "/v1/account/sealed/payload-profile/bootstrap",
            post(bootstrap),
        )
        .route("/v1/account/sealed/payload-profile/current", post(current))
        .route(
            "/v1/account/sealed/payload-profile/challenges",
            post(reserve),
        )
        .route(
            "/v1/account/sealed/payload-profile/challenges/status",
            post(status),
        )
        .route(
            "/v1/account/sealed/payload-profile/challenges/proof",
            post(proof),
        )
        .route("/v1/account/sealed/payload-profile/elections", post(accept))
        .with_state(Arc::new(state)))
}

macro_rules! handler {
    ($name:ident,$op:ident) => {
        async fn $name(State(state): State<Arc<ProfileHttpState>>, request: Request) -> Response {
            wire_response(handle(&state, Operation::$op, request).await)
        }
    };
}
handler!(bootstrap, Bootstrap);
handler!(current, Current);
handler!(reserve, Reserve);
handler!(status, Status);
handler!(proof, Proof);
handler!(accept, Accept);

fn wire_response(result: Result<(StatusCode, serde_json::Value), StatusCode>) -> Response {
    let (status, value) = match result {
        Ok(reply) => reply,
        Err(status) => {
            let (status, error) = match status {
                StatusCode::BAD_REQUEST
                | StatusCode::REQUEST_TIMEOUT
                | StatusCode::PAYLOAD_TOO_LARGE
                | StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                    (StatusCode::BAD_REQUEST, "invalid_request")
                }
                StatusCode::UNAUTHORIZED => (status, "authentication_required"),
                StatusCode::FORBIDDEN => (status, "origin_or_csrf_refused"),
                StatusCode::NOT_FOUND => (status, "not_found"),
                StatusCode::CONFLICT => (status, "conflict"),
                StatusCode::GONE => (status, "expired"),
                StatusCode::UNPROCESSABLE_ENTITY => (status, "unsupported_state"),
                StatusCode::TOO_MANY_REQUESTS => (status, "rate_limited"),
                _ => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
            };
            (status, serde_json::json!({"error":error}))
        }
    };
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
}

fn mapped(e: live::Error) -> StatusCode {
    match e {
        live::Error::Authentication => StatusCode::FORBIDDEN,
        live::Error::Conflict => StatusCode::CONFLICT,
        live::Error::Expired => StatusCode::GONE,
        live::Error::NotFound => StatusCode::NOT_FOUND,
        live::Error::Unsupported => StatusCode::UNPROCESSABLE_ENTITY,
        live::Error::Unavailable | live::Error::Database(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
fn source(headers: &HeaderMap) -> Result<ordinary_owner03::RequestSource<'_>, StatusCode> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let single = |name: &str| {
        let mut values = headers.get_all(name).iter();
        let value = values
            .next()
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;
        if values.next().is_some() {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(value)
    };
    let cookie = |name: &str| {
        let mut found = None;
        for line in headers.get_all(header::COOKIE) {
            for part in line.to_str().map_err(|_| StatusCode::FORBIDDEN)?.split(';') {
                if let Some((key, value)) = part.trim().split_once('=')
                    && key == name
                    && found.replace(value).is_some()
                {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }
        found.ok_or(StatusCode::UNAUTHORIZED)
    };
    Ok(ordinary_owner03::RequestSource {
        session_cookie: cookie(crate::http_auth::SESSION_COOKIE)?,
        origin: single("origin")?,
        csrf_cookie: cookie(crate::http_auth::CSRF_COOKIE)?,
        csrf_header: single(crate::http_auth::CSRF_HEADER)?,
    })
}

async fn preflight(
    s: &ProfileHttpState,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<(), StatusCode> {
    let source = source(headers)?;
    let mut db = crate::runtime_db::connect(&s.database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let tx = db
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    crate::payload_profile_elections::require(&tx)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut owner = ordinary_owner03::authenticate(&tx, &s.hasher, &s.origin, source)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let identity = owner.selected_identity();
    let subject = format!("{}:{}", identity.account, identity.user);
    let allowed = auth::abuse_limits::consume_payload_profile(&tx, &s.hasher, &subject, mutation)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    owner
        .revalidate()
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    drop(owner);
    // This independent request debit survives later body/factor/effect refusal.
    // No effect or factor has been attempted in this transaction.
    tx.commit()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !allowed {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(())
}

async fn handle(
    s: &ProfileHttpState,
    op: Operation,
    request: Request,
) -> Result<(StatusCode, serde_json::Value), StatusCode> {
    let (parts, body) = request.into_parts();
    // Authenticate and commit request admission before reading an untrusted
    // stream, without holding owner locks or a DB client while it arrives.
    preflight(s, &parts.headers, op.mutation()).await?;
    if parts.headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = tokio::time::timeout(Duration::from_secs(5), to_bytes(body, 96 * 1024))
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let body = request::parse(op, &bytes)?;
    let mut db = crate::runtime_db::connect(&s.database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let tx = db
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut owner =
        ordinary_owner03::authenticate(&tx, &s.hasher, &s.origin, source(&parts.headers)?)
            .await
            .map_err(|_| StatusCode::FORBIDDEN)?;
    let reply = match body {
        Body::Current(line) => live::current(&tx, &mut owner, line, &s.origin)
            .await
            .map_err(mapped)?,
        Body::Bootstrap(line) => live::bootstrap(&tx, &mut owner, line, &s.origin)
            .await
            .map_err(mapped)?,
        Body::Status(opening, line) => live::status(&tx, &mut owner, opening, line)
            .await
            .map_err(mapped)?
            .projection(),
        Body::Proof(opening, challenge) => {
            let line:uuid::Uuid=tx.query_opt("SELECT line_id FROM public.payload_profile_election_challenges WHERE account_id=$1 AND opening_id=$2 AND challenge_id=$3",&[&owner.selected_identity().account,&opening,&challenge]).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?.ok_or(StatusCode::NOT_FOUND)?.try_get(0).map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
            let r = live::status(&tx, &mut owner, opening, line)
                .await
                .map_err(mapped)?;
            r.proof_projection(owner.checked_at_ms()).map_err(mapped)?
        }
        Body::Reserve {
            opening,
            line,
            successor,
            password,
            factor,
        } => {
            match live::status(&tx, &mut owner, opening, line).await {
                Ok(r) => {
                    if !r.matches_successor(&successor) {
                        return Err(StatusCode::CONFLICT);
                    }
                    let value = r.projection();
                    drop(owner);
                    tx.commit()
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    return Ok((StatusCode::OK, value));
                }
                Err(live::Error::NotFound) => {}
                Err(e) => return Err(mapped(e)),
            }
            let answer = {
                match step_up::verify(owner, &s.hasher, &s.cipher, &password, &factor)
                    .await
                    .map_err(|_| StatusCode::FORBIDDEN)?
                {
                    step_up::Outcome::Rejected(reason) => Err(reason),
                    step_up::Outcome::Verified(mut proof) => Ok(live::reserve(
                        &tx, &mut proof, opening, line, &successor, &s.origin,
                    )
                    .await
                    .map_err(mapped)?
                    .projection()),
                }
            };
            return finish_mutation(tx, answer).await;
        }
        Body::Accept {
            opening,
            challenge,
            successor,
            bundle,
            password,
            factor,
        } => {
            if let Some(value) =
                live::historical_accept(&tx, &mut owner, opening, challenge, &successor, &bundle)
                    .await
                    .map_err(mapped)?
            {
                drop(owner);
                tx.commit()
                    .await
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                return Ok((StatusCode::OK, value));
            }
            let answer = {
                match step_up::verify(owner, &s.hasher, &s.cipher, &password, &factor)
                    .await
                    .map_err(|_| StatusCode::FORBIDDEN)?
                {
                    step_up::Outcome::Rejected(reason) => Err(reason),
                    step_up::Outcome::Verified(mut proof) => Ok(live::accept(
                        &tx, &mut proof, opening, challenge, &successor, &bundle, &s.origin,
                    )
                    .await
                    .map_err(mapped)?),
                }
            };
            return finish_mutation(tx, answer).await;
        }
    };
    drop(owner);
    tx.commit()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((StatusCode::OK, reply))
}

async fn finish_mutation(
    tx: tokio_postgres::Transaction<'_>,
    answer: Result<serde_json::Value, step_up::Rejection>,
) -> Result<(StatusCode, serde_json::Value), StatusCode> {
    // Only a rejected credential budget or a fully accepted transaction reaches
    // this COMMIT. Any live transition error above drops/rolls back its factor.
    tx.commit()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    match answer {
        Ok(value) => Ok((StatusCode::CREATED, value)),
        Err(step_up::Rejection::InvalidCredentials) => Err(StatusCode::UNAUTHORIZED),
        Err(step_up::Rejection::RateLimited) => Err(StatusCode::TOO_MANY_REQUESTS),
    }
}

#[cfg(test)]
mod tests;
