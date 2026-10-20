// SPDX-License-Identifier: AGPL-3.0-only
//! Additive actual03 content-consent HTTP routes. Explicit library mounting
//! requires its closed storage; main/default routes remain unchanged.
use super::*;
use crate::conversation_interval03::{IntegrationReader03, live as interval};
use crate::sealed_inbound::line_activation::v2_runtime::object_body;
use uuid::Uuid;
mod body;
use body::{Body, Operation};

pub async fn router(state: ProfileHttpState) -> Result<Router, &'static str> {
    let db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| "interval database unavailable")?;
    crate::conversation_profile03_storage::require(&*db)
        .await
        .map_err(|_| "interval schema unavailable")?;
    Ok(Router::new()
        .route(
            "/v1/owner/conversation/interval03/challenges",
            post(reserve),
        )
        .route("/v1/owner/conversation/interval03/requests", post(request))
        .route("/v1/owner/conversation/interval03/status", post(status))
        .route("/v1/owner/conversation/interval03/stop", post(stop))
        .with_state(Arc::new(state)))
}
macro_rules! route {
    ($name:ident,$op:ident) => {
        async fn $name(State(state): State<Arc<ProfileHttpState>>, request: Request) -> Response {
            let result = handle(&state, Operation::$op, request).await;
            if matches!(&result, Ok((StatusCode::NO_CONTENT, _))) {
                let mut response = StatusCode::NO_CONTENT.into_response();
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                response
                    .headers_mut()
                    .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
                response
            } else {
                wire_response(result)
            }
        }
    };
}
route!(reserve, Reserve);
route!(request, Request);
route!(status, Status);
route!(stop, Stop);
async fn handle(
    s: &ProfileHttpState,
    op: Operation,
    request: Request,
) -> Result<(StatusCode, serde_json::Value), StatusCode> {
    let (parts, stream) = request.into_parts();
    preflight(s, &parts.headers, !matches!(op, Operation::Status)).await?;
    if parts.headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = tokio::time::timeout(Duration::from_secs(5), to_bytes(stream, 96 * 1024))
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let input = body::parse(op, &bytes)?;
    let mut db = crate::runtime_db::connect(&s.database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let tx = db
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    crate::conversation_profile03_storage::require(&tx)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut owner =
        ordinary_owner03::authenticate(&tx, &s.hasher, &s.origin, source(&parts.headers)?)
            .await
            .map_err(|_| StatusCode::FORBIDDEN)?;
    let (code, reply) = match input {
        Body::Reserve {
            opening,
            line,
            peer,
            archive,
            phone,
            browser,
            expires,
            integrations,
        } => {
            let (new, reply) = interval::reserve(
                &tx,
                &mut owner,
                interval::Reserve03 {
                    opening,
                    line,
                    peer: peer.as_bytes(),
                    archive,
                    phone,
                    browser,
                    expires_ms: expires,
                    integrations: &integrations,
                },
                &s.origin,
            )
            .await
            .map_err(mapped)?;
            (
                if new {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                reply,
            )
        }
        Body::Status { opening, interval } => (
            StatusCode::OK,
            interval::owner_status(&tx, &mut owner, opening, interval)
                .await
                .map_err(mapped)?,
        ),
        Body::Stop { interval } => {
            interval::stop(&tx, &mut owner, interval)
                .await
                .map_err(mapped)?;
            (StatusCode::NO_CONTENT, serde_json::Value::Null)
        }
        Body::Request {
            opening,
            interval,
            statement,
            signature,
            password,
            factor,
        } => {
            if let Some(reply) = interval::historical_request(
                &tx, &mut owner, opening, interval, &statement, &signature,
            )
            .await
            .map_err(mapped)?
            {
                drop(owner);
                tx.commit()
                    .await
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                return Ok((StatusCode::OK, reply));
            }
            let answer = {
                match step_up::verify(owner, &s.hasher, &s.cipher, &password, &factor)
                    .await
                    .map_err(|_| StatusCode::FORBIDDEN)?
                {
                    step_up::Outcome::Rejected(reason) => Err(reason),
                    step_up::Outcome::Verified(mut proof) => Ok(interval::request(
                        &tx, &mut proof, opening, interval, &statement, &signature, &s.origin,
                    )
                    .await
                    .map_err(mapped)?
                    .1),
                }
            };
            return finish_mutation(tx, answer).await;
        }
    };
    owner
        .revalidate()
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    drop(owner);
    tx.commit()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((code, reply))
}
