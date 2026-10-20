// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit additive manifest install/history composition. The existing
//! first-only profile current endpoint and its consumers are unchanged.
use super::*;
use crate::manifest_install03::live as manifests;
mod body;
use body::{Body, Operation};
/// Library composition only. Startup does not mount this router implicitly.
pub async fn manifest_router(state: ProfileHttpState) -> Result<Router, &'static str> {
    let db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| "manifest database unavailable")?;
    crate::payload_profile_manifests::require(&*db)
        .await
        .map_err(|_| "manifest schema unavailable")?;
    Ok(Router::new()
        .route(
            "/v1/account/sealed/payload-profile/manifests",
            post(install),
        )
        .route(
            "/v1/account/sealed/payload-profile/manifests/status",
            post(status),
        )
        .route(
            "/v1/account/sealed/payload-profile/manifests/history",
            post(history),
        )
        .route(
            "/v1/account/sealed/payload-profile/manifests/current",
            post(current),
        )
        .with_state(Arc::new(state)))
}
macro_rules! handler {
    ($name:ident,$op:ident) => {
        async fn $name(State(state): State<Arc<ProfileHttpState>>, request: Request) -> Response {
            wire_response(handle(&state, Operation::$op, request).await)
        }
    };
}
handler!(install, Install);
handler!(status, Status);
handler!(history, History);
handler!(current, Current);
async fn handle(
    s: &ProfileHttpState,
    op: Operation,
    request: Request,
) -> Result<(StatusCode, serde_json::Value), StatusCode> {
    let (parts, stream) = request.into_parts();
    preflight(s, &parts.headers, matches!(op, Operation::Install)).await?;
    if parts.headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let raw = tokio::time::timeout(Duration::from_secs(5), to_bytes(stream, 96 * 1024))
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let body = body::parse(op, &raw)?;
    let mut db = crate::runtime_db::connect(&s.database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let tx = db
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    crate::payload_profile_manifests::require(&tx)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut owner =
        ordinary_owner03::authenticate(&tx, &s.hasher, &s.origin, source(&parts.headers)?)
            .await
            .map_err(|_| StatusCode::FORBIDDEN)?;
    let value = match body {
        Body::Current(line) => manifests::current_owner(&tx, &mut owner, line, &s.origin)
            .await
            .map_err(mapped)?,
        Body::Status { opening, hashes } => {
            manifests::observed_status(&tx, &mut owner, opening, hashes, &s.origin)
                .await
                .map_err(mapped)?
        }
        Body::History(cursor) => manifests::history(&tx, &mut owner, &cursor, &s.origin)
            .await
            .map_err(mapped)?,
        Body::Install {
            opening,
            statement,
            successor,
            signature,
            password,
            factor,
        } => {
            let command = manifests::InstallCommand03 {
                opening,
                statement: &statement,
                successor: &successor,
                signature: &signature,
            };
            if let Some(value) = manifests::exact_historical(&tx, &mut owner, &command, &s.origin)
                .await
                .map_err(mapped)?
            {
                drop(owner);
                tx.commit()
                    .await
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                return Ok((StatusCode::OK, value));
            }
            let answer = match step_up::verify(owner, &s.hasher, &s.cipher, &password, &factor)
                .await
                .map_err(|_| StatusCode::FORBIDDEN)?
            {
                step_up::Outcome::Rejected(reason) => Err(reason),
                step_up::Outcome::Verified(mut proof) => {
                    Ok(manifests::install(&tx, &mut proof, command, &s.origin)
                        .await
                        .map_err(mapped)?)
                }
            };
            return finish_mutation(tx, answer).await;
        }
    };
    drop(owner);
    tx.commit()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((StatusCode::OK, value))
}
