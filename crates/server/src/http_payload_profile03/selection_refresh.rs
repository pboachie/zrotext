// SPDX-License-Identifier: AGPL-3.0-only
//! Optional authenticated same-phone restoration. No implicit root, physical
//! selection, current content permission or main-startup mount is created.
use super::*;
use crate::{
    sealed_inbound::line_activation::v2_runtime::object_body, selection_refresh03::live as refresh,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
enum Op {
    Reserve,
    Status,
    Proof,
    Approve,
    Installed,
}
object_body! {struct Reserve{v:u8,opening_id:String,line_id:String,password:String,factor:String}}
object_body! {struct Status{v:u8,opening_id:String,line_id:String}}
object_body! {struct Proof{v:u8,opening_id:String,refresh_id:String}}
object_body! {struct Approve{v:u8,opening_id:String,refresh_id:String,bundle:String,password:String,factor:String}}
enum Input {
    Reserve {
        opening: Uuid,
        line: Uuid,
        password: String,
        factor: String,
    },
    Status {
        opening: Uuid,
        line: Uuid,
    },
    Proof {
        opening: Uuid,
        refresh: Uuid,
    },
    Approve {
        opening: Uuid,
        refresh: Uuid,
        bundle: Vec<u8>,
        password: String,
        factor: String,
    },
    Installed {
        opening: Uuid,
        refresh: Uuid,
    },
}
fn parse(op: Op, raw: &[u8]) -> Result<Input, StatusCode> {
    macro_rules! body {
        ($t:ty) => {
            serde_json::from_slice::<$t>(raw).map_err(|_| StatusCode::BAD_REQUEST)?
        };
    }
    if raw.is_empty() || raw.len() > 96 * 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(match op {
        Op::Reserve => {
            let b = body!(Reserve);
            request::version(b.v)?;
            request::credentials(&b.password, &b.factor)?;
            Input::Reserve {
                opening: request::id(&b.opening_id)?,
                line: request::id(&b.line_id)?,
                password: b.password,
                factor: b.factor,
            }
        }
        Op::Status => {
            let b = body!(Status);
            request::version(b.v)?;
            Input::Status {
                opening: request::id(&b.opening_id)?,
                line: request::id(&b.line_id)?,
            }
        }
        Op::Proof | Op::Installed => {
            let b = body!(Proof);
            request::version(b.v)?;
            let opening = request::id(&b.opening_id)?;
            let refresh = request::id(&b.refresh_id)?;
            if matches!(op, Op::Proof) {
                Input::Proof { opening, refresh }
            } else {
                Input::Installed { opening, refresh }
            }
        }
        Op::Approve => {
            let b = body!(Approve);
            request::version(b.v)?;
            request::credentials(&b.password, &b.factor)?;
            Input::Approve {
                opening: request::id(&b.opening_id)?,
                refresh: request::id(&b.refresh_id)?,
                bundle: request::binary(&b.bundle, 745, 745)?,
                password: b.password,
                factor: b.factor,
            }
        }
    })
}
pub(super) async fn router(state: ProfileHttpState) -> Result<Router, &'static str> {
    let db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| "refresh database unavailable")?;
    crate::payload_profile_selections::require(&*db)
        .await
        .map_err(|_| "refresh schema unavailable")?;
    Ok(Router::new()
        .route(
            "/v1/account/sealed/payload-profile/selection-refresh/challenges",
            post(reserve),
        )
        .route(
            "/v1/account/sealed/payload-profile/selection-refresh/challenges/status",
            post(status),
        )
        .route(
            "/v1/account/sealed/payload-profile/selection-refresh/challenges/proof",
            post(proof),
        )
        .route(
            "/v1/account/sealed/payload-profile/selection-refresh/approvals",
            post(approve),
        )
        .route(
            "/v1/account/sealed/payload-profile/selection-refresh/installed",
            post(installed),
        )
        .with_state(Arc::new(state)))
}
macro_rules! route {
    ($name:ident,$op:ident) => {
        async fn $name(State(state): State<Arc<ProfileHttpState>>, request: Request) -> Response {
            wire_response(handle(&state, Op::$op, request).await)
        }
    };
}
route!(reserve, Reserve);
route!(status, Status);
route!(proof, Proof);
route!(approve, Approve);
route!(installed, Installed);
async fn handle(
    state: &ProfileHttpState,
    op: Op,
    request: Request,
) -> Result<(StatusCode, serde_json::Value), StatusCode> {
    let (parts, body) = request.into_parts();
    preflight(
        state,
        &parts.headers,
        matches!(op, Op::Reserve | Op::Approve),
    )
    .await?;
    if parts.headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let raw = tokio::time::timeout(Duration::from_secs(5), to_bytes(body, 96 * 1024))
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let input = parse(op, &raw)?;
    let mut db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let tx = db
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    crate::payload_profile_selections::require(&tx)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut owner =
        ordinary_owner03::authenticate(&tx, &state.hasher, &state.origin, source(&parts.headers)?)
            .await
            .map_err(|_| StatusCode::FORBIDDEN)?;
    let reply = match input {
        Input::Status { opening, line } => {
            refresh::status(&tx, &mut owner, opening, line, &state.origin)
                .await
                .map_err(mapped)?
        }
        Input::Proof { opening, refresh } => {
            refresh::proof(&tx, &mut owner, opening, refresh, &state.origin)
                .await
                .map_err(mapped)?
        }
        Input::Installed { opening, refresh } => {
            refresh::installed(&tx, &mut owner, opening, refresh, &state.origin)
                .await
                .map_err(mapped)?
        }
        Input::Reserve {
            opening,
            line,
            password,
            factor,
        } => {
            match refresh::status(&tx, &mut owner, opening, line, &state.origin).await {
                Ok(reply) => {
                    drop(owner);
                    tx.commit()
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    return Ok((StatusCode::OK, reply));
                }
                Err(live::Error::NotFound) => {}
                Err(error) => return Err(mapped(error)),
            }
            let answer =
                match step_up::verify(owner, &state.hasher, &state.cipher, &password, &factor)
                    .await
                    .map_err(|_| StatusCode::FORBIDDEN)?
                {
                    step_up::Outcome::Rejected(reason) => Err(reason),
                    step_up::Outcome::Verified(mut proof) => {
                        Ok(
                            refresh::reserve(&tx, &mut proof, opening, line, &state.origin)
                                .await
                                .map_err(mapped)?
                                .1,
                        )
                    }
                };
            return finish_mutation(tx, answer).await;
        }
        Input::Approve {
            opening,
            refresh,
            bundle,
            password,
            factor,
        } => {
            if let Some(reply) = refresh::historical_approval(
                &tx,
                &mut owner,
                opening,
                refresh,
                &bundle,
                &state.origin,
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
            let answer =
                match step_up::verify(owner, &state.hasher, &state.cipher, &password, &factor)
                    .await
                    .map_err(|_| StatusCode::FORBIDDEN)?
                {
                    step_up::Outcome::Rejected(reason) => Err(reason),
                    step_up::Outcome::Verified(mut proof) => Ok(refresh::approve(
                        &tx,
                        &mut proof,
                        opening,
                        refresh,
                        &bundle,
                        &state.origin,
                    )
                    .await
                    .map_err(mapped)?
                    .1),
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
    Ok((StatusCode::OK, reply))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passive_refresh_shapes_cannot_import_authority_or_alternative_ids() {
        let valid=serde_json::json!({"v":1,"opening_id":Uuid::from_u128(1),"refresh_id":Uuid::from_u128(2)}).to_string();
        assert!(parse(Op::Proof, valid.as_bytes()).is_ok());
        assert!(parse(Op::Installed, valid.as_bytes()).is_ok());
        for raw in [
            format!("{{\"fresh_mfa\":true,{}", &valid[1..]),
            format!("{{\"v\":1,{}", &valid[1..]),
            valid.replace(
                "00000000-0000-0000-0000-000000000001",
                "00000000000000000000000000000001",
            ),
            "[]".into(),
        ] {
            assert!(parse(Op::Proof, raw.as_bytes()).is_err());
        }
    }
}
