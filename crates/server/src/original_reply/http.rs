// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{
    Router,
    body::to_bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use std::sync::Arc;
#[derive(Clone)]
pub struct StateData {
    pub database_url: String,
    pub hasher: Arc<TokenHasher>,
}
#[derive(Deserialize)]
#[serde(tag = "method", deny_unknown_fields)]
enum RequestBody {
    #[serde(rename = "current")]
    Current {
        v: u8,
        accepted_manifest_version: i64,
    },
    #[serde(rename = "read")]
    Read {
        v: u8,
        event_id: Uuid,
        accepted_manifest_version: i64,
    },
    #[serde(rename = "page")]
    Page {
        v: u8,
        accepted_manifest_version: i64,
        cursor: Option<page::Cursor>,
        limit: u16,
    },
    #[serde(rename = "consume")]
    Consume {
        v: u8,
        accepted_manifest_version: i64,
        params: Box<consumption::Request>,
    },
    #[serde(rename = "status")]
    Status {
        v: u8,
        accepted_manifest_version: i64,
        consumption_id: Uuid,
    },
}
pub fn router(state: StateData, enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route("/v1/reply-events", post(call))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}
async fn no_store(request: Request, next: middleware::Next) -> Response {
    let mut r = next.run(request).await;
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    r
}
fn failure(e: ConversationError) -> Response {
    let (status, code) = match e {
        ConversationError::Invalid => (StatusCode::BAD_REQUEST, "invalid"),
        ConversationError::Database(_) | ConversationError::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
        _ => (StatusCode::FORBIDDEN, "refused"),
    };
    (
        status,
        axum::Json(serde_json::json!({"error":{"code":code}})),
    )
        .into_response()
}
async fn call(State(state): State<Arc<StateData>>, request: Request) -> Response {
    let result=tokio::time::timeout(std::time::Duration::from_secs(10),async{
  if request.uri().query().is_some()||request.headers().contains_key(header::COOKIE)||request.headers().contains_key(header::ORIGIN){return Err(ConversationError::Invalid)}
  if request.headers().get_all(header::AUTHORIZATION).iter().count()!=1{return Err(ConversationError::Forbidden)}
  let token=request.headers().get(header::AUTHORIZATION).and_then(|v|v.to_str().ok()).and_then(|s|s.strip_prefix("Bearer ")).ok_or(ConversationError::Forbidden)?;
  let output_token=request.headers().get("x-zrotext-output-authorization").map(|v|v.to_str().ok().and_then(|s|s.strip_prefix("Bearer ")).map(|s|zeroize::Zeroizing::new(s.to_owned())).ok_or(ConversationError::Invalid)).transpose()?;
  if request.headers().get_all("x-zrotext-output-authorization").iter().count()>1{return Err(ConversationError::Invalid)}
  let token=zeroize::Zeroizing::new(token.to_owned());
  if !credential_shape(&token){return Err(ConversationError::Forbidden)}
  if request.headers().get(header::CONTENT_TYPE).and_then(|v|v.to_str().ok()).is_none_or(|s|s.split(';').next().map(str::trim)!=Some("application/json")){return Err(ConversationError::Invalid)}
  let bytes=to_bytes(request.into_body(),4096).await.map_err(|_|ConversationError::Invalid)?;
  let body:RequestBody=serde_json::from_slice(&bytes).map_err(|_|ConversationError::Invalid)?;
  let mut client=crate::runtime_db::connect(&state.database_url).await.map_err(|_|ConversationError::Unavailable)?;
  let p=authenticate(&client,&state.hasher,&token).await?;
  let output=if let Some(token)=output_token{Some(crate::workflow_runtime::authenticate(&client,&state.hasher,&token).await.map_err(|_|ConversationError::Forbidden)?)}else{None};
  if output.is_some()&&!matches!(&body,RequestBody::Consume{..}){return Err(ConversationError::Invalid)}
  let value=match body{
   RequestBody::Current{v:1,accepted_manifest_version}=>serde_json::json!({"kind":"current","result":current(&mut client,&p,accepted_manifest_version).await?}),
   RequestBody::Read{v:1,event_id,accepted_manifest_version}=>serde_json::json!({"kind":"read","result":read(&mut client,&p,event_id,accepted_manifest_version).await?}),
   RequestBody::Page{v:1,accepted_manifest_version,cursor,limit}=>serde_json::json!({"kind":"page","result":page::page(&mut client,&p,accepted_manifest_version,cursor,limit).await?}),
   RequestBody::Consume{v:1,accepted_manifest_version,params}=>serde_json::json!({"kind":"consume","result":consumption::consume(&mut client,&p,accepted_manifest_version,*params,output.as_ref()).await?}),
   RequestBody::Status{v:1,accepted_manifest_version,consumption_id}=>serde_json::json!({"kind":"status","result":page::status(&mut client,&p,accepted_manifest_version,consumption_id).await?}),
   _=>return Err(ConversationError::Invalid),
  };
  let bytes=serde_json::to_vec(&value).map_err(|_|ConversationError::Unavailable)?;
  if bytes.len()>512*1024{return Err(ConversationError::Unavailable)}
  Ok(([(header::CONTENT_TYPE,"application/json")],bytes).into_response())
 }).await;
    match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => failure(e),
        Err(_) => failure(ConversationError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn disabled_original_reader_has_no_route_and_never_opens_database() {
        let app = router(
            StateData {
                database_url: "postgres://unused".into(),
                hasher: Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
            },
            false,
        );
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/reply-events")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    #[test]
    fn reader_requests_reject_unknown_fields_and_model_supplied_authority() {
        for value in [
            serde_json::json!({"v":1,"method":"current","accepted_manifest_version":1,"allowed":true}),
            serde_json::json!({"v":1,"method":"read","event_id":Uuid::new_v4(),"accepted_manifest_version":1,"output_credential":"example"}),
            serde_json::json!({"v":1,"method":"consume","accepted_manifest_version":1,"params":{"request_id":Uuid::new_v4(),"event_id":Uuid::new_v4(),"active_request_id":null,"descriptor":null,"send":true}}),
        ] {
            assert!(serde_json::from_value::<RequestBody>(value).is_err())
        }
        assert!(serde_json::from_value::<RequestBody>(serde_json::json!({"v":1,"method":"consume","accepted_manifest_version":1,"params":{"request_id":Uuid::new_v4(),"event_id":Uuid::new_v4(),"active_request_id":null,"descriptor":null}})).is_ok());
    }
}
